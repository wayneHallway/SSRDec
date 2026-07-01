#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disk-safe Bringup-Bench build/test runner.

Key safeguards:
1. Each run uses an isolated temporary suite and automatically removes old ones.
2. Every make command runs in its own process group; timeouts terminate the
   entire group so background processes cannot retain FOO or .host files.
3. Logs are size-limited before being written to prevent unbounded test output
   from filling the disk.
4. Only the most recent N output directories are retained.
5. Each benchmark attempts make clean and removes residual host executables.
6. Temporary directories and child processes are cleaned on errors, Ctrl-C,
   and normal exit.
"""

import atexit
import csv
import errno
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ================= Configuration =================
COMPILER = "gcc"
OPT_LEVEL = "-O0"

OUTPUT_BASE_DIR = "./build_outputs"
TARGET_ARCH = "host"

SOURCE_DIR = "/home/lhw/TraceCoder-main/results/O0"
BENCH_DIR = "/home/lhw/codetran/recon/bringup-bench"

BUILD_TIMEOUT = 120
TEST_TIMEOUT = 120
CLEAN_TIMEOUT = 30

# Whether to copy all of bringup-bench into a temporary directory.
# True: preserve the original BENCH_DIR; recommended.
# False: overwrite and build sources directly in the original BENCH_DIR; not recommended.
USE_TEMP_SUITE_DIR = True

# Whether to remove the current run's temporary directory.
# True is strongly recommended; repeated runs can otherwise fill the disk quickly.
CLEAN_TEMP_SUITE_DIR = True

# Keep all temporary suites here for centralized cleanup.
# Avoid the project directory so they are not mistaken for experiment outputs.
TEMP_PARENT_DIR = "/tmp/bringup_bench_suites"

# At startup, remove old suites under TEMP_PARENT_DIR and retain the newest N.
KEEP_LAST_TEMP_RUNS = 1

# Retain only the newest N output runs.
KEEP_LAST_OUTPUT_RUNS = 5

# Maximum number of characters stored in each build.log or test.log.
# Oversized logs retain their head and tail, with the middle truncated.
MAX_LOG_CHARS = 300_000
MAX_JSON_LOG_CHARS = 60_000

# Whether to copy compiled host executables into the output directory.
# Use False when only pass rates matter to reduce disk usage significantly.
COPY_HOST_EXECUTABLE = False

# Whether to run make clean after each benchmark test.
# True reduces disk usage; use False to retain intermediate artifacts for debugging.
CLEAN_AFTER_EACH_BENCH = True

# Stop early below this free-space threshold to avoid filling the root filesystem.
MIN_FREE_SPACE_GB = 5.0

# Whether startup should terminate stale current-user processes holding deleted
# bringup-bench files. Use caution: matching processes whose command line
# contains BENCH_DIR or TEMP_PARENT_DIR will be terminated.
KILL_STALE_DELETED_FILE_PROCESSES_AT_START = False
# ============================================

_ACTIVE_PROCESS_GROUPS = set()
_TMP_ROOT = None


def now_run_id():
    return time.strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}"


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def disk_free_gb(path):
    """Return free space, in GiB, on the filesystem containing path."""
    target = path if os.path.exists(path) else os.path.dirname(os.path.abspath(path)) or "/"
    usage = shutil.disk_usage(target)
    return usage.free / (1024 ** 3)


def check_free_space_or_raise(path, min_gb=MIN_FREE_SPACE_GB):
    free = disk_free_gb(path)
    if free < min_gb:
        raise RuntimeError(
            f"Insufficient disk space: the filesystem containing {path} has "
            f"{free:.2f} GB free, below the {min_gb:.2f} GB threshold. "
            "Stopping to avoid filling the disk."
        )


def compact_text(text, max_chars):
    """Limit log size while retaining its beginning and end."""
    if text is None:
        return ""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    omitted = len(text) - max_chars
    return (
        text[:half]
        + f"\n\n...[log too large; omitted {omitted} characters from the middle]...\n\n"
        + text[-half:]
    )


def run_cmd(cmd, cwd, timeout=None):
    """
    Run a shell command and return (success, output).

    Key behavior:
    - start_new_session=True creates an isolated process group.
    - On timeout, killpg terminates make and all of its child processes.
    - communicate() ensures the stdout pipe closes without leaking descriptors.
    """
    proc = None
    pgid = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            start_new_session=True,
        )
        pgid = os.getpgid(proc.pid)
        _ACTIVE_PROCESS_GROUPS.add(pgid)

        try:
            out, _ = proc.communicate(timeout=timeout)
            return proc.returncode == 0, out or ""
        except subprocess.TimeoutExpired:
            kill_process_group(pgid)
            out, _ = proc.communicate()
            return False, compact_text(
                (out or "")
                + f"\n[Timeout] Execution timed out after {timeout}s; "
                f"terminated process group pgid={pgid}.\n",
                MAX_LOG_CHARS,
            )

    except Exception as e:
        if pgid is not None:
            kill_process_group(pgid)
        return False, f"[Exception] {type(e).__name__}: {e}"
    finally:
        if pgid is not None:
            _ACTIVE_PROCESS_GROUPS.discard(pgid)


def kill_process_group(pgid):
    """Send SIGTERM, then SIGKILL, to reclaim child processes reliably."""
    if pgid is None:
        return
    for sig, wait_s in ((signal.SIGTERM, 1.5), (signal.SIGKILL, 0.2)):
        try:
            os.killpg(pgid, sig)
            time.sleep(wait_s)
        except ProcessLookupError:
            return
        except Exception:
            pass


def kill_all_active_process_groups():
    for pgid in list(_ACTIVE_PROCESS_GROUPS):
        kill_process_group(pgid)
        _ACTIVE_PROCESS_GROUPS.discard(pgid)


def safe_rmtree(path):
    if not path or not os.path.exists(path):
        return
    try:
        shutil.rmtree(path)
    except Exception as e:
        print(f"⚠️ Failed to remove directory {path}: {e}")


def cleanup_current_tmp_root():
    global _TMP_ROOT
    kill_all_active_process_groups()
    if USE_TEMP_SUITE_DIR and CLEAN_TEMP_SUITE_DIR and _TMP_ROOT:
        safe_rmtree(_TMP_ROOT)
        _TMP_ROOT = None


def handle_exit_signal(signum, frame):
    print(f"\n⚠️ Received signal {signum}; cleaning child processes and temporary files...")
    cleanup_current_tmp_root()
    sys.exit(128 + signum)


atexit.register(cleanup_current_tmp_root)
signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)


def cleanup_old_dirs(parent_dir, keep_last_n):
    """Remove old direct children of parent_dir, retaining the newest keep_last_n."""
    if keep_last_n is None or keep_last_n < 0:
        return
    if not os.path.isdir(parent_dir):
        return

    dirs = []
    for name in os.listdir(parent_dir):
        path = os.path.join(parent_dir, name)
        if os.path.isdir(path):
            try:
                dirs.append((os.path.getmtime(path), path))
            except OSError:
                pass

    dirs.sort(reverse=True)
    for _, path in dirs[keep_last_n:]:
        safe_rmtree(path)


def cleanup_old_outputs(output_base_dir, opt_dir_name, keep_last_n=KEEP_LAST_OUTPUT_RUNS):
    opt_root = os.path.join(output_base_dir, opt_dir_name)
    cleanup_old_dirs(opt_root, keep_last_n)


def cleanup_stale_deleted_file_processes():
    """
    Optionally terminate stale current-user processes that retain related
    deleted files. Disabled by default to avoid disrupting other experiments.
    """
    if not KILL_STALE_DELETED_FILE_PROCESSES_AT_START:
        return

    try:
        me = str(os.getuid())
        cmd = ["lsof", "-nP", "+L1"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
        pids = set()
        for line in res.stdout.splitlines()[1:]:
            if "(deleted)" not in line:
                continue
            if BENCH_DIR not in line and TEMP_PARENT_DIR not in line and "bringup-bench" not in line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            pid = parts[1]
            user = parts[2]
        # lsof's USER column may contain a name rather than a UID, so do not require a match.
            if pid.isdigit() and int(pid) != os.getpid():
                pids.add(int(pid))
        for pid in sorted(pids):
            try:
                os.kill(pid, signal.SIGKILL)
                print(f"🧹 Terminated stale process holding deleted files: PID={pid}")
            except ProcessLookupError:
                pass
            except PermissionError:
                print(f"⚠️ Permission denied while terminating stale process PID={pid}")
    except FileNotFoundError:
        print("⚠️ lsof is not installed; skipping cleanup of deleted-file holders.")
    except Exception as e:
        print(f"⚠️ Failed to clean up processes holding deleted files: {e}")


def collect_benchmarks(source_dir):
    """
    Recursively collect benchmark source files from SOURCE_DIR.

    Priority:
    1. <bench>.c
    2. <bench>_fixed.c
    """
    bench_set = set()
    file_map = {}

    for root, _, files in os.walk(source_dir):
        for f in files:
            if f.endswith(".c") and not f.endswith("_fixed.c"):
                bench = f[:-2]
                bench_set.add(bench)
                file_map.setdefault(bench, {})
                file_map[bench]["primary"] = os.path.join(root, f)
            elif f.endswith("_fixed.c"):
                bench = f[:-8]
                bench_set.add(bench)
                file_map.setdefault(bench, {})
                file_map[bench]["fallback"] = os.path.join(root, f)

    return sorted(bench_set), file_map


def choose_source_file(bench, file_map):
    """Prefer a regular .c file, falling back to _fixed.c."""
    paths = file_map.get(bench, {})
    primary_path = paths.get("primary")
    fallback_path = paths.get("fallback")

    if primary_path and os.path.exists(primary_path):
        return primary_path, "primary"
    if fallback_path and os.path.exists(fallback_path):
        return fallback_path, "fallback"
    return None, None


def is_executable_binary(path):
    """Return whether a file is a genuine ELF or Mach-O executable."""
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        return False

    try:
        with open(path, "rb") as fp:
            header = fp.read(4)
        return (
            header.startswith(b"\x7fELF")
            or header
            in (
                b"\xcf\xfa\xed\xfe",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe",
            )
        )
    except Exception:
        return False


def find_host_executable(bench_dir, bench_name, build_start_time=None):
    """Find the host executable produced by the current build."""
    guesses = [
        bench_name + ".host",
        bench_name,
        bench_name + ".elf",
        "main.host",
        "main",
        "main.elf",
        "a.out",
    ]

    candidates = []

    def add_candidate(path):
        if not is_executable_binary(path):
            return
        if build_start_time is not None:
            try:
                if os.path.getmtime(path) < build_start_time - 1:
                    return
            except Exception:
                return
        candidates.append(path)

    for name in guesses:
        add_candidate(os.path.join(bench_dir, name))

    skip_suffixes = (
        ".c", ".h", ".cpp", ".o", ".out", ".hash",
        ".txt", ".md", ".py", ".sh", ".S", ".json", ".log",
    )

    for root, _, files in os.walk(bench_dir):
        for f in files:
            if f.endswith(skip_suffixes):
                continue
            add_candidate(os.path.join(root, f))

    if not candidates:
        return None

    candidates = list(set(candidates))
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def remove_old_host_outputs(bench_dir, bench_name):
    """Remove residual host executable artifacts from the benchmark directory."""
    names = [
        bench_name + ".host",
        bench_name,
        bench_name + ".elf",
        "main.host",
        "main",
        "main.elf",
        "a.out",
    ]

    for name in names:
        path = os.path.join(bench_dir, name)
        if os.path.isfile(path):
            try:
                if is_executable_binary(path) or os.access(path, os.X_OK):
                    os.remove(path)
            except Exception:
                pass


def copy_whole_suite_to_temp(run_id):
    """
    Copy the entire Bringup-Bench project into a temporary directory.

    Behavior:
    - Store every temporary suite under TEMP_PARENT_DIR.
    - Remove old suites before startup.
    - Ignore known disposable cache directories.
    """
    ensure_dir(TEMP_PARENT_DIR)
    cleanup_old_dirs(TEMP_PARENT_DIR, KEEP_LAST_TEMP_RUNS)
    check_free_space_or_raise(TEMP_PARENT_DIR)

    tmp_root = tempfile.mkdtemp(prefix=f"bringup_suite_{run_id}_", dir=TEMP_PARENT_DIR)
    tmp_suite_dir = os.path.join(tmp_root, "bringup-bench")

    ignore_patterns = shutil.ignore_patterns(
        ".git",
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".cache",
    )

    shutil.copytree(BENCH_DIR, tmp_suite_dir, ignore=ignore_patterns)
    return tmp_root, tmp_suite_dir


def prepare_suite_dir(run_id):
    if USE_TEMP_SUITE_DIR:
        return copy_whole_suite_to_temp(run_id)
    return None, BENCH_DIR


def write_text_file(path, content, max_chars=MAX_LOG_CHARS):
    """Write a log file with size limits applied."""
    ensure_dir(os.path.dirname(path))
    content = compact_text(content or "", max_chars)
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)


def rate_value(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def make_metric(name, description, numerator, denominator):
    rate = rate_value(numerator, denominator)
    return {
        "name": name,
        "description": description,
        "numerator": numerator,
        "denominator": denominator,
        "rate": rate,
        "percent": rate * 100.0,
    }


def format_final_result(compile_percent, link_percent, execution_percent, title=""):
    lines = []
    if title:
        lines.append(title)
    lines.extend([
        f".c \u2192 .o       {compile_percent:.0f}%",
        f"link          {link_percent:.0f}%",
        f"execution     {execution_percent:.0f}%",
    ])
    return "\n".join(lines)


def write_metrics_reports(output_dir, config, metrics, benchmark_results, errors):
    ensure_dir(output_dir)

    report = {
        "config": config,
        "metrics": metrics,
        "benchmark_results": benchmark_results,
        "errors": errors,
    }

    summary_json = os.path.join(output_dir, "metrics_summary.json")
    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=4)

    summary_csv = os.path.join(output_dir, "metrics_summary.csv")
    with open(summary_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["name", "description", "numerator", "denominator", "rate", "percent"],
        )
        writer.writeheader()
        for metric in metrics:
            writer.writerow(metric)

    results_json = os.path.join(output_dir, "benchmark_results.json")
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, ensure_ascii=False, indent=4)

    summary_md = os.path.join(output_dir, "metrics_summary.md")
    lines = [
        "# Bringup-Bench Metrics Summary",
        "",
        "| Metric | Meaning | Result | Rate |",
        "| --- | --- | ---: | ---: |",
    ]
    for metric in metrics:
        lines.append(
            "| {name} | {description} | {numerator}/{denominator} | {percent:.2f}% |".format(
                **metric
            )
        )
    lines.extend(
        [
            "",
            "## Output Files",
            "- JSON summary: `metrics_summary.json`",
            "- CSV summary: `metrics_summary.csv`",
            "- Benchmark details: `benchmark_results.json`",
        ]
    )
    write_text_file(summary_md, "\n".join(lines) + "\n", max_chars=MAX_LOG_CHARS)

    return {
        "summary_json": summary_json,
        "summary_csv": summary_csv,
        "summary_md": summary_md,
        "results_json": results_json,
    }


def print_log_tail(title, log, n=50):
    """Print the final n lines of a log."""
    print(title)
    lines = (log or "").strip().split("\n")
    tail = lines[-n:] if lines else [""]
    print("      " + "\n      ".join(tail))


def make_command(rule):
    return (
        f'make TARGET={TARGET_ARCH} '
        f'CC="{COMPILER}" '
        f'EXTRA_CFLAGS="{OPT_LEVEL}" '
        f'{rule}'
    )


def make_translation_unit_compile_command(source_c_path, object_path):
    return (
        f'{shlex.quote(COMPILER)} {OPT_LEVEL} -I. '
        f'-c {shlex.quote(source_c_path)} '
        f'-o {shlex.quote(object_path)} -w'
    )


def clean_benchmark_dir(bench_build_dir, bench):
    """Best-effort cleanup of the current benchmark's build artifacts."""
    if not os.path.isdir(bench_build_dir):
        return
    clean_cmd = make_command("clean")
    run_cmd(clean_cmd, bench_build_dir, timeout=CLEAN_TIMEOUT)
    remove_old_host_outputs(bench_build_dir, bench)


def main():
    global _TMP_ROOT

    run_id = now_run_id()
    opt_dir_name = OPT_LEVEL.strip("-") or "default"
    out_root = os.path.join(OUTPUT_BASE_DIR, opt_dir_name)
    out_dir = os.path.abspath(os.path.join(out_root, run_id))

    ensure_dir(out_dir)
    cleanup_old_outputs(OUTPUT_BASE_DIR, opt_dir_name, KEEP_LAST_OUTPUT_RUNS)
    check_free_space_or_raise(out_dir)
    cleanup_stale_deleted_file_processes()

    benchmarks, file_map = collect_benchmarks(SOURCE_DIR)
    tmp_root, suite_dir = prepare_suite_dir(run_id)
    _TMP_ROOT = tmp_root

    print(f"🎯 Starting {len(benchmarks)} benchmark(s)")
    print(f"📁 SOURCE_DIR: {SOURCE_DIR}")
    print(f"📁 Original BENCH_DIR: {BENCH_DIR}")
    print(f"📁 Active build suite: {suite_dir}")
    print(f"📁 Output directory: {out_dir}")
    print(f"🎯 TARGET: {TARGET_ARCH}")
    print(f"🔧 CC: {COMPILER}")
    print(f"🔧 EXTRA_CFLAGS: {OPT_LEVEL}")
    print(f"🧯 Maximum stored log size: {MAX_LOG_CHARS} chars/file")
    print(f"🧹 Output runs retained: {KEEP_LAST_OUTPUT_RUNS}")
    print(f"🧹 Old temporary suites retained: {KEEP_LAST_TEMP_RUNS}")
    print(f"💾 Minimum free-space threshold: {MIN_FREE_SPACE_GB:.1f} GB")

    if USE_TEMP_SUITE_DIR:
        print("🧪 Mode: copy bringup-bench to a temporary directory")
    else:
        print("⚠️ Mode: build in the original bringup-bench tree and overwrite sources")
    print()

    total_benchmarks = len(benchmarks)
    translation_unit_success_count = 0
    link_success_count = 0
    build_success_count = 0
    test_success_count = 0
    build_fail_count = 0
    test_fail_count = 0
    skipped_count = 0
    stopped_by_disk_guard = False

    error_summary = {}
    benchmark_results = []

    try:
        for bench in benchmarks:
            try:
                check_free_space_or_raise(out_dir)
            except RuntimeError as e:
                print(f"\n🛑 {e}")
                stopped_by_disk_guard = True
                break

            source_c_path, source_kind = choose_source_file(bench, file_map)

            if not source_c_path:
                print(f"⚠️ Skipping {bench}: no .c or _fixed.c file found in SOURCE_DIR")
                skipped_count += 1
                benchmark_results.append({
                    "benchmark": bench,
                    "source_file": "",
                    "target_file": "",
                    "build_dir": "",
                    "translation_unit_compile": False,
                    "link_success": False,
                    "full_build": False,
                    "execution_success": False,
                    "skipped": True,
                    "stage": "source",
                    "error": "Missing Source",
                })
                error_summary[bench] = {
                    "stage": "source",
                    "error_type": "Missing Source",
                    "full_log": "No .c or _fixed.c file was found in SOURCE_DIR",
                }
                continue

            if source_kind == "primary":
                print(f"📖 [{bench}] Reading primary source: {source_c_path}")
            else:
                print(f"📖 [{bench}] Primary .c file not found; using fallback: {source_c_path}")

            bench_build_dir = os.path.join(suite_dir, bench)

            if not os.path.isdir(bench_build_dir):
                print(
                    f"⚠️ Skipping {bench}: matching benchmark directory not found "
                    f"in the suite: {bench_build_dir}"
                )
                skipped_count += 1
                benchmark_results.append({
                    "benchmark": bench,
                    "source_file": source_c_path,
                    "target_file": "",
                    "build_dir": bench_build_dir,
                    "translation_unit_compile": False,
                    "link_success": False,
                    "full_build": False,
                    "execution_success": False,
                    "skipped": True,
                    "stage": "benchmark_dir",
                    "error": "Missing Benchmark Directory",
                })
                error_summary[bench] = {
                    "stage": "benchmark_dir",
                    "error_type": "Missing Benchmark Directory",
                    "source_file": source_c_path,
                    "build_dir": bench_build_dir,
                    "full_log": (
                        f"Matching benchmark directory not found in suite: "
                        f"{bench_build_dir}"
                    ),
                }
                continue

            target_c_path = os.path.join(bench_build_dir, bench + ".c")

            try:
                shutil.copy2(source_c_path, target_c_path)
            except Exception as e:
                print(f"❌ {bench}: failed to overwrite source: {e}")
                skipped_count += 1
                benchmark_results.append({
                    "benchmark": bench,
                    "source_file": source_c_path,
                    "target_file": target_c_path,
                    "build_dir": bench_build_dir,
                    "translation_unit_compile": False,
                    "link_success": False,
                    "full_build": False,
                    "execution_success": False,
                    "skipped": True,
                    "stage": "copy_source",
                    "error": str(e),
                })
                error_summary[bench] = {
                    "stage": "copy_source",
                    "error_type": "Copy Source Error",
                    "source_file": source_c_path,
                    "target_file": target_c_path,
                    "build_dir": bench_build_dir,
                    "full_log": str(e),
                }
                continue

            bench_out_dir = os.path.join(out_dir, bench)
            ensure_dir(bench_out_dir)

            bench_result = {
                "benchmark": bench,
                "source_file": source_c_path,
                "source_kind": source_kind,
                "target_file": target_c_path,
                "build_dir": bench_build_dir,
                "translation_unit_compile": False,
                "link_success": False,
                "full_build": False,
                "execution_success": False,
                "skipped": False,
                "stage": "",
                "error": "",
            }

            tu_object_path = os.path.join(bench_out_dir, f"{bench}.tu.o")
            tu_compile_cmd = make_translation_unit_compile_command(target_c_path, tu_object_path)
            tu_compile_start = time.time()
            tu_compile_ok, tu_compile_log = run_cmd(
                tu_compile_cmd,
                bench_build_dir,
                timeout=BUILD_TIMEOUT,
            )
            tu_compile_time = time.time() - tu_compile_start
            tu_compile_log_path = os.path.join(bench_out_dir, "translation_unit_compile.log")
            write_text_file(tu_compile_log_path, tu_compile_log)
            bench_result.update({
                "translation_unit_compile": tu_compile_ok,
                "translation_unit_compile_command": tu_compile_cmd,
                "translation_unit_compile_time": tu_compile_time,
                "translation_unit_compile_log_path": tu_compile_log_path,
                "translation_unit_object": tu_object_path if tu_compile_ok else "",
            })
            if tu_compile_ok:
                translation_unit_success_count += 1
            else:
                print(f"{bench:<24} | TU compile: ❌ FAIL ({tu_compile_time:6.2f}s)")

            build_cmd = make_command("clean build")
            test_cmd = make_command("test")

            remove_old_host_outputs(bench_build_dir, bench)

            # ---------- Build stage ----------
            build_start_time = time.time()
            build_ok, build_log = run_cmd(
                build_cmd,
                bench_build_dir,
                timeout=BUILD_TIMEOUT,
            )
            build_time = time.time() - build_start_time

            build_log_path = os.path.join(bench_out_dir, "build.log")
            write_text_file(build_log_path, build_log)

            elf_path = find_host_executable(
                bench_build_dir,
                bench,
                build_start_time=build_start_time,
            )

            copied_elf_path = None
            if COPY_HOST_EXECUTABLE and elf_path:
                copied_elf_path = os.path.join(bench_out_dir, os.path.basename(elf_path))
                try:
                    shutil.copy2(elf_path, copied_elf_path)
                except Exception:
                    copied_elf_path = None

            if elf_path:
                link_success_count += 1
                bench_result["link_success"] = True
            bench_result.update({
                "build_command": build_cmd,
                "build_time": build_time,
                "build_log_path": build_log_path,
                "host_executable": elf_path,
                "copied_host_executable": copied_elf_path,
            })

            if not build_ok:
                build_fail_count += 1
                bench_result.update({
                    "full_build": False,
                    "stage": "build",
                    "error": "Compile Error",
                })
                benchmark_results.append(bench_result)
                print(
                    f"{bench:<24} | Build: ❌ FAIL ({build_time:6.2f}s) "
                    f"| Run: ⏸️ SKIP"
                )
                print_log_tail("  [!] Compilation error summary, final 50 lines:", build_log, n=50)
                print("-" * 75)

                error_summary[bench] = {
                    "stage": "build",
                    "error_type": "Compile Error",
                    "source_file": source_c_path,
                    "target_file": target_c_path,
                    "build_dir": bench_build_dir,
                    "build_command": build_cmd,
                    "build_log_path": build_log_path,
                    "host_executable": elf_path,
                    "copied_host_executable": copied_elf_path,
                    "full_log": compact_text(build_log, MAX_JSON_LOG_CHARS),
                }

                if CLEAN_AFTER_EACH_BENCH:
                    clean_benchmark_dir(bench_build_dir, bench)
                continue

            build_success_count += 1
            bench_result["full_build"] = True

            # ---------- Test stage ----------
            test_start_time = time.time()
            test_ok, test_log = run_cmd(
                test_cmd,
                bench_build_dir,
                timeout=TEST_TIMEOUT,
            )
            test_time = time.time() - test_start_time

            test_log_path = os.path.join(bench_out_dir, "test.log")
            write_text_file(test_log_path, test_log)
            bench_result.update({
                "test_command": test_cmd,
                "test_time": test_time,
                "test_log_path": test_log_path,
            })

            if test_ok:
                test_success_count += 1
                bench_result.update({
                    "execution_success": True,
                    "stage": "test",
                })
                print(
                    f"{bench:<24} | Build: ✅ PASS ({build_time:6.2f}s) "
                    f"| Run: ✅ PASS ({test_time:6.2f}s)"
                )
                if elf_path:
                    print(f"  [host] {elf_path}")
            else:
                test_fail_count += 1
                bench_result.update({
                    "execution_success": False,
                    "stage": "test",
                    "error": "Execution/Test Error",
                })
                print(
                    f"{bench:<24} | Build: ✅ PASS ({build_time:6.2f}s) "
                    f"| Run: ❌ FAIL ({test_time:6.2f}s)"
                )
                print_log_tail("  [!] Execution error summary, final 50 lines:", test_log, n=50)
                print("-" * 75)

                error_summary[bench] = {
                    "stage": "test",
                    "error_type": "Execution/Test Error",
                    "source_file": source_c_path,
                    "target_file": target_c_path,
                    "build_dir": bench_build_dir,
                    "build_command": build_cmd,
                    "test_command": test_cmd,
                    "build_log_path": build_log_path,
                    "test_log_path": test_log_path,
                    "host_executable": elf_path,
                    "copied_host_executable": copied_elf_path,
                    "full_log": compact_text(test_log, MAX_JSON_LOG_CHARS),
                }

            if CLEAN_AFTER_EACH_BENCH:
                clean_benchmark_dir(bench_build_dir, bench)

            benchmark_results.append(bench_result)

    finally:
        # Before summarizing, ensure no child process still holds a deleted file.
        kill_all_active_process_groups()

    # ---------- Summary ----------
    json_report_path = os.path.join(out_dir, "error_summary.json")

    build_rate_total = build_success_count / total_benchmarks if total_benchmarks else 0.0
    test_rate_total = test_success_count / total_benchmarks if total_benchmarks else 0.0
    translation_unit_rate = translation_unit_success_count / total_benchmarks if total_benchmarks else 0.0
    link_rate_total = link_success_count / total_benchmarks if total_benchmarks else 0.0

    metrics = [
        make_metric(
            "Translation-unit Compile Rate",
            "Whether each single .c file can produce a .o object file.",
            translation_unit_success_count,
            total_benchmarks,
        ),
        make_metric(
            "Link Success Rate",
            "Whether all built objects can link into an executable.",
            link_success_count,
            total_benchmarks,
        ),
        make_metric(
            "Full Build Rate",
            "Whether the original Makefile or full build flow succeeds.",
            build_success_count,
            total_benchmarks,
        ),
        make_metric(
            "Execution Rate",
            "Whether tests pass among all submitted programs.",
            test_success_count,
            total_benchmarks,
        ),
    ]

    report_data = {
        "config": {
            "compiler": COMPILER,
            "opt_level": OPT_LEVEL,
            "target_arch": TARGET_ARCH,
            "source_dir": SOURCE_DIR,
            "original_bench_dir": BENCH_DIR,
            "actual_suite_dir": suite_dir,
            "output_dir": out_dir,
            "use_temp_suite_dir": USE_TEMP_SUITE_DIR,
            "clean_temp_suite_dir": CLEAN_TEMP_SUITE_DIR,
            "temp_parent_dir": TEMP_PARENT_DIR,
            "keep_last_temp_runs": KEEP_LAST_TEMP_RUNS,
            "keep_last_output_runs": KEEP_LAST_OUTPUT_RUNS,
            "max_log_chars": MAX_LOG_CHARS,
            "max_json_log_chars": MAX_JSON_LOG_CHARS,
            "copy_host_executable": COPY_HOST_EXECUTABLE,
            "clean_after_each_bench": CLEAN_AFTER_EACH_BENCH,
            "min_free_space_gb": MIN_FREE_SPACE_GB,
            "build_timeout": BUILD_TIMEOUT,
            "test_timeout": TEST_TIMEOUT,
            "clean_timeout": CLEAN_TIMEOUT,
            "build_rule": "make TARGET=<target> clean build",
            "test_rule": "make TARGET=<target> test",
            "stopped_by_disk_guard": stopped_by_disk_guard,
        },
        "metrics": metrics,
        "summary": {
            "total_benchmarks": total_benchmarks,
            "translation_unit_compile_success": translation_unit_success_count,
            "link_success": link_success_count,
            "build_success": build_success_count,
            "build_fail": build_fail_count,
            "test_success": test_success_count,
            "test_fail_after_build_success": test_fail_count,
            "skipped": skipped_count,
            "total_errors": len(error_summary),
            "translation_unit_compile_rate_total": translation_unit_rate,
            "link_success_rate_total": link_rate_total,
            "build_success_rate_total": build_rate_total,
            "test_success_rate_total": test_rate_total,
        },
        "benchmark_results": benchmark_results,
        "errors": error_summary,
    }

    with open(json_report_path, "w", encoding="utf-8") as jf:
        json.dump(report_data, jf, ensure_ascii=False, indent=4)

    metrics_report_paths = write_metrics_reports(
        output_dir=out_dir,
        config=report_data["config"],
        metrics=metrics,
        benchmark_results=benchmark_results,
        errors=error_summary,
    )

    if USE_TEMP_SUITE_DIR and CLEAN_TEMP_SUITE_DIR:
        safe_rmtree(tmp_root)
        _TMP_ROOT = None

    final_result = format_final_result(
        compile_percent=metrics[0]["percent"],
        link_percent=metrics[1]["percent"],
        execution_percent=metrics[3]["percent"],
        title="Our Method:",
    )
    write_text_file(os.path.join(out_dir, "final_result.txt"), final_result + "\n", max_chars=MAX_LOG_CHARS)
    print()
    print(final_result)

    if USE_TEMP_SUITE_DIR and not CLEAN_TEMP_SUITE_DIR:
        write_text_file(os.path.join(out_dir, "retained_temp_suite.txt"), f"{tmp_root}\n", max_chars=MAX_LOG_CHARS)

    return report_data


if __name__ == "__main__":
    main()
