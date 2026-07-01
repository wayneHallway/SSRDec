#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disk-safe Bringup-Bench build/test runner.

主要改造点：
1. 每次运行使用独立临时 suite，但会自动清理旧临时目录。
2. 所有 make 命令放入独立进程组，超时时杀掉整个进程组，避免 FOO / .host 被后台进程占用。
3. 日志落盘前做大小限制，避免 test 输出无限增长占满磁盘。
4. 输出目录只保留最近 N 次运行。
5. 每个 benchmark 结束后尽量 make clean，并删除 host 可执行残留。
6. 程序异常退出、Ctrl-C、正常退出时都会尝试清理临时目录和子进程。
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

# ================= 配置区域 =================
COMPILER = "gcc"
OPT_LEVEL = "-O0"

OUTPUT_BASE_DIR = "./build_outputs"
TARGET_ARCH = "host"

SOURCE_DIR = "/home/lhw/TraceCoder-main/results/O0"
BENCH_DIR = "/home/lhw/codetran/recon/bringup-bench"

BUILD_TIMEOUT = 120
TEST_TIMEOUT = 120
CLEAN_TIMEOUT = 30

# 是否复制整个 bringup-bench 到临时目录。
# True: 不污染原始 BENCH_DIR，推荐。
# False: 直接在原始 BENCH_DIR 中覆盖源码并构建，不推荐。
USE_TEMP_SUITE_DIR = True

# 是否删除本次运行的临时目录。
# 强烈建议 True；否则多次运行会很快占满磁盘。
CLEAN_TEMP_SUITE_DIR = True

# 临时 suite 统一放在这里，方便集中清理。
# 不建议放到项目目录中，避免被误认为实验输出。
TEMP_PARENT_DIR = "/tmp/bringup_bench_suites"

# 启动时清理 TEMP_PARENT_DIR 下较旧的临时 suite，只保留最近 N 个。
KEEP_LAST_TEMP_RUNS = 1

# 输出目录只保留最近 N 次运行。
KEEP_LAST_OUTPUT_RUNS = 5

# 每个 build.log / test.log 最大保存字符数。
# 原始日志过大时保存 head + tail，中间截断。
MAX_LOG_CHARS = 300_000
MAX_JSON_LOG_CHARS = 60_000

# 是否把编译出的 host 可执行复制到输出目录。
# 如果你只关心通过率，建议 False，可显著减少磁盘占用。
COPY_HOST_EXECUTABLE = False

# 每个 benchmark 测试结束后是否执行 make clean。
# True 会降低磁盘占用；如果你需要保留中间产物调试，可改 False。
CLEAN_AFTER_EACH_BENCH = True

# 磁盘剩余空间低于该值时提前停止，避免把 / 写满。
MIN_FREE_SPACE_GB = 5.0

# 启动时是否尝试清理当前用户残留的 bringup-bench deleted 文件占用进程。
# 谨慎：会杀掉命令行中包含 BENCH_DIR 或 TEMP_PARENT_DIR 的相关残留进程。
KILL_STALE_DELETED_FILE_PROCESSES_AT_START = False
# ============================================

_ACTIVE_PROCESS_GROUPS = set()
_TMP_ROOT = None


def now_run_id():
    return time.strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}"


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def disk_free_gb(path):
    """返回 path 所在文件系统剩余 GB。"""
    target = path if os.path.exists(path) else os.path.dirname(os.path.abspath(path)) or "/"
    usage = shutil.disk_usage(target)
    return usage.free / (1024 ** 3)


def check_free_space_or_raise(path, min_gb=MIN_FREE_SPACE_GB):
    free = disk_free_gb(path)
    if free < min_gb:
        raise RuntimeError(
            f"磁盘剩余空间不足：{path} 所在文件系统仅剩 {free:.2f} GB，"
            f"低于阈值 {min_gb:.2f} GB。已主动停止，避免写满磁盘。"
        )


def compact_text(text, max_chars):
    """限制日志大小，保留开头和结尾。"""
    if text is None:
        return ""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    omitted = len(text) - max_chars
    return (
        text[:half]
        + f"\n\n...[日志过大，中间截断 {omitted} 个字符]...\n\n"
        + text[-half:]
    )


def run_cmd(cmd, cwd, timeout=None):
    """
    执行 shell 命令，返回 success, output。

    关键点：
    - 使用 start_new_session=True 创建独立进程组；
    - timeout 时 killpg，杀掉 make 及其所有子进程；
    - communicate() 后确保 stdout pipe 关闭，避免 fd 残留。
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
                (out or "") + f"\n[Timeout] 执行超时 ({timeout}s)，已杀掉整个进程组 pgid={pgid}。\n",
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
    """先 SIGTERM 后 SIGKILL，尽量完整回收子进程。"""
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
        print(f"⚠️ 删除目录失败: {path}, 原因: {e}")


def cleanup_current_tmp_root():
    global _TMP_ROOT
    kill_all_active_process_groups()
    if USE_TEMP_SUITE_DIR and CLEAN_TEMP_SUITE_DIR and _TMP_ROOT:
        safe_rmtree(_TMP_ROOT)
        _TMP_ROOT = None


def handle_exit_signal(signum, frame):
    print(f"\n⚠️ 收到信号 {signum}，正在清理子进程和临时目录...")
    cleanup_current_tmp_root()
    sys.exit(128 + signum)


atexit.register(cleanup_current_tmp_root)
signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)


def cleanup_old_dirs(parent_dir, keep_last_n):
    """清理 parent_dir 下旧的直接子目录，只保留最近 keep_last_n 个。"""
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
    可选清理：杀掉当前用户下仍占用 deleted 文件且路径相关的残留进程。
    默认关闭，避免误杀正在运行的其它实验。
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
            # lsof 的 USER 列可能是用户名，不一定是 uid；这里不强制匹配。
            if pid.isdigit() and int(pid) != os.getpid():
                pids.add(int(pid))
        for pid in sorted(pids):
            try:
                os.kill(pid, signal.SIGKILL)
                print(f"🧹 已清理残留 deleted 文件占用进程 PID={pid}")
            except ProcessLookupError:
                pass
            except PermissionError:
                print(f"⚠️ 无权限清理残留进程 PID={pid}")
    except FileNotFoundError:
        print("⚠️ 未安装 lsof，跳过 deleted 文件占用进程清理。")
    except Exception as e:
        print(f"⚠️ 清理 deleted 文件占用进程失败: {e}")


def collect_benchmarks(source_dir):
    """
    从 SOURCE_DIR 中递归收集 benchmark 源文件。

    优先级：
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
    """优先选择普通 .c；没有普通 .c 时选择 _fixed.c。"""
    paths = file_map.get(bench, {})
    primary_path = paths.get("primary")
    fallback_path = paths.get("fallback")

    if primary_path and os.path.exists(primary_path):
        return primary_path, "primary"
    if fallback_path and os.path.exists(fallback_path):
        return fallback_path, "fallback"
    return None, None


def is_executable_binary(path):
    """判断是否是真正的 ELF 或 Mach-O 可执行文件。"""
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
    """查找本次 build 生成的 host 可执行文件。"""
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
    """删除当前 benchmark 目录里可能残留的 host 可执行产物。"""
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
    复制整个 Bringup-Bench 工程到临时目录。

    改造点：
    - 所有临时 suite 都放到 TEMP_PARENT_DIR；
    - 启动前清理旧 suite；
    - 忽略明显无用的缓存目录。
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
    """写日志文件，并限制体积。"""
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
    """打印日志最后 n 行。"""
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
    """尽量清理当前 benchmark 的构建产物。"""
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

    print(f"🎯 开始处理，共 {len(benchmarks)} 个项目")
    print(f"📁 SOURCE_DIR: {SOURCE_DIR}")
    print(f"📁 原始 BENCH_DIR: {BENCH_DIR}")
    print(f"📁 实际构建 suite: {suite_dir}")
    print(f"📁 输出目录: {out_dir}")
    print(f"🎯 TARGET: {TARGET_ARCH}")
    print(f"🔧 CC: {COMPILER}")
    print(f"🔧 EXTRA_CFLAGS: {OPT_LEVEL}")
    print(f"🧯 日志最大保存: {MAX_LOG_CHARS} chars/file")
    print(f"🧹 输出目录保留最近: {KEEP_LAST_OUTPUT_RUNS} 次")
    print(f"🧹 临时 suite 保留最近: {KEEP_LAST_TEMP_RUNS} 个旧目录")
    print(f"💾 最小剩余空间阈值: {MIN_FREE_SPACE_GB:.1f} GB")

    if USE_TEMP_SUITE_DIR:
        print("🧪 当前模式：复制整个 bringup-bench 到临时目录，不污染原工程")
    else:
        print("⚠️ 当前模式：直接在原始 bringup-bench 中构建，会覆盖源码")
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
                print(f"⚠️ 跳过 {bench}: SOURCE_DIR 中没有找到 .c 或 _fixed.c")
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
                    "full_log": "SOURCE_DIR 中没有找到 .c 或 _fixed.c",
                }
                continue

            if source_kind == "primary":
                print(f"📖 [{bench}] 读取普通源文件: {source_c_path}")
            else:
                print(f"📖 [{bench}] 未找到普通 .c，回退读取: {source_c_path}")

            bench_build_dir = os.path.join(suite_dir, bench)

            if not os.path.isdir(bench_build_dir):
                print(f"⚠️ 跳过 {bench}: suite 中没有对应 benchmark 目录: {bench_build_dir}")
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
                    "full_log": f"suite 中没有对应 benchmark 目录: {bench_build_dir}",
                }
                continue

            target_c_path = os.path.join(bench_build_dir, bench + ".c")

            try:
                shutil.copy2(source_c_path, target_c_path)
            except Exception as e:
                print(f"❌ {bench}: 覆盖源码失败: {e}")
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

            # ---------- Build 阶段 ----------
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
                    f"{bench:<24} | 编译: ❌ FAIL ({build_time:6.2f}s) "
                    f"| 执行: ⏸️ SKIP"
                )
                print_log_tail("  [!] 编译报错摘要 最后50行:", build_log, n=50)
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

            # ---------- Test 阶段 ----------
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
                    f"{bench:<24} | 编译: ✅ PASS ({build_time:6.2f}s) "
                    f"| 执行: ✅ PASS ({test_time:6.2f}s)"
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
                    f"{bench:<24} | 编译: ✅ PASS ({build_time:6.2f}s) "
                    f"| 执行: ❌ FAIL ({test_time:6.2f}s)"
                )
                print_log_tail("  [!] 执行报错摘要 最后50行:", test_log, n=50)
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
        # 正常汇总前也先确保没有子进程仍占用 deleted 文件。
        kill_all_active_process_groups()

    # ---------- 汇总 ----------
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
