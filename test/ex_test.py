#!/usr/bin/env python3
import os
import subprocess
import time
import shutil
import json
import tempfile

# ================= 配置区域 =================
COMPILER = "gcc"
OPT_LEVEL = "-O0"
OUTPUT_BASE_DIR = "./build_outputs"
TARGET_ARCH = "host"
SOURCE_DIR = "/home/lhw/codetran/decompile/dec-tool-v4/O0"
BENCH_DIR = "/home/lhw/codetran/recon/bringup-bench"
BUILD_TIMEOUT = 120
TEST_TIMEOUT = 120
USE_TEMP_SUITE_DIR = True
CLEAN_TEMP_SUITE_DIR = True
# ============================================


def run_cmd(cmd, cwd, timeout=None):
    """执行 shell 命令，返回 success, output"""
    try:
        res = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return res.returncode == 0, res.stdout
    except subprocess.TimeoutExpired:
        return False, f"[Timeout] 执行超时 ({timeout}s)!"
    except Exception as e:
        return False, str(e)


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
    """优先选择普通 .c；没有普通 .c 时选择 _fixed.c"""
    paths = file_map.get(bench, {})
    primary_path = paths.get("primary")
    fallback_path = paths.get("fallback")

    if primary_path and os.path.exists(primary_path):
        return primary_path, "primary"
    if fallback_path and os.path.exists(fallback_path):
        return fallback_path, "fallback"
    return None, None


def is_executable_binary(path):
    """判断是否是真正的 ELF 或 Mach-O 可执行文件"""
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        return False

    try:
        with open(path, "rb") as fp:
            header = fp.read(4)
        return (
            header.startswith(b"\x7fELF")
            or header in (
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
    """
    查找 host 可执行文件。

    重点：
    1. 优先找 <bench>.host；
    2. 不把 <bench>.out 当可执行文件；
    3. 只接受 ELF/Mach-O；
    4. 如果传入 build_start_time，只接受本次 build 后生成/更新的文件。
    """
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
        ".txt", ".md", ".py", ".sh", ".S", ".json", ".log"
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
    """
    删除当前 benchmark 目录里可能残留的旧 host 可执行产物。
    不删除 .out/.hash/.c/.h/Makefile。
    """
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


def copy_whole_suite_to_temp():
    tmp_root = tempfile.mkdtemp(prefix="bringup_suite_")
    tmp_suite_dir = os.path.join(tmp_root, "bringup-bench")
    ignore_patterns = shutil.ignore_patterns(".git", "__pycache__")
    shutil.copytree(BENCH_DIR, tmp_suite_dir, ignore=ignore_patterns)
    return tmp_root, tmp_suite_dir


def prepare_suite_dir():
    if USE_TEMP_SUITE_DIR:
        return copy_whole_suite_to_temp()
    return None, BENCH_DIR


def write_text_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)


def print_log_tail(title, log, n=50):
    print(title)
    lines = log.strip().split("\n")
    if not lines or lines == [""]:
        print("      <empty log>")
    else:
        print("      " + "\n      ".join(lines[-n:]))


def get_build_and_test_cmds():
    """统一生成构建和测试命令。"""
    build_cmd = (
        f'make TARGET={TARGET_ARCH} '
        f'CC="{COMPILER}" '
        f'EXTRA_CFLAGS="{OPT_LEVEL}" '
        f'clean build'
    )
    test_cmd = (
        f'make TARGET={TARGET_ARCH} '
        f'CC="{COMPILER}" '
        f'EXTRA_CFLAGS="{OPT_LEVEL}" '
        f'test'
    )
    return build_cmd, test_cmd


def run_comprehensive_evaluation(code_str, task_id, variant_name="Root"):
    """
    外部 InspectCoder/BFS 脚本需要调用的测试函数。

    必须返回四个值：
        is_compiled: bool
        is_run_success: bool
        report_log: str
        elf_path: str | None

    这个函数会：
    1. 把 code_str 写入 BENCH_DIR/task_id/task_id.c；
    2. 执行 make clean build；
    3. 查找 host 可执行文件；
    4. 执行 make test；
    5. 返回编译/执行结果和完整日志。
    """
    bench_build_dir = os.path.join(BENCH_DIR, task_id)
    if not os.path.isdir(bench_build_dir):
        return False, False, f"⚠️ Error: 找不到构建目录 {bench_build_dir}", None

    target_c_path = os.path.join(bench_build_dir, f"{task_id}.c")
    try:
        with open(target_c_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(code_str)
    except Exception as e:
        return False, False, f"⚠️ Error: 无法写入代码到 {target_c_path}: {e}", None

    build_cmd, test_cmd = get_build_and_test_cmds()
    remove_old_host_outputs(bench_build_dir, task_id)

    report_parts = []
    report_parts.append(f"[Variant] {variant_name}")
    report_parts.append(f"[Source File] {target_c_path}")
    report_parts.append(f"[Build Directory] {bench_build_dir}")
    report_parts.append(f"[Build Command]\n{build_cmd}")

    build_start_time = time.time()
    build_ok, build_log = run_cmd(build_cmd, bench_build_dir, timeout=BUILD_TIMEOUT)
    build_time = time.time() - build_start_time

    elf_path = find_host_executable(
        bench_build_dir,
        task_id,
        build_start_time=build_start_time,
    )

    report_parts.append(f"[Build Time] {build_time:.2f}s")
    report_parts.append(f"[Build Log]\n{build_log}")
    report_parts.append(f"[Host Executable] {elf_path}")

    if not build_ok:
        report_parts.append("[Compilation Failed]")
        report_log = "\n\n".join(report_parts)
        print(f"      [{variant_name:<15}] 编译: ❌ FAIL | 执行: ⏸️ SKIP")
        return False, False, report_log, elf_path

    report_parts.append("[Compilation]: SUCCESS")
    report_parts.append(f"[Test Command]\n{test_cmd}")

    test_start_time = time.time()
    test_ok, test_log = run_cmd(test_cmd, bench_build_dir, timeout=TEST_TIMEOUT)
    test_time = time.time() - test_start_time

    report_parts.append(f"[Test Time] {test_time:.2f}s")
    report_parts.append(f"[Test Log]\n{test_log}")

    if test_ok:
        report_parts.append("[Dynamic Test Run]: SUCCESS")
        report_log = "\n\n".join(report_parts)
        print(f"      [{variant_name:<15}] 编译: ✅ PASS | 执行: ✅ PASS")
        return True, True, report_log, elf_path

    report_parts.append("[Dynamic Test Run Failed]")
    report_log = "\n\n".join(report_parts)
    print(f"      [{variant_name:<15}] 编译: ✅ PASS | 执行: ❌ FAIL")
    return True, False, report_log, elf_path


def main():
    """
    保留原来的批量测试能力。
    注意：被 InspectCoder import 时不会执行 main()。
    """
    global BENCH_DIR

    run_id = time.strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}"
    opt_dir_name = OPT_LEVEL.strip("-") or "default"
    out_dir = os.path.join(OUTPUT_BASE_DIR, opt_dir_name, run_id)
    os.makedirs(out_dir, exist_ok=True)

    benchmarks, file_map = collect_benchmarks(SOURCE_DIR)
    original_bench_dir = BENCH_DIR
    tmp_root, suite_dir = prepare_suite_dir()

    # 如果单独运行这个脚本且开启了临时 suite，则后续单测函数也使用临时 suite。
    BENCH_DIR = suite_dir

    print(f"🎯 开始处理，共 {len(benchmarks)} 个项目")
    print(f"📁 SOURCE_DIR: {SOURCE_DIR}")
    print(f"📁 原始 BENCH_DIR: {original_bench_dir}")
    print(f"📁 实际构建 suite: {BENCH_DIR}")
    print(f"📁 输出目录: {out_dir}")
    print(f"🎯 TARGET: {TARGET_ARCH}")
    print(f"🔧 CC: {COMPILER}")
    print(f"🔧 EXTRA_CFLAGS: {OPT_LEVEL}")

    if USE_TEMP_SUITE_DIR:
        print("🧪 当前模式：复制整个 bringup-bench 到临时目录，不污染原工程")
    else:
        print("⚠️ 当前模式：直接在原始 bringup-bench 中构建，会覆盖源码")
    print()

    total_benchmarks = len(benchmarks)
    build_success_count = 0
    test_success_count = 0
    build_fail_count = 0
    test_fail_count = 0
    skipped_count = 0
    error_summary = {}

    for bench in benchmarks:
        source_c_path, source_kind = choose_source_file(bench, file_map)

        if not source_c_path:
            print(f"⚠️ 跳过 {bench}: SOURCE_DIR 中没有找到 .c 或 _fixed.c")
            skipped_count += 1
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

        bench_build_dir = os.path.join(BENCH_DIR, bench)
        if not os.path.isdir(bench_build_dir):
            print(f"⚠️ 跳过 {bench}: suite 中没有对应 benchmark 目录: {bench_build_dir}")
            skipped_count += 1
            error_summary[bench] = {
                "stage": "benchmark_dir",
                "error_type": "Missing Benchmark Directory",
                "source_file": source_c_path,
                "build_dir": bench_build_dir,
                "full_log": f"suite 中没有对应 benchmark 目录: {bench_build_dir}",
            }
            continue

        try:
            with open(source_c_path, "r", encoding="utf-8", errors="ignore") as f:
                code_str = f.read()
        except Exception as e:
            print(f"❌ {bench}: 读取源码失败: {e}")
            skipped_count += 1
            error_summary[bench] = {
                "stage": "read_source",
                "error_type": "Read Source Error",
                "source_file": source_c_path,
                "build_dir": bench_build_dir,
                "full_log": str(e),
            }
            continue

        bench_out_dir = os.path.join(out_dir, bench)
        os.makedirs(bench_out_dir, exist_ok=True)

        eval_start_time = time.time()
        is_compiled, is_run_success, report_log, elf_path = run_comprehensive_evaluation(
            code_str,
            bench,
            variant_name=bench,
        )
        eval_time = time.time() - eval_start_time

        eval_log_path = os.path.join(bench_out_dir, "evaluation.log")
        write_text_file(eval_log_path, report_log)

        copied_elf_path = None
        if elf_path:
            copied_elf_path = os.path.join(bench_out_dir, os.path.basename(elf_path))
            try:
                shutil.copy2(elf_path, copied_elf_path)
            except Exception:
                copied_elf_path = None

        if is_compiled:
            build_success_count += 1
        else:
            build_fail_count += 1

        if is_compiled and is_run_success:
            test_success_count += 1
            print(f"{bench:<24} | 编译: ✅ PASS ({eval_time:6.2f}s) | 执行: ✅ PASS")
            if elf_path:
                print(f"  [host] {elf_path}")
        elif is_compiled:
            test_fail_count += 1
            print(f"{bench:<24} | 编译: ✅ PASS ({eval_time:6.2f}s) | 执行: ❌ FAIL")
            print_log_tail("  [!] 执行报错摘要 最后50行:", report_log, n=50)
            print("-" * 75)
            error_summary[bench] = {
                "stage": "test",
                "error_type": "Execution/Test Error",
                "source_file": source_c_path,
                "build_dir": bench_build_dir,
                "evaluation_log_path": eval_log_path,
                "host_executable": elf_path,
                "copied_host_executable": copied_elf_path,
                "full_log": report_log,
            }
        else:
            print(f"{bench:<24} | 编译: ❌ FAIL ({eval_time:6.2f}s) | 执行: ⏸️ SKIP")
            print_log_tail("  [!] 编译报错摘要 最后50行:", report_log, n=50)
            print("-" * 75)
            error_summary[bench] = {
                "stage": "build",
                "error_type": "Compile Error",
                "source_file": source_c_path,
                "build_dir": bench_build_dir,
                "evaluation_log_path": eval_log_path,
                "host_executable": elf_path,
                "copied_host_executable": copied_elf_path,
                "full_log": report_log,
            }

    json_report_path = os.path.join(out_dir, "error_summary.json")

    build_rate_total = build_success_count / total_benchmarks if total_benchmarks else 0.0
    test_rate_among_built = test_success_count / build_success_count if build_success_count else 0.0
    test_rate_total = test_success_count / total_benchmarks if total_benchmarks else 0.0

    report_data = {
        "config": {
            "compiler": COMPILER,
            "opt_level": OPT_LEVEL,
            "target_arch": TARGET_ARCH,
            "source_dir": SOURCE_DIR,
            "original_bench_dir": original_bench_dir,
            "actual_suite_dir": BENCH_DIR,
            "output_dir": out_dir,
            "use_temp_suite_dir": USE_TEMP_SUITE_DIR,
            "clean_temp_suite_dir": CLEAN_TEMP_SUITE_DIR,
            "build_timeout": BUILD_TIMEOUT,
            "test_timeout": TEST_TIMEOUT,
            "callable_api": "run_comprehensive_evaluation(code_str, task_id, variant_name='Root')",
        },
        "summary": {
            "total_benchmarks": total_benchmarks,
            "build_success": build_success_count,
            "build_fail": build_fail_count,
            "test_success": test_success_count,
            "test_fail_after_build_success": test_fail_count,
            "skipped": skipped_count,
            "total_errors": len(error_summary),
            "build_success_rate_total": build_rate_total,
            "test_success_rate_among_build_success": test_rate_among_built,
            "test_success_rate_total": test_rate_total,
        },
        "errors": error_summary,
    }

    with open(json_report_path, "w", encoding="utf-8") as jf:
        json.dump(report_data, jf, ensure_ascii=False, indent=4)

    if USE_TEMP_SUITE_DIR and CLEAN_TEMP_SUITE_DIR and tmp_root:
        try:
            shutil.rmtree(tmp_root)
        except Exception as e:
            print(f"⚠️ 删除临时目录失败: {tmp_root}, 原因: {e}")

    print()
    print("=" * 75)
    print("📊 汇总结果")
    print("=" * 75)
    print(f"总 benchmark 数: {total_benchmarks}")
    print(f"跳过数量: {skipped_count}")
    print()
    print(f"📊 编译通过率: {build_success_count}/{total_benchmarks} ({build_rate_total * 100:.2f}%)")
    print(f"🏃 执行通过率: {test_success_count}/{build_success_count} ({test_rate_among_built * 100:.2f}%，以编译通过为分母)")
    print(f"🏃 执行通过率占总数: {test_success_count}/{total_benchmarks} ({test_rate_total * 100:.2f}%)")
    print()
    print(f"编译失败数: {build_fail_count}")
    print(f"编译成功但执行失败数: {test_fail_count}")
    print(f"错误总数: {len(error_summary)}")
    print()
    print(f"📄 JSON 汇总报告: {json_report_path}")
    print(f"📁 输出目录: {out_dir}")

    if USE_TEMP_SUITE_DIR and not CLEAN_TEMP_SUITE_DIR:
        print()
        print("🧪 临时 Bringup-Bench 目录已保留，方便排查:")
        print(f"   {tmp_root}")


if __name__ == "__main__":
    main()
