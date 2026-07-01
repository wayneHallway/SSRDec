#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import shlex
import re
import argparse
import csv
import time
from pathlib import Path


# ================= Default configuration =================

DEFAULT_JSON_FILE = "/home/lhw/codetran/test/step1_results.json"

# Directory containing recovered C files, for example:
# /home/lhw/codetran/recon/reconstruct_xxx/O1
DEFAULT_C_DIR = "/home/lhw/inspect/inspect-human/O3"

# Test one optimization level; pass --target-type all to disable filtering.
DEFAULT_TARGET_TYPE = "O3"

# Native host environment.
DEFAULT_CC = "gcc"
DEFAULT_RUNNER_CMD = ""

# ARM cross-execution example:
# DEFAULT_CC = "aarch64-linux-gnu-gcc"
# DEFAULT_RUNNER_CMD = "qemu-aarch64 -L /usr/aarch64-linux-gnu"

COMPILE_TIMEOUT = 8
LINK_TIMEOUT = 8
RUN_TIMEOUT = 3


CUSTOM_ASSERT_MACRO = r"""
#include <stdio.h>
#include <stdlib.h>

#ifdef assert
#undef assert
#endif

#define assert(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "[FAIL] %s\n", #expr); \
            exit(1); \
        } else { \
            printf("[PASS] %s\n", #expr); \
        } \
    } while(0)
"""


def read_text(path: Path) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def safe_write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def now_run_id():
    return time.strftime("%Y%m%d_%H%M%S")


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


def write_metrics_reports(output_dir: Path, config, metrics, task_results, failures):
    output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "config": config,
        "metrics": metrics,
        "task_results": task_results,
        "failures": failures,
    }

    summary_json = output_dir / "metrics_summary.json"
    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=4)

    summary_csv = output_dir / "metrics_summary.csv"
    with open(summary_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["name", "description", "numerator", "denominator", "rate", "percent"],
        )
        writer.writeheader()
        for metric in metrics:
            writer.writerow(metric)

    task_json = output_dir / "task_results.json"
    with open(task_json, "w", encoding="utf-8") as f:
        json.dump(task_results, f, ensure_ascii=False, indent=4)

    summary_md = output_dir / "metrics_summary.md"
    lines = [
        "# Build Metrics Summary",
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
            f"- JSON summary: `{summary_json.name}`",
            f"- CSV summary: `{summary_csv.name}`",
            f"- Task details: `{task_json.name}`",
        ]
    )
    safe_write_text(summary_md, "\n".join(lines) + "\n")

    return {
        "summary_json": str(summary_json),
        "summary_csv": str(summary_csv),
        "summary_md": str(summary_md),
        "task_json": str(task_json),
    }


def strip_assert_include(c_test: str) -> str:
    """
    Remove #include <assert.h> from test code so it does not override the
    custom assert implementation.
    """
    return re.sub(r'#include\s*<assert\.h>', '', c_test)


def strip_main_if_needed(c_code: str, strip_main: bool) -> str:
    """
    A main function in both fixed.c and the JSON c_test causes a duplicate
    definition.

    main is preserved by default because safely removing a C function with a
    regular expression is difficult. If task_x_fixed.c contains main, either:
    1. Disable JSON test concatenation with --no-json-test.
    2. Ensure fixed.c contains function implementations only.
    """
    if not strip_main:
        return c_code

    pattern = re.compile(
        r'\bint\s+main\s*\([^)]*\)\s*\{',
        re.MULTILINE
    )
    m = pattern.search(c_code)
    if not m:
        return c_code

    # Remove the main function body with basic brace matching.
    start = m.start()
    brace_pos = c_code.find("{", m.end() - 1)
    if brace_pos == -1:
        return c_code

    depth = 0
    end = None
    for i in range(brace_pos, len(c_code)):
        if c_code[i] == "{":
            depth += 1
        elif c_code[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    if end is None:
        return c_code

    return c_code[:start] + "\n/* main removed by tester */\n" + c_code[end:]


def extract_task_id_from_filename(path: Path):
    """
    Supported file names:
    1. task_0_fixed.c
    2. task_0_O0_fixed.c
    3. task_15_O1_fixed.c
    4. task_20_O0-l3_fixed.c

    Return the task ID.
    """
    m = re.match(r"task_(\d+)(?:_[A-Za-z0-9\-]+)?_fixed\.c$", path.name)
    if not m:
        return None
    return int(m.group(1))


def load_json_items(json_path: Path):
    if not json_path.exists():
        raise FileNotFoundError(f"找不到 JSON 文件: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("JSON 顶层结构必须是 list，每个元素对应一个任务。")

    return data


def build_test_map_from_json(json_items, target_type):
    """
    Build a task_id-to-JSON-item map so task_x_fixed.c can be matched to its test.
    """
    test_map = {}

    for idx, item in enumerate(json_items):
        task_id = item.get("task_id", idx)
        opt_type = item.get("type", "Unknown")

        if target_type is not None and opt_type != target_type:
            continue

        test_map[int(task_id)] = item

    return test_map


def collect_tasks_from_json(json_items, target_type):
    """
    Original mode: read C implementations from the JSON nova_output field.
    """
    tasks = []

    for idx, item in enumerate(json_items):
        task_id = item.get("task_id", idx)
        opt_type = item.get("type", "Unknown")

        if target_type is not None and opt_type != target_type:
            continue

        c_func = item.get("nova_output", "")
        c_test = item.get("c_test", "")

        tasks.append({
            "idx": idx,
            "task_id": task_id,
            "type": opt_type,
            "source_name": f"json_index_{idx}",
            "c_code": c_func,
            "c_test": c_test,
            "has_json_test": bool(c_test.strip()),
        })

    return tasks

def extract_opt_type_from_filename(path: Path):
    """
    Extract the optimization level from a file name.

    Supported forms:
    task_0_O0_fixed.c      -> O0
    task_1_O1_fixed.c      -> O1
    task_2_O0-l3_fixed.c   -> O0-l3
    task_3_fixed.c         -> None
    """
    m = re.match(r"task_\d+_([A-Za-z0-9\-]+)_fixed\.c$", path.name)
    if not m:
        return None
    return m.group(1)

def collect_tasks_from_c_dir(c_dir: Path, json_items, target_type, use_json_test=True):
    """
    Directory mode: read task_x_fixed.c or task_x_O0_fixed.c directly.

    Supported file names:
    - task_0_fixed.c
    - task_0_O0_fixed.c
    - task_1_O1_fixed.c
    - task_2_O0-l3_fixed.c

    When use_json_test=True, match c_test from JSON by task_id.
    An optimization level in the file name takes precedence over the JSON value.
    """
    if not c_dir.exists():
        raise FileNotFoundError(f"找不到 C 文件目录: {c_dir}")

    c_files = sorted(
        c_dir.glob("task_*_fixed.c"),
        key=lambda p: extract_task_id_from_filename(p)
        if extract_task_id_from_filename(p) is not None
        else 10**18
    )

    if not c_files:
        raise FileNotFoundError(f"目录中没有找到 task_*_fixed.c 文件: {c_dir}")

    test_map = {}
    if use_json_test:
        test_map = build_test_map_from_json(json_items, target_type)

    tasks = []

    for file_path in c_files:
        task_id = extract_task_id_from_filename(file_path)
        if task_id is None:
            print(f"⚠️ 跳过 {file_path.name}: 文件名不符合 task_x_fixed.c 或 task_x_O0_fixed.c 格式。")
            continue

        file_opt_type = extract_opt_type_from_filename(file_path)

        # If the file name has an optimization level, use it for target_type filtering.
        if target_type is not None and file_opt_type is not None:
            if file_opt_type != target_type:
                print(
                    f"⚠️ 跳过 {file_path.name}: 文件优化等级是 {file_opt_type}, "
                    f"当前 target_type={target_type}。"
                )
                continue

        c_code = read_text(file_path)

        json_item = test_map.get(task_id, {})
        opt_type = file_opt_type or json_item.get("type", target_type or "Unknown")
        c_test = json_item.get("c_test", "") if use_json_test else ""

        if target_type is not None and use_json_test:
            if task_id not in test_map:
                print(
                    f"⚠️ 跳过 {file_path.name}: JSON 中没有找到 "
                    f"task_id={task_id}, type={target_type} 的测试。"
                )
                continue

        tasks.append({
            "idx": task_id,
            "task_id": task_id,
            "type": opt_type,
            "source_name": str(file_path),
            "c_code": c_code,
            "c_test": c_test,
            "has_json_test": bool(c_test.strip()),
        })

    return tasks


def build_full_c_code(c_code: str, c_test: str, use_json_test: bool, strip_main: bool):
    """
    Build the final C source used for compilation and testing.
    """
    c_code = strip_main_if_needed(c_code, strip_main=strip_main)

    if use_json_test and c_test.strip():
        c_test_modified = strip_assert_include(c_test)
        return (
            c_code
            + "\n\n// --- Injected test code ---\n"
            + CUSTOM_ASSERT_MACRO
            + "\n"
            + c_test_modified
            + "\n"
        )

    return c_code


def run_one_task_legacy(
    task,
    temp_dir: Path,
    task_output_dir: Path,
    cc: str,
    runner_cmd,
    use_json_test: bool,
    strip_main: bool,
    keep_temp: bool,
):
    task_id = task["task_id"]
    opt_type = task["type"]
    idx = task["idx"]

    full_c_code = build_full_c_code(
        c_code=task["c_code"],
        c_test=task["c_test"],
        use_json_test=use_json_test,
        strip_main=strip_main,
    )

    src_path = temp_dir / f"task_{task_id}.c"
    exe_path = temp_dir / f"task_{task_id}.out"

    safe_write_text(src_path, full_c_code)

    print(f"========== 测试任务 (Task ID: {task_id}, Type: {opt_type}) ==========")
    print(f"  📄 来源: {task['source_name']}")

    # 1. Compilation stage.
    compile_cmd = [cc, str(src_path), "-o", str(exe_path), "-lm", "-w"]

    try:
        comp_res = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT
        )

        if comp_res.returncode != 0:
            print("  ❌ 编译失败")
            if comp_res.stderr.strip():
                print(f"      {comp_res.stderr.strip()[:4000]}")

            return {
                "passed": False,
                "compiled": False,
                "failure": {
                    "task_id": task_id,
                    "type": opt_type,
                    "stage": "Compile",
                    "error": "编译失败",
                    "details": comp_res.stderr.strip(),
                    "source": task["source_name"],
                    "temp_source": str(src_path) if keep_temp else "",
                }
            }

    except subprocess.TimeoutExpired:
        print("  ❌ 编译超时")
        return {
            "passed": False,
            "compiled": False,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Compile",
                "error": "编译超时",
                "details": "",
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            }
        }

    except Exception as e:
        print(f"  ❌ 编译异常: {e}")
        return {
            "passed": False,
            "compiled": False,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Compile",
                "error": "编译异常",
                "details": str(e),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            }
        }

    # 2. Execution stage.
    run_cmd = runner_cmd + [str(exe_path)]

    try:
        run_res = subprocess.run(
            run_cmd,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT
        )

        for line in run_res.stdout.splitlines():
            if "[PASS]" in line:
                print(f"    ✅ 用例通过: {line.split('[PASS]')[-1].strip()}")

        if run_res.returncode == 0:
            print("  🎉 测试通过\n")
            return {
                "passed": True,
                "compiled": True,
                "failure": None
            }

        print(f"  ❌ 运行失败 (Exit Code: {run_res.returncode})")

        fail_found = False
        for line in run_res.stderr.splitlines():
            if "[FAIL]" in line:
                print(f"    ❌ 用例失败: {line.split('[FAIL]')[-1].strip()}")
                fail_found = True

        if not fail_found:
            if run_res.stderr.strip():
                error_msg = run_res.stderr.strip().splitlines()[0]
                print(f"    ⚠️ 原生报错: {error_msg}")
                error_reason = f"原生报错: {error_msg}"
            else:
                error_reason = f"程序异常退出，exit code={run_res.returncode}"
                print(f"    ⚠️ {error_reason}")
        else:
            error_reason = "断言失败"

        print()

        return {
            "passed": False,
            "compiled": True,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Run",
                "error": error_reason,
                "details": run_res.stderr.strip(),
                "stdout": run_res.stdout.strip(),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            }
        }

    except subprocess.TimeoutExpired:
        print("  ❌ 运行超时，可能死循环\n")
        return {
            "passed": False,
            "compiled": True,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Run",
                "error": "运行超时，可能死循环",
                "details": "",
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            }
        }

    except Exception as e:
        print(f"  ❌ 运行异常: {e}\n")
        return {
            "passed": False,
            "compiled": True,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Run",
                "error": "运行异常",
                "details": str(e),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            }
        }


def run_one_task(
    task,
    temp_dir: Path,
    task_output_dir: Path,
    cc: str,
    runner_cmd,
    use_json_test: bool,
    strip_main: bool,
    keep_temp: bool,
):
    task_id = task["task_id"]
    opt_type = task["type"]

    full_c_code = build_full_c_code(
        c_code=task["c_code"],
        c_test=task["c_test"],
        use_json_test=use_json_test,
        strip_main=strip_main,
    )

    src_path = temp_dir / f"task_{task_id}.c"
    obj_path = temp_dir / f"task_{task_id}.o"
    exe_path = temp_dir / f"task_{task_id}.out"

    safe_write_text(src_path, full_c_code)
    safe_write_text(task_output_dir / "source.c", full_c_code)

    print(f"========== Test Task (Task ID: {task_id}, Type: {opt_type}) ==========")
    print(f"  Source: {task['source_name']}")

    task_result = {
        "task_id": task_id,
        "type": opt_type,
        "source": task["source_name"],
        "generated_source": str(task_output_dir / "source.c"),
        "object_path": str(obj_path) if keep_temp else "",
        "executable_path": str(exe_path) if keep_temp else "",
        "translation_unit_compile": False,
        "link_success": False,
        "full_build": False,
        "execution_success": False,
        "executed": False,
        "stage": "",
        "error": "",
    }

    compile_cmd = [cc, "-c", str(src_path), "-o", str(obj_path), "-w"]
    try:
        comp_res = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        safe_write_text(
            task_output_dir / "compile.log",
            (comp_res.stdout or "") + (comp_res.stderr or ""),
        )
        if comp_res.returncode != 0:
            print("  Translation-unit compile: FAIL")
            task_result.update({"stage": "Translation-unit Compile", "error": "compile failed"})
            return {
                "passed": False,
                "compiled": False,
                "object_compiled": False,
                "linked": False,
                "full_build": False,
                "executed": False,
                "task_result": task_result,
                "failure": {
                    "task_id": task_id,
                    "type": opt_type,
                    "stage": "Translation-unit Compile",
                    "error": "compile failed",
                    "details": comp_res.stderr.strip(),
                    "source": task["source_name"],
                    "temp_source": str(src_path) if keep_temp else "",
                },
            }
    except subprocess.TimeoutExpired:
        safe_write_text(task_output_dir / "compile.log", f"[Timeout] compile timeout ({COMPILE_TIMEOUT}s)\n")
        task_result.update({"stage": "Translation-unit Compile", "error": "compile timeout"})
        return {
            "passed": False,
            "compiled": False,
            "object_compiled": False,
            "linked": False,
            "full_build": False,
            "executed": False,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Translation-unit Compile",
                "error": "compile timeout",
                "details": "",
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }
    except Exception as e:
        safe_write_text(task_output_dir / "compile.log", f"[Exception] {type(e).__name__}: {e}\n")
        task_result.update({"stage": "Translation-unit Compile", "error": "compile exception"})
        return {
            "passed": False,
            "compiled": False,
            "object_compiled": False,
            "linked": False,
            "full_build": False,
            "executed": False,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Translation-unit Compile",
                "error": "compile exception",
                "details": str(e),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }

    task_result["translation_unit_compile"] = True

    link_cmd = [cc, str(obj_path), "-o", str(exe_path), "-lm", "-w"]
    try:
        link_res = subprocess.run(
            link_cmd,
            capture_output=True,
            text=True,
            timeout=LINK_TIMEOUT,
        )
        safe_write_text(
            task_output_dir / "link.log",
            (link_res.stdout or "") + (link_res.stderr or ""),
        )
        if link_res.returncode != 0:
            print("  Link: FAIL")
            task_result.update({"stage": "Link", "error": "link failed"})
            return {
                "passed": False,
                "compiled": True,
                "object_compiled": True,
                "linked": False,
                "full_build": False,
                "executed": False,
                "task_result": task_result,
                "failure": {
                    "task_id": task_id,
                    "type": opt_type,
                    "stage": "Link",
                    "error": "link failed",
                    "details": link_res.stderr.strip(),
                    "source": task["source_name"],
                    "temp_source": str(src_path) if keep_temp else "",
                },
            }
    except subprocess.TimeoutExpired:
        safe_write_text(task_output_dir / "link.log", f"[Timeout] link timeout ({LINK_TIMEOUT}s)\n")
        task_result.update({"stage": "Link", "error": "link timeout"})
        return {
            "passed": False,
            "compiled": True,
            "object_compiled": True,
            "linked": False,
            "full_build": False,
            "executed": False,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Link",
                "error": "link timeout",
                "details": "",
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }
    except Exception as e:
        safe_write_text(task_output_dir / "link.log", f"[Exception] {type(e).__name__}: {e}\n")
        task_result.update({"stage": "Link", "error": "link exception"})
        return {
            "passed": False,
            "compiled": True,
            "object_compiled": True,
            "linked": False,
            "full_build": False,
            "executed": False,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Link",
                "error": "link exception",
                "details": str(e),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }

    task_result["link_success"] = True
    task_result["full_build"] = True

    run_cmd = runner_cmd + [str(exe_path)]
    try:
        run_res = subprocess.run(
            run_cmd,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT,
        )
        safe_write_text(
            task_output_dir / "run.log",
            (run_res.stdout or "") + (run_res.stderr or ""),
        )
        task_result["executed"] = True

        if run_res.returncode == 0:
            print("  Execution: PASS\n")
            task_result.update({"execution_success": True, "stage": "Execution"})
            return {
                "passed": True,
                "compiled": True,
                "object_compiled": True,
                "linked": True,
                "full_build": True,
                "executed": True,
                "task_result": task_result,
                "failure": None,
            }

        print(f"  Execution: FAIL (exit code {run_res.returncode})\n")
        error_reason = f"exit code={run_res.returncode}"
        if run_res.stderr.strip():
            error_reason = run_res.stderr.strip().splitlines()[0]
        task_result.update({"stage": "Execution", "error": error_reason})
        return {
            "passed": False,
            "compiled": True,
            "object_compiled": True,
            "linked": True,
            "full_build": True,
            "executed": True,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Execution",
                "error": error_reason,
                "details": run_res.stderr.strip(),
                "stdout": run_res.stdout.strip(),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }
    except subprocess.TimeoutExpired:
        safe_write_text(task_output_dir / "run.log", f"[Timeout] run timeout ({RUN_TIMEOUT}s)\n")
        print("  Execution: TIMEOUT\n")
        task_result.update({"executed": True, "stage": "Execution", "error": "run timeout"})
        return {
            "passed": False,
            "compiled": True,
            "object_compiled": True,
            "linked": True,
            "full_build": True,
            "executed": True,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Execution",
                "error": "run timeout",
                "details": "",
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }
    except Exception as e:
        safe_write_text(task_output_dir / "run.log", f"[Exception] {type(e).__name__}: {e}\n")
        print(f"  Execution: EXCEPTION {e}\n")
        task_result.update({"executed": True, "stage": "Execution", "error": "run exception"})
        return {
            "passed": False,
            "compiled": True,
            "object_compiled": True,
            "linked": True,
            "full_build": True,
            "executed": True,
            "task_result": task_result,
            "failure": {
                "task_id": task_id,
                "type": opt_type,
                "stage": "Execution",
                "error": "run exception",
                "details": str(e),
                "source": task["source_name"],
                "temp_source": str(src_path) if keep_temp else "",
            },
        }


def execute_tasks(args):
    target_type = None if args.target_type.lower() in {"all", "none", "null"} else args.target_type

    json_path = Path(args.json_file)
    c_dir = Path(args.c_dir)

    json_items = []
    if args.mode == "json" or args.use_json_test:
        json_items = load_json_items(json_path)

    if args.mode == "json":
        tasks = collect_tasks_from_json(
            json_items=json_items,
            target_type=target_type,
        )
        use_json_test = True

    elif args.mode == "c_dir":
        tasks = collect_tasks_from_c_dir(
            c_dir=c_dir,
            json_items=json_items,
            target_type=target_type,
            use_json_test=args.use_json_test,
        )
        use_json_test = args.use_json_test

    else:
        raise ValueError(f"未知 mode: {args.mode}")

    total_tasks = len(tasks)

    if total_tasks == 0:
        print(f"⚠️ 没有找到可测试任务。mode={args.mode}, target_type={target_type}")
        return

    run_id = now_run_id()
    output_dir = Path(args.output_dir) if args.output_dir else Path("metric_outputs") / "test-human" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    failed_output_file = args.failed_output
    if not failed_output_file:
        failed_output_file = str(output_dir / f"failed_tasks_{target_type if target_type else 'all'}_{args.mode}.json")

    cc = args.cc
    runner_cmd = shlex.split(args.runner_cmd) if args.runner_cmd.strip() else []

    print(f"📥 成功加载 {total_tasks} 个测试任务")
    print(f"  mode        : {args.mode}")
    print(f"  target_type : {target_type or '全部'}")
    print(f"  cc          : {cc}")
    print(f"  runner_cmd  : {runner_cmd or '直接运行'}")
    print(f"  json_test   : {use_json_test}")
    print()

    passed_tasks = 0
    object_compiled_tasks = 0
    linked_tasks = 0
    full_build_tasks = 0
    failed_summary = []
    failed_tasks_details = []
    task_results = []

    if args.keep_temp:
        temp_root = Path(tempfile.mkdtemp(prefix="c_eval_keep_"))
        temp_context = None
        print(f"🧪 keep-temp 已启用，临时目录保留在: {temp_root}")
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="c_eval_")
        temp_root = Path(temp_context.name)

    try:
        for task in tasks:
            task_output_dir = output_dir / "tasks" / f"task_{task['task_id']}"
            result = run_one_task(
                task=task,
                temp_dir=temp_root,
                task_output_dir=task_output_dir,
                cc=cc,
                runner_cmd=runner_cmd,
                use_json_test=use_json_test,
                strip_main=args.strip_main,
                keep_temp=args.keep_temp,
            )

            task_results.append(result["task_result"])

            if result["object_compiled"]:
                object_compiled_tasks += 1

            if result["linked"]:
                linked_tasks += 1

            if result["full_build"]:
                full_build_tasks += 1

            if result["passed"]:
                passed_tasks += 1
            else:
                failure = result["failure"]
                failed_tasks_details.append(failure)
                failed_summary.append(
                    f"Task {failure['task_id']} (Type {failure['type']}) - "
                    f"{failure['stage']} - {failure['error']}"
                )

    finally:
        if temp_context is not None:
            temp_context.cleanup()

    metrics = [
        make_metric(
            "Translation-unit Compile Rate",
            "Whether each single .c file can produce a .o object file.",
            object_compiled_tasks,
            total_tasks,
        ),
        make_metric(
            "Link Success Rate",
            "Whether object files can link into an executable.",
            linked_tasks,
            total_tasks,
        ),
        make_metric(
            "Full Build Rate",
            "Whether the full single-file build flow succeeds.",
            full_build_tasks,
            total_tasks,
        ),
        make_metric(
            "Execution Rate",
            "Whether tests pass among all submitted programs.",
            passed_tasks,
            total_tasks,
        ),
    ]

    report_paths = write_metrics_reports(
        output_dir=output_dir,
        config={
            "mode": args.mode,
            "target_type": target_type or "all",
            "json_file": str(json_path),
            "c_dir": str(c_dir),
            "cc": cc,
            "runner_cmd": args.runner_cmd,
            "use_json_test": use_json_test,
            "strip_main": args.strip_main,
            "compile_timeout": COMPILE_TIMEOUT,
            "link_timeout": LINK_TIMEOUT,
            "run_timeout": RUN_TIMEOUT,
        },
        metrics=metrics,
        task_results=task_results,
        failures=failed_tasks_details,
    )

    final_result = format_final_result(
        compile_percent=metrics[0]["percent"],
        link_percent=metrics[1]["percent"],
        execution_percent=metrics[3]["percent"],
    )
    safe_write_text(output_dir / "final_result.txt", final_result + "\n")
    print(final_result)

    if failed_summary:
        try:
            with open(failed_output_file, "w", encoding="utf-8") as f:
                json.dump(failed_tasks_details, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"⚠️ 保存失败任务日志文件时出错: {e}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="支持从 JSON 或 task_x_fixed.c 目录中读取 C 代码并执行测试。"
    )

    parser.add_argument(
        "--mode",
        choices=["json", "c_dir"],
        default="c_dir",
        help="json: 从 JSON 的 nova_output 读取代码；c_dir: 从 task_x_fixed.c 文件读取代码。"
    )

    parser.add_argument(
        "--json-file",
        default=DEFAULT_JSON_FILE,
        help="JSON 文件路径，用于读取 c_test 或原始 nova_output。"
    )

    parser.add_argument(
        "--c-dir",
        default=DEFAULT_C_DIR,
        help="包含 task_x_fixed.c 的目录。"
    )

    parser.add_argument(
        "--target-type",
        default=DEFAULT_TARGET_TYPE,
        help='过滤优化级别，例如 O0/O1/O2/O3；传 all 表示不过滤。'
    )

    parser.add_argument(
        "--cc",
        default=DEFAULT_CC,
        help="C 编译器，例如 gcc 或 aarch64-linux-gnu-gcc。"
    )

    parser.add_argument(
        "--runner-cmd",
        default=DEFAULT_RUNNER_CMD,
        help='运行器命令，例如 "qemu-aarch64 -L /usr/aarch64-linux-gnu"。本地运行留空。'
    )

    parser.add_argument(
        "--use-json-test",
        action="store_true",
        default=True,
        help="c_dir 模式下，是否从 JSON 中读取对应 c_test 并拼接测试。默认开启。"
    )

    parser.add_argument(
        "--no-json-test",
        action="store_false",
        dest="use_json_test",
        help="c_dir 模式下，不拼接 JSON 测试，直接编译运行 task_x_fixed.c。"
    )

    parser.add_argument(
        "--strip-main",
        action="store_true",
        help="尝试删除 fixed.c 中的 main 函数，避免和 JSON 的 c_test 里的 main 冲突。默认关闭。"
    )

    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="保留临时编译目录，方便排查失败任务。默认自动清理。"
    )

    parser.add_argument(
        "--failed-output",
        default="",
        help="失败任务日志输出路径。默认自动生成。"
    )

    parser.add_argument(
        "--output-dir",
        default="",
        help="指标、日志和任务明细输出目录。默认写入 metric_outputs/test-human/<timestamp>。"
    )

    return parser.parse_args()


if __name__ == "__main__":
    execute_tasks(parse_args())
