#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
External C test runner for InspectCoder.

Import mode:
    InspectCoder imports this file and calls:
        run_comprehensive_evaluation(code_str, task_id, variant_name="Root")

    Return value:
        (is_compiled, is_run_success, report_log, elf_path)

Standalone mode:
    python3 external_c_test_runner_full.py \
        --mode c_dir \
        --c-dir /path/to/c/files/O0 \
        --json-file /path/to/step1_results.json \
        --target-type O0

Important design:
    - This file does NOT need a hardcoded C_SOURCE_DIR when used by InspectCoder.
    - --c-dir is only for standalone batch testing.
    - The external tester owns JSON-test injection and compilation/execution.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ==================== Default config ====================
JSON_FILE = os.environ.get("EXT_TEST_JSON_FILE", "/home/lhw/codetran/test/step1_results.json")
TARGET_TYPE = os.environ.get("EXT_TEST_TARGET_TYPE", "O0")  # e.g. O0/O1/O2/O3; use "all" or empty for no filter

CC = os.environ.get("EXT_TEST_CC", "gcc")
RUNNER_CMD = shlex.split(os.environ.get("EXT_TEST_RUNNER_CMD", ""))

COMPILE_TIMEOUT = int(os.environ.get("EXT_TEST_COMPILE_TIMEOUT", "8"))
RUN_TIMEOUT = int(os.environ.get("EXT_TEST_RUN_TIMEOUT", "3"))

# Work directory for candidate .c/.out files. Kept by default so InspectCoder can use elf_path with GDB.
TEST_WORK_ROOT = os.environ.get("EXT_TEST_WORK_ROOT", "/tmp/inspectcoder_external_test")
KEEP_EVAL_ARTIFACTS = os.environ.get("EXT_TEST_KEEP_ARTIFACTS", "1") not in {"0", "false", "False", "no", "NO"}

# JSON field names. Your previous JSON used nova_output and c_test.
CODE_FIELD_CANDIDATES = ["nova_output", "code", "c_code", "source", "output"]
TEST_FIELD_CANDIDATES = ["c_test", "test", "test_code", "unit_test"]

# If True, when JSON c_test is injected, try to remove an existing main() from candidate code.
# This avoids duplicate main errors when task_x_O0.c already contains a main generated elsewhere.
REMOVE_MAIN_WHEN_INJECT_TEST = os.environ.get("EXT_TEST_REMOVE_MAIN", "1") not in {"0", "false", "False", "no", "NO"}

# When JSON c_test is available, inject it. If False, directly compile/run code_str.
USE_JSON_TEST = os.environ.get("EXT_TEST_USE_JSON_TEST", "1") not in {"0", "false", "False", "no", "NO"}

# Cache JSON items across calls.
_JSON_ITEMS_CACHE: Optional[List[Dict[str, Any]]] = None

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


def normalize_target_type(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in {"all", "none", "null"}:
        return None
    return s


def parse_task_id_and_type(value: Any) -> Tuple[str, Optional[str]]:
    """
    Accepts task ids and filenames such as:
      0                  -> ("0", None)
      task_0             -> ("0", None)
      task_0_O0          -> ("0", "O0")
      task_0_O0.c        -> ("0", "O0")
      task_0_O0_fixed.c  -> ("0", "O0")
      task_0_fixed.c     -> ("0", None)
    """
    s = str(value).strip()
    base = os.path.basename(s)

    patterns = [
        r"^task_(\d+)_(O\d+)_fixed\.c$",
        r"^task_(\d+)_(O\d+)\.c$",
        r"^task_(\d+)_(O\d+)$",
        r"^task_(\d+)_fixed\.c$",
        r"^task_(\d+)\.c$",
        r"^task_(\d+)$",
        r"^(\d+)_(O\d+)_fixed\.c$",
        r"^(\d+)_(O\d+)\.c$",
        r"^(\d+)_(O\d+)$",
        r"^(\d+)_fixed\.c$",
        r"^(\d+)\.c$",
        r"^(\d+)$",
    ]

    for pat in patterns:
        m = re.match(pat, base)
        if not m:
            continue
        if len(m.groups()) == 2:
            return m.group(1), m.group(2)
        return m.group(1), None

    if base.endswith("_fixed.c"):
        return base[:-8], None
    if base.endswith(".c"):
        return base[:-2], None
    return base, None


def load_json_items(json_path: Optional[str] = None) -> List[Dict[str, Any]]:
    global _JSON_ITEMS_CACHE

    path = json_path or JSON_FILE
    if _JSON_ITEMS_CACHE is not None and path == JSON_FILE:
        return _JSON_ITEMS_CACHE

    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"找不到 JSON 测试文件: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("JSON 顶层必须是 list，每个元素对应一个任务。")

    # Ensure dict items.
    items = [x for x in data if isinstance(x, dict)]
    if path == JSON_FILE:
        _JSON_ITEMS_CACHE = items
    return items


def item_task_id(item: Dict[str, Any], fallback_idx: int) -> str:
    return str(item.get("task_id", fallback_idx))


def find_json_item(task_id: Any, target_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    norm_task_id, inferred_type = parse_task_id_and_type(task_id)
    effective_type = normalize_target_type(target_type) or normalize_target_type(inferred_type) or normalize_target_type(TARGET_TYPE)

    try:
        items = load_json_items(JSON_FILE)
    except Exception:
        return None

    candidates: List[Tuple[int, Dict[str, Any]]] = []

    for idx, item in enumerate(items):
        this_id = item_task_id(item, idx)
        this_type = str(item.get("type", "")).strip() or None

        if str(this_id) != str(norm_task_id):
            continue

        # If an effective type is set, prefer exact type. Keep non-exact as lower priority only if no exact match exists.
        if effective_type is None:
            score = 0
        elif this_type == effective_type:
            score = 0
        else:
            score = 10
        candidates.append((score, item))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0])
    best_score, best_item = candidates[0]

    # If type was required and only mismatched candidates exist, return None to avoid wrong tests.
    if effective_type is not None and best_score > 0:
        return None

    return best_item


def first_nonempty_field(item: Dict[str, Any], fields: List[str]) -> str:
    for name in fields:
        value = item.get(name, "")
        if isinstance(value, str) and value.strip():
            return value
    return ""


def strip_assert_include(c_test: str) -> str:
    return re.sub(r'#include\s*<assert\.h>', '', c_test)


def remove_main_function(c_code: str) -> str:
    """
    Best-effort removal of int main(...) { ... }.
    This is intentionally conservative and only removes common main signatures.
    """
    pattern = re.compile(
        r"(^|\n)\s*(?:int|void)\s+main\s*\([^;{}]*\)\s*\{",
        re.MULTILINE,
    )
    m = pattern.search(c_code)
    if not m:
        return c_code

    start = m.start()
    # Preserve preceding newline if included.
    if c_code[start] == "\n":
        start += 1

    brace_pos = c_code.find("{", m.end() - 1)
    if brace_pos < 0:
        return c_code

    depth = 0
    end = None
    in_str = False
    in_chr = False
    esc = False
    line_comment = False
    block_comment = False

    i = brace_pos
    while i < len(c_code):
        ch = c_code[i]
        nxt = c_code[i + 1] if i + 1 < len(c_code) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue

        if in_chr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                in_chr = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "'":
            in_chr = True
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
        i += 1

    if end is None:
        return c_code

    return c_code[:start] + "\n/* main removed by external_c_test_runner_full.py before JSON test injection */\n" + c_code[end:]


def build_full_c_code(code_str: str, task_id: Any) -> Tuple[str, str]:
    """
    Returns (full_c_code, test_source_desc).
    If JSON c_test is found and USE_JSON_TEST=True, inject it.
    Otherwise compile/run code_str directly.
    """
    if not USE_JSON_TEST:
        return code_str, "direct-code-no-json-test"

    item = find_json_item(task_id)
    if not item:
        return code_str, "direct-code-json-test-not-found"

    c_test = first_nonempty_field(item, TEST_FIELD_CANDIDATES)
    if not c_test.strip():
        return code_str, "direct-code-json-test-empty"

    candidate_code = code_str
    if REMOVE_MAIN_WHEN_INJECT_TEST:
        candidate_code = remove_main_function(candidate_code)

    c_test_modified = strip_assert_include(c_test)
    full = (
        candidate_code
        + "\n\n// --- injected by external_c_test_runner_full.py ---\n"
        + CUSTOM_ASSERT_MACRO
        + "\n"
        + c_test_modified
        + "\n"
    )
    return full, "json-c_test-injected"


def safe_name(value: Any) -> str:
    return re.sub(r"[^0-9A-Za-z_.-]+", "_", str(value))[:120]


def make_eval_dir(task_id: Any, variant_name: str) -> Path:
    root = Path(TEST_WORK_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    dirname = f"task_{safe_name(task_id)}__{safe_name(variant_name)}__pid{os.getpid()}__{int(time.time() * 1000)}"
    path = root / dirname
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_comprehensive_evaluation(code_str: str, task_id: Any, variant_name: str = "Root") -> Tuple[bool, bool, str, Optional[str]]:
    """
    Standard InspectCoder-compatible external test entry.

    Args:
        code_str: candidate C code to test.
        task_id: task id, may be "0", "task_0_O0", "task_0_O0.c", etc.
        variant_name: BFS variant name such as Root, D1-B1.

    Returns:
        is_compiled, is_run_success, report_log, elf_path
    """
    norm_task_id, inferred_type = parse_task_id_and_type(task_id)
    eval_dir = make_eval_dir(task_id, variant_name)
    src_path = eval_dir / f"task_{safe_name(norm_task_id)}_{safe_name(variant_name)}.c"
    exe_path = eval_dir / f"task_{safe_name(norm_task_id)}_{safe_name(variant_name)}.out"

    full_c_code, test_source_desc = build_full_c_code(code_str, task_id)
    src_path.write_text(full_c_code, encoding="utf-8")

    report_parts: List[str] = []
    report_parts.append(f"[External Tester] task_id={task_id} normalized={norm_task_id} inferred_type={inferred_type} variant={variant_name}")
    report_parts.append(f"[External Tester] JSON_FILE={JSON_FILE}")
    report_parts.append(f"[External Tester] TARGET_TYPE={TARGET_TYPE}")
    report_parts.append(f"[External Tester] test_source={test_source_desc}")
    report_parts.append(f"[External Tester] work_dir={eval_dir}")

    compile_cmd = [CC, str(src_path), "-o", str(exe_path), "-lm", "-w"]
    report_parts.append(f"[Compile Cmd] {' '.join(shlex.quote(x) for x in compile_cmd)}")

    try:
        comp_res = subprocess.run(
            compile_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=COMPILE_TIMEOUT,
        )
        compile_log = comp_res.stdout or ""
        report_parts.append(f"[Compile Exit Code] {comp_res.returncode}")
        if compile_log.strip():
            report_parts.append("[Compile Output]\n" + compile_log.strip())

        if comp_res.returncode != 0:
            report = "\n".join(report_parts)
            if not KEEP_EVAL_ARTIFACTS:
                shutil.rmtree(eval_dir, ignore_errors=True)
            return False, False, report, None

    except subprocess.TimeoutExpired:
        report_parts.append(f"[Compile Timeout] {COMPILE_TIMEOUT}s")
        report = "\n".join(report_parts)
        if not KEEP_EVAL_ARTIFACTS:
            shutil.rmtree(eval_dir, ignore_errors=True)
        return False, False, report, None
    except Exception as e:
        report_parts.append(f"[Compile Exception] {repr(e)}")
        report = "\n".join(report_parts)
        if not KEEP_EVAL_ARTIFACTS:
            shutil.rmtree(eval_dir, ignore_errors=True)
        return False, False, report, None

    run_cmd = RUNNER_CMD + [str(exe_path)]
    report_parts.append(f"[Run Cmd] {' '.join(shlex.quote(x) for x in run_cmd)}")

    try:
        run_res = subprocess.run(
            run_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=RUN_TIMEOUT,
        )
        report_parts.append(f"[Run Exit Code] {run_res.returncode}")
        if run_res.stdout.strip():
            report_parts.append("[Run STDOUT]\n" + run_res.stdout.strip())
        if run_res.stderr.strip():
            report_parts.append("[Run STDERR]\n" + run_res.stderr.strip())

        report = "\n".join(report_parts)
        return True, run_res.returncode == 0, report, str(exe_path)

    except subprocess.TimeoutExpired:
        report_parts.append(f"[Run Timeout] {RUN_TIMEOUT}s")
        report = "\n".join(report_parts)
        return True, False, report, str(exe_path)
    except Exception as e:
        report_parts.append(f"[Run Exception] {repr(e)}")
        report = "\n".join(report_parts)
        return True, False, report, str(exe_path)


def collect_c_files(c_dir: str) -> List[Path]:
    p = Path(c_dir)
    if not p.is_dir():
        raise FileNotFoundError(f"找不到 C 文件目录: {c_dir}")
    return sorted([x for x in p.iterdir() if x.is_file() and x.suffix == ".c"])


def run_c_dir(c_dir: str, output_json: Optional[str] = None) -> None:
    c_files = collect_c_files(c_dir)
    print(f"[*] Standalone c_dir mode: {c_dir}")
    print(f"[*] Found {len(c_files)} C files")

    results = []
    for c_file in c_files:
        code = c_file.read_text(encoding="utf-8", errors="ignore")
        task_id, _ = parse_task_id_and_type(c_file.name)
        is_comp, is_run, log, elf = run_comprehensive_evaluation(code, c_file.name, "Standalone")
        print("=" * 80)
        print(f"File: {c_file.name} | task_id={task_id} | compile={is_comp} | run={is_run}")
        print(log)
        results.append({
            "file": str(c_file),
            "task_id": task_id,
            "compiled": is_comp,
            "run_success": is_run,
            "elf_path": elf,
            "log": log,
        })

    if output_json:
        Path(output_json).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[*] Results saved to {output_json}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="External C test runner for InspectCoder.")
    parser.add_argument("--mode", choices=["single", "c_dir"], default="c_dir")
    parser.add_argument("--c-dir", default="", help="Only used in standalone c_dir mode.")
    parser.add_argument("--json-file", default=JSON_FILE)
    parser.add_argument("--target-type", default=TARGET_TYPE, help="O0/O1/O2/O3/all")
    parser.add_argument("--cc", default=CC)
    parser.add_argument("--runner-cmd", default=" ".join(RUNNER_CMD))
    parser.add_argument("--compile-timeout", type=int, default=COMPILE_TIMEOUT)
    parser.add_argument("--run-timeout", type=int, default=RUN_TIMEOUT)
    parser.add_argument("--work-root", default=TEST_WORK_ROOT)
    parser.add_argument("--no-json-test", action="store_true")
    parser.add_argument("--no-remove-main", action="store_true")
    parser.add_argument("--cleanup", action="store_true", help="Remove eval dirs after compile failure; compiled ELF may still be needed by GDB in import mode.")
    parser.add_argument("--output-json", default="")
    return parser.parse_args()


def apply_cli_args(args: argparse.Namespace) -> None:
    global JSON_FILE, TARGET_TYPE, CC, RUNNER_CMD, COMPILE_TIMEOUT, RUN_TIMEOUT
    global TEST_WORK_ROOT, USE_JSON_TEST, REMOVE_MAIN_WHEN_INJECT_TEST, KEEP_EVAL_ARTIFACTS
    global _JSON_ITEMS_CACHE

    JSON_FILE = args.json_file
    TARGET_TYPE = normalize_target_type(args.target_type) or ""
    CC = args.cc
    RUNNER_CMD = shlex.split(args.runner_cmd) if args.runner_cmd.strip() else []
    COMPILE_TIMEOUT = args.compile_timeout
    RUN_TIMEOUT = args.run_timeout
    TEST_WORK_ROOT = args.work_root
    USE_JSON_TEST = not args.no_json_test
    REMOVE_MAIN_WHEN_INJECT_TEST = not args.no_remove_main
    KEEP_EVAL_ARTIFACTS = not args.cleanup
    _JSON_ITEMS_CACHE = None


def main() -> None:
    args = parse_args()
    apply_cli_args(args)

    if args.mode == "c_dir":
        if not args.c_dir:
            raise SystemExit("--mode c_dir 需要提供 --c-dir")
        run_c_dir(args.c_dir, args.output_json or None)
    else:
        raise SystemExit("single mode is reserved for import usage; use c_dir for standalone testing.")


if __name__ == "__main__":
    main()
