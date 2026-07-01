#!/usr/bin/env python3
import os
import sys
import re
import requests
import json
import time
import subprocess
import glob
import select
import signal
import importlib.util
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Any

# ================= 基础配置区 =================
# 【InspectCoder修改】增加 -g 参数以保留调试符号，支持 GDB 动态分析
OPT_LEVEL = "-O0 -g"
OPT_LEVEL2 = "-O3"

SOURCE_BASE_DIR = "/home/lhw/codetran/decompile/dec-tool-v4-ghidra/O3"
BENCH_DIR = "/home/lhw/codetran/recon/bringup-bench"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(
    SCRIPT_DIR,
    "ghidra-fixexe",
    OPT_LEVEL2.strip("-") or "default",
)

# ================= 外部测试代码配置 =================
# 改成你外部测试代码的真实路径。
#
# 外部测试脚本中必须提供：
#   run_comprehensive_evaluation(code_str, task_id, variant_name="Root")
#
# 返回值必须是：
#   is_compiled, is_run_success, report_log, elf_path
#
# 即：
#   bool, bool, str, str|None
#
# 注意：
# 外部测试脚本必须把主流程写在：
#   if __name__ == "__main__":
#       main()
# 下面。
# 否则本脚本 import 外部测试脚本时，外部脚本会立刻执行。
EXTERNAL_TESTER_PATH = "/home/lhw/inspect/test/ex_test.py"

# True: 使用外部测试代码
# False: 不使用外部测试代码，此时会返回测试器未启用错误
USE_EXTERNAL_TESTER = True

_EXTERNAL_TESTER_MODULE = None
# ======================================================

API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL_NAME = "deepseek-v4-flash"
CURRENT_TASK_API_FAILED = False
# --- BFS 树搜索超参数设置 ---
MAX_DEPTH = 2              # 搜索最大深度
BRANCHES_PER_NODE = 2      # 架构师每轮发散的假设数量

# --- InspectCoder 超参数 ---
MAX_DEBUG_TURNS = 2

# ================= 工具链与外部环境配置 =================
COMPILER = "gcc"
MAKE_TARGET = "build"
TARGET_ARCH = "host"
EXEC_TIMEOUT = 30

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# --- 外部知识注入 (Ghidra 字典) ---
GHIDRA_KNOWLEDGE_BASE = """
[Ghidra Type Definitions Reference]:
typedef unsigned char    byte;
typedef unsigned short   ushort;
typedef unsigned int     uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short   undefined2;
typedef unsigned int     undefined4;
typedef unsigned long    undefined8;
Note: Replace all undefined/Ghidra specific types with standard C types (e.g., uint64_t for undefined8, uint32_t for undefined4) by including <stdint.h>.
"""


def run_cmd(cmd, cwd, timeout=None):
    try:
        is_shell = isinstance(cmd, str)
        res = subprocess.run(
            cmd,
            cwd=cwd,
            shell=is_shell,
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


def find_executable(bench_dir, bench_name):
    """
    保留原来的 ELF 查找工具，主要给当前脚本内部或调试备用。
    如果你完全依赖外部测试脚本，这个函数一般不会被直接用于测试。
    """
    guesses = [
        bench_name,
        bench_name + ".elf",
        bench_name + ".out",
        "main",
        "main.elf",
        "a.out",
    ]

    for guess in guesses:
        path = os.path.join(bench_dir, guess)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    for root, _, files in os.walk(bench_dir):
        for f in files:
            if f.endswith((".c", ".cpp", ".h", ".o", ".sh", ".py", ".txt", ".md", ".S")):
                continue

            path = os.path.join(root, f)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                try:
                    with open(path, "rb") as fp:
                        header = fp.read(4)
                        if header.startswith(b"\x7fELF") or header in (
                            b"\xcf\xfa\xed\xfe",
                            b"\xce\xfa\xed\xfe",
                            b"\xfe\xed\xfa\xcf",
                            b"\xfe\xed\xfa\xce",
                            b"\xca\xfe\xba\xbe",
                        ):
                            return path
                except Exception:
                    pass

    return None


def load_external_tester():
    """
    动态加载外部测试脚本。

    外部测试脚本必须提供：
        run_comprehensive_evaluation(code_str, task_id, variant_name="Root")

    外部测试脚本的函数必须返回：
        is_compiled, is_run_success, report_log, elf_path
    """
    global _EXTERNAL_TESTER_MODULE

    if _EXTERNAL_TESTER_MODULE is not None:
        return _EXTERNAL_TESTER_MODULE

    if not USE_EXTERNAL_TESTER:
        raise RuntimeError("USE_EXTERNAL_TESTER=False，外部测试器未启用")

    if not os.path.isfile(EXTERNAL_TESTER_PATH):
        raise FileNotFoundError(f"找不到外部测试脚本: {EXTERNAL_TESTER_PATH}")

    spec = importlib.util.spec_from_file_location(
        "external_test_runner",
        EXTERNAL_TESTER_PATH,
    )

    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载外部测试脚本: {EXTERNAL_TESTER_PATH}")

    tester = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tester)

    if not hasattr(tester, "run_comprehensive_evaluation"):
        raise AttributeError(
            "外部测试脚本中没有找到 run_comprehensive_evaluation("
            "code_str, task_id, variant_name) 函数"
        )

    # 同步当前脚本的关键配置给外部测试脚本。
    # 这样 BFS 修复代码和外部测试代码使用同一套 benchmark 配置。
    if hasattr(tester, "BENCH_DIR"):
        tester.BENCH_DIR = BENCH_DIR

    if hasattr(tester, "COMPILER"):
        tester.COMPILER = COMPILER

    if hasattr(tester, "TARGET_ARCH"):
        tester.TARGET_ARCH = TARGET_ARCH

    if hasattr(tester, "MAKE_TARGET"):
        tester.MAKE_TARGET = MAKE_TARGET

    if hasattr(tester, "EXEC_TIMEOUT"):
        tester.EXEC_TIMEOUT = EXEC_TIMEOUT

    # 是否同步 OPT_LEVEL：
    # 如果你希望外部测试脚本保留自己的优化参数，
    # 可以注释掉下面两行。
    if hasattr(tester, "OPT_LEVEL"):
        tester.OPT_LEVEL = OPT_LEVEL

    _EXTERNAL_TESTER_MODULE = tester
    return tester


def run_comprehensive_evaluation(code_str, task_id, variant_name="Root"):
    """
    统一测试入口。

    BFS / InspectCoder 的其他部分仍然调用这个函数；
    但这个函数内部会转发给外部测试代码。

    外部测试函数必须返回：
        is_compiled, is_run_success, report_log, elf_path

    即：
        bool, bool, str, str|None
    """
    if USE_EXTERNAL_TESTER:
        try:
            tester = load_external_tester()

            result = tester.run_comprehensive_evaluation(
                code_str,
                task_id,
                variant_name,
            )

            if not isinstance(result, tuple) or len(result) != 4:
                return (
                    False,
                    False,
                    "[External Tester Error]\n"
                    "外部 run_comprehensive_evaluation() 返回值格式错误。\n"
                    "期望返回: (is_compiled, is_run_success, report_log, elf_path)\n",
                    None,
                )

            is_compiled, is_run_success, report_log, elf_path = result

            is_compiled = bool(is_compiled)
            is_run_success = bool(is_run_success)
            report_log = "" if report_log is None else str(report_log)

            return is_compiled, is_run_success, report_log, elf_path

        except Exception as e:
            return (
                False,
                False,
                f"[External Tester Exception]\n{repr(e)}\n",
                None,
            )

    return (
        False,
        False,
        "[Internal Tester Disabled]\n"
        "当前 USE_EXTERNAL_TESTER=False，并且本脚本内部测试逻辑已被外部测试适配器替换。\n",
        None,
    )


# ================= InspectWare: 状态化调试中间件 =================
class InspectWareGDB:
    def __init__(self, elf_path):
        self.elf_path = elf_path
        self.p = subprocess.Popen(
            ["gdb", "-q", "--nx", elf_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.execute("set pagination off")
        self.execute("set confirm off")

    def _read_until_prompt(self, timeout=3.0):
        out = ""
        start = time.time()

        while True:
            if time.time() - start > timeout:
                self.p.send_signal(signal.SIGINT)
                out += "\n[InspectWare Middleware] ⚠️ Execution timeout! Sent SIGINT to pause the program.\n"
                timeout += 2.0

            r, _, _ = select.select([self.p.stdout], [], [], 0.1)
            if r:
                char = self.p.stdout.read(1)
                if not char:
                    break

                out += char
                if "(gdb) " in out[-6:]:
                    break

        return out.replace("(gdb) ", "").strip()

    def execute(self, cmd, timeout=3.0):
        if self.p.poll() is not None:
            return "[InspectWare] GDB process has terminated."

        self.p.stdin.write(cmd + "\n")
        self.p.stdin.flush()
        output = self._read_until_prompt(timeout=timeout)
        return output

    def execute_batch(self, cmds, timeout=5.0):
        results = []

        for cmd in cmds:
            res = self.execute(cmd, timeout=timeout)
            results.append(f"> {cmd}\n{res}")

        return "\n".join(results)

    def close(self):
        if self.p.poll() is None:
            try:
                self.p.stdin.write("quit\n")
                self.p.stdin.flush()
                self.p.terminate()
                self.p.wait(timeout=1)
            except Exception:
                self.p.kill()


# ================= LLM API 核心 =================
def _call_llm_api(messages, is_json=False):
    global CURRENT_TASK_API_FAILED

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }

    payload = {
        "model": MODEL_NAME,
        "messages": messages,
    }

    if is_json:
        payload["response_format"] = {"type": "json_object"}

    for i in range(5):
        try:
            response = requests.post(
                API_URL,
                json=payload,
                headers=headers,
                timeout=240,
            )
            response.raise_for_status()
            response_data = response.json()["choices"][0]["message"]
            content = response_data.get("content", "")

            if content.strip():
                return content

            print(f"    [-] API 返回空内容 (重试 {i + 1}/5)")
        except Exception as e:
            wait_time = 2 ** i
            print(f"    [-] API 请求失败 (重试 {i + 1}/5): {str(e)}. 等待 {wait_time}s...")
            time.sleep(wait_time)

    CURRENT_TASK_API_FAILED = True
    print("    [!] LLM API 连续失败，当前任务将不会保存重构代码。")
    return ""


# ================= InspectCoder 智能体 1: Program Inspector =================
def program_inspector_agent(code: str, error_log: str, elf_path: str) -> str:
    print("    [Program Inspector] 🔍 启动动态分析 (Batch Debugging) 针对执行错误...")
    debugger = InspectWareGDB(elf_path)

    system_prompt = """You are a Program Inspector in an agentic program repair system.
Your task is to dynamically analyze the C program using a stateful debugger (GDB) to find the root cause of a runtime or logic error.

To save API calls, you should issue multiple GDB commands in a SINGLE batch.
Available Actions (JSON format MUST be used):
1. `{"action": "batch_execute", "commands": ["break <line>", "run", "info locals", "print var"]}` - Execute a sequence of GDB commands.
2. `{"action": "propose_repair", "plan": "<detailed root cause and fix plan>"}` - End debugging and provide the root cause analysis.

IMPORTANT: Respond ONLY with a valid JSON.
Example:
{
  "thought": "I need to inspect the state before the output mismatch at line 25.",
  "action": "batch_execute",
  "commands": ["break 25", "run", "info locals"]
}"""

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"[Source Code]\n```c\n{code}\n```\n\n"
                f"[Error Output]\n{error_log}\n\n"
                "Start your debugging session now. Propose a repair when ready."
            ),
        },
    ]

    repair_plan = ""

    for turn in range(MAX_DEBUG_TURNS):
        response_text = _call_llm_api(messages, is_json=True)

        try:
            data = json.loads(response_text)
            action = data.get("action")
            thought = data.get("thought", "Analyzing...")

            print(f"      [Inspector Turn {turn + 1}] 🤔 {thought[:60]}... ⚙️ Action: {action}")
            messages.append({"role": "assistant", "content": response_text})

            if action == "propose_repair":
                repair_plan = data.get("plan", "")
                print("      [Inspector] 💡 诊断完成，出具初步 Repair Plan!")
                break

            elif action == "batch_execute":
                cmds = data.get("commands", [])
                observation = debugger.execute_batch(cmds)
                messages.append(
                    {
                        "role": "user",
                        "content": f"[GDB Batch Observation]\n{observation}",
                    }
                )

            else:
                messages.append(
                    {
                        "role": "user",
                        "content": "[InspectWare Error] Invalid action.",
                    }
                )

        except Exception as e:
            messages.append(
                {
                    "role": "user",
                    "content": f"[System] JSON Error: {e}. Respond in valid JSON.",
                }
            )

    debugger.close()

    if not repair_plan:
        repair_plan = "Dynamic debugging session ended. Fall back to static analysis based on error logs."

    return repair_plan


@dataclass
class BFSNode:
    code: str
    depth: int
    error_log: str
    elf_path: Optional[str]
    is_compiled: bool
    failed_history: List[str] = field(default_factory=list)


# ================= InspectCoder 智能体 2: Patch Coder =================
def combined_architect_editor_agent(node: BFSNode, static_repair_plan: str) -> List[dict]:
    print(f"    [Patch Coder] 🛠️ 基于静态分析报告生成 {BRANCHES_PER_NODE} 个修复编译错误的方案...")

    system_prompt = "You are a Patch Coder, a precise C/C++ modifier in the InspectCoder dual-agent framework."
    history_str = "\n".join([f"- {h}" for h in node.failed_history]) if node.failed_history else "None yet."

    user_prompt = f"""
{GHIDRA_KNOWLEDGE_BASE}

[Current Broken Code]:
```c
{node.code}
```

[Error Log / Compiler Output]:
{node.error_log}

[Static Analysis Insights / Repair Plan]:
{static_repair_plan}

[History of FAILED Attempts (DO NOT REPEAT THESE)]:
{history_str}

Task:
Analyze the COMPILATION error and provide exactly {BRANCHES_PER_NODE} RADICALLY DIFFERENT ways to fix the bug.

FORMAT RULES FOR BLOCKS:
1. The `search` string MUST exactly match a contiguous snippet of the [Current Broken Code] (including spaces/indentation).
2. Do not rewrite the entire file, only replace the strictly necessary parts.

Respond ONLY with a valid JSON in the exact format below:
{{
    "branches": [
        {{
            "strategy_type": "<e.g., Header Inclusion, Type Cast, Missing Declaration>",
            "hypothesis": "<Explanation of why this fixes the compile error>",
            "blocks": [
                {{
                    "search": "<Exact lines to replace>",
                    "replace": "<New lines to substitute>"
                }}
            ]
        }}
    ]
}}
"""

    response = _call_llm_api(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        is_json=True,
    )

    try:
        data = json.loads(response)
        return data.get("branches", [])
    except json.JSONDecodeError:
        print("    [Patch Coder] ⚠️ 无法解析 JSON。")
        return []


# ================= InspectCoder 智能体 3: Functional Analyzer =================
def functional_analyzer_agent(node: BFSNode, gdb_insights: str) -> str:
    print("    [Functional Analyzer] 🧠 深度分析运行时报错，推导功能缺陷并定位具体行号...")

    system_prompt = """You are a Master Program Analyzer in a multi-agent system.
Your task is to analyze a C program that compiles successfully but fails during execution (Runtime Error, Output Mismatch, or Logic Bug).
You will be provided with the Source Code, the Execution Error Log, and GDB Debugging Insights.

Your objective is to generate a highly specific, directive "Modification Prompt" that will be fed to a downstream "Coder Agent".

Your analysis MUST include:
1. Deep Root Cause: Why did the program fail functionally? What is the logical flaw?
2. Functional Deficiency: What is the code doing wrong vs. what it *should* be doing.
3. EXACT Line Numbers/Functions: Pinpoint exactly which lines or functions need to be rewritten.
4. The "Modifier Prompt": The final section MUST be a clear, commanding prompt addressed to the Coder Agent, telling it exactly how to fix the code, mentioning the specific line numbers to target.

Format your response exactly like this:
[Root Cause Analysis]
...
[Functional Deficiency]
...
[Target Line Numbers]
Lines X to Y in function Z.
[Modifier Prompt]
<The actual prompt you want to send to the Coder Agent>"""

    user_prompt = f"""
[Source Code]:
```c
{node.code}
```

[Execution Error Output]:
{node.error_log}

[GDB Dynamic Debugging Insights]:
{gdb_insights}

Analyze the above and provide the required sections. Focus heavily on generating a precise [Modifier Prompt].
"""

    response = _call_llm_api(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        is_json=False,
    )

    modifier_prompt = response
    if "[Modifier Prompt]" in response:
        modifier_prompt = response.split("[Modifier Prompt]")[-1].strip()

    return modifier_prompt


# ================= InspectCoder 智能体 4: Functional Modifier =================
def functional_modifier_agent(original_code: str, modifier_prompt: str, failed_history: List[str]) -> List[dict]:
    print("    [Functional Modifier] ✍️ 接收分析师指令，开始在特定行进行精准的 Search/Replace...")

    history_str = "\n".join([f"- {h}" for h in failed_history]) if failed_history else "None yet."
    system_prompt = "You are a Precise Function Modifier Agent. You ONLY output valid JSON."

    user_prompt = f"""
{GHIDRA_KNOWLEDGE_BASE}

[Original Code]:
```c
{original_code}
```

[History of FAILED Attempts (DO NOT REPEAT THESE)]:
{history_str}

[ARCHITECT'S MODIFICATION DIRECTIVE]:
{modifier_prompt}

Task:
Strictly follow the [ARCHITECT'S MODIFICATION DIRECTIVE]. Locate the specific lines mentioned, and generate exactly {BRANCHES_PER_NODE} different ways to implement the requested fix (to provide options for the BFS search).

FORMAT RULES:
1. The `search` string MUST exactly match a contiguous snippet of the [Original Code] (including spaces, newlines, and indentation).
2. ONLY replace the lines targeted by the Architect. Do not rewrite the whole file.

Respond ONLY with a valid JSON in the exact format below:
{{
    "branches": [
        {{
            "strategy_type": "<Brief description of this specific implementation variant>",
            "hypothesis": "<Brief explanation of how this implements the Architect's directive>",
            "blocks": [
                {{
                    "search": "<Exact lines to replace from Original Code>",
                    "replace": "<New corrected lines>"
                }}
            ]
        }}
    ]
}}
"""

    response = _call_llm_api(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        is_json=True,
    )

    try:
        data = json.loads(response)
        return data.get("branches", [])
    except json.JSONDecodeError:
        print("    [Functional Modifier] ⚠️ 无法解析 JSON。")
        return []


# ================= 补丁应用 =================
def apply_patch(original_code: str, patch_text: str) -> Optional[str]:
    pattern = re.compile(r"<<<<\n(.*?)\n====\n(.*?)\n>>>>", re.DOTALL)
    blocks = pattern.findall(patch_text)

    if not blocks:
        return None

    modified_code = original_code

    for search_block, replace_block in blocks:
        if search_block not in modified_code:
            stripped_search = search_block.strip()
            if stripped_search in modified_code:
                modified_code = modified_code.replace(
                    stripped_search,
                    replace_block.strip(),
                    1,
                )
            else:
                return None
        else:
            modified_code = modified_code.replace(search_block, replace_block, 1)

    return modified_code


# ================= BFS Tree Search =================
def bfs_tree_search(original_code: str, task_id: str) -> str:
    print(
        f"\n  >>> 启动 BFS + InspectCoder 工作流 "
        f"(深度:{MAX_DEPTH}, 分支:{BRANCHES_PER_NODE}) (Task:{task_id}) <<<"
    )

    is_compiled, is_run_success, root_log, root_elf = run_comprehensive_evaluation(
        original_code,
        task_id,
        "Root",
    )

    if is_compiled and is_run_success:
        print("    [!] 🎯 原始代码已成功编译并运行通过！直接采纳。")
        return original_code

    best_fallback_code = original_code
    max_compiled_depth = 0 if is_compiled else -1

    root_node = BFSNode(
        code=original_code,
        depth=0,
        error_log=root_log,
        elf_path=root_elf,
        is_compiled=is_compiled,
        failed_history=[],
    )

    queue = [root_node]

    while queue:
        current_node = queue.pop(0)

        if current_node.depth >= MAX_DEPTH:
            continue

        print(
            f"\n  [扩展节点] 深度: {current_node.depth}/{MAX_DEPTH} "
            f"| 历史失败数: {len(current_node.failed_history)}"
        )

        branches = []

        if current_node.is_compiled and current_node.elf_path:
            print("    [Execution Logic Flow] 检测到编译成功但执行报错，启动深度功能分析链路...")

            gdb_insights = program_inspector_agent(
                current_node.code,
                current_node.error_log,
                current_node.elf_path,
            )

            modifier_prompt = functional_analyzer_agent(current_node, gdb_insights)
            print(f"    [Analyzer Prompt Snippet] 📝 {modifier_prompt[:150]}...")

            branches = functional_modifier_agent(
                current_node.code,
                modifier_prompt,
                current_node.failed_history,
            )

        else:
            print("    [Compilation Logic Flow] 编译失败，保持原有逻辑进行静态语法/链接语义修复...")

            repair_plan = (
                "STATIC ANALYSIS MODE: Compilation failed. "
                "Fix the syntax and linker errors strictly based on the compiler error output. "
                "Pay attention to missing headers or incorrect types."
            )

            branches = combined_architect_editor_agent(current_node, repair_plan)

        if not branches:
            continue

        for idx, branch in enumerate(branches[:BRANCHES_PER_NODE]):
            hypothesis = branch.get("hypothesis", "Unknown")
            blocks = branch.get("blocks", [])

            print(f"\n    [分支 {idx + 1}/{len(branches)}] 假设: {hypothesis[:80]}...")

            patch_text = "".join(
                [
                    (
                        f"<<<<\n{b.get('search', '')}\n"
                        f"====\n{b.get('replace', '')}\n>>>>\n"
                    )
                    for b in blocks
                ]
            )

            new_code = apply_patch(current_node.code, patch_text)

            if not new_code:
                print("      [!] 补丁打入失败 (原代码无匹配段落)。")
                continue

            variant_name = f"D{current_node.depth + 1}-B{idx + 1}"

            is_comp, is_run, child_log, child_elf = run_comprehensive_evaluation(
                new_code,
                task_id,
                variant_name,
            )

            child_depth = current_node.depth + 1

            if is_comp and is_run:
                print(f"\n    [!] 🎯 {variant_name} 完美修复问题！搜索结束。")
                return new_code

            if is_comp:
                if child_depth > max_compiled_depth:
                    max_compiled_depth = child_depth
                    best_fallback_code = new_code
                    print(f"      [+] 暂存最优备胎代码 (深度: {max_compiled_depth}，可编译但运行失败)")

            new_history = current_node.failed_history.copy()
            failed_tail = child_log.splitlines()[-1] if child_log.splitlines() else "Unknown"
            new_history.append(f"Hypothesis: {hypothesis} | Failed: {failed_tail}")

            queue.append(
                BFSNode(
                    code=new_code,
                    depth=child_depth,
                    error_log=child_log,
                    elf_path=child_elf,
                    is_compiled=is_comp,
                    failed_history=new_history,
                )
            )

    print(
        f"  <<< BFS 搜索耗尽，未找到满分修复，"
        f"返回可编译且修改最深的版本 (深度: {max_compiled_depth}) >>>"
    )

    return best_fallback_code


def process_tasks():
    if not os.path.exists(SOURCE_BASE_DIR):
        print(f"[-] 找不到源码目录: {SOURCE_BASE_DIR}")
        return

    if USE_EXTERNAL_TESTER:
        try:
            load_external_tester()
            print(f"[*] 已加载外部测试脚本: {EXTERNAL_TESTER_PATH}")
        except Exception as e:
            print(f"[-] 外部测试脚本加载失败: {e}")
            return

    c_files = [f for f in sorted(os.listdir(SOURCE_BASE_DIR)) if f.endswith(".c")]
    print(f"[*] InspectCoder 增强架构启动！发现 {len(c_files)} 个任务...")

    for filename in c_files:
        global CURRENT_TASK_API_FAILED
        
        CURRENT_TASK_API_FAILED = False
        if filename.endswith("_fixed.c"):
            task_id = filename[:-8]
        else:
            task_id = filename[:-2]

        file_path = os.path.join(SOURCE_BASE_DIR, filename)
        output_file = os.path.join(OUTPUT_DIR, f"{task_id}_fixed.c")

        # 如果输出目录中已经有对应结果，则跳过，不再重构
        if os.path.exists(output_file):
            print(f"  [=] Task {task_id} 已存在输出文件，跳过重构: {output_file}")
            continue
        print(f"\n{'=' * 50}\n处理任务 Task {task_id} | 文件: {filename}\n{'=' * 50}")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                full_c_code = file.read()

            if not full_c_code.strip():
                print(f"  [!] Task {task_id} 源码为空，跳过。")
                continue

            best_code = bfs_tree_search(full_c_code, task_id)

            if CURRENT_TASK_API_FAILED:
                print(f"  [!] Task {task_id} 因 LLM API 连续失败，跳过保存重构代码。")
                continue

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(
                    "/* \n"
                    f" * Task ID: {task_id}\n"
                    " * Architecture: BFS Tree + InspectCoder (External Test Runner)\n"
                    f" * External Tester: {EXTERNAL_TESTER_PATH}\n"
                    " */\n\n"
                )
                f.write(best_code)

            print(f"  [+] ⭐ Task {task_id} 重构完成！-> {output_file}")

        except Exception as e:
            print(f"  [-] Task {task_id} 异常: {e}")


if __name__ == "__main__":
    main_start = time.time()
    process_tasks()
    print(f"\n[*] 批处理结束，总耗时: {time.time() - main_start:.2f} 秒。")
