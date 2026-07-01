#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASM Semantic Memory-Guided Ghidra Recovery
==========================================

This script is a lightweight extension of the original tool-calling
assembly-to-C reconstruction workflow.  It keeps the original overall behavior:

    assembly + optional Ghidra pseudocode -> LLM -> recovered C

but inserts one meaningful intermediate step:

    assembly -> soft semantic memory report -> LLM memory/context

The ASM memory report is deliberately *loose*.  It is not a hard verifier and
not a strict constraint system.  It summarizes useful semantic hints from the
assembly so that, when the model reads Ghidra pseudocode, it can use the report
as memory to better understand control flow, calls, data access, type widths,
constants, labels, and possible decompiler artifacts.

Recommended use:
    export DEEPSEEK_API_KEY="your-key"
    python asm_memory_guided_ghidra_recovery_v2.py
    python asm_memory_guided_ghidra_recovery_v2.py /path/to/asm_dir

Environment overrides:
    ASM_INPUT_DIR       input assembly directory
    GHIDRA_DIR          Ghidra pseudocode directory
    RECOVER_OUTPUT_DIR  output directory
    DEEPSEEK_MODEL      model name
"""

from __future__ import annotations

import os
import sys
import json
import time
import re
import inspect
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

from openai import OpenAI

try:
    from tqdm import tqdm
except ImportError:
    print("提示: 未安装 tqdm，将不显示进度条。建议使用 'pip install tqdm' 安装。")

    def tqdm(iterable, **kwargs):  # type: ignore
        return iterable

# ==================== ⚙️ 核心配置区域 ⚙️ ====================
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
API_BASE = os.environ.get("DEEPSEEK_API_BASE", "https://api.deepseek.com").strip()
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash").strip()

INPUT_DIR = os.environ.get(
    "ASM_INPUT_DIR",
    "/home/lhw/codetran/decompile/data/bring-86-mac-O2",
)
OUTPUT_DIR = os.environ.get(
    "RECOVER_OUTPUT_DIR",
    "/home/lhw/codetran/decompile/dec-tool-v4/O2-86-bring",
)
GHIDRA_DIR = os.environ.get(
    "GHIDRA_DIR",
    "/home/lhw/codetran/ghidra/dec-bring/O2",
)

RATE_LIMIT_DELAY = float(os.environ.get("RATE_LIMIT_DELAY", "1.0"))
DECOMPILE_TEMPERATURE = float(os.environ.get("DECOMPILE_TEMPERATURE", "0.1"))
DECOMPILE_MAX_TOKENS = int(os.environ.get("DECOMPILE_MAX_TOKENS", "384000"))
MAX_AGENT_STEPS = int(os.environ.get("MAX_AGENT_STEPS", "4"))

# 这版 memory 是轻量提示，不做硬约束。默认保存报告，便于论文图和实验记录。
SAVE_ASM_MEMORY = os.environ.get("SAVE_ASM_MEMORY", "1") != "0"
SKIP_EXISTING = os.environ.get("SKIP_EXISTING", "0") == "1"
ASM_MEMORY_MAX_ITEMS = int(os.environ.get("ASM_MEMORY_MAX_ITEMS", "80"))
ASM_SNIPPET_MAX_CHARS = int(os.environ.get("ASM_SNIPPET_MAX_CHARS", "250000"))
# ==========================================================

if API_KEY and API_KEY != "这里替换成你的API_KEY":
    openai_client: Optional[OpenAI] = OpenAI(api_key=API_KEY, base_url=API_BASE)
else:
    openai_client = None


# ==================== 🛠️ 工具定义区域 🛠️ ====================
def read_file_tool(filename: str) -> Dict[str, Any]:
    """
    Reads the content of a local file to assist in decompilation.
    :param filename: The absolute path of the file to read.
    :return: The content of the file or an error message.
    """
    path = Path(filename)
    if not path.exists():
        return {"error": f"File not found: {filename}"}
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return {"file_path": str(path), "content": content}
    except Exception as e:
        return {"error": str(e)}


TOOL_REGISTRY = {
    "read_file": read_file_tool,
}


def get_tool_str_representation(tool_name: str) -> str:
    tool = TOOL_REGISTRY[tool_name]
    return f"Name: {tool_name}\nDescription: {tool.__doc__.strip()}\nSignature: {inspect.signature(tool)}"


# ==================== 🧠 ASM Semantic Memory ====================
_BRANCH_MNEMONICS = {
    # AArch64 common branches
    "b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz",
    "beq", "b.eq", "bne", "b.ne", "bgt", "b.gt", "bge", "b.ge", "blt", "b.lt",
    "ble", "b.le", "bhi", "b.hs", "blo", "b.lo", "bcs", "b.cc", "bcc", "b.mi",
    "bpl", "b.vs", "b.vc", "b.al",
    # x86/x64 common branches
    "jmp", "call", "retq", "retl", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp", "jecxz", "jrcxz",
}
_CALL_MNEMONICS = {"bl", "blr", "call", "callq", "calll"}
_RETURN_MNEMONICS = {"ret", "retq", "retl", "bx"}
_LOAD_STORE_PREFIXES = (
    "ldr", "ldp", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
    "str", "stp", "strb", "strh",
    "mov", "movq", "movl", "movw", "movb",
)
_ARITH_MNEMONICS = {
    "add", "sub", "mul", "smull", "umull", "sdiv", "udiv", "and", "orr", "eor", "xor",
    "lsl", "lsr", "asr", "ror", "shl", "shr", "sar", "lea", "cmp", "test", "cset", "csinc",
}


def _strip_asm_comment(line: str) -> str:
    # 尽量温和地去注释，避免破坏字符串伪指令。
    # 常见注释: //, ;, #。其中 # 可能是 AArch64 immediate，因此只在行首或空格后 # 且不是 #0x/#数字时弱处理。
    line = re.sub(r"//.*$", "", line)
    if ";" in line:
        line = line.split(";", 1)[0]
    return line.rstrip()


def _normalize_instruction_line(line: str) -> str:
    line = _strip_asm_comment(line).strip()
    # 去掉地址前缀，例如 "4005d0: add ..."
    line = re.sub(r"^\s*[0-9a-fA-F]+:\s*", "", line)
    return line


def _get_mnemonic(line: str) -> str:
    line = _normalize_instruction_line(line)
    if not line or line.endswith(":") or line.startswith("."):
        return ""
    parts = line.split(None, 1)
    return parts[0].lower() if parts else ""


def _infer_arch_hint(asm_text: str) -> str:
    lower = asm_text.lower()
    aarch64_score = len(re.findall(r"\b[xw][0-9]{1,2}\b", lower)) + len(re.findall(r"\b(bl|ldr|str|adrp|cbz|cbnz)\b", lower))
    x86_score = len(re.findall(r"\b(eax|ebx|ecx|edx|rax|rbx|rcx|rdx|rsp|rbp|rip)\b", lower)) + len(re.findall(r"\b(callq|jmp|movq|leaq)\b", lower))
    if aarch64_score > x86_score * 1.5:
        return "AArch64-like"
    if x86_score > aarch64_score * 1.5:
        return "x86/x64-like"
    return "unknown / mixed"


def _push_limited(bucket: List[str], item: str, max_items: int) -> None:
    item = item.strip()
    if item and item not in bucket and len(bucket) < max_items:
        bucket.append(item)


def extract_asm_semantic_memory(asm_text: str, max_items: int = ASM_MEMORY_MAX_ITEMS) -> Dict[str, Any]:
    """
    Extract a *soft* semantic memory from ASM.

    This is intentionally heuristic and lightweight.  It does not attempt to
    build a full formal CFG/SSA.  The output is meant to become a readable
    memory report for an LLM, not a hard constraint solver.
    """
    lines = asm_text.splitlines()
    labels: List[str] = []
    function_like_labels: List[str] = []
    basic_block_labels: List[str] = []
    branch_samples: List[str] = []
    return_samples: List[str] = []
    call_targets: List[str] = []
    call_samples: List[str] = []
    dataflow_samples: List[str] = []
    memory_samples: List[str] = []
    type_width_hints: List[str] = []
    constants_and_strings: List[str] = []
    global_or_address_samples: List[str] = []
    artifact_labels: List[str] = []

    # Label extraction.
    for raw in lines:
        s = raw.strip()
        m = re.match(r"^([A-Za-z_.$][\w.$@-]*):\s*$", s)
        if m:
            label = m.group(1)
            _push_limited(labels, label, max_items)
            if re.search(r"^(LBB|\.L|LAB_|loc_|bb_|L[0-9])", label):
                _push_limited(basic_block_labels, label, max_items)
                _push_limited(artifact_labels, label, max_items)
            elif not label.startswith("."):
                _push_limited(function_like_labels, label, max_items)

    # Instruction-level samples.
    for raw in lines:
        line = _normalize_instruction_line(raw)
        if not line or line.endswith(":"):
            continue
        mnemonic = _get_mnemonic(line)
        if not mnemonic:
            continue

        # Calls and branches.
        if mnemonic in _CALL_MNEMONICS:
            _push_limited(call_samples, line, max_items)
            # target is usually last operand for both bl and call.
            target = line.split()[-1].strip(",") if len(line.split()) > 1 else ""
            if target:
                _push_limited(call_targets, target, max_items)
        elif mnemonic in _BRANCH_MNEMONICS or mnemonic.startswith("j"):
            if mnemonic in _RETURN_MNEMONICS:
                _push_limited(return_samples, line, max_items)
            else:
                _push_limited(branch_samples, line, max_items)

        # Load/store / memory patterns.
        if mnemonic.startswith(_LOAD_STORE_PREFIXES) or "[" in line or "(" in line and ")" in line:
            if any(tok in line for tok in ["[", "]", "(", ")", "ptr", "PTR", "DAT_", ".LC", "@", ":lo12"]):
                _push_limited(memory_samples, line, max_items)

        # Dataflow/arithmetic samples.
        if mnemonic in _ARITH_MNEMONICS or re.match(r"^(mov|ldr|str|add|sub|cmp|test|lea)", mnemonic):
            _push_limited(dataflow_samples, line, max_items)

        # Type-width hints.
        # AArch64: wN => 32-bit, xN => 64-bit; ldrb/strb byte; ldrh/strh halfword.
        if re.search(r"\bw[0-9]{1,2}\b", line):
            _push_limited(type_width_hints, f"32-bit register usage: {line}", max_items)
        if re.search(r"\bx[0-9]{1,2}\b", line):
            _push_limited(type_width_hints, f"64-bit register/pointer usage: {line}", max_items)
        if re.match(r"^(ldrb|strb|movb)\b", mnemonic):
            _push_limited(type_width_hints, f"byte-width access: {line}", max_items)
        if re.match(r"^(ldrh|strh|movw)\b", mnemonic):
            _push_limited(type_width_hints, f"halfword-width access: {line}", max_items)
        if re.match(r"^(ldrsb|ldrsh|ldrsw|sxt|sx)\b", mnemonic):
            _push_limited(type_width_hints, f"signed-extension hint: {line}", max_items)
        if re.match(r"^(uxt|zx|movz)\b", mnemonic):
            _push_limited(type_width_hints, f"zero-extension hint: {line}", max_items)

        # Constants / strings / global addresses.
        if re.search(r"#-?0x[0-9a-fA-F]+|#-?\d+|\$-?0x[0-9a-fA-F]+|\$-?\d+", line):
            _push_limited(constants_and_strings, line, max_items)
        if re.search(r"\.string|\.asciz|\.ascii|\.quad|\.word|\.byte|\.long", line):
            _push_limited(constants_and_strings, line, max_items)
        if re.search(r"\b(adrp|adr|lea|leaq)\b|DAT_|PTR_|\.LC|:lo12:", line):
            _push_limited(global_or_address_samples, line, max_items)

    # Simple counts help the LLM know report scale without needing every line.
    nonempty_instruction_count = sum(1 for raw in lines if _get_mnemonic(raw))

    report: Dict[str, Any] = {
        "arch_hint": _infer_arch_hint(asm_text),
        "line_count": len(lines),
        "instruction_like_line_count": nonempty_instruction_count,
        "label_count": len(labels),
        "function_like_labels": function_like_labels,
        "basic_block_labels": basic_block_labels,
        "artifact_or_compiler_labels": artifact_labels,
        "branch_samples": branch_samples,
        "return_samples": return_samples,
        "call_targets": call_targets,
        "call_samples": call_samples,
        "dataflow_samples": dataflow_samples,
        "memory_access_samples": memory_samples,
        "type_width_hints": type_width_hints,
        "constants_and_strings": constants_and_strings,
        "global_or_address_samples": global_or_address_samples,
        "memory_usage_note": (
            "This is a soft semantic memory report extracted from ASM. "
            "Use it as guidance when interpreting Ghidra pseudocode, not as mandatory rewrite rules."
        ),
    }
    return report


def _markdown_list(title: str, values: List[str], max_show: int = 20) -> str:
    out = [f"### {title}"]
    if not values:
        out.append("- Not obvious from lightweight extraction.")
    else:
        for v in values[:max_show]:
            out.append(f"- `{v}`")
        if len(values) > max_show:
            out.append(f"- ... ({len(values) - max_show} more omitted)")
    return "\n".join(out)


def render_asm_memory_markdown(name: str, memory: Dict[str, Any]) -> str:
    """Render the semantic memory as an LLM-friendly report."""
    sections = [
        f"# ASM Semantic Memory Report for `{name}`",
        "",
        "This report is a lightweight memory extracted from the assembly before reading Ghidra pseudocode.",
        "It is **soft guidance**, not a hard constraint system.  Use it to understand Ghidra output, recover intent, and avoid obvious decompiler artifacts.",
        "",
        "## Summary",
        f"- Architecture hint: **{memory.get('arch_hint', 'unknown')}**",
        f"- Assembly lines: **{memory.get('line_count', 0)}**",
        f"- Instruction-like lines: **{memory.get('instruction_like_line_count', 0)}**",
        f"- Label count: **{memory.get('label_count', 0)}**",
        "",
        "## How to use this memory",
        "- Prefer Ghidra pseudocode for high-level structure when it is readable.",
        "- Use this ASM memory to interpret confusing Ghidra temporaries, labels, pointer arithmetic, calls, constants, and type widths.",
        "- Do not mechanically copy register names or block labels into final C unless necessary.",
        "- If the memory is ambiguous, keep a conservative C expression instead of inventing unsupported semantics.",
        "",
        _markdown_list("Function-like labels", memory.get("function_like_labels", [])),
        "",
        _markdown_list("Basic-block / compiler labels", memory.get("basic_block_labels", [])),
        "",
        _markdown_list("Branch and control-flow samples", memory.get("branch_samples", [])),
        "",
        _markdown_list("Return samples", memory.get("return_samples", [])),
        "",
        _markdown_list("Call targets", memory.get("call_targets", [])),
        "",
        _markdown_list("Call instruction samples", memory.get("call_samples", [])),
        "",
        _markdown_list("Data-flow / arithmetic samples", memory.get("dataflow_samples", [])),
        "",
        _markdown_list("Memory access samples", memory.get("memory_access_samples", [])),
        "",
        _markdown_list("Type-width hints", memory.get("type_width_hints", [])),
        "",
        _markdown_list("Constants / strings / labels", memory.get("constants_and_strings", [])),
        "",
        _markdown_list("Global/address-related samples", memory.get("global_or_address_samples", [])),
        "",
        "## Final reminder",
        "This report should act like memory while polishing Ghidra code: useful for grounding, but not a replacement for careful reconstruction.",
    ]
    return "\n".join(sections)


def save_asm_memory_reports(name: str, memory: Dict[str, Any], markdown: str) -> None:
    if not SAVE_ASM_MEMORY:
        return
    mem_dir = Path(OUTPUT_DIR) / "_asm_memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    (mem_dir / f"{name}_asm_memory.json").write_text(
        json.dumps(memory, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (mem_dir / f"{name}_asm_memory.md").write_text(markdown, encoding="utf-8")


# ==================== Prompt / Tool Calling ====================
def get_full_system_prompt() -> str:
    tool_str_repr = "\n\n".join(
        [f"TOOL:\n{get_tool_str_representation(name)}" for name in TOOL_REGISTRY]
    )

    return f"""You are an expert reverse engineer. Your task is to reconstruct a COMPLETE, COMPILABLE, and EXECUTABLE C program.

Available Tools:
{tool_str_repr}

Usage: Reply with EXACTLY ONE LINE to use a tool:
tool: TOOL_NAME({{"JSON_ARGS"}})

CRITICAL RULES FOR RECONSTRUCTION & FINAL OUTPUT:
1. GHIDRA AS STRUCTURAL REFERENCE: If a Ghidra pseudocode file is provided, read it first and use it as the main high-level structural candidate.
2. ASM SEMANTIC MEMORY AS SOFT GUIDANCE: The user prompt includes an ASM Semantic Memory Report. Treat it as memory/hints extracted from the assembly. It can help interpret confusing Ghidra variables, labels, pointer arithmetic, constants, calls, and type widths.
3. LOOSE GUIDANCE, NOT HARD CONSTRAINTS: Do NOT treat every ASM-memory item as a mandatory rewrite rule. If the ASM memory is ambiguous, preserve behavior and keep the Ghidra structure conservative.
4. ORGANIC CONNECTION: Organically connect functions, global variables, data references, helper declarations, and dependencies into a single coherent C program.
5. CLEAN NATIVE C: When safe, refactor messy gotos, LBB/LAB labels, do-while(1), register-like variables, and synthetic temporaries into clearer native C. Do not remove labels/gotos mechanically if they are needed for control flow.
6. NO HALLUCINATION: Do not invent external behavior. The assembly and Ghidra code are evidence; inferred names should remain conservative.
7. PURE C CODE ONLY: Once ready to output final code, output ONLY valid standard C code. No markdown, explanations, notes, greetings, or comments about your process.
"""


def extract_tool_invocations(text: str) -> List[Tuple[str, Dict[str, Any]]]:
    invocations: List[Tuple[str, Dict[str, Any]]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("tool:"):
            continue
        try:
            after = line[len("tool:"):].strip()
            name, rest = after.split("(", 1)
            name = name.strip()
            if not rest.endswith(")"):
                continue
            json_str = rest[:-1].strip()
            args = json.loads(json_str)
            invocations.append((name, args))
        except Exception:
            continue
    return invocations


def extract_c_code(raw_output: str) -> str:
    """Clean LLM output and return plain C code."""
    code_block_match = re.search(r"`{3}(?:c|cpp|C)?\s*\n(.*?)\n`{3}", raw_output, re.DOTALL)
    if code_block_match:
        code = code_block_match.group(1)
    else:
        code = raw_output
        code = re.sub(r"^(Here is.*?:\n|Here's.*?:\n)", "", code, flags=re.IGNORECASE)
        code = re.sub(r"`{3}(?:c|cpp|C)?\s*\n?", "", code)
        code = re.sub(r"`{3}\s*$", "", code)

    lines: List[str] = []
    for line in code.split("\n"):
        stripped = line.strip()
        if stripped and any(
            stripped.startswith(word)
            for word in ["Here is", "This function", "Note:", "Explanation:", "The above"]
        ):
            continue
        lines.append(line)
    result = "\n".join(lines).strip()
    return result if result else raw_output.strip()


# ==================== Ghidra Path Matching ====================
def locate_ghidra_reference(name: str) -> Optional[str]:
    ghidra_dir_path = Path(GHIDRA_DIR)
    if not ghidra_dir_path.exists():
        return None

    candidates = [
        ghidra_dir_path / "decompile" / f"{name}_ghidra.c",
        ghidra_dir_path / f"{name}_ghidra.c",
        ghidra_dir_path / f"{name}.c",
    ]
    for p in candidates:
        if p.exists():
            return str(p)

    # Fallback: keep original loose matching style.
    for file_path in ghidra_dir_path.rglob("*.c"):
        if file_path.name == f"{name}.c" or file_path.name.startswith(f"{name}_"):
            return str(file_path)
    return None


# ==================== 🧠 Agent 核心循环 🧠 ====================
def run_agent_decompilation(name: str, x86_asm: str) -> Dict[str, Any]:
    """Run one ASM-memory-guided tool-calling reconstruction task."""
    if openai_client is None:
        return {"success": False, "error": "OpenAI client is not configured.", "tokens": 0}

    ghidra_path = locate_ghidra_reference(name)

    asm_memory = extract_asm_semantic_memory(x86_asm)
    asm_memory_markdown = render_asm_memory_markdown(name, asm_memory)
    save_asm_memory_reports(name, asm_memory, asm_memory_markdown)

    if ghidra_path:
        hint_text = (
            f"REQUIRED: Read the Ghidra reference first using "
            f"`tool: read_file({{\"filename\": \"{ghidra_path}\"}})`."
        )
    else:
        hint_text = "No Ghidra reference found. Use the ASM Semantic Memory Report and the raw assembly to build the complete program."

    asm_for_prompt = x86_asm.strip()
    if len(asm_for_prompt) > ASM_SNIPPET_MAX_CHARS:
        asm_for_prompt = asm_for_prompt[:ASM_SNIPPET_MAX_CHARS] + "\n\n/* [ASM truncated in prompt; use semantic memory report as compact guidance.] */"

    user_prompt = f"""Task: Recover and polish the complete C program for `{name}`.

{hint_text}

Important design intent:
- This workflow is intentionally close to simple ASM + Ghidra reading.
- The added step is an ASM Semantic Memory Report.
- Use the report as memory while understanding and polishing Ghidra pseudocode.
- Do not over-constrain the rewrite. Prefer a readable, coherent C program that preserves observed behavior.

ASM Semantic Memory Report:
{asm_memory_markdown}

Raw Assembly Evidence:
{asm_for_prompt}

Final output requirement:
Output standard C code ONLY. Do not include explanations or markdown.
"""

    conversation = [
        {"role": "system", "content": get_full_system_prompt()},
        {"role": "user", "content": user_prompt},
    ]

    total_tokens = 0
    final_c_code: Optional[str] = None

    for step in range(1, MAX_AGENT_STEPS + 1):
        try:
            response = openai_client.chat.completions.create(
                model=MODEL,
                messages=conversation,
                temperature=DECOMPILE_TEMPERATURE,
                max_tokens=DECOMPILE_MAX_TOKENS,
            )
        except Exception as e:
            return {
                "success": False,
                "error": f"API Error: {str(e)}",
                "tokens": total_tokens,
                "asm_memory_saved": SAVE_ASM_MEMORY,
                "ghidra_path": ghidra_path,
            }

        assistant_message = response.choices[0].message.content or ""
        usage = response.usage
        if usage:
            total_tokens += usage.total_tokens

        conversation.append({"role": "assistant", "content": assistant_message})
        tool_invocations = extract_tool_invocations(assistant_message)

        if not tool_invocations:
            final_c_code = extract_c_code(assistant_message)
            break

        for tool_name, args in tool_invocations:
            if tool_name not in TOOL_REGISTRY:
                conversation.append({
                    "role": "user",
                    "content": f"tool_result({json.dumps({'error': f'Unknown tool: {tool_name}'}, ensure_ascii=False)})",
                })
                continue

            if tool_name == "read_file":
                filename_to_read = args.get("filename")
                if not filename_to_read and ghidra_path:
                    filename_to_read = ghidra_path
                elif not filename_to_read:
                    filename_to_read = "."

                print(f"  [Agent 执行工具] 读取参考文件: {filename_to_read}")
                tool_res = read_file_tool(str(filename_to_read))
                conversation.append({
                    "role": "user",
                    "content": f"tool_result({json.dumps(tool_res, ensure_ascii=False)})",
                })

    if not final_c_code:
        return {
            "success": False,
            "error": "Agent failed to produce final C code within max steps.",
            "tokens": total_tokens,
            "asm_memory_saved": SAVE_ASM_MEMORY,
            "ghidra_path": ghidra_path,
        }

    return {
        "success": True,
        "c_code": final_c_code,
        "tokens": total_tokens,
        "error": None,
        "asm_memory_saved": SAVE_ASM_MEMORY,
        "ghidra_path": ghidra_path,
    }


# ==================== 🚀 批量工作流 🚀 ====================
def process_single_file(name: str, x86_asm: str) -> Dict[str, Any]:
    c_file = Path(OUTPUT_DIR) / f"{name}.c"
    if SKIP_EXISTING and c_file.exists() and c_file.stat().st_size > 0:
        return {
            "success": True,
            "name": name,
            "tokens": 0,
            "error": None,
            "skipped": True,
            "c_code_path": str(c_file),
        }

    result = run_agent_decompilation(name, x86_asm)
    result["name"] = name

    if result.get("success"):
        c_file.parent.mkdir(parents=True, exist_ok=True)
        c_file.write_text(result["c_code"], encoding="utf-8")
        result["c_code_path"] = str(c_file)
    return result


def run_workflow(input_dir: str) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    input_path = Path(input_dir)
    if not input_path.exists():
        print(f"❌ 目录不存在: {input_dir}")
        return

    asm_files = list(input_path.glob("*.s")) + list(input_path.glob("*.asm"))
    if not asm_files:
        print(f"❌ 未找到汇编文件 (.s 或 .asm) 在目录: {input_dir}")
        return

    print(f"✓ 找到 {len(asm_files)} 个汇编文件，准备生成 ASM memory 并恢复 C...\n")

    assemblies: List[Dict[str, str]] = []
    for asm_file in sorted(asm_files):
        content = asm_file.read_text(encoding="utf-8", errors="replace")
        assemblies.append({"name": asm_file.stem, "x86_assembly": content})

    print("=" * 72)
    print(f"🤖 启动 ASM Semantic Memory + Ghidra Tool-Calling 恢复流程 (模型: {MODEL})")
    print(f"📁 汇编输入目录: {input_dir}")
    print(f"📁 Ghidra参考目录: {GHIDRA_DIR}")
    print(f"📁 代码输出目录: {OUTPUT_DIR}")
    print(f"🧠 ASM memory报告: {'开启' if SAVE_ASM_MEMORY else '关闭'}")
    print(f"⏭️  跳过已有输出: {'开启' if SKIP_EXISTING else '关闭'}")
    print("=" * 72 + "\n")

    results: List[Dict[str, Any]] = []
    stats = {"total": len(assemblies), "success": 0, "failed": 0, "skipped": 0, "total_tokens": 0}

    for item in tqdm(assemblies, desc="恢复进度"):
        result = process_single_file(item["name"], item["x86_assembly"])
        results.append(result)

        if result.get("success"):
            stats["success"] += 1
            stats["total_tokens"] += int(result.get("tokens", 0) or 0)
            if result.get("skipped"):
                stats["skipped"] += 1
        else:
            stats["failed"] += 1
            print(f"\n❌ [{item['name']}] 恢复失败: {result.get('error')}")

        time.sleep(RATE_LIMIT_DELAY)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = Path(OUTPUT_DIR) / f"report_{timestamp}.txt"
    with report_file.open("w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("ASM Semantic Memory-Guided Ghidra Recovery Report\n")
        f.write("=" * 72 + "\n")
        f.write(f"模型: {MODEL}\n")
        f.write(f"汇编输入目录: {input_dir}\n")
        f.write(f"Ghidra参考目录: {GHIDRA_DIR}\n")
        f.write(f"代码输出目录: {OUTPUT_DIR}\n")
        f.write(f"总处理文件数: {stats['total']}\n")
        f.write(f"成功数: {stats['success']} ({stats['success']/max(1, stats['total'])*100:.1f}%)\n")
        f.write(f"失败数: {stats['failed']}\n")
        f.write(f"跳过已有输出数: {stats['skipped']}\n")
        f.write(f"总消耗 Token: {stats['total_tokens']}\n")
        f.write(f"ASM memory保存: {'yes' if SAVE_ASM_MEMORY else 'no'}\n")
        f.write("\n")

        failures = [r for r in results if not r.get("success")]
        if failures:
            f.write("失败详情:\n")
            for r in failures:
                f.write(f"- {r.get('name')}: {r.get('error')}\n")
            f.write("\n")

        f.write("样本详情:\n")
        for r in results:
            f.write(
                f"- {r.get('name')}: "
                f"success={r.get('success')} "
                f"skipped={r.get('skipped', False)} "
                f"tokens={r.get('tokens', 0)} "
                f"ghidra={r.get('ghidra_path')} "
                f"output={r.get('c_code_path')}\n"
            )

    print(
        f"\n🎉 任务完成! 成功率: {stats['success']}/{stats['total']} "
        f"({stats['success']/max(1, stats['total'])*100:.1f}%)"
    )
    print(f"📄 报告已保存: {report_file}")
    if SAVE_ASM_MEMORY:
        print(f"🧠 ASM memory 已保存到: {Path(OUTPUT_DIR) / '_asm_memory'}")


def main() -> None:
    if not openai_client:
        print("⚠️ 警告: 您尚未配置正确的 API_KEY。请设置环境变量 DEEPSEEK_API_KEY\n")
        sys.exit(1)

    target_dir = sys.argv[1] if len(sys.argv) > 1 else INPUT_DIR
    run_workflow(target_dir)


if __name__ == "__main__":
    main()
