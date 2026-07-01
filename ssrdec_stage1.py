#!/usr/bin/env python3
"""SSRDec Stage 1: Assembly-Guided Structure Recovery.

The script implements the two operations described for Stage 1:

1. Semantic Extraction distills recovery-relevant assembly evidence into a
   compact ASM Hint.
2. Candidate Recovery combines the decompiler-generated pseudocode, ASM Hint,
   and supporting raw assembly to generate the Initial Candidate.

The ASM Hint is soft guidance rather than a formal control-flow model. Candidate
Recovery preserves the pseudocode scaffold and revises only structures that are
inconsistent with the supporting assembly evidence.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

try:
    from tqdm import tqdm
except ImportError:
    print("tqdm is not installed; progress bars are disabled.")

    def tqdm(iterable: Iterable[Any], **_: Any) -> Iterable[Any]:
        return iterable


API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
API_URL = os.environ.get(
    "DEEPSEEK_API_URL",
    "https://api.deepseek.com/v1/chat/completions",
).strip()
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash").strip()

INPUT_DIR = Path(
    os.environ.get(
        "ASM_INPUT_DIR",
        "/home/lhw/codetran/decompile/data/bring-86-mac-O2",
    )
)
GHIDRA_DIR = Path(
    os.environ.get(
        "GHIDRA_DIR",
        "/home/lhw/codetran/ghidra/dec-bring/O2",
    )
)
OUTPUT_DIR = Path(
    os.environ.get(
        "SSRDEC_STAGE1_OUTPUT_DIR",
        os.environ.get(
            "RECOVER_OUTPUT_DIR",
            "/home/lhw/codetran/decompile/ssrdec-stage1/O2-86-bring",
        ),
    )
)

TEMPERATURE = float(os.environ.get("DECOMPILE_TEMPERATURE", "0.1"))
MAX_TOKENS = int(os.environ.get("DECOMPILE_MAX_TOKENS", "65536"))
RAW_ASM_MAX_CHARS = int(os.environ.get("ASM_SNIPPET_MAX_CHARS", "250000"))
ASM_HINT_MAX_ITEMS = int(os.environ.get("ASM_HINT_MAX_ITEMS", "80"))
RATE_LIMIT_DELAY = float(os.environ.get("RATE_LIMIT_DELAY", "1.0"))
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "240"))
LLM_RETRIES = int(os.environ.get("LLM_RETRIES", "5"))
SAVE_ASM_HINT = os.environ.get("SAVE_ASM_HINT", "1") != "0"
SKIP_EXISTING = os.environ.get("SKIP_EXISTING", "0") == "1"

BRANCH_MNEMONICS = {
    "b",
    "beq",
    "b.eq",
    "bne",
    "b.ne",
    "bgt",
    "b.gt",
    "bge",
    "b.ge",
    "blt",
    "b.lt",
    "ble",
    "b.le",
    "bhi",
    "b.hs",
    "blo",
    "b.lo",
    "bcs",
    "b.cc",
    "bcc",
    "b.mi",
    "bpl",
    "b.vs",
    "b.vc",
    "b.al",
    "br",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
    "jmp",
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jecxz",
    "jrcxz",
}
CALL_MNEMONICS = {"bl", "blr", "call", "callq", "calll"}
RETURN_MNEMONICS = {"ret", "retq", "retl", "bx"}
DATAFLOW_PREFIXES = (
    "mov",
    "lea",
    "adr",
    "add",
    "sub",
    "mul",
    "div",
    "and",
    "orr",
    "eor",
    "xor",
    "cmp",
    "test",
    "cset",
    "csinc",
    "lsl",
    "lsr",
    "asr",
    "shl",
    "shr",
    "sar",
)
MEMORY_PREFIXES = (
    "ldr",
    "ldp",
    "str",
    "stp",
    "mov",
    "push",
    "pop",
)


@dataclass
class Stage1Result:
    name: str
    success: bool
    skipped: bool = False
    tokens: int = 0
    error: Optional[str] = None
    ghidra_path: Optional[str] = None
    asm_path: Optional[str] = None
    output_path: Optional[str] = None
    asm_hint_json: Optional[str] = None
    asm_hint_markdown: Optional[str] = None


def strip_assembly_comment(line: str) -> str:
    """Remove common assembly comments without removing AArch64 immediates."""
    line = re.sub(r"//.*$", "", line)
    if ";" in line:
        line = line.split(";", 1)[0]
    return line.rstrip()


def normalize_assembly_line(line: str) -> str:
    """Remove incidental addresses, byte dumps, comments, and extra spacing."""
    line = strip_assembly_comment(line).strip()
    line = re.sub(r"^\s*(?:0x)?[0-9a-fA-F]+:\s*", "", line)
    line = re.sub(r"^(?:[0-9a-fA-F]{2}\s+){1,16}", "", line)
    return re.sub(r"\s+", " ", line).strip()


def mnemonic_of(line: str) -> str:
    normalized = normalize_assembly_line(line)
    if not normalized or normalized.endswith(":") or normalized.startswith("."):
        return ""
    return normalized.split(None, 1)[0].lower()


def infer_architecture(assembly: str) -> str:
    lower = assembly.lower()
    aarch64_score = len(re.findall(r"\b[xw][0-9]{1,2}\b", lower))
    aarch64_score += len(re.findall(r"\b(?:adrp|cbz|cbnz|tbz|tbnz|ldp|stp)\b", lower))
    x86_score = len(
        re.findall(
            r"\b(?:eax|ebx|ecx|edx|esi|edi|rax|rbx|rcx|rdx|rsp|rbp|rip)\b",
            lower,
        )
    )
    x86_score += len(re.findall(r"\b(?:callq|leaq|movq|retq)\b", lower))
    if aarch64_score > x86_score * 1.5:
        return "AArch64-like"
    if x86_score > aarch64_score * 1.5:
        return "x86/x64-like"
    return "unknown or mixed"


def append_unique(bucket: List[str], value: str, limit: int) -> None:
    value = value.strip()
    if value and value not in bucket and len(bucket) < limit:
        bucket.append(value)


def extract_target(instruction: str) -> str:
    operands = instruction.split(None, 1)
    if len(operands) < 2:
        return ""
    target = operands[1].split(",")[-1].strip()
    return target.lstrip("*")


def extract_asm_hint(assembly: str, max_items: int = ASM_HINT_MAX_ITEMS) -> Dict[str, Any]:
    """Distill representative recovery evidence from an assembly listing."""
    labels: List[str] = []
    path_labels: List[str] = []
    function_labels: List[str] = []
    branches: List[str] = []
    returns: List[str] = []
    call_targets: List[str] = []
    calls: List[str] = []
    dataflow: List[str] = []
    memory: List[str] = []
    widths_and_extensions: List[str] = []
    constants: List[str] = []
    addresses: List[str] = []

    raw_lines = assembly.splitlines()
    normalized_lines = [normalize_assembly_line(line) for line in raw_lines]

    for line in normalized_lines:
        match = re.match(r"^([A-Za-z_.$][\w.$@-]*):$", line)
        if not match:
            continue
        label = match.group(1)
        append_unique(labels, label, max_items)
        if re.match(r"^(?:LBB|\.L|LAB_|loc_|bb_|L[0-9])", label):
            append_unique(path_labels, label, max_items)
        elif not label.startswith("."):
            append_unique(function_labels, label, max_items)

    for line in normalized_lines:
        if not line or line.endswith(":"):
            continue
        mnemonic = mnemonic_of(line)
        if not mnemonic:
            continue

        if mnemonic in CALL_MNEMONICS:
            append_unique(calls, line, max_items)
            append_unique(call_targets, extract_target(line), max_items)
        elif mnemonic in RETURN_MNEMONICS:
            append_unique(returns, line, max_items)
        elif mnemonic in BRANCH_MNEMONICS or mnemonic.startswith("j"):
            append_unique(branches, line, max_items)

        if mnemonic.startswith(DATAFLOW_PREFIXES):
            append_unique(dataflow, line, max_items)

        has_memory_syntax = any(token in line for token in ("[", "]", "(", ")", "PTR", "ptr"))
        if mnemonic.startswith(MEMORY_PREFIXES) and has_memory_syntax:
            append_unique(memory, line, max_items)

        if re.search(r"\bw[0-9]{1,2}\b", line):
            append_unique(widths_and_extensions, f"32-bit operand: {line}", max_items)
        if re.search(r"\bx[0-9]{1,2}\b", line):
            append_unique(widths_and_extensions, f"64-bit operand or pointer: {line}", max_items)
        if re.match(r"^(?:ldrb|strb|movb)\b", mnemonic):
            append_unique(widths_and_extensions, f"byte access: {line}", max_items)
        if re.match(r"^(?:ldrh|strh|movw)\b", mnemonic):
            append_unique(widths_and_extensions, f"halfword access: {line}", max_items)
        if re.match(r"^(?:ldrsb|ldrsh|ldrsw|sxt|sx)\w*\b", mnemonic):
            append_unique(widths_and_extensions, f"signed extension: {line}", max_items)
        if re.match(r"^(?:uxt|zx|movz)\w*\b", mnemonic):
            append_unique(widths_and_extensions, f"zero extension: {line}", max_items)

        if re.search(r"(?:#|\$)-?(?:0x[0-9a-fA-F]+|\d+)", line):
            append_unique(constants, line, max_items)
        if re.search(r"\.(?:string|asciz|ascii|quad|word|byte|long)\b", line):
            append_unique(constants, line, max_items)
        if re.search(r"\b(?:adrp|adr|lea|leaq)\b|DAT_|PTR_|\.LC|:lo12:", line):
            append_unique(addresses, line, max_items)

    return {
        "architecture_hint": infer_architecture(assembly),
        "assembly_line_count": len(raw_lines),
        "instruction_line_count": sum(1 for line in raw_lines if mnemonic_of(line)),
        "label_count": len(labels),
        "function_like_labels": function_labels,
        "path_boundary_labels": path_labels,
        "branch_and_control_transfers": branches,
        "returns": returns,
        "call_targets": call_targets,
        "call_instructions": calls,
        "dataflow_operations": dataflow,
        "memory_operations": memory,
        "operand_widths_and_extensions": widths_and_extensions,
        "constants_and_literals": constants,
        "address_references": addresses,
        "guidance": (
            "The ASM Hint is soft recovery evidence. Use the supporting raw assembly "
            "to verify an interpretation before changing the pseudocode scaffold."
        ),
    }


def markdown_list(title: str, values: Sequence[str], max_show: int = 20) -> str:
    lines = [f"### {title}"]
    if not values:
        lines.append("- No representative observation was retained.")
    else:
        lines.extend(f"- `{value}`" for value in values[:max_show])
        if len(values) > max_show:
            lines.append(f"- ... ({len(values) - max_show} additional observations omitted)")
    return "\n".join(lines)


def render_asm_hint(name: str, hint: Dict[str, Any]) -> str:
    sections = [
        f"# ASM Hint for `{name}`",
        "",
        "The hint contains compact, recovery-relevant observations extracted from assembly.",
        "It is soft guidance rather than a formal CFG or a mandatory rewrite specification.",
        "",
        "## Summary",
        f"- Architecture hint: **{hint.get('architecture_hint', 'unknown')}**",
        f"- Assembly lines: **{hint.get('assembly_line_count', 0)}**",
        f"- Instruction-like lines: **{hint.get('instruction_line_count', 0)}**",
        f"- Labels: **{hint.get('label_count', 0)}**",
        "",
        markdown_list("Function-like labels", hint.get("function_like_labels", [])),
        "",
        markdown_list("Path-boundary labels", hint.get("path_boundary_labels", [])),
        "",
        markdown_list("Branches and control transfers", hint.get("branch_and_control_transfers", [])),
        "",
        markdown_list("Returns", hint.get("returns", [])),
        "",
        markdown_list("Call targets", hint.get("call_targets", [])),
        "",
        markdown_list("Call instructions", hint.get("call_instructions", [])),
        "",
        markdown_list("Dataflow operations", hint.get("dataflow_operations", [])),
        "",
        markdown_list("Memory operations", hint.get("memory_operations", [])),
        "",
        markdown_list("Operand widths and extensions", hint.get("operand_widths_and_extensions", [])),
        "",
        markdown_list("Constants and literals", hint.get("constants_and_literals", [])),
        "",
        markdown_list("Address references", hint.get("address_references", [])),
        "",
        "## Interpretation rule",
        "Use the hint to locate relevant assembly regions, then inspect the surrounding raw instructions before revising a source-level construct.",
    ]
    return "\n".join(sections)


def locate_ghidra_pseudocode(name: str) -> Optional[Path]:
    if not GHIDRA_DIR.exists():
        return None
    candidates = [
        GHIDRA_DIR / "decompile" / f"{name}_ghidra.c",
        GHIDRA_DIR / f"{name}_ghidra.c",
        GHIDRA_DIR / f"{name}.c",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    for candidate in GHIDRA_DIR.rglob("*.c"):
        if candidate.name == f"{name}.c" or candidate.name.startswith(f"{name}_"):
            return candidate
    return None


def extract_c_code(model_output: str) -> str:
    fenced = re.search(r"```(?:c|cpp|C)?\s*\n(.*?)\n```", model_output, re.DOTALL)
    code = fenced.group(1) if fenced else model_output
    code = re.sub(r"^\s*(?:Here is|The recovered code is).*?:\s*\n", "", code, flags=re.IGNORECASE)
    code = re.sub(r"```(?:c|cpp|C)?", "", code)
    code = code.replace("```", "")
    return code.strip()


def build_candidate_recovery_messages(
    name: str,
    pseudocode: str,
    asm_hint: str,
    raw_assembly: str,
) -> List[Dict[str, str]]:
    system_prompt = """You are the Candidate Recovery component of SSRDec Stage 1.
Generate a complete standard C Initial Candidate from decompiler-generated pseudocode, a compact ASM Hint, and supporting raw assembly.

Recovery requirements:
1. Preserve the pseudocode scaffold rather than translating the assembly from scratch.
2. Use the ASM Hint to identify relevant regions, and use the surrounding raw assembly to verify each interpretation.
3. Check branch conditions, successor paths, loop continuations, exits, and returns first. Consult operand widths, constants, calls, and memory operations when they affect those decisions.
4. If the pseudocode is consistent with the assembly evidence, preserve its structure.
5. If it is inconsistent, revise only the affected condition, state update, interface, memory access, or control-flow construct.
6. Avoid unrelated renaming, formatting changes, and broad refactoring.
7. When several C forms are supported, choose a conservative structured representation.
8. Do not invent behavior that is unsupported by the pseudocode or assembly.
9. Return only complete compilable C code. Do not return markdown or an explanation.
"""
    user_prompt = f"""[Task]
Generate the Initial Candidate for `{name}`.

[Decompiler-Generated Pseudocode]
{pseudocode}

[ASM Hint]
{asm_hint}

[Supporting Raw Assembly]
{raw_assembly}

[Output]
Return standard C code only.
"""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]



def call_candidate_recovery(messages: Sequence[Dict[str, str]]) -> Tuple[str, int]:
    """Call the configured chat-completions endpoint with retry."""
    if not API_KEY:
        raise RuntimeError("DEEPSEEK_API_KEY is not configured.")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }
    payload = {
        "model": MODEL,
        "messages": list(messages),
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
    }
    last_error: Optional[Exception] = None
    for attempt in range(LLM_RETRIES):
        try:
            response = requests.post(
                API_URL,
                json=payload,
                headers=headers,
                timeout=LLM_TIMEOUT,
            )
            response.raise_for_status()
            body = response.json()
            content = body["choices"][0]["message"].get("content", "")
            if not content.strip():
                raise RuntimeError("Candidate Recovery returned empty content.")
            usage = body.get("usage") or {}
            total_tokens = int(usage.get("total_tokens", 0) or 0)
            return content, total_tokens
        except Exception as exc:
            last_error = exc
            if attempt + 1 < LLM_RETRIES:
                time.sleep(2**attempt)
    raise RuntimeError(f"Candidate Recovery API failed: {last_error}")


def save_asm_hint(name: str, hint: Dict[str, Any], markdown: str) -> tuple[Optional[str], Optional[str]]:
    if not SAVE_ASM_HINT:
        return None, None
    hint_dir = OUTPUT_DIR / "_asm_hint"
    hint_dir.mkdir(parents=True, exist_ok=True)
    json_path = hint_dir / f"{name}_asm_hint.json"
    markdown_path = hint_dir / f"{name}_asm_hint.md"
    json_path.write_text(json.dumps(hint, indent=2, ensure_ascii=True), encoding="utf-8")
    markdown_path.write_text(markdown, encoding="utf-8")
    return str(json_path), str(markdown_path)


def recover_initial_candidate(name: str, assembly_path: Path) -> Stage1Result:
    output_path = OUTPUT_DIR / f"{name}.c"
    if SKIP_EXISTING and output_path.is_file() and output_path.stat().st_size > 0:
        return Stage1Result(
            name=name,
            success=True,
            skipped=True,
            asm_path=str(assembly_path),
            output_path=str(output_path),
        )

    if not API_KEY:
        return Stage1Result(name=name, success=False, error="DEEPSEEK_API_KEY is not configured.")

    ghidra_path = locate_ghidra_pseudocode(name)
    if ghidra_path is None:
        return Stage1Result(
            name=name,
            success=False,
            asm_path=str(assembly_path),
            error="No matching Ghidra pseudocode file was found.",
        )

    assembly = assembly_path.read_text(encoding="utf-8", errors="replace")
    pseudocode = ghidra_path.read_text(encoding="utf-8", errors="replace")
    hint = extract_asm_hint(assembly)
    hint_markdown = render_asm_hint(name, hint)
    hint_json_path, hint_markdown_path = save_asm_hint(name, hint, hint_markdown)

    prompt_assembly = assembly
    if len(prompt_assembly) > RAW_ASM_MAX_CHARS:
        prompt_assembly = prompt_assembly[:RAW_ASM_MAX_CHARS]
        prompt_assembly += "\n\n[Raw assembly truncated at the configured context limit.]"

    try:
        model_output, total_tokens = call_candidate_recovery(
            build_candidate_recovery_messages(
                name=name,
                pseudocode=pseudocode,
                asm_hint=hint_markdown,
                raw_assembly=prompt_assembly,
            )
        )
    except Exception as exc:
        return Stage1Result(
            name=name,
            success=False,
            asm_path=str(assembly_path),
            ghidra_path=str(ghidra_path),
            asm_hint_json=hint_json_path,
            asm_hint_markdown=hint_markdown_path,
            error=f"Candidate Recovery API error: {exc}",
        )

    initial_candidate = extract_c_code(model_output)
    if not initial_candidate:
        return Stage1Result(
            name=name,
            success=False,
            asm_path=str(assembly_path),
            ghidra_path=str(ghidra_path),
            asm_hint_json=hint_json_path,
            asm_hint_markdown=hint_markdown_path,
            error="Candidate Recovery returned empty code.",
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path.write_text(initial_candidate + "\n", encoding="utf-8")
    provenance_dir = OUTPUT_DIR / "_provenance"
    provenance_dir.mkdir(parents=True, exist_ok=True)
    provenance = {
        "task": name,
        "stage": "Assembly-Guided Structure Recovery",
        "model": MODEL,
        "temperature": TEMPERATURE,
        "assembly_path": str(assembly_path),
        "ghidra_path": str(ghidra_path),
        "asm_hint_json": hint_json_path,
        "asm_hint_markdown": hint_markdown_path,
        "output_path": str(output_path),
        "raw_assembly_truncated": len(assembly) > RAW_ASM_MAX_CHARS,
        "total_tokens": total_tokens,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (provenance_dir / f"{name}_stage1.json").write_text(
        json.dumps(provenance, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )

    return Stage1Result(
        name=name,
        success=True,
        tokens=total_tokens,
        asm_path=str(assembly_path),
        ghidra_path=str(ghidra_path),
        output_path=str(output_path),
        asm_hint_json=hint_json_path,
        asm_hint_markdown=hint_markdown_path,
    )


def discover_assembly_files(input_dir: Path) -> List[Path]:
    files = list(input_dir.glob("*.s")) + list(input_dir.glob("*.asm"))
    return sorted(set(files), key=lambda path: path.name)


def write_run_report(results: Sequence[Stage1Result]) -> Path:
    report_dir = OUTPUT_DIR / "_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"stage1_{timestamp}.json"
    payload = {
        "stage": "Assembly-Guided Structure Recovery",
        "model": MODEL,
        "input_dir": str(INPUT_DIR),
        "ghidra_dir": str(GHIDRA_DIR),
        "output_dir": str(OUTPUT_DIR),
        "total": len(results),
        "successful": sum(result.success for result in results),
        "failed": sum(not result.success for result in results),
        "skipped": sum(result.skipped for result in results),
        "total_tokens": sum(result.tokens for result in results),
        "results": [asdict(result) for result in results],
    }
    report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return report_path


def run_stage1(input_dir: Path) -> int:
    if not input_dir.is_dir():
        print(f"Input assembly directory does not exist: {input_dir}")
        return 1

    assembly_files = discover_assembly_files(input_dir)
    if not assembly_files:
        print(f"No .s or .asm files were found in: {input_dir}")
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("SSRDec Stage 1: Assembly-Guided Structure Recovery")
    print(f"Model: {MODEL}")
    print(f"Assembly input: {input_dir}")
    print(f"Ghidra pseudocode: {GHIDRA_DIR}")
    print(f"Initial Candidate output: {OUTPUT_DIR}")
    print(f"Tasks: {len(assembly_files)}")

    results: List[Stage1Result] = []
    for assembly_path in tqdm(assembly_files, desc="Stage 1"):
        result = recover_initial_candidate(assembly_path.stem, assembly_path)
        results.append(result)
        if not result.success:
            print(f"[{result.name}] failed: {result.error}")
        time.sleep(RATE_LIMIT_DELAY)

    report_path = write_run_report(results)
    successful = sum(result.success for result in results)
    print(f"Completed: {successful}/{len(results)} tasks succeeded.")
    print(f"Run report: {report_path}")
    return 0 if successful == len(results) else 2


def main() -> int:
    if not API_KEY:
        print("DEEPSEEK_API_KEY is not configured.")
        return 1
    target_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else INPUT_DIR
    return run_stage1(target_dir)


if __name__ == "__main__":
    raise SystemExit(main())
