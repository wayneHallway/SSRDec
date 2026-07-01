#!/usr/bin/env python3
"""SSRDec Stage 2: Tree-Search-Based Semantic Recovery.

The script implements the two operations described for Stage 2:

1. Root-Cause-Guided Repair analyzes compilation or execution feedback and
   derives alternative program-level Repair Hypotheses.
2. Hypothesis-Driven Tree Search applies every hypothesis independently to a
   separate copy of the same parent candidate, evaluates each child, and keeps
   a path-specific Failed History.

Execution-error diagnosis uses an Analyzer-defined inspection objective and a
stateful GDB Inspector. A candidate is returned only after compilation, linking,
and all available tests succeed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

import requests


SOURCE_BASE_DIR = Path(
    os.environ.get(
        "SSRDEC_STAGE1_OUTPUT_DIR",
        "/home/lhw/codetran/decompile/ssrdec-stage1/O2-86-bring",
    )
)
OUTPUT_DIR = Path(
    os.environ.get(
        "SSRDEC_STAGE2_OUTPUT_DIR",
        str(SOURCE_BASE_DIR.parent / f"{SOURCE_BASE_DIR.name}-stage2"),
    )
)
ASM_HINT_DIR = Path(
    os.environ.get("ASM_HINT_DIR", str(SOURCE_BASE_DIR / "_asm_hint"))
)

EXTERNAL_TESTER_PATH = Path(
    os.environ.get(
        "EXTERNAL_TESTER_PATH",
        "/home/lhw/inspect/test/ex_test.py",
    )
)
USE_EXTERNAL_TESTER = os.environ.get("USE_EXTERNAL_TESTER", "1") != "0"

API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
API_URL = os.environ.get(
    "DEEPSEEK_API_URL",
    "https://api.deepseek.com/v1/chat/completions",
).strip()
MODEL_NAME = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash").strip()
LLM_TEMPERATURE = float(os.environ.get("REPAIR_TEMPERATURE", "0.1"))
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "240"))
LLM_RETRIES = int(os.environ.get("LLM_RETRIES", "5"))

MAX_DEPTH = int(os.environ.get("SSRDEC_MAX_DEPTH", "2"))
BRANCHING_FACTOR = int(os.environ.get("SSRDEC_BRANCHING_FACTOR", "2"))
MAX_GDB_TURNS = int(os.environ.get("SSRDEC_MAX_GDB_TURNS", "2"))
GDB_COMMAND_TIMEOUT = float(os.environ.get("GDB_COMMAND_TIMEOUT", "5.0"))

OPT_LEVEL = os.environ.get("OPT_LEVEL", "-O0 -g")
COMPILER = os.environ.get("COMPILER", "gcc")
MAKE_TARGET = os.environ.get("MAKE_TARGET", "build")
TARGET_ARCH = os.environ.get("TARGET_ARCH", "host")
EXEC_TIMEOUT = int(os.environ.get("EXEC_TIMEOUT", "30"))
BENCH_DIR = os.environ.get(
    "BENCH_DIR",
    "/home/lhw/codetran/recon/bringup-bench",
)

GHIDRA_TYPE_REFERENCE = """
[Ghidra Type Reference]
typedef unsigned char  byte;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;
typedef unsigned char  undefined1;
typedef unsigned short undefined2;
typedef unsigned int   undefined4;
typedef unsigned long  undefined8;
Map unresolved Ghidra-specific types to standard C types only when the candidate relations and diagnostics support the mapping.
""".strip()

_EXTERNAL_TESTER_MODULE: Any = None
CURRENT_TASK_API_FAILED = False


@dataclass
class EvaluationResult:
    compiled: bool
    passed: bool
    report: str
    executable_path: Optional[str]

    @property
    def failure_type(self) -> str:
        if self.compiled and self.passed:
            return "accepted"
        if not self.compiled:
            return "compilation"
        return "execution"


@dataclass
class RepairHypothesis:
    hypothesis_id: str
    root_cause: str
    evidence: List[str]
    affected_relations: List[str]
    coordinated_modifications: List[str]


@dataclass
class HistoryEntry:
    hypothesis: RepairHypothesis
    modification_summary: str
    evaluation: EvaluationResult


@dataclass
class RepairNode:
    node_id: str
    code: str
    evaluation: EvaluationResult
    failed_history: List[HistoryEntry]
    depth: int


@dataclass
class ModifierResult:
    code: str
    summary: str
    blocks: List[Dict[str, str]]


@dataclass
class SearchResult:
    validated_code: Optional[str]
    accepted_node_id: Optional[str]
    explored_nodes: int
    reason: str
    trace: List[Dict[str, Any]] = field(default_factory=list)


def load_external_tester() -> Any:
    """Load and configure the external build-and-test harness."""
    global _EXTERNAL_TESTER_MODULE

    if _EXTERNAL_TESTER_MODULE is not None:
        return _EXTERNAL_TESTER_MODULE
    if not USE_EXTERNAL_TESTER:
        raise RuntimeError("The external tester is disabled.")
    if not EXTERNAL_TESTER_PATH.is_file():
        raise FileNotFoundError(f"External tester not found: {EXTERNAL_TESTER_PATH}")

    spec = importlib.util.spec_from_file_location(
        "ssrdec_external_test_runner",
        EXTERNAL_TESTER_PATH,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load external tester: {EXTERNAL_TESTER_PATH}")

    tester = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tester)
    if not hasattr(tester, "run_comprehensive_evaluation"):
        raise AttributeError(
            "The external tester must define "
            "run_comprehensive_evaluation(code_str, task_id, variant_name)."
        )

    shared_configuration = {
        "BENCH_DIR": BENCH_DIR,
        "COMPILER": COMPILER,
        "TARGET_ARCH": TARGET_ARCH,
        "MAKE_TARGET": MAKE_TARGET,
        "EXEC_TIMEOUT": EXEC_TIMEOUT,
        "OPT_LEVEL": OPT_LEVEL,
    }
    for name, value in shared_configuration.items():
        if hasattr(tester, name):
            setattr(tester, name, value)

    _EXTERNAL_TESTER_MODULE = tester
    return tester


def evaluate_candidate(code: str, task_id: str, variant_name: str) -> EvaluationResult:
    """Compile, link, and execute a candidate through the external harness."""
    if not USE_EXTERNAL_TESTER:
        return EvaluationResult(
            compiled=False,
            passed=False,
            report="The external tester is disabled.",
            executable_path=None,
        )

    try:
        tester = load_external_tester()
        result = tester.run_comprehensive_evaluation(code, task_id, variant_name)
        if not isinstance(result, tuple) or len(result) != 4:
            return EvaluationResult(
                compiled=False,
                passed=False,
                report=(
                    "External tester returned an invalid value. Expected "
                    "(compiled, passed, report, executable_path)."
                ),
                executable_path=None,
            )
        compiled, passed, report, executable_path = result
        return EvaluationResult(
            compiled=bool(compiled),
            passed=bool(passed),
            report="" if report is None else str(report),
            executable_path=None if executable_path is None else str(executable_path),
        )
    except Exception as exc:
        return EvaluationResult(
            compiled=False,
            passed=False,
            report=f"External tester exception: {exc!r}",
            executable_path=None,
        )


class GDBInspector:
    """Stateful GDB interface used to collect runtime observations."""

    def __init__(self, executable_path: str) -> None:
        self.executable_path = executable_path
        self.process = subprocess.Popen(
            ["gdb", "-q", "--nx", executable_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._read_until_prompt(GDB_COMMAND_TIMEOUT)
        self.execute("set pagination off")
        self.execute("set confirm off")
        self.execute("set print pretty on")

    def _read_until_prompt(self, timeout: float) -> str:
        if self.process.stdout is None:
            return "GDB stdout is unavailable."

        output = ""
        deadline = time.monotonic() + timeout
        interrupted = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if interrupted:
                    output += "\n[GDB] Command timed out after interrupt."
                    break
                self.process.send_signal(signal.SIGINT)
                interrupted = True
                deadline = time.monotonic() + 2.0

            readable, _, _ = select.select([self.process.stdout], [], [], 0.1)
            if not readable:
                if self.process.poll() is not None:
                    break
                continue

            character = self.process.stdout.read(1)
            if not character:
                break
            output += character
            if output.endswith("(gdb) "):
                break

        return output.removesuffix("(gdb) ").strip()

    def execute(self, command: str, timeout: float = GDB_COMMAND_TIMEOUT) -> str:
        if self.process.poll() is not None:
            return "GDB process has terminated."
        if self.process.stdin is None:
            return "GDB stdin is unavailable."
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self._read_until_prompt(timeout)

    def execute_batch(self, commands: Sequence[str]) -> str:
        observations: List[str] = []
        for command in commands:
            result = self.execute(command)
            observations.append(f"> {command}\n{result}")
        return "\n".join(observations)

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        try:
            if self.process.stdin is not None:
                self.process.stdin.write("quit\n")
                self.process.stdin.flush()
            self.process.terminate()
            self.process.wait(timeout=1)
        except Exception:
            self.process.kill()

    def __enter__(self) -> "GDBInspector":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def extract_json_object(text: str) -> Dict[str, Any]:
    """Parse a JSON object, accepting an optional fenced response."""
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            text = text[start : end + 1]
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("Expected a JSON object.")
    return parsed


def call_llm(messages: Sequence[Dict[str, str]], json_mode: bool = False) -> str:
    """Call the configured LLM with retry and task-level failure tracking."""
    global CURRENT_TASK_API_FAILED

    if not API_KEY:
        CURRENT_TASK_API_FAILED = True
        return ""

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }
    payload: Dict[str, Any] = {
        "model": MODEL_NAME,
        "messages": list(messages),
        "temperature": LLM_TEMPERATURE,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    for attempt in range(LLM_RETRIES):
        try:
            response = requests.post(
                API_URL,
                json=payload,
                headers=headers,
                timeout=LLM_TIMEOUT,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"].get("content", "")
            if content.strip():
                return content
            print(f"LLM returned empty content; retry {attempt + 1}/{LLM_RETRIES}.")
        except Exception as exc:
            wait_seconds = 2**attempt
            print(
                f"LLM request failed; retry {attempt + 1}/{LLM_RETRIES}: "
                f"{exc}. Waiting {wait_seconds}s."
            )
            time.sleep(wait_seconds)

    CURRENT_TASK_API_FAILED = True
    print("LLM requests failed repeatedly; the current task will not be saved.")
    return ""


def render_failed_history(history: Sequence[HistoryEntry]) -> str:
    if not history:
        return "No failed repair has been recorded on this path."
    entries: List[Dict[str, Any]] = []
    for index, entry in enumerate(history, start=1):
        entries.append(
            {
                "step": index,
                "hypothesis_id": entry.hypothesis.hypothesis_id,
                "root_cause": entry.hypothesis.root_cause,
                "modification_summary": entry.modification_summary,
                "result": entry.evaluation.failure_type,
                "report_tail": "\n".join(entry.evaluation.report.splitlines()[-8:]),
            }
        )
    return json.dumps(entries, indent=2, ensure_ascii=True)


def load_asm_hint(task_id: str) -> str:
    candidates = [
        ASM_HINT_DIR / f"{task_id}_asm_hint.md",
        ASM_HINT_DIR / f"{task_id}_asm_memory.md",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return "No ASM Hint was available for this task."


def request_inspection_objective(node: RepairNode, asm_hint: str) -> str:
    """Ask the Analyzer to define a focused runtime inspection objective."""
    system_prompt = """You are the Analyzer in SSRDec Root-Cause-Guided Repair.
The candidate compiles but fails an available test. Define a focused GDB inspection objective that can localize the first meaningful divergence behind the observed symptom.

Use the candidate, execution discrepancy, path-specific Failed History, and optional ASM Hint. Request observations about relevant stack frames, variables, pointer targets, memory regions, branch decisions, loop state, or call relations. Do not propose a repair yet.

Return one JSON object with:
{
  "inspection_objective": "...",
  "suggested_commands": ["..."],
  "reason": "..."
}
"""
    user_prompt = f"""[Candidate Code]
```c
{node.code}
```

[Execution Feedback]
{node.evaluation.report}

[Failed History]
{render_failed_history(node.failed_history)}

[ASM Hint]
{asm_hint}
"""
    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        json_mode=True,
    )
    try:
        data = extract_json_object(response)
        objective = str(data.get("inspection_objective", "")).strip()
        commands = data.get("suggested_commands", [])
        if isinstance(commands, list) and commands:
            command_text = "\n".join(f"- {command}" for command in commands)
            objective += f"\nSuggested commands:\n{command_text}"
        return objective or "Inspect the failing path, local state, and branch decisions."
    except Exception:
        return "Inspect the failing path, local state, and branch decisions."


def collect_runtime_observations(
    node: RepairNode,
    inspection_objective: str,
) -> str:
    """Let the Inspector interact with GDB and return observations only."""
    executable_path = node.evaluation.executable_path
    if not executable_path:
        return "No executable path was provided by the evaluation harness."

    system_prompt = """You are the Inspector in SSRDec execution-error diagnosis.
Interact with a stateful GDB session to collect runtime evidence for the Analyzer-defined objective. You may set breakpoints, run the program, inspect frames, print typed or casted values, examine pointer targets or memory, and observe branch or loop state.

Available actions:
1. {"action":"batch_execute","commands":["break ...","run","info locals"]}
2. {"action":"finish","observations":"A concise evidence report without a repair proposal."}

Return valid JSON only. Do not propose source-code modifications.
"""
    messages: List[Dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"[Inspection Objective]\n{inspection_objective}\n\n"
                f"[Candidate Code]\n```c\n{node.code}\n```\n\n"
                f"[Execution Feedback]\n{node.evaluation.report}"
            ),
        },
    ]

    collected: List[str] = []
    with GDBInspector(executable_path) as inspector:
        for turn in range(MAX_GDB_TURNS):
            response = call_llm(messages, json_mode=True)
            try:
                data = extract_json_object(response)
            except Exception as exc:
                messages.append(
                    {
                        "role": "user",
                        "content": f"Invalid JSON: {exc}. Return one valid JSON object.",
                    }
                )
                continue

            action = str(data.get("action", "")).strip()
            messages.append({"role": "assistant", "content": response})
            if action == "finish":
                observations = str(data.get("observations", "")).strip()
                if observations:
                    collected.append(observations)
                break
            if action != "batch_execute":
                messages.append(
                    {
                        "role": "user",
                        "content": "Unsupported action. Use batch_execute or finish.",
                    }
                )
                continue

            commands = data.get("commands", [])
            if not isinstance(commands, list) or not commands:
                messages.append(
                    {
                        "role": "user",
                        "content": "batch_execute requires a non-empty commands list.",
                    }
                )
                continue
            observation = inspector.execute_batch([str(command) for command in commands])
            collected.append(observation)
            messages.append(
                {
                    "role": "user",
                    "content": f"[GDB Observation]\n{observation}",
                }
            )

    if not collected:
        return "The Inspector did not obtain additional runtime observations."
    return "\n\n".join(collected)


def normalize_string_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def derive_repair_hypotheses(
    node: RepairNode,
    asm_hint: str,
    runtime_observations: str,
) -> List[RepairHypothesis]:
    """Derive alternative program-level hypotheses from the observed failure."""
    failure_type = node.evaluation.failure_type
    if failure_type == "compilation":
        diagnosis_instructions = """
For compilation-error diagnosis, parse compiler and linker messages, trace each reported symbol and location through related declarations, definitions, interfaces, and call sites, and identify the shared recovery decision behind the diagnostics. Do not repair diagnostics independently when they arise from one inconsistent program relation.
"""
    else:
        diagnosis_instructions = """
For execution-error diagnosis, correlate the expected-actual discrepancy with the candidate, runtime observations, ASM Hint, and prior failed repairs. Identify the recovery decision at which behavior diverges, including control-flow, signedness, data representation, memory relation, interface, or state-update errors. A hypothesis must explain the symptom rather than merely patch the latest output.
"""

    system_prompt = f"""You are the Analyzer in SSRDec Root-Cause-Guided Repair.
Generate at most {BRANCHING_FACTOR} alternative Repair Hypotheses for one failed candidate.
{diagnosis_instructions}
Each hypothesis must contain:
- a suspected root cause;
- evidence supporting it;
- all affected program relations;
- coordinated modifications required to address it.

The alternatives must represent genuinely different explanations or repair directions. Use Failed History to avoid repeating a direction that reproduced an earlier failure or regressed behavior on the same path. Do not produce patches.

Return valid JSON only:
{{
  "hypotheses": [
    {{
      "hypothesis_id": "H1",
      "root_cause": "...",
      "evidence": ["..."],
      "affected_relations": ["..."],
      "coordinated_modifications": ["..."]
    }}
  ]
}}
"""
    user_prompt = f"""{GHIDRA_TYPE_REFERENCE}

[Failure Type]
{failure_type}

[Candidate Code]
```c
{node.code}
```

[Evaluation Feedback]
{node.evaluation.report}

[Failed History for This Path]
{render_failed_history(node.failed_history)}

[Runtime Observations]
{runtime_observations}

[ASM Hint]
{asm_hint}
"""
    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        json_mode=True,
    )

    try:
        data = extract_json_object(response)
    except Exception as exc:
        print(f"Analyzer returned invalid JSON: {exc}")
        return []

    raw_hypotheses = data.get("hypotheses", [])
    if not isinstance(raw_hypotheses, list):
        return []

    hypotheses: List[RepairHypothesis] = []
    seen_root_causes: set[str] = set()
    for index, item in enumerate(raw_hypotheses[:BRANCHING_FACTOR], start=1):
        if not isinstance(item, dict):
            continue
        root_cause = str(item.get("root_cause", "")).strip()
        if not root_cause or root_cause.lower() in seen_root_causes:
            continue
        seen_root_causes.add(root_cause.lower())
        hypotheses.append(
            RepairHypothesis(
                hypothesis_id=str(item.get("hypothesis_id", f"H{index}")).strip() or f"H{index}",
                root_cause=root_cause,
                evidence=normalize_string_list(item.get("evidence")),
                affected_relations=normalize_string_list(item.get("affected_relations")),
                coordinated_modifications=normalize_string_list(
                    item.get("coordinated_modifications")
                ),
            )
        )
    return hypotheses


def apply_patch_blocks(code: str, blocks: Sequence[Dict[str, str]]) -> Optional[str]:
    """Apply exact search-and-replace blocks to one independent parent copy."""
    modified = code
    if not blocks:
        return None
    for block in blocks:
        search = str(block.get("search", ""))
        replace = str(block.get("replace", ""))
        if not search or search not in modified:
            return None
        modified = modified.replace(search, replace, 1)
    return modified if modified != code else None


def modify_from_hypothesis(code: str, hypothesis: RepairHypothesis) -> Optional[ModifierResult]:
    """Apply exactly one Repair Hypothesis to one copy of its parent candidate."""
    system_prompt = """You are the Modifier in SSRDec Root-Cause-Guided Repair.
Apply one Repair Hypothesis to a separate copy of its parent candidate. Coordinate every affected declaration, definition, call site, control-flow condition, memory relation, or state update named by the hypothesis. Do not introduce a different diagnosis and do not make unrelated changes.

Return valid JSON only:
{
  "modification_summary": "...",
  "blocks": [
    {"search":"an exact contiguous substring from the parent code","replace":"replacement text"}
  ]
}

Every search string must match the parent code exactly. Use the fewest blocks needed for a globally consistent repair.
"""
    user_prompt = f"""{GHIDRA_TYPE_REFERENCE}

[Parent Candidate]
```c
{code}
```

[Repair Hypothesis]
{json.dumps(asdict(hypothesis), indent=2, ensure_ascii=True)}
"""
    response = call_llm(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        json_mode=True,
    )
    try:
        data = extract_json_object(response)
    except Exception as exc:
        print(f"Modifier returned invalid JSON: {exc}")
        return None

    blocks = data.get("blocks", [])
    if not isinstance(blocks, list):
        return None
    normalized_blocks: List[Dict[str, str]] = []
    for block in blocks:
        if not isinstance(block, dict):
            return None
        normalized_blocks.append(
            {
                "search": str(block.get("search", "")),
                "replace": str(block.get("replace", "")),
            }
        )

    modified_code = apply_patch_blocks(code, normalized_blocks)
    if modified_code is None:
        return None
    return ModifierResult(
        code=modified_code,
        summary=str(data.get("modification_summary", "Applied the Repair Hypothesis.")).strip(),
        blocks=normalized_blocks,
    )


def code_digest(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()


def evaluation_to_dict(evaluation: EvaluationResult) -> Dict[str, Any]:
    return {
        "compiled": evaluation.compiled,
        "passed": evaluation.passed,
        "failure_type": evaluation.failure_type,
        "report": evaluation.report,
        "executable_path": evaluation.executable_path,
    }


def history_to_dict(history: Sequence[HistoryEntry]) -> List[Dict[str, Any]]:
    return [
        {
            "hypothesis": asdict(entry.hypothesis),
            "modification_summary": entry.modification_summary,
            "evaluation": evaluation_to_dict(entry.evaluation),
        }
        for entry in history
    ]


def hypothesis_driven_tree_search(
    initial_candidate: str,
    task_id: str,
    asm_hint: str,
) -> SearchResult:
    """Explore alternative Repair Hypotheses in breadth-first order."""
    root_evaluation = evaluate_candidate(initial_candidate, task_id, "Root")
    root = RepairNode(
        node_id="Root",
        code=initial_candidate,
        evaluation=root_evaluation,
        failed_history=[],
        depth=0,
    )
    trace: List[Dict[str, Any]] = [
        {
            "node_id": root.node_id,
            "parent_id": None,
            "depth": root.depth,
            "evaluation": evaluation_to_dict(root.evaluation),
            "history": [],
        }
    ]

    if root_evaluation.compiled and root_evaluation.passed:
        return SearchResult(
            validated_code=initial_candidate,
            accepted_node_id=root.node_id,
            explored_nodes=1,
            reason="The Initial Candidate passed compilation, linking, and all tests.",
            trace=trace,
        )

    queue: Deque[RepairNode] = deque([root])
    visited = {code_digest(initial_candidate)}
    explored_nodes = 1

    while queue:
        parent = queue.popleft()
        if parent.depth >= MAX_DEPTH:
            continue

        print(
            f"Expanding {parent.node_id}: depth={parent.depth}, "
            f"failure={parent.evaluation.failure_type}, "
            f"history={len(parent.failed_history)}"
        )

        runtime_observations = "Not required for compilation-error diagnosis."
        if parent.evaluation.failure_type == "execution":
            inspection_objective = request_inspection_objective(parent, asm_hint)
            runtime_observations = collect_runtime_observations(
                parent,
                inspection_objective,
            )

        hypotheses = derive_repair_hypotheses(
            parent,
            asm_hint=asm_hint,
            runtime_observations=runtime_observations,
        )
        if not hypotheses:
            print(f"No Repair Hypothesis was generated for {parent.node_id}.")
            continue

        for branch_index, hypothesis in enumerate(hypotheses, start=1):
            modifier_result = modify_from_hypothesis(parent.code, hypothesis)
            if modifier_result is None:
                print(
                    f"Modifier failed for {parent.node_id}/{hypothesis.hypothesis_id}; "
                    "the exact patch did not apply."
                )
                continue

            digest = code_digest(modifier_result.code)
            if digest in visited:
                print(f"Duplicate child skipped for {parent.node_id}/{hypothesis.hypothesis_id}.")
                continue
            visited.add(digest)

            child_depth = parent.depth + 1
            child_id = f"{parent.node_id}.D{child_depth}B{branch_index}"
            child_evaluation = evaluate_candidate(
                modifier_result.code,
                task_id,
                child_id,
            )
            child_history = list(parent.failed_history)
            child_history.append(
                HistoryEntry(
                    hypothesis=hypothesis,
                    modification_summary=modifier_result.summary,
                    evaluation=child_evaluation,
                )
            )
            child = RepairNode(
                node_id=child_id,
                code=modifier_result.code,
                evaluation=child_evaluation,
                failed_history=child_history,
                depth=child_depth,
            )
            explored_nodes += 1
            trace.append(
                {
                    "node_id": child.node_id,
                    "parent_id": parent.node_id,
                    "depth": child.depth,
                    "hypothesis": asdict(hypothesis),
                    "modification_summary": modifier_result.summary,
                    "patch_blocks": modifier_result.blocks,
                    "evaluation": evaluation_to_dict(child.evaluation),
                    "history": history_to_dict(child.failed_history),
                }
            )

            print(
                f"Evaluated {child.node_id}: compiled={child_evaluation.compiled}, "
                f"passed={child_evaluation.passed}"
            )
            if child_evaluation.compiled and child_evaluation.passed:
                return SearchResult(
                    validated_code=child.code,
                    accepted_node_id=child.node_id,
                    explored_nodes=explored_nodes,
                    reason="A candidate passed compilation, linking, and all tests.",
                    trace=trace,
                )

            if child.depth < MAX_DEPTH:
                queue.append(child)

    return SearchResult(
        validated_code=None,
        accepted_node_id=None,
        explored_nodes=explored_nodes,
        reason="No validated candidate remained in the search queue.",
        trace=trace,
    )


def task_id_from_filename(filename: str) -> str:
    return filename[:-8] if filename.endswith("_fixed.c") else filename[:-2]


def write_search_trace(task_id: str, result: SearchResult) -> Path:
    trace_dir = OUTPUT_DIR / "_search_traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"{task_id}.json"
    payload = {
        "task_id": task_id,
        "stage": "Tree-Search-Based Semantic Recovery",
        "model": MODEL_NAME,
        "max_depth": MAX_DEPTH,
        "branching_factor": BRANCHING_FACTOR,
        "max_gdb_turns": MAX_GDB_TURNS,
        "accepted_node_id": result.accepted_node_id,
        "explored_nodes": result.explored_nodes,
        "reason": result.reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "trace": result.trace,
    }
    trace_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return trace_path


def process_task(source_path: Path) -> Tuple[bool, str]:
    global CURRENT_TASK_API_FAILED
    CURRENT_TASK_API_FAILED = False

    task_id = task_id_from_filename(source_path.name)
    output_path = OUTPUT_DIR / f"{task_id}_fixed.c"
    if output_path.is_file() and output_path.stat().st_size > 0:
        return True, f"Skipped existing validated output: {output_path}"

    initial_candidate = source_path.read_text(encoding="utf-8", errors="replace")
    if not initial_candidate.strip():
        return False, "Initial Candidate is empty."

    asm_hint = load_asm_hint(task_id)
    result = hypothesis_driven_tree_search(initial_candidate, task_id, asm_hint)
    trace_path = write_search_trace(task_id, result)

    if CURRENT_TASK_API_FAILED:
        return False, f"LLM API failed repeatedly. Trace: {trace_path}"
    if result.validated_code is None:
        return False, f"No validated candidate was found. Trace: {trace_path}"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path.write_text(result.validated_code.rstrip() + "\n", encoding="utf-8")
    return True, f"Validated candidate: {output_path} | Trace: {trace_path}"


def process_tasks() -> int:
    if not SOURCE_BASE_DIR.is_dir():
        print(f"Initial Candidate directory does not exist: {SOURCE_BASE_DIR}")
        return 1
    if not API_KEY:
        print("DEEPSEEK_API_KEY is not configured.")
        return 1

    try:
        load_external_tester()
    except Exception as exc:
        print(f"External tester initialization failed: {exc}")
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    source_files = sorted(
        path
        for path in SOURCE_BASE_DIR.iterdir()
        if path.is_file() and path.suffix == ".c"
    )
    print("SSRDec Stage 2: Tree-Search-Based Semantic Recovery")
    print(f"Model: {MODEL_NAME}")
    print(f"Initial Candidates: {SOURCE_BASE_DIR}")
    print(f"Validated outputs: {OUTPUT_DIR}")
    print(f"Maximum depth: {MAX_DEPTH}")
    print(f"Branching factor: {BRANCHING_FACTOR}")
    print(f"Tasks: {len(source_files)}")

    succeeded = 0
    for source_path in source_files:
        task_id = task_id_from_filename(source_path.name)
        print(f"\nTask {task_id}: {source_path.name}")
        try:
            success, message = process_task(source_path)
        except Exception as exc:
            success, message = False, f"Unhandled task exception: {exc!r}"
        print(message)
        succeeded += int(success)

    print(f"\nCompleted: {succeeded}/{len(source_files)} tasks produced validated outputs.")
    return 0 if succeeded == len(source_files) else 2


def main() -> int:
    start_time = time.monotonic()
    status = process_tasks()
    print(f"Elapsed time: {time.monotonic() - start_time:.2f}s")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
