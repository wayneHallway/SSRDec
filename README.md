# SSRDec

SSRDec is a two-stage binary-to-C recovery pipeline. It combines Ghidra
pseudocode, assembly evidence, an LLM, compilation feedback, runtime tests, and
optional GDB observations to produce validated C source code.

The repository also includes utilities for preparing binaries, running Ghidra
headlessly, analyzing decompiler output, and testing recovered programs against
Bringup-Bench or JSON-provided test cases.

## Pipeline

```text
binary/object
    ├── Ghidra pseudocode
    └── assembly listing
             │
             ▼
Stage 1: Assembly-Guided Structure Recovery
  - extracts a compact ASM Hint
  - combines the hint, raw assembly, and Ghidra pseudocode
  - asks the LLM for an Initial Candidate
             │
             ▼
Stage 2: Tree-Search-Based Semantic Recovery
  - compiles and executes each candidate
  - diagnoses compilation or execution failures
  - explores alternative repair hypotheses
  - optionally gathers runtime evidence with GDB
             │
             ▼
validated C source
```

## Repository layout

```text
SSRDec/
├── ssrdec_stage1.py       # Assembly-guided Initial Candidate recovery
├── ssrdec_stage2.py       # Test-guided semantic repair and tree search
├── ghidra/                # Binary preparation and Ghidra helper scripts
│   ├── decompile.py       # Ghidra/Jython C decompiler post-script
│   ├── decompile-s.py     # Ghidra/Jython assembly extraction post-script
│   ├── ghidra-bring.py    # Batch-decompile Bringup-Bench object files
│   ├── ghidra-human.py    # Batch-decompile HumanEval ELF files
│   ├── asm-human-o.py     # Compile JSON C functions into object files
│   ├── asm-human-elf.py   # Compile JSON C functions into ELF executables
│   ├── analysis.py        # Find C constructs that hinder type recovery
│   └── ghidra-gen-s.py    # Experimental angr-to-GraphVectorDB CFG loader
└── test/
    ├── ex_test.py         # Bringup-Bench harness used by Stage 2
    ├── ex_test-human.py   # Importable and standalone JSON test harness
    ├── test-human.py      # HumanEval-style batch test and metrics runner
    ├── test-bring.py      # Disk-safe Bringup-Bench batch runner
    └── build_outputs/     # Generated benchmark logs and executables
```

## Requirements

The main pipeline is designed for a Linux-like environment and requires:

- Python 3.9 or newer
- `requests`
- `tqdm` (optional; Stage 1 falls back to no progress bar)
- a DeepSeek-compatible chat-completions API key
- GCC, Make, and a compatible benchmark/test suite
- GDB for runtime inspection in Stage 2

Install the Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests tqdm
```

Optional utilities require additional software:

- Ghidra for `decompile.py`, `decompile-s.py`, `ghidra-bring.py`, and
  `ghidra-human.py`
- `pycparser` for `ghidra/analysis.py`
- an AArch64 cross-compiler such as `aarch64-linux-gnu-gcc` for the
  `asm-human-*.py` defaults
- `angr` and `numpy` for `ghidra/ghidra-gen-s.py`

`ghidra/ghidra-gen-s.py` also expects a project-specific `graph_rag_db.py`,
which is not included in this repository.

## Input conventions

Stage 1 matches files by stem. For an assembly input named `foo.s`, it searches
`GHIDRA_DIR` for pseudocode in forms such as:

```text
decompile/foo_ghidra.c
foo_ghidra.c
foo.c
```

Stage 2 treats each Stage 1 `.c` file stem as its task ID. For Bringup-Bench,
that ID must match a benchmark directory under `BENCH_DIR`.

## Quick start

### 1. Prepare Ghidra pseudocode and assembly

Run Ghidra's headless analyzer with the included post-scripts, or edit and run
one of the batch wrappers in `ghidra/`. The wrapper scripts currently contain
machine-specific absolute paths, so update their configuration blocks first.

Example headless invocations:

```bash
/path/to/ghidra/support/analyzeHeadless /tmp/ghidra-project project \
  -import /path/to/program.o \
  -scriptPath "$PWD/ghidra" \
  -postScript decompile.py /path/to/output/program_ghidra.c \
  -deleteProject
```

```bash
/path/to/ghidra/support/analyzeHeadless /tmp/ghidra-project project \
  -import /path/to/program.o \
  -scriptPath "$PWD/ghidra" \
  -postScript decompile-s.py /path/to/assembly/program.s \
  -deleteProject
```

`decompile.py` uses Ghidra's Jython/Python 2 runtime and is not intended to be
executed with normal Python 3.

### 2. Run Stage 1

```bash
export DEEPSEEK_API_KEY="your-api-key"
export ASM_INPUT_DIR="/path/to/assembly"
export GHIDRA_DIR="/path/to/ghidra-pseudocode"
export SSRDEC_STAGE1_OUTPUT_DIR="/path/to/stage1-output"

python ssrdec_stage1.py
```

An assembly directory can also be passed as the first positional argument:

```bash
python ssrdec_stage1.py /path/to/assembly
```

Stage 1 writes:

- one Initial Candidate `.c` file per assembly input;
- JSON and Markdown ASM Hints under `_asm_hint/`;
- task provenance under `_provenance/`;
- a timestamped run report under `_reports/`.

### 3. Run Stage 2

Stage 2 dynamically imports a tester that must provide:

```python
run_comprehensive_evaluation(code_str, task_id, variant_name)
```

The function must return:

```python
(compiled: bool, passed: bool, report: str, executable_path: str | None)
```

The included `test/ex_test.py` implements this interface for Bringup-Bench:

```bash
export DEEPSEEK_API_KEY="your-api-key"
export SSRDEC_STAGE1_OUTPUT_DIR="/path/to/stage1-output"
export SSRDEC_STAGE2_OUTPUT_DIR="/path/to/stage2-output"
export EXTERNAL_TESTER_PATH="$PWD/test/ex_test.py"
export BENCH_DIR="/path/to/bringup-bench"
export COMPILER="gcc"
export TARGET_ARCH="host"
export OPT_LEVEL="-O0 -g"

python ssrdec_stage2.py
```

Stage 2 writes:

- validated candidates as `<task>_fixed.c`;
- a per-task JSON search trace under `_search_traces/`.

Existing non-empty validated outputs are skipped.

## Configuration

All main-pipeline settings are environment variables.

### Shared API settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | empty | Required API key |
| `DEEPSEEK_API_URL` | `https://api.deepseek.com/v1/chat/completions` | Chat-completions endpoint |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | Model name |
| `LLM_TIMEOUT` | `240` | Request timeout in seconds |
| `LLM_RETRIES` | `5` | Number of API attempts |

### Stage 1 settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASM_INPUT_DIR` | machine-specific path | Directory containing `.s` or `.asm` files |
| `GHIDRA_DIR` | machine-specific path | Directory containing Ghidra pseudocode |
| `SSRDEC_STAGE1_OUTPUT_DIR` | machine-specific path | Initial Candidate output directory |
| `DECOMPILE_TEMPERATURE` | `0.1` | Candidate-recovery temperature |
| `DECOMPILE_MAX_TOKENS` | `65536` | Maximum response tokens |
| `ASM_SNIPPET_MAX_CHARS` | `250000` | Raw assembly prompt limit |
| `ASM_HINT_MAX_ITEMS` | `80` | Maximum retained items per hint category |
| `RATE_LIMIT_DELAY` | `1.0` | Delay between tasks in seconds |
| `SAVE_ASM_HINT` | `1` | Set to `0` to disable hint files |
| `SKIP_EXISTING` | `0` | Set to `1` to preserve existing candidates |

`RECOVER_OUTPUT_DIR` is retained as a fallback alias for
`SSRDEC_STAGE1_OUTPUT_DIR`.

### Stage 2 settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `SSRDEC_STAGE1_OUTPUT_DIR` | machine-specific path | Initial Candidate directory |
| `SSRDEC_STAGE2_OUTPUT_DIR` | `<stage1>-stage2` | Validated output directory |
| `ASM_HINT_DIR` | `<stage1>/_asm_hint` | ASM Hint directory |
| `EXTERNAL_TESTER_PATH` | machine-specific path | Importable test harness |
| `SSRDEC_MAX_DEPTH` | `2` | Maximum repair-tree depth |
| `SSRDEC_BRANCHING_FACTOR` | `2` | Hypotheses generated per failed node |
| `SSRDEC_MAX_GDB_TURNS` | `2` | Maximum GDB inspection turns |
| `GDB_COMMAND_TIMEOUT` | `5.0` | Per-command GDB timeout |
| `REPAIR_TEMPERATURE` | `0.1` | Repair-model temperature |
| `BENCH_DIR` | machine-specific path | Benchmark suite root |
| `COMPILER` | `gcc` | C compiler |
| `OPT_LEVEL` | `-O0 -g` | Compiler flags |
| `TARGET_ARCH` | `host` | Benchmark target |
| `MAKE_TARGET` | `build` | Build target exposed to compatible testers |
| `EXEC_TIMEOUT` | `30` | Execution timeout exposed to compatible testers |

## Test utilities

### HumanEval-style runner

`test/ex_test-human.py` can be imported by Stage 2 or run directly:

```bash
python test/ex_test-human.py \
  --mode c_dir \
  --c-dir /path/to/candidates \
  --json-file /path/to/tests.json \
  --target-type O0
```

The JSON is expected to contain task records and test code in fields such as
`c_test`; accepted source-code field names are documented in the script.

`test/test-human.py` provides a second batch workflow with metric reports:

```bash
python test/test-human.py \
  --mode c_dir \
  --c-dir /path/to/candidates \
  --json-file /path/to/tests.json \
  --target-type O0 \
  --cc gcc
```

Use `--no-json-test` when candidates already contain a complete `main`
function, or `--strip-main` when injected JSON tests should provide `main`.

### Bringup-Bench runners

`test/ex_test.py` is the compact Stage 2-compatible harness.
`test/test-bring.py` is the disk-safe batch runner; it isolates suites, limits
log size, removes stale artifacts, and guards against low disk space.

Both scripts currently use configuration constants near the top of the file.
Update `SOURCE_DIR`, `BENCH_DIR`, compiler, target, optimization flags, and
timeouts before standalone use.

## Ghidra utilities

Typical preparation for JSON-based HumanEval data:

```bash
python ghidra/asm-human-o.py
python ghidra/asm-human-elf.py
```

Edit `JSON_FILE`, `CC`, and output settings in those scripts first. Input
records are expected to provide `task_id`, `type`, and `c_func`; ELF generation
can also use `c_test` to supply a `main` function.

Analyze recovered C for decompiler-hostile constructs:

```bash
python -m pip install pycparser
python ghidra/analysis.py /path/to/c/source
```

The analyzer reports unions, bit-fields, pointer type punning, suspicious
negative array indexes, and parse failures.

## Operational notes

- Several helper scripts retain absolute paths from the original experiment
  environment. Review every configuration block before running them.
- The external test harness writes candidate code into benchmark task
  directories. Use a disposable suite or the temporary-suite batch runners
  when the original benchmark tree must remain untouched.
- Stage 2 launches GDB only when execution diagnostics need runtime evidence
  and the tester returns an executable path.
- API calls can consume substantial tokens. Start with a small input set and
  inspect Stage 1 reports and Stage 2 search traces before scaling up.
- `test/build_outputs/` contains generated artifacts and can grow quickly.

## Exit codes

The two main stages use the following exit statuses:

| Code | Meaning |
| --- | --- |
| `0` | Every discovered task succeeded |
| `1` | Configuration or initialization failure |
| `2` | Processing completed, but one or more tasks failed |

