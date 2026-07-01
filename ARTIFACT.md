# Artifact Availability

An anonymized replication package is available at:

**[ANONYMIZED ARTIFACT URL]**

The artifact contains:

1. The implementation of SSRDec, including Assembly-Guided Structure Recovery, Tree-Search-Based Semantic Recovery, and the prompts used by their LLM-based components.
2. Scripts for preparing binaries, running Ghidra in headless mode, extracting and processing decompiler-generated pseudocode and assembly code, and analyzing decompiler output.
3. Test harnesses and batch evaluation utilities for HumanEval-style test cases and BringUpBench, including scripts for compiling, executing, and evaluating recovered programs.

The top-level README provides detailed instructions for setting up the environment, preparing the inputs and benchmarks, configuring the required environment variables, and running both stages of SSRDec. It also describes the repository structure, input conventions, configuration options, and generated outputs, including ASM Hints, Initial Candidates, provenance records, run reports, validated C programs, and per-task search traces.

The artifact requires Python 3.9 or later, GCC, GNU Make, GDB, the required Python packages, and access to a compatible LLM service. Ghidra is required for generating decompiler pseudocode and assembly listings. Some auxiliary utilities require additional dependencies, as documented in the README.

API credentials are not included in the artifact. Users must provide their own credentials through the `DEEPSEEK_API_KEY` environment variable and configure the required input, output, benchmark, and tool paths according to the instructions in the README.