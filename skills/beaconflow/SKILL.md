# BeaconFlow

Use this skill when analyzing binary execution coverage, control flow, or path differences with the `beaconflow` MCP server or CLI.

Repository: https://github.com/mansujiaosheng/BeaconFlow

## Two Workflows

### Workflow A: IDA/Ghidra + DynamoRIO (x86/x64 targets)

Use when IDA or Ghidra can open the target binary. **Supports both PE and ELF targets** — ELF files on Windows automatically run via WSL with the bundled Linux DynamoRIO.

1. Export metadata with IDA or Ghidra:

   ```powershell
   # IDA
   idat64 -A -S"ida_scripts/export_ida_metadata.py metadata.json" target.exe

   # Ghidra (pyghidra)
   python ghidra_scripts\export_ghidra_metadata.py target_elf metadata.json
   ```

2. Collect coverage with `collect_drcov` or CLI `collect`:

   ```powershell
   # PE target (Windows native)
   python -m beaconflow.cli collect --target target.exe --output-dir runs -- arg1

   # ELF target (auto WSL)
   python -m beaconflow.cli collect --target target_elf --output-dir runs -- arg1
   ```

   The `collect` command returns a JSON result with `log_path`, `returncode`, `stdout`, `stderr`, and `backend` (`windows-native`, `wsl`, `linux-native`).

3. Analyze with `analyze_flow` or `flow` command. Use `--from`/`--to` to focus on a specific function or address range:

   ```powershell
   # Focus from a function name
   python -m beaconflow.cli flow --metadata metadata.json --coverage drcov.log --from main --format markdown

   # Focus on an address range
   python -m beaconflow.cli flow --metadata metadata.json --coverage drcov.log --from 0x401000 --to 0x402000 --format markdown
   ```

4. For flattening or path recovery, prefer `record_flow`: run the target once and recover the ordered executed basic-block flow.

5. Use `diff_flow` to compare two inputs at block/edge level.

### Workflow B: QEMU address log (LoongArch/MIPS/ARM etc.)

Use when IDA cannot open the target (unsupported architecture) or no DynamoRIO is available.

1. Single trace collection with `collect_qemu`:

   ```json
   {
     "target_path": "/path/to/binary",
     "qemu_arch": "loongarch64",
     "stdin": "test_input",
     "auto_newline": true,
     "trace_mode": "in_asm"
   }
   ```

2. Multi-input exploration with `qemu_explore` — the key tool when you don't know the correct input:

   ```json
   {
     "target_path": "/path/to/binary",
     "qemu_arch": "loongarch64",
     "stdin_cases": ["input1", "input2", "input3"],
     "auto_newline": true,
     "failure_regex": "Wrong",
     "success_regex": "Correct",
     "address_min": "0x220000",
     "address_max": "0x244000",
     "gap": "0x200",
     "jobs": 3,
     "format": "markdown"
   }
   ```

   `qemu_explore` runs all inputs in parallel, classifies verdicts, and ranks path novelty. The input with the highest `new_blocks_vs_baseline` triggered the most new code paths and should be analyzed first.

3. Generate fallback metadata with `metadata_from_address_log`, then use `analyze_flow` and `diff_flow` the same way as Workflow A.

4. For precise loop counts, dispatcher frequency, timing/path-oracle work, or branch ranking based on hit deltas, collect with `trace_mode: "exec,nochain"`. The default `in_asm` mode is useful for fast path discovery, but BeaconFlow marks its hit counts as `translation-log`, not exact execution counts.

5. On Windows, if QEMU is not installed natively, BeaconFlow automatically detects and uses QEMU inside WSL.

### Ghidra + pyghidra: Enhanced Metadata Export

When IDA does not support the target architecture (e.g., LoongArch), or you prefer not to use IDA, use Ghidra + pyghidra to export metadata. The output JSON is fully compatible with IDA-exported metadata and can be used with all `flow`, `flow-diff`, `analyze` commands.

1. Install pyghidra:

   ```powershell
   pip install pyghidra
   ```

   Requires JDK 17+ and a Ghidra installation.

2. Export metadata:

   ```powershell
   python ghidra_scripts\export_ghidra_metadata.py <binary_path> [output.json]
   ```

   If Ghidra is not discoverable, set `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME` to your local Ghidra installation:

   ```powershell
   $env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_PUBLIC"
   python ghidra_scripts\export_ghidra_metadata.py target.exe metadata.json
   ```

3. Combine with Workflow B for precise analysis:

   ```powershell
   # Export Ghidra metadata (replaces fallback metadata)
   python ghidra_scripts\export_ghidra_metadata.py flagchecker flagchecker_metadata.json

   # Collect QEMU trace
   python -m beaconflow.cli collect-qemu --target flagchecker --qemu-arch loongarch64 --stdin "test" --auto-newline --output-dir runs

   # Analyze with Ghidra metadata + QEMU trace
   python -m beaconflow.cli flow --metadata flagchecker_metadata.json --address-log runs/case000.in_asm.qemu.log --address-min 0x220000 --address-max 0x244000 --format markdown
   ```

**Why pyghidra instead of analyzeHeadless**: Ghidra 12.0.4's `analyzeHeadless.bat` can fail with OSGi Felix initialization errors (JDK version mismatch, cache permission issues). pyghidra calls Ghidra Java API directly via JPype, bypassing OSGi entirely — more stable and reliable.

**Verified architectures**:

| Architecture | Format | Result |
| --- | --- | --- |
| x86_64 | ELF | ✅ 28 functions (simple_flagchecker) |
| x86_64 | PE | ✅ 102 functions (simple_pe) |
| LoongArch | ELF | ✅ 2870 functions (ACTF flagchecker, statically linked) |

## Tools

| Tool | Purpose |
| --- | --- |
| `collect_drcov` | Run a target under bundled DynamoRIO drcov, return log path. Supports PE and ELF (via WSL). |
| `collect_qemu` | Run a target under QEMU user-mode tracing, return log path and output. |
| `qemu_explore` | Run multiple QEMU traced inputs in parallel, classify verdicts, rank path novelty. |
| `analyze_coverage` | Map drcov blocks to IDA/Ghidra-exported functions and basic blocks. |
| `analyze_flow` | Map a drcov or address-log file to ordered basic-block flow and real transitions. |
| `deflatten_flow` | Remove dispatcher blocks from execution flow, reconstruct real control flow edges. Key tool for CFF deflattening. |
| `deflatten_merge` | Merge multiple deflatten results to restore complete real CFG. Identifies common paths and input-dependent branches. |
| `recover_state_transitions` | Recover state transition table from multiple traces. Identifies deterministic vs input-dependent state variable transitions for CFF deflattening. |
| `branch_rank` | Rank input-dependent branch points across bad/better/good traces. Start here when you need the next branch worth opening in IDA/Ghidra. |
| `ai_summary` | Compact an existing BeaconFlow JSON report into `summary`, `data_quality`, and `ai_digest` for fast AI reading. |
| `record_flow` | Run a target once and return the ordered executed flow. Prefer for flattened CFG triage. |
| `diff_coverage` | Compare two coverage runs at function level. |
| `diff_flow` | Compare two runs at block/edge level. Outputs only-left/only-right blocks, edges, and hit-count deltas. |
| `metadata_from_address_log` | Build fallback metadata by clustering one or more address logs. |
| `trace_values` | Trace register/memory/compare values at key decision points. Extracts compare events, input sites, and dispatcher states. Optionally uses coverage data to infer branch results. |
| `trace_compare` | Extract compare semantics at input check points. Identifies cmp reg/imm, cmp reg/reg, test, strcmp/strncmp/memcmp, strlen, and switch/jump table patterns. Outputs structured comparison information with inferred results. |
| `doctor` | Check BeaconFlow environment and dependencies. Verifies Python, beaconflow, IDA, Ghidra, DynamoRIO drrun, QEMU, WSL, MCP, and PyYAML. |
| `input_taint` | Lightweight taint analysis: trace input bytes to branch decisions. Identifies input sources, compare sinks, and register propagation paths. |
| `feedback_explore` | Generate input modification plan based on failed compare results. Uses trace_compare to identify failed comparisons, then suggests byte-level patches. Supports multi-round exploration strategy. |
| `decompile_function` | Generate pseudo-code summary for a function from metadata. Produces block-level pseudo-code with branch conditions, calls, and loop detection. |
| `normalize_ir` | Convert function instructions to normalized IR (architecture-independent). Supports x86/x64, ARM/AArch64, MIPS, LoongArch, RISC-V. |
| `sig_match` | Match crypto/VM/packer/anti-debug signatures in metadata. Identifies AES, DES, RC4, TEA, ChaCha20, SM4, MD5/SHA, Base64, CRC, VM interpreters, UPX, VMProtect, and anti-debug techniques. |
| `init_case` | Initialize a case workspace for a target binary. Creates .case/ directory with manifest.json, metadata/, runs/, reports/, notes/. |
| `summarize_case` | Summarize the current case workspace status. Shows target info, metadata count, runs count with verdict summary, reports count, and notes count. |
| `add_metadata_to_case` | Add a metadata file to the case workspace. |
| `add_run_to_case` | Add a run/trace result to the case workspace. |
| `add_report_to_case` | Add an analysis report to the case workspace. |
| `add_note_to_case` | Add a note to the case workspace. Useful for AI Agent to record analysis findings across rounds. |
| `list_case_runs` | List all runs in the case workspace. |
| `list_case_reports` | List all reports in the case workspace. |
| `list_case_notes` | List all notes in the case workspace. |
| `export_wasm_metadata` | Export metadata from a WebAssembly (.wasm) binary using pure Python parser. No external dependencies required. |

## Key Parameters

- `auto_newline`: Append `\n` to stdin if missing. Many programs (flag checkers, CTF challenges) require a newline to read stdin. Default is `true` for QEMU tools, `false` for drcov tools.
- `trace_mode`: QEMU `-d` flag. `in_asm` (default) is a translation-block log — hit counts are not precise loop counts. Use `exec,nochain` for precise execution counts.
- `dispatcher_mode`: Dispatcher selection mode for `deflatten_flow`, `deflatten_merge`, and `recover_state_transitions`. Default is `strict`, which requires hot + multi-predecessor + multi-successor shape and is safer against hot-loop/state-machine false positives. Use `balanced` for more candidates, `aggressive` for legacy heuristic-like exploration.
- `address_min` / `address_max`: Filter address-log events to a specific range. Essential for stripping QEMU runtime noise from the target's own code.
- `gap`: Address clustering threshold for `metadata_from_address_log`. Addresses separated by more than this gap start a new function region.
- `success_regex` / `failure_regex`: Classify `qemu_explore` runs by matching stdout/stderr.
- `jobs`: Number of parallel QEMU workers in `qemu_explore`. Default is all inputs in parallel.
- `focus_function`: Filter `analyze_flow` / `diff_flow` to a single function name or start address.
- `from` / `to`: Address range filtering for `flow` and `flow-diff`. Accepts function names (e.g., `main`, `check_flag`) or hex addresses (e.g., `0x401000`). `--from` uses the function's start address (inclusive), `--to` uses the function's end address (exclusive).
- `timeout`: Timeout in seconds for `collect` and `record-flow`. Default is 120. If the target hangs, the drcov log is still preserved.

## Deflattening Defaults

Use `dispatcher_mode: "strict"` unless there is clear evidence that a typical CFF dispatcher is being missed. Strict mode intentionally does not select low-confidence hot blocks that only have one predecessor or one successor; those are often loops, state machines, VM dispatchers, or normal hot code.

Read `dispatcher_candidates` before trusting `dispatcher_blocks`. A candidate with `selected: false`, `confidence: low`, and a warning about missing multi-predecessor or multi-successor shape is evidence to inspect manually, not a block to remove automatically.

When using QEMU `in_asm`, do not use hit counts as a decisive dispatcher signal. Recollect with `trace_mode: "exec,nochain"` before making conclusions from hit count, loop count, or timing/path-oracle behavior.

## Interpretation Rules

- First read top-level `ai_digest` and `data_quality` before scanning long lists. `ai_digest.top_findings` gives the highest-value evidence, `recommended_actions` gives machine-actionable next steps, and `data_quality.hit_count_precision` tells whether hit counts are reliable.
- Use `ai-summary` / `ai_summary` on large saved JSON reports before loading the full report into context.
- BeaconFlow preserves the drcov BB Table order (or QEMU address log order) to recover the observed basic-block flow for one run.
- Use the recovered flow to ignore static CFG regions that were not exercised by the current input.
- Register values, memory values, and branch conditions require a richer trace source such as Tenet, Frida, Pin, or custom DynamoRIO instrumentation.
- Treat uncovered security-sensitive functions as fuzzing or input-generation targets.
- For flattened control flow, use `deflatten_flow` to remove dispatcher blocks and reconstruct real edges. The Real Execution Spine shows the actual control flow without dispatcher noise.
- To fully deflatten a function, run with multiple inputs and merge the deflatten results to cover all paths. Use `deflatten_merge` to combine multiple traces and identify common vs input-dependent edges.
- Use `recover_state_transitions` to go further: it builds a state transition table showing which real blocks set the state variable to a constant (deterministic) vs which set it based on input (input-dependent). This is the key to understanding the flattened control flow's state machine.
- In `qemu_explore`, focus on inputs with high `new_blocks_vs_baseline` — they reached code not seen by the baseline input and are most likely to reveal different logic paths.
- Different `output_fingerprint` with no path novelty usually means data-state differences, not control-flow differences.
- QEMU `-d in_asm` hit counts should not be treated as precise loop iteration counts; use `-d exec,nochain` or a stronger trace for that.
- Always check `summary.hit_count_precision` and `warnings` in `flow`, `deflatten`, `deflatten_merge`, `recover_state`, and `branch_rank` reports. If it says `translation-log`, treat hit deltas as weak evidence.
- Ghidra-exported metadata is fully compatible with IDA-exported metadata. Prefer Ghidra for architectures IDA does not support (LoongArch, etc.).
- When both IDA and Ghidra metadata are available, they may differ in function naming and basic-block boundaries, but the JSON schema is identical.
- Dispatcher identification is still heuristic-based. Default `strict` mode reduces false positives by requiring hot + multi-predecessor + multi-successor shape. Adjust `dispatcher_mode`, `dispatcher_min_hits`, `dispatcher_min_pred`, and `dispatcher_min_succ` only after checking candidate warnings.
- State variable recovery (knowing *why* the dispatcher chose a specific block) requires richer trace data than BeaconFlow currently provides.
- Use `trace_values` to extract compare semantics at decision points. The `immediate_compares` output is the most actionable: when the right operand is a constant, you know the expected value. Combined with coverage data, `branch_result` tells you whether the comparison succeeded or failed.
- Use `sig_match` to quickly identify crypto algorithms, VM protections, packers, and anti-debug techniques in the target binary. High-confidence matches (2+ evidence) are reliable; medium-confidence matches need further confirmation.
- Use `init_case` to create a persistent workspace for each analysis target. This lets you work across multiple rounds without re-specifying paths. Use `add_note` to record findings, `add_run` to track test inputs, and `summarize_case` to review progress.
