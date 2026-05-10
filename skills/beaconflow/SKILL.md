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

4. On Windows, if QEMU is not installed natively, BeaconFlow automatically detects and uses QEMU inside WSL.

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

   If Ghidra is not at the default path (`D:\TOOL\ghidra_12.0.4_PUBLIC`), set the environment variable:

   ```powershell
   $env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.0.4_PUBLIC"
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
| `record_flow` | Run a target once and return the ordered executed flow. Prefer for flattened CFG triage. |
| `diff_coverage` | Compare two coverage runs at function level. |
| `diff_flow` | Compare two runs at block/edge level. Outputs only-left/only-right blocks, edges, and hit-count deltas. |
| `metadata_from_address_log` | Build fallback metadata by clustering one or more address logs. |

## Key Parameters

- `auto_newline`: Append `\n` to stdin if missing. Many programs (flag checkers, CTF challenges) require a newline to read stdin. Default is `true` for QEMU tools, `false` for drcov tools.
- `trace_mode`: QEMU `-d` flag. `in_asm` (default) is a translation-block log — hit counts are not precise loop counts. Use `exec,nochain` for precise execution counts.
- `address_min` / `address_max`: Filter address-log events to a specific range. Essential for stripping QEMU runtime noise from the target's own code.
- `gap`: Address clustering threshold for `metadata_from_address_log`. Addresses separated by more than this gap start a new function region.
- `success_regex` / `failure_regex`: Classify `qemu_explore` runs by matching stdout/stderr.
- `jobs`: Number of parallel QEMU workers in `qemu_explore`. Default is all inputs in parallel.
- `focus_function`: Filter `analyze_flow` / `diff_flow` to a single function name or start address.
- `from` / `to`: Address range filtering for `flow` and `flow-diff`. Accepts function names (e.g., `main`, `check_flag`) or hex addresses (e.g., `0x401000`). `--from` uses the function's start address (inclusive), `--to` uses the function's end address (exclusive).
- `timeout`: Timeout in seconds for `collect` and `record-flow`. Default is 120. If the target hangs, the drcov log is still preserved.

## Interpretation Rules

- BeaconFlow preserves the drcov BB Table order (or QEMU address log order) to recover the observed basic-block flow for one run.
- Use the recovered flow to ignore static CFG regions that were not exercised by the current input.
- Register values, memory values, and branch conditions require a richer trace source such as Tenet, Frida, Pin, or custom DynamoRIO instrumentation.
- Treat uncovered security-sensitive functions as fuzzing or input-generation targets.
- For flattened control flow, use `deflatten_flow` to remove dispatcher blocks and reconstruct real edges. The Real Execution Spine shows the actual control flow without dispatcher noise.
- To fully deflatten a function, run with multiple inputs and merge the deflatten results to cover all paths.
- In `qemu_explore`, focus on inputs with high `new_blocks_vs_baseline` — they reached code not seen by the baseline input and are most likely to reveal different logic paths.
- Different `output_fingerprint` with no path novelty usually means data-state differences, not control-flow differences.
- QEMU `-d in_asm` hit counts should not be treated as precise loop iteration counts; use `-d exec,nochain` or a stronger trace for that.
- Ghidra-exported metadata is fully compatible with IDA-exported metadata. Prefer Ghidra for architectures IDA does not support (LoongArch, etc.).
- When both IDA and Ghidra metadata are available, they may differ in function naming and basic-block boundaries, but the JSON schema is identical.
- Dispatcher identification is heuristic-based (high hit count + many predecessors/successors). Adjust `--dispatcher-min-hits`, `--dispatcher-min-pred`, `--dispatcher-min-succ` if needed.
- State variable recovery (knowing *why* the dispatcher chose a specific block) requires richer trace data than BeaconFlow currently provides.
