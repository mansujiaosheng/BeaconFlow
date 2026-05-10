# BeaconFlow

Use this skill when analyzing binary execution coverage, control flow, or path differences with the `beaconflow` MCP server or CLI.

## Workflow

1. Export IDA metadata without opening the UI:

   ```powershell
   idat64 -A -S"ida_scripts/export_ida_metadata.py metadata.json" target.exe
   ```

2. For flattening or path recovery, prefer `record_flow`: run the target once and recover the ordered executed basic-block flow.

3. For pure coverage, collect coverage with `collect_drcov` or the BeaconFlow CLI `collect` command, then ask `analyze_coverage` for a summary:

   - `metadata_path`: IDA metadata JSON
   - `coverage_path`: drcov coverage file
   - `format`: `json` or `markdown`

4. Use `diff_coverage` when comparing two inputs or test cases.

## Tools

- `collect_drcov`: run a Windows target under bundled DynamoRIO drcov and return the generated log path.
- `analyze_coverage`: map drcov blocks to IDA-exported functions and basic blocks.
- `analyze_flow`: map an existing drcov file to ordered target-module basic-block flow and real transitions.
- `record_flow`: run a target once and return the ordered executed flow. Prefer this for flattened control-flow triage.
- `diff_coverage`: compare two coverage runs.

## Interpretation Rules

- BeaconFlow preserves the drcov BB Table order to recover the observed basic-block flow for one run.
- Use the recovered flow to ignore static CFG regions that were not exercised by the current input.
- Register values, memory values, and branch conditions require a richer trace source such as Tenet, Frida, Pin, or custom DynamoRIO instrumentation.
- Treat uncovered security-sensitive functions as fuzzing or input-generation targets.
- For flattened control flow, use coverage to identify dispatcher-heavy functions and then compare multiple runs to infer real state transitions.
