# BeaconFlow QEMU Explore

## Summary

- Target: `D:\CTF\ACTF2026\flagchecker\flagchecker`
- QEMU arch: `loongarch64`
- Trace mode: `in_asm`
- Metadata: `qemu_explore\qemu_explore_metadata.json`
- Runs: 20
- Union functions: 12
- Union blocks: 5406

## Runs

| Case | Verdict | Return | Unique Blocks | New vs Baseline | New Global | Output | Stdin |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| `case000` | `failure` | 0 | 5342 | 0 | 5342 | `df8cb67d5caed483` | `ACTF{00000000000000000000000000000000}\n` |
| `case001` | `failure` | 0 | 5295 | 3 | 3 | `df8cb67d5caed483` | `ACTF{10000000000000000000000000000000}\n` |
| `case002` | `failure` | 0 | 5295 | 9 | 9 | `df8cb67d5caed483` | `ACTF{20000000000000000000000000000000}\n` |
| `case003` | `failure` | 0 | 5310 | 16 | 16 | `df8cb67d5caed483` | `ACTF{30000000000000000000000000000000}\n` |
| `case004` | `failure` | 0 | 5321 | 0 | 0 | `df8cb67d5caed483` | `ACTF{40000000000000000000000000000000}\n` |
| `case005` | `failure` | 0 | 5317 | 3 | 0 | `df8cb67d5caed483` | `ACTF{50000000000000000000000000000000}\n` |
| `case006` | `failure` | 0 | 5293 | 16 | 0 | `df8cb67d5caed483` | `ACTF{60000000000000000000000000000000}\n` |
| `case007` | `failure` | 0 | 5308 | 11 | 8 | `df8cb67d5caed483` | `ACTF{70000000000000000000000000000000}\n` |
| `case008` | `failure` | 0 | 5283 | 10 | 7 | `df8cb67d5caed483` | `ACTF{80000000000000000000000000000000}\n` |
| `case009` | `failure` | 0 | 5271 | 16 | 0 | `df8cb67d5caed483` | `ACTF{90000000000000000000000000000000}\n` |
| `case010` | `failure` | 0 | 5317 | 19 | 3 | `df8cb67d5caed483` | `ACTF{a0000000000000000000000000000000}\n` |
| `case011` | `failure` | 0 | 5301 | 24 | 5 | `df8cb67d5caed483` | `ACTF{b0000000000000000000000000000000}\n` |
| `case012` | `failure` | 0 | 5284 | 3 | 3 | `df8cb67d5caed483` | `ACTF{c0000000000000000000000000000000}\n` |
| `case013` | `failure` | 0 | 5319 | 11 | 0 | `df8cb67d5caed483` | `ACTF{d0000000000000000000000000000000}\n` |
| `case014` | `failure` | 0 | 5311 | 0 | 0 | `df8cb67d5caed483` | `ACTF{e0000000000000000000000000000000}\n` |
| `case015` | `failure` | 0 | 5292 | 6 | 3 | `df8cb67d5caed483` | `ACTF{f0000000000000000000000000000000}\n` |
| `case016` | `failure` | 0 | 5268 | 3 | 0 | `df8cb67d5caed483` | `ACTF{01000000000000000000000000000000}\n` |
| `case017` | `failure` | 0 | 5313 | 10 | 0 | `df8cb67d5caed483` | `ACTF{02000000000000000000000000000000}\n` |
| `case018` | `failure` | 0 | 5286 | 19 | 7 | `df8cb67d5caed483` | `ACTF{03000000000000000000000000000000}\n` |
| `case019` | `failure` | 0 | 5286 | 3 | 0 | `df8cb67d5caed483` | `ACTF{04000000000000000000000000000000}\n` |

## AI Notes

- Inputs with nonzero `New vs Baseline` reached code not seen by case000; inspect those first.
- Different output fingerprints with no path novelty usually mean data-state differences, not control-flow differences.
- Use the generated metadata path with `flow` or `flow-diff` for detailed block and edge analysis.
- QEMU `in_asm` hit counts are translation-log evidence, not exact execution counts; use `exec,nochain` when timing, loop counts, dispatcher frequency, or branch-rank hit deltas matter.

## Recommended Runs

- `case011` verdict=`failure` new_vs_baseline=24 new_global=5 stdin=`ACTF{b0000000000000000000000000000000}\n`
- `case018` verdict=`failure` new_vs_baseline=19 new_global=7 stdin=`ACTF{03000000000000000000000000000000}\n`
- `case010` verdict=`failure` new_vs_baseline=19 new_global=3 stdin=`ACTF{a0000000000000000000000000000000}\n`
- `case003` verdict=`failure` new_vs_baseline=16 new_global=16 stdin=`ACTF{30000000000000000000000000000000}\n`
- `case006` verdict=`failure` new_vs_baseline=16 new_global=0 stdin=`ACTF{60000000000000000000000000000000}\n`
