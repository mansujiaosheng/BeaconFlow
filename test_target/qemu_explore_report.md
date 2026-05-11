# BeaconFlow QEMU Explore

## Summary

- Target: `D:\CTF\ACTF2026\flagchecker\flagchecker`
- QEMU arch: `loongarch64`
- Trace mode: `in_asm`
- Metadata: `qemu_explore\qemu_explore_metadata.json`
- Runs: 3
- Union functions: 7
- Union blocks: 5463

## Runs

| Case | Verdict | Return | Unique Blocks | New vs Baseline | New Global | Output | Stdin |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| `case000` | `failure` | 0 | 5256 | 0 | 5256 | `df8cb67d5caed483` | `ACTF{00000000000000000000000000000000}\n` |
| `case001` | `failure` | 0 | 5271 | 25 | 25 | `df8cb67d5caed483` | `ACTF{1234567890abcdef1234567890abcdef}\n` |
| `case002` | `success` | 0 | 5417 | 185 | 182 | `fdcac192c6ce6d5b` | `ACTF{fce553ec44532f11ff209e1213c92acd}\n` |

## AI Notes

- Inputs with nonzero `New vs Baseline` reached code not seen by case000; inspect those first.
- Different output fingerprints with no path novelty usually mean data-state differences, not control-flow differences.
- Use the generated metadata path with `flow` or `flow-diff` for detailed block and edge analysis.
- QEMU `in_asm` hit counts are translation-log evidence, not exact execution counts; use `exec,nochain` when timing, loop counts, dispatcher frequency, or branch-rank hit deltas matter.

## Recommended Runs

- `case002` verdict=`success` new_vs_baseline=185 new_global=182 stdin=`ACTF{fce553ec44532f11ff209e1213c92acd}\n`
- `case001` verdict=`failure` new_vs_baseline=25 new_global=25 stdin=`ACTF{1234567890abcdef1234567890abcdef}\n`
- `case000` verdict=`failure` new_vs_baseline=0 new_global=5256 stdin=`ACTF{00000000000000000000000000000000}\n`
