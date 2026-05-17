# BeaconFlow Report Schema

本文档定义 BeaconFlow 面向 AI Agent 的统一报告结构。

目标：让不同工具输出的 JSON/Markdown 报告具有一致的顶层字段，使 AI 能稳定读取摘要、证据质量、下一步动作和详细数据。

## 1. 顶层结构

所有 stable 报告建议采用：

```json
{
  "schema_version": "beaconflow.report.v1",
  "tool": "flow",
  "target": {},
  "inputs": {},
  "summary": {},
  "ai_digest": {
    "top_findings": [],
    "recommended_actions": [],
    "evidence_refs": []
  },
  "data_quality": {
    "confidence": "high",
    "score": 90,
    "hit_count_precision": "exact",
    "mapping_ratio": 0.98,
    "limitations": [],
    "recommended_recollection": []
  },
  "evidence": [],
  "details": {}
}
```

## 2. 字段解释

### `schema_version`

固定格式：

```text
beaconflow.report.v1
```

如果未来破坏兼容，升级为：

```text
beaconflow.report.v2
```

### `tool`

生成报告的工具名，例如：

```text
analyze
flow
flow-diff
qemu-explore
deflatten
detect-roles
decision-points
input-taint
trace-compare
feedback-explore
```

### `target`

目标文件信息：

```json
{
  "path": "D:\\case\\target.exe",
  "format": "PE|ELF|WASM|unknown",
  "arch": "x86_64|x86|arm|aarch64|mips|loongarch64|wasm|unknown",
  "image_base": "0x140000000",
  "sha256": null
}
```

### `inputs`

本次分析使用的输入文件、stdin、覆盖率或日志。

```json
{
  "metadata_path": "metadata.json",
  "coverage_path": "case000.drcov.log",
  "address_log_path": null,
  "stdin": "ACTF{test}",
  "left": null,
  "right": null
}
```

### `summary`

人和程序都能快速读懂的摘要。不同工具可以有不同字段，但必须短。

```json
{
  "covered_functions": 12,
  "covered_basic_blocks": 151,
  "unique_transitions": 230,
  "focus_function": "check_flag"
}
```

### `ai_digest`

AI 最优先读取的部分。

```json
{
  "top_findings": [
    {
      "id": "finding.001",
      "title": "Right input reaches an extra validation block",
      "severity": "high",
      "summary": "Block 0x401280 is only reached by case001.",
      "evidence_refs": ["ev.block.0001"]
    }
  ],
  "recommended_actions": [
    {
      "id": "act.001",
      "action": "inspect_block",
      "reason": "The block is only reached by the more promising input.",
      "command": "python -m beaconflow.cli inspect-block --metadata metadata.json --address 0x401280 --format markdown",
      "confidence": "high"
    }
  ],
  "evidence_refs": ["ev.block.0001", "ev.transition.0002"]
}
```

### `data_quality`

报告可靠性。

```json
{
  "confidence": "high",
  "score": 90,
  "hit_count_precision": "exact",
  "mapping_ratio": 0.98,
  "unmapped_events": 12,
  "limitations": [
    "No limitations detected."
  ],
  "recommended_recollection": []
}
```

建议枚举：

```text
confidence: high | medium | low
hit_count_precision: exact | mostly_exact | approximate | translation_log | unknown
```

### `evidence`

所有可引用证据。

```json
{
  "id": "ev.transition.0002",
  "type": "transition",
  "address": "0x401280",
  "function": "check_flag",
  "basic_block": "0x401260-0x40129f",
  "description": "Transition only appears in right input.",
  "source": {
    "kind": "drcov",
    "path": "runs/case001.drcov.log",
    "line": null
  },
  "confidence": "high"
}
```

### `details`

工具自己的完整详细数据。AI 通常最后读这里。

```json
{
  "flow": [],
  "transitions": [],
  "hot_blocks": [],
  "function_order": []
}
```

## 3. Markdown 报告结构

Markdown 报告建议固定顺序：

```markdown
# BeaconFlow <Tool Name> Report

## Summary

## AI Digest

### Top Findings

### Recommended Actions

## Data Quality

## Evidence

## Details

## Raw Notes / Limitations
```

`markdown-brief` 只保留：

```markdown
# BeaconFlow <Tool Name> Brief

## Summary
## AI Digest
## Data Quality
## Top Evidence
```

## 4. 工具级 schema 建议

### flow

```json
{
  "summary": {
    "unique_blocks": 0,
    "unique_transitions": 0,
    "functions_seen": 0,
    "truncated": false,
    "focus_function": null
  },
  "details": {
    "function_order": [],
    "execution_spine": [],
    "branch_points": [],
    "join_points": [],
    "dispatcher_candidates": [],
    "loop_like_edges": []
  }
}
```

### flow-diff

```json
{
  "summary": {
    "left_only_blocks": 0,
    "right_only_blocks": 0,
    "left_only_edges": 0,
    "right_only_edges": 0,
    "changed_hit_counts": 0
  },
  "details": {
    "left_only_ranges": [],
    "right_only_ranges": [],
    "top_differences": []
  }
}
```

### qemu-explore

```json
{
  "summary": {
    "total_cases": 0,
    "success_cases": 0,
    "failure_cases": 0,
    "best_case": null
  },
  "details": {
    "runs": [],
    "ranked_cases": [],
    "novel_blocks": [],
    "novel_ranges": []
  }
}
```

### detect-roles

```json
{
  "summary": {
    "functions_analyzed": 0,
    "roles_detected": 0
  },
  "details": {
    "roles": [
      {
        "function": "check_flag",
        "role": "validator",
        "score": 0.85,
        "confidence": "high",
        "evidence_refs": []
      }
    ]
  }
}
```

### input-taint

```json
{
  "summary": {
    "input_sources": 0,
    "compare_sinks": 0,
    "taint_edges": 0,
    "mappings": 0
  },
  "data_quality": {
    "confidence": "medium",
    "limitations": [
      "Static register propagation is heuristic and may miss memory aliases."
    ]
  },
  "details": {
    "input_sources": [],
    "compare_sinks": [],
    "input_to_branch": []
  }
}
```

## 5. 置信度规则

推荐默认规则：

| 条件 | 置信度 |
|---|---|
| drcov + metadata 映射率高 | high |
| QEMU `exec,nochain` + 地址范围明确 | medium-high |
| QEMU `in_asm` + 地址范围明确 | medium |
| fallback metadata | medium-low |
| 地址范围未限制且静态链接大 ELF | low |
| 启发式 taint / roles / feedback | low-medium |

## 6. schema 校验建议

实现 `beaconflow schema --validate` 时至少检查：

```text
- schema_version 存在
- tool 存在
- ai_digest 存在
- data_quality 存在
- evidence_refs 指向存在的 evidence id
- confidence 枚举合法
- recommended_actions 是数组
```

实现 `beaconflow schema --validate-all reports/` 时：

```text
- 遍历 JSON 报告
- 自动识别 tool
- 输出错误文件和字段路径
- 返回非 0 exit code
```

## 7. 不允许的报告格式

不要只输出大数组：

```json
[
  {"address": "0x401000"},
  {"address": "0x401004"}
]
```

不要只输出自然语言总结：

```text
这个输入可能比较好，可以继续看。
```

不要缺少证据来源：

```json
{
  "top_findings": ["This block is important"]
}
```

必须能回答：

```text
这个结论来自哪个文件？
哪个地址？
哪个函数？
置信度多少？
下一步命令是什么？
```
