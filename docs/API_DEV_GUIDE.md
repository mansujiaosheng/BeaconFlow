# BeaconFlow API / Dev Guide

本文档用于指导后续 AI / Codex / 开发者继续维护 BeaconFlow。

核心目标：每增加一个能力，都必须同时考虑 CLI、MCP、报告 schema、测试、README 状态标记，避免出现“代码有、MCP 没有、文档写错、AI 调不动”的情况。

## 1. 功能状态分级

每个命令、MCP tool、报告类型都必须标记状态。

| 状态 | 含义 | 能否写入 README 主流程 |
|---|---|---|
| stable | 已有测试，参数基本稳定，报告结构稳定 | 可以 |
| beta | 可用，但报告或参数可能调整 | 只能写入专家命令或 EXPERIMENTAL |
| experimental | 启发式强，误报可能较多 | 只能写入 EXPERIMENTAL |
| planned | 还没实现或只存在设计 | 只能写入 ROADMAP |
| deprecated | 保留兼容，但不推荐新用 | 不写主流程 |

建议在代码中维护一张 registry，例如：

```python
COMMAND_STATUS = {
    "flow": "stable",
    "flow-diff": "stable",
    "qemu-explore": "beta",
    "input-taint": "experimental",
    "feedback-explore": "experimental",
}
```

## 2. CLI / MCP 命名规范

CLI 使用短横线，MCP 使用下划线。

| CLI | MCP |
|---|---|
| `analyze` | `analyze_coverage` |
| `diff` | `diff_coverage` |
| `flow` | `analyze_flow` |
| `flow-diff` | `diff_flow` |
| `record-flow` | `record_flow` |
| `collect` | `collect_drcov` |
| `collect-qemu` | `collect_qemu` |
| `qemu-explore` | `qemu_explore` |
| `metadata-from-address-log` | `metadata_from_address_log` |
| `inspect-block` | `inspect_block` |
| `inspect-function` | `inspect_function` |
| `decision-points` | `find_decision_points` |
| `inspect-decision-point` | `inspect_decision_point` |
| `detect-roles` | `detect_roles` |
| `inspect-role` | `inspect_role` |
| `export-wasm-metadata` | `export_wasm_metadata` |
| `decompile-function` | `decompile_function` |
| `normalize-ir` | `normalize_ir` |
| `input-taint` | `input_taint` |
| `trace-compare` | `trace_compare` |
| `feedback-explore` | `feedback_explore` |
| `schema` | `schema` |
| `case-check` | `case_check` |
| `to-html` | `to_html` |

新增命令时必须更新这张表，并加测试检查 CLI / MCP / 文档是否一致。

## 3. 新增 CLI 命令流程

新增命令必须完成：

```text
1. 在 beaconflow/cli.py 注册 parser
2. 增加 _cmd_xxx 入口函数
3. 核心逻辑放到 beaconflow/analysis/ 或对应模块，不要全塞进 cli.py
4. 支持 --format json / markdown，能支持 markdown-brief 更好
5. 支持 --output
6. 返回统一 report schema
7. 加 tests/test_cli_xxx.py
8. 更新 docs/API_DEV_GUIDE.md
9. 如果是 beta/experimental，更新 docs/EXPERIMENTAL.md
10. 如果是 stable 主入口，更新 README.md
```

## 4. 新增 MCP tool 流程

新增 MCP tool 必须完成：

```text
1. 在 beaconflow/mcp/server.py 的 TOOLS 中注册 schema
2. 参数名使用 snake_case
3. 复用 CLI 同一份核心逻辑，不复制算法
4. 缺参数时返回可读错误
5. 文件不存在时返回可读错误
6. 支持 format=json/markdown
7. 输出中保留 schema_version/tool/data_quality
8. 加 tests/test_mcp_xxx.py 或 smoke test
9. 更新 CLI/MCP 映射表
```

MCP 错误返回建议：

```json
{
  "ok": false,
  "error": {
    "type": "missing_file",
    "message": "metadata_path does not exist",
    "path": "D:\\case\\metadata.json",
    "suggestion": "Run export metadata first."
  }
}
```

## 5. 统一报告字段要求

所有稳定报告都必须包含：

```json
{
  "schema_version": "beaconflow.report.v1",
  "tool": "tool-name",
  "target": {},
  "inputs": {},
  "summary": {},
  "ai_digest": {
    "top_findings": [],
    "recommended_actions": [],
    "evidence_refs": []
  },
  "data_quality": {
    "confidence": "high|medium|low",
    "hit_count_precision": "exact|approximate|unknown",
    "mapping_ratio": 0.0,
    "limitations": [],
    "recommended_recollection": []
  },
  "evidence": [],
  "details": {}
}
```

具体规范见 `docs/REPORT_SCHEMA.md`。

## 6. 证据引用规范

AI 结论必须能追到证据。

推荐 evidence item：

```json
{
  "id": "ev.flow.transition.0001",
  "type": "transition",
  "address": "0x401234",
  "function": "check_flag",
  "basic_block": "0x401220-0x40124f",
  "description": "Right input reaches a block not seen in baseline.",
  "source": {
    "kind": "drcov|qemu_log|metadata|frida_log|gdb_log",
    "path": "runs/case001.drcov.log",
    "line": null
  },
  "confidence": "high"
}
```

`ai_digest.evidence_refs` 只能引用 `evidence[].id` 中存在的 ID。

## 7. data_quality 规则

建议规则：

| 数据来源 | 默认置信度 | hit count |
|---|---|---|
| DynamoRIO drcov | high | exact 或 mostly-exact |
| QEMU `exec,nochain` | medium-high | approximate |
| QEMU `in_asm` | medium | translation-log，不适合当真实执行次数 |
| fallback metadata from address log | medium-low | unknown |
| static heuristic roles | medium-low | unknown |
| input-taint 启发式 | low-medium | unknown |
| feedback-explore | low-medium | unknown |

报告中必须写清楚限制，例如：

```text
QEMU in_asm logs translated basic blocks, not exact dynamic execution counts.
```

## 8. quickstart 入口设计

当前 README 主入口保留：

```text
quickstart-pe
quickstart-qemu
quickstart-flatten
```

后续可以考虑增加别名，但不要破坏旧命令：

```text
triage-native -> quickstart-pe
triage-qemu   -> quickstart-qemu
triage-wasm   -> export-wasm-metadata + roles + ir + summary
```

如果实现别名，应满足：

```text
1. 原 quickstart 命令继续可用
2. README 优先展示 triage-* 或 quickstart-* 其中一套，不混用
3. doctor 能提示推荐入口
```

## 9. case workspace 规范

推荐 workspace：

```text
case_root/
  manifest.json
  target/
  metadata/
  runs/
  reports/
  imported/
  notes/
```

`manifest.json` 建议：

```json
{
  "schema_version": "beaconflow.case.v1",
  "case_name": "example",
  "targets": [],
  "metadata": [],
  "runs": [],
  "reports": [],
  "notes": [],
  "last_summary": null
}
```

`case-check` 至少检查：

```text
- 文件存在性
- report schema
- metadata/report 时间关系
- QEMU 地址范围是否为空或过宽
- 是否存在 unmapped events 过高
- 是否缺少 ai_digest
- 是否缺少 recommended_actions
```

## 10. 测试要求

最低测试矩阵：

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m beaconflow.cli --help
python -m beaconflow.cli doctor --format markdown
python tests\smoke_beaconflow.py
```

新增功能需要至少三类测试：

```text
1. 参数缺失 / 文件不存在
2. 最小 fixture 正常输出
3. JSON schema 校验
```

如果是 MCP tool，再加：

```text
4. tools/list 能看到该工具
5. call tool 最小参数能返回 ok
6. 错误输入不会污染 stdio JSON-RPC
```

## 11. 文档更新规则

不要把计划中功能写进 README 主流程。

文档归属：

```text
README.md                 stable 主入口 + 常用专家命令
docs/API_DEV_GUIDE.md     开发规则、CLI/MCP 映射、测试要求
docs/REPORT_SCHEMA.md     报告 schema
docs/EXPERIMENTAL.md      beta/experimental 能力、限制、误报说明
docs/ROADMAP.md           未来开发计划
```

## 12. 给 Codex 的修改要求模板

可以把下面这段直接交给 Codex：

```text
请按 docs/API_DEV_GUIDE.md 的规则修改 BeaconFlow。
不要直接堆新命令。
每个新增能力必须同时更新：
- CLI parser
- MCP tool schema
- report schema
- tests
- docs
如果能力不稳定，只能写入 docs/EXPERIMENTAL.md，不能写进 README 主流程。
```
