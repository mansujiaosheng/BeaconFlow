# BeaconFlow Codex 修改任务单

把这份文档直接交给 Codex / 另一个 AI 执行。

## 总目标

不要继续盲目增加功能。先把 BeaconFlow 的入口、文档、schema、测试和 MCP 对齐做好。

本轮修改目标：

```text
1. README 收敛成稳定主入口
2. docs 分层
3. report schema 统一
4. CLI / MCP / docs 自动对齐
5. case-check / doctor 增强
```

## 任务 1：替换 README.md

使用本次提供的 `README.md` 替换仓库根目录 README。

要求：

```text
- README 只展示 stable 或当前能跑的命令
- planned 功能不要写进 README
- beta/experimental 只在专家命令表中出现，不写成长教程
- 保留 quickstart-pe / quickstart-qemu / quickstart-flatten
```

验收：

```powershell
python -m beaconflow.cli --help
python -m beaconflow.cli doctor --format markdown
```

README 中出现的主命令必须能在 `--help` 里找到。

## 任务 2：新增 docs 目录文档

新增：

```text
docs/API_DEV_GUIDE.md
docs/REPORT_SCHEMA.md
docs/EXPERIMENTAL.md
docs/ROADMAP.md
```

要求：

```text
- 如果 docs 目录不存在就创建
- 不要把这些内容塞回 README
```

## 任务 3：建立命令状态 registry

新增或整理一个状态表，例如：

```python
COMMAND_STATUS = {
    "quickstart-pe": "stable",
    "quickstart-qemu": "stable",
    "quickstart-flatten": "stable",
    "flow": "stable",
    "flow-diff": "stable",
    "qemu-explore": "beta",
    "input-taint": "experimental",
    "feedback-explore": "experimental",
}
```

位置可以是：

```text
beaconflow/registry.py
```

或者已有合适模块。

## 任务 4：建立 CLI / MCP 映射表

新增：

```python
CLI_MCP_MAPPING = {
    "analyze": "analyze_coverage",
    "diff": "diff_coverage",
    "flow": "analyze_flow",
    "flow-diff": "diff_flow",
    "record-flow": "record_flow",
    "collect": "collect_drcov",
    "collect-qemu": "collect_qemu",
    "qemu-explore": "qemu_explore",
    "metadata-from-address-log": "metadata_from_address_log",
    "inspect-block": "inspect_block",
    "inspect-function": "inspect_function",
    "decision-points": "find_decision_points",
    "inspect-decision-point": "inspect_decision_point",
    "detect-roles": "detect_roles",
    "inspect-role": "inspect_role",
    "export-wasm-metadata": "export_wasm_metadata",
    "decompile-function": "decompile_function",
    "normalize-ir": "normalize_ir",
    "input-taint": "input_taint",
    "trace-compare": "trace_compare",
    "feedback-explore": "feedback_explore",
    "schema": "schema",
    "case-check": "case_check",
    "to-html": "to_html",
}
```

如果实际命令名不同，以代码实际 parser 和 MCP TOOLS 为准，并同步修改 docs。

## 任务 5：增加 docs sync 测试

新增测试：

```text
tests/test_docs_sync.py
```

至少检查：

```text
1. README 主入口命令存在于 CLI parser
2. docs/API_DEV_GUIDE.md 中的 stable CLI 命令存在
3. CLI_MCP_MAPPING 中的 MCP tool 存在于 server TOOLS
4. experimental 命令不出现在 README 主教程里
```

不要要求 README 记录每一个专家命令，避免测试太脆。

## 任务 6：report schema 校验增强

确保 `schema` 命令能做：

```powershell
python -m beaconflow.cli schema --list
python -m beaconflow.cli schema --validate report.json
python -m beaconflow.cli schema --validate-all reports/
```

最低校验：

```text
- schema_version
- tool
- ai_digest
- data_quality
- evidence_refs 是否指向 evidence id
- confidence 枚举是否合法
```

## 任务 7：让核心报告补齐 ai_digest / data_quality

优先补：

```text
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

所有报告至少有：

```json
{
  "schema_version": "beaconflow.report.v1",
  "tool": "...",
  "ai_digest": {
    "top_findings": [],
    "recommended_actions": [],
    "evidence_refs": []
  },
  "data_quality": {
    "confidence": "medium",
    "limitations": [],
    "recommended_recollection": []
  }
}
```

## 任务 8：case-check 增强

`case-check` 输出 JSON/Markdown，至少包含：

```text
- status: ok/warn/error
- missing_files
- stale_reports
- invalid_reports
- low_confidence_reports
- qemu_range_warnings
- recommended_actions
```

示例 recommended action：

```json
{
  "action": "run_schema_validate_all",
  "command": "python -m beaconflow.cli schema --validate-all reports/",
  "reason": "Some reports do not contain schema_version."
}
```

## 任务 9：doctor 增强

`doctor` 输出：

```text
- Python version
- package import OK
- optional MCP dependency
- DynamoRIO path
- WSL availability
- QEMU availability
- IDA command availability
- Ghidra / pyghidra availability
- recommended entrypoint
```

示例：

```text
Recommended entrypoint:
- PE/Windows: quickstart-pe
- non-x86 ELF: quickstart-qemu
- existing trace + metadata: quickstart-flatten
```

## 任务 10：不要做这些

本轮不要做：

```text
- 不要新写大型 hook 框架
- 不要引入完整符号执行引擎
- 不要大改现有 CLI 参数名导致旧命令失效
- 不要把 planned 功能写进 README
- 不要让 README 超过必要长度
```

## 验收命令

最后至少跑：

```powershell
python -m compileall beaconflow tests
python -m unittest discover -s tests -p "test_*.py"
python -m beaconflow.cli --help
python -m beaconflow.cli doctor --format markdown
python -m beaconflow.cli schema --list
```

如果有 fixture reports：

```powershell
python -m beaconflow.cli schema --validate-all tests\fixtures\reports
```

## 交付说明

完成后输出：

```text
- 改了哪些文件
- 哪些命令已验证
- 哪些功能仍然是 beta/experimental
- 是否存在与当前代码不一致的文档项
```
