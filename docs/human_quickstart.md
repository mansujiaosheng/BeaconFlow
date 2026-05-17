# BeaconFlow 快速上手指南

## 30 秒快速开始

```bash
# 1. 安装
pip install -e .

# 2. 检查环境
beaconflow doctor

# 3. 一键分析
beaconflow triage --target xxx --output-dir out
```

## 我该用哪个命令？

| 场景 | 命令 |
|------|------|
| 拿到一个新 exe | `beaconflow triage --target xxx.exe --output-dir out` |
| 拿到一个非 x86 ELF | `beaconflow triage-qemu --target xxx --qemu-arch loongarch64 --output-dir out` |
| 拿到一个 wasm | `beaconflow triage-wasm --target xxx.wasm --output-dir out` |
| 拿到一个 pyc | `beaconflow triage-pyc --target xxx.pyc --output-dir out` |
| 想看分析结果 | `beaconflow summarize-case --root out` |
| 想生成 hook 脚本 | `beaconflow suggest-hook --metadata-path out/metadata.json` |
| 想运行时追踪 | `beaconflow trace-calls --target xxx.exe --stdin "test"` |
| 想反平坦化 | `beaconflow deflatten --metadata out/metadata.json --coverage out/xxx.drcov` |
| 检查环境 | `beaconflow doctor` |
| 运行自检 | `beaconflow benchmark --builtin` |

## 典型工作流（3 步）

### Step 1：triage 一键分析

```bash
beaconflow triage --target suspicious.exe --output-dir out
```

自动完成静态分析、字符串提取、导入表梳理，生成 `metadata.json` 和结构化报告。

### Step 2：查看结果

```bash
beaconflow summarize-case --root out
```

输出 roles（样本角色定位）和 decision_points（关键判断节点），快速把握样本行为特征。

### Step 3：深入分析

根据 Step 2 的结果，选择合适的深入手段：

- **运行时追踪**：`beaconflow trace-calls --target xxx.exe --stdin "test"`
- **生成 hook 脚本**：`beaconflow suggest-hook --metadata-path out/metadata.json`
- **反平坦化**：`beaconflow deflatten --metadata out/metadata.json --coverage out/xxx.drcov`

## MCP 使用方式（给 AI Agent 用）

BeaconFlow 提供 MCP（Model Context Protocol）接口，AI Agent 可通过 MCP 直接调用分析能力：

1. 启动 MCP 服务：`beaconflow mcp serve`
2. Agent 通过标准 MCP 协议连接，即可调用 triage、summarize-case、suggest-hook 等全部命令
3. 适用于自动化分析流水线、AI 辅助逆向等场景

## 更多文档

- [Triage 分析指南](triage_guide.md)
- [运行时追踪指南](runtime_tracing_guide.md)
- [CLI 命令速查](cli_cheatsheet.md)
- [案例工作区指南](case_workspace_guide.md)
- [函数参考](function_reference.md)
- [模板指南](template_guide.md)
- [导入器指南](importer_guide.md)
