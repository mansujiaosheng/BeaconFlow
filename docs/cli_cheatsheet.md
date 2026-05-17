# BeaconFlow CLI 命令速查表

快速查找所有 BeaconFlow CLI 命令及其参数。

## 一键 Triage

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `triage-native` | PE/ELF 本地分析 | `--target`, `--output-dir` |
| `triage-qemu` | QEMU 跨架构分析 | `--target`, `--qemu-arch`, `--output-dir` |
| `triage-wasm` | WASM 分析 | `--target`, `--output-dir` |

## 一键 Quickstart

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `quickstart-pe` | PE 完整流程 | `--target`, `--output-dir` |
| `quickstart-qemu` | QEMU 完整流程 | `--target`, `--qemu-arch`, `--output-dir` |
| `quickstart-flatten` | 反平坦化流程 | `--metadata`, `--address-log`, `--output-dir` |

## Metadata 导出

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `export-ghidra-metadata` | Ghidra 导出 metadata | `--target`, `--output` |
| `export-wasm-metadata` | WASM 导出 metadata | `--target`, `--output` |
| `wasm-analyze` | WASM triage 报告 | `--target` |
| `metadata-from-address-log` | 地址日志生成 fallback metadata | `--address-log`, `--output` |

## 覆盖率与执行流

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `collect` | 采集 drcov 覆盖率 | `--target`, `--output-dir` |
| `collect-qemu` | 采集 QEMU trace | `--target`, `--qemu-arch`, `--output-dir` |
| `qemu-explore` | 多输入路径探索 | `--target`, `--qemu-arch`, `--stdin` |
| `analyze` | 分析覆盖率 | `--metadata`, `--coverage` |
| `flow` | 恢复执行流 | `--metadata`, `--coverage` 或 `--address-log` |
| `flow-diff` | 对比两次执行流 | `--metadata`, `--left-*`, `--right-*` |
| `diff` | 函数级覆盖率对比 | `--metadata`, `--left`, `--right` |
| `record-flow` | 一步运行并记录流 | `--metadata`, `--target`, `--output-dir` |

## 反平坦化与分支排序

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `deflatten` | 反平坦化 | `--metadata`, `--coverage` 或 `--address-log` |
| `deflatten-merge` | 合并多次反平坦化 | `--metadata`, `--coverage` 或 `--address-log` (≥2) |
| `recover-state` | 状态变量恢复 | `--metadata`, `--coverage` 或 `--address-log` (≥2) |
| `branch-rank` | 输入相关分支排序 | `--metadata`, `--bad-*` |

## 静态分析

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `inspect-block` | 查看基本块上下文 | `--metadata`, `--address` |
| `inspect-function` | 查看函数上下文 | `--metadata`, `--name` 或 `--address` |
| `find-decision-points` | 查找决策点 | `--metadata` |
| `inspect-decision-point` | 查看决策点详情 | `--metadata`, `--address` |
| `detect-roles` | 检测函数角色 | `--metadata` |
| `inspect-role` | 查看角色详情 | `--metadata`, `--name` 或 `--address` |
| `trace-values` | 追踪比较值 | `--metadata` |
| `trace-compare` | 比较语义提取 | `--metadata` |
| `input-taint` | 输入污点分析 | `--metadata` |
| `feedback-explore` | 反馈式输入探索 | `--metadata` |
| `decompile-function` | 伪代码摘要 | `--metadata`, `--name` 或 `--address` |
| `normalize-ir` | 统一 IR | `--metadata`, `--name` 或 `--address` |
| `sig-match` | 特征签名匹配 | `--metadata` |
| `ai-summary` | 压缩报告 | `--input` |

## 运行时追踪

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `trace-calls` | 库函数参数提取 | `--target` |
| `trace-compare-rt` | 比较指令值提取 | `--target`, `--metadata` 或 `--address` |

## 模板库与建议引擎

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `list-templates` | 列出所有模板 | 无 |
| `generate-template` | 生成模板文件 | `--template-name`, `--output` |
| `suggest-hook` | 推荐 Frida 模板 | `--decision-points` 或 `--roles` |
| `suggest-angr` | 推荐 angr 参数 | `--flow-diff` 或 `--roles` |
| `suggest-debug` | 推荐断点脚本 | `--decision-points`, `--debugger` |

## 外部工具导入

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `import-frida-log` | 导入 Frida 日志 | `--log` |
| `import-gdb-log` | 导入 GDB 日志 | `--log` |
| `import-angr-result` | 导入 angr 结果 | `--result` |
| `import-jadx-summary` | 导入 JADX 摘要 | `--summary` |

## Case Workspace

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `init-case` | 初始化工作区 | `--target` |
| `summarize-case` | 汇总工作区 | 无 |
| `add-metadata` | 添加 metadata | `--name`, `--path` |
| `add-run` | 添加运行记录 | `--name` |
| `add-report` | 添加分析报告 | `--name`, `--path` |
| `add-note` | 添加笔记 | `--content` |
| `list-runs` | 列出运行记录 | 无 |
| `list-reports` | 列出分析报告 | 无 |
| `list-notes` | 列出笔记 | 无 |
| `destroy-case` | 删除工作区 | 无 |

## 辅助工具

| 命令 | 用途 | 必需参数 |
| --- | --- | --- |
| `export-annotations` | 生成 IDA/Ghidra 标注脚本 | `--output-dir` |
| `corpus-init` | 初始化 fuzz corpus | `--corpus-dir` |
| `corpus-minimize` | 最小化 corpus | `--corpus-dir` |
| `corpus-from-reports` | 从报告提取种子 | `--corpus-dir`, `--reports` |
| `generate-harness` | 生成 fuzz harness | `--target`, `--output` |
| `import-fuzz` | 导入 fuzz 结果 | `--result-dir`, `--corpus-dir` |
| `dr-generate-client` | 生成 DR 客户端 | `--type`, `--output` |
| `dr-run-client` | 运行 DR 客户端 | `--client`, `--target` |
| `dr-import-trace` | 导入 DR trace | `--log`, `--metadata` |
| `schema` | Schema 操作 | `--list` 或 `--name` |
| `doctor` | 环境诊断 | 无 |

## 通用参数

| 参数 | 适用命令 | 说明 |
| --- | --- | --- |
| `--format` | 所有分析命令 | 输出格式：json/markdown/markdown-brief |
| `--output` | 所有分析命令 | 输出文件路径 |
| `--focus-function` | flow/decision-points/roles/trace-* | 聚焦特定函数 |
| `--address-min/max` | QEMU 相关命令 | 地址范围 |
| `--stdin` | collect/trace-calls/triage | stdin 输入 |
| `--auto-newline` | collect/qemu-explore | 自动追加换行符 |
| `--timeout` | collect/trace-calls/triage | 超时秒数 |
