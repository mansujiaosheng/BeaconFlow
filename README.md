# BeaconFlow

BeaconFlow 是一个面向 AI Agent 的 headless 二进制执行流分析工具。

它的目标不是替代 IDA、Ghidra、Frida、angr 或调试器，而是把这些工具产生的静态信息、覆盖率、地址日志和运行时证据整理成 AI 容易读取的结构化报告，帮助 AI 快速回答：

- 哪些函数和基本块实际执行过；
- 两组输入触发了哪些不同路径；
- 哪些分支、比较、dispatcher、join point 最值得回到反汇编里看；
- QEMU / drcov / Frida / 静态 metadata 的证据质量如何；
- 下一步应该采集什么、打开哪里、hook 哪里、换什么输入继续试。

## 核心原则

BeaconFlow 只做三件事：

1. **采集证据**：metadata、drcov、QEMU address log、runtime trace。
2. **压缩证据**：flow、flow-diff、decision-points、roles、taint、trace-compare。
3. **给 AI 可执行建议**：`ai_digest`、`recommended_actions`、`data_quality`、`report_confidence`。

BeaconFlow 不应该变成完整反编译器、完整符号执行框架或完整调试器。遇到这些需求时，它应该生成模板、导入外部工具输出，然后把结果统一成报告。

## 安装

```powershell
git clone https://github.com/mansujiaosheng/BeaconFlow.git
cd BeaconFlow
python -m pip install -e .
```

可选安装 MCP 依赖：

```powershell
python -m pip install -e ".[mcp]"
```

验证：

```powershell
python -m beaconflow.cli --help
python -m beaconflow.cli doctor --format markdown
python -m unittest discover -s tests -p "test_*.py"
```

## 推荐入口

第一次使用时，不要从几十个子命令里选，优先使用下面三个 quickstart。

### 1. PE / Windows native 目标

适合 Windows `.exe`、`.dll` 相关样本，使用 Ghidra/IDA metadata + DynamoRIO drcov。

```powershell
python -m beaconflow.cli quickstart-pe `
  --target D:\case\target.exe `
  --output-dir D:\case\beacon_quick `
  -- arg1 arg2
```

输出目录建议包含：

```text
beacon_quick/
  metadata.json
  runs/
  coverage.json
  coverage.md
  flow.json
  flow.md
  quickstart-pe.md
```

AI 优先阅读：

```text
quickstart-pe.md
flow.md
coverage.md
```

### 2. QEMU / 非 x86 ELF 目标

适合 LoongArch、MIPS、ARM、AArch64 等目标，尤其是 IDA 不好打开或本机无法直接运行的样本。

```powershell
python -m beaconflow.cli quickstart-qemu `
  --target D:\case\flagchecker `
  --qemu-arch loongarch64 `
  --output-dir D:\case\beacon_qemu `
  --stdin "ACTF{00000000000000000000000000000000}" `
  --stdin "ACTF{ffffffffffffffffffffffffffffffff}" `
  --auto-newline `
  --failure-regex "Wrong" `
  --format markdown
```

对静态链接 ELF，如果运行库噪声太多，手动限制地址范围：

```powershell
python -m beaconflow.cli quickstart-qemu `
  --target D:\case\flagchecker `
  --qemu-arch loongarch64 `
  --output-dir D:\case\beacon_qemu `
  --stdin "ACTF{test}" `
  --auto-newline `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --format markdown
```

AI 优先阅读：

```text
quickstart-qemu.md
explore_report.md
flow.md
flow_diff.md
```

### 3. 控制流平坦化 / dispatcher 分析

适合已经有 metadata 和一份 drcov / QEMU address log 的情况。

```powershell
python -m beaconflow.cli quickstart-flatten `
  --metadata D:\case\metadata.json `
  --address-log D:\case\wrong.in_asm.qemu.log `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --output-dir D:\case\beacon_flatten
```

AI 优先阅读：

```text
quickstart-flatten.md
deflatten.md
decision_points.md
roles.md
```

## 常用专家命令

quickstart 跑完之后，再按需要使用专家命令。

| 场景 | 命令 |
|---|---|
| 分析单次覆盖率 | `analyze` |
| 恢复执行流 | `flow` |
| 比较两次执行流 | `flow-diff` |
| 采集 drcov | `collect` |
| 采集 QEMU 地址日志 | `collect-qemu` |
| 多输入 QEMU 探索 | `qemu-explore` |
| 从地址日志生成 fallback metadata | `metadata-from-address-log` |
| 查看基本块上下文 | `inspect-block` |
| 查看函数上下文 | `inspect-function` |
| 找决策点 | `decision-points` / `inspect-decision-point` |
| 函数角色检测 | `detect-roles` / `inspect-role` |
| 反平坦化辅助 | `deflatten` |
| WASM metadata 导出 | `export-wasm-metadata` |
| WASM 函数摘要 | `decompile-function` |
| IR 归一化 | `normalize-ir` |
| 输入污点启发式分析 | `input-taint` |
| 比较失败点分析 | `trace-compare` |
| 反馈式输入探索 | `feedback-explore` |
| 报告转 HTML | `to-html` |
| JSON schema 检查 | `schema` |
| case 工作区检查 | `case-check` |

如果某个命令还处于 beta 或 experimental，请在 `docs/EXPERIMENTAL.md` 标明，避免 AI Agent 把启发式结果当成确定事实。

## 报告读取顺序

所有面向 AI 的报告都应该尽量提供统一顶层字段：

```json
{
  "schema_version": "beaconflow.report.v1",
  "tool": "flow",
  "summary": {},
  "ai_digest": {
    "top_findings": [],
    "recommended_actions": [],
    "evidence_refs": []
  },
  "data_quality": {
    "confidence": "high",
    "limitations": [],
    "recommended_recollection": []
  },
  "evidence": [],
  "details": {}
}
```

AI 读取顺序：

1. `ai_digest.top_findings`
2. `ai_digest.recommended_actions`
3. `data_quality`
4. `evidence`
5. `details`

详细规范见：

```text
docs/REPORT_SCHEMA.md
```

## 推荐 case 目录结构

```text
case_root/
  target/
    target.exe
  metadata/
    ida_metadata.json
    ghidra_metadata.json
    wasm_metadata.json
  runs/
    case000.drcov.log
    case001.in_asm.qemu.log
  reports/
    flow.json
    flow.md
    flow_diff.json
    flow_diff.md
    roles.md
    decision_points.md
  imported/
    frida.log
    gdb.log
    angr_result.json
  notes/
    analyst.md
  manifest.json
```

`case-check` 应检查：

- 目标文件是否存在；
- metadata 是否过期；
- report schema 是否有效；
- QEMU 地址范围是否过宽；
- 是否存在低置信度报告；
- 是否缺少下一步建议；
- 是否有无法映射的覆盖率事件。

## 文档分层

为了避免 README 过长，文档按下面方式维护：

```text
README.md                    只写稳定入口和最小工作流
docs/API_DEV_GUIDE.md        CLI / MCP / 新工具接入规范
docs/REPORT_SCHEMA.md        统一报告 schema
docs/EXPERIMENTAL.md         beta / experimental 功能和限制
docs/ROADMAP.md              后续开发路线
```

README 不写还没实现的命令。计划中能力只放进 `docs/ROADMAP.md`。

## 开发优先级

当前阶段优先做稳定化，而不是继续堆功能：

1. 收敛 README 入口。
2. 统一 report schema。
3. 让 CLI / MCP / docs 三方自动对齐。
4. 强化 `case-check`。
5. 把 Frida / GDB / angr / JADX 做成模板生成和日志导入，不做大而全替代品。
