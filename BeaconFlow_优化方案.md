# BeaconFlow 插件优化方案

> 适用对象：BeaconFlow 后续开发、README 重构、MCP 工具整理、给 Codex / Claude / Cursor Agent 的开发交接。  
> 生成时间：2026-05-17  
> 核心结论：**下一阶段不要继续堆底层逆向能力，而要把入口、证据质量、报告结构、发布体验做扎实。**

---

## 1. 当前项目定位

BeaconFlow 当前已经不只是“覆盖率分析脚本”，而是一个面向 AI Agent 的二进制分析证据汇总层。

推荐继续采用这个定位：

```text
BeaconFlow = AI-oriented binary analysis evidence summarizer
```

也就是：

```text
收集证据 → 清洗证据 → 归一化证据 → 关联证据 → 总结给 AI → 推荐下一步动作
```

它不应该替代：

```text
IDA / Ghidra / Frida / angr / Triton / JADX / JEB / GDB / LLDB / QEMU / DynamoRIO
```

它应该负责：

```text
1. 调用或接入这些工具的结果
2. 把日志、覆盖率、执行流、hook 输出、solver 输出统一整理成 evidence
3. 给 AI 一个短、准、可引用、可继续行动的报告
```

一句话：

> **BeaconFlow 不要做新的 IDA、Frida、angr，而要做 AI 逆向分析的证据中枢。**

---

## 2. 目前已经实现的核心能力

根据当前进度文档和仓库 README，BeaconFlow 已经具备以下能力。

### 2.1 采集层能力

| 能力 | 当前状态 | 说明 |
|---|---|---|
| DynamoRIO drcov 覆盖率采集 | 已有 | 适合 x86/x64 PE/ELF |
| QEMU address log | 已有 | 适合 LoongArch、MIPS、ARM、AArch64、RISC-V 等非 x86 目标 |
| IDA metadata 导出 | 已有 | 导出函数、基本块、CFG |
| Ghidra metadata 导出 | 已有 | 可弥补 IDA 架构支持不足 |
| WASM metadata / analyze | 已有 | 支持 WASM 题目基础分析 |
| Frida trace-calls / trace-compare-rt | 已有或已接入 | 用于提取 strcmp/memcmp/cmp 等运行时比较证据 |
| flow / flow-diff | 已有 | 分析单次路径和多输入路径差异 |
| qemu-explore / feedback-explore | 已有 | 多输入探索和反馈式输入修改 |

### 2.2 证据总结层能力

| 能力 | 当前状态 | 说明 |
|---|---|---|
| `ai_digest` | 已完成 | 所有报告统一附加 AI 摘要 |
| `evidence_id` | 已完成 | 方便多轮引用证据 |
| `missing_evidence` | 已完成 | 标出当前还缺什么证据 |
| `next_actions` / `recommended_actions` | 已完成 | 给 AI 下一步操作建议 |
| `report_confidence` | 已完成 | 报告级置信度 |
| `summarize-case` | 已强化 | 案例级汇总入口 |
| `schema --validate` | 已完成 | 稳定 JSON Schema 校验 |

### 2.3 一键工作流能力

当前进度文档显示已经实现：

```text
triage-native
triage-qemu
triage-wasm
quickstart-pe
quickstart-qemu
quickstart-flatten
```

这些说明项目已经开始从“零散工具集合”向“playbook 工作流”过渡。

### 2.4 外部工具导入能力

当前进度显示已经实现：

```text
import-frida-log
import-gdb-log
import-angr-result
import-jadx-summary
```

这是非常正确的方向。BeaconFlow 不需要重新实现 Frida/GDB/angr/JADX，只需要把它们的结果变成统一 evidence。

### 2.5 模板推荐能力

当前进度显示已经实现：

```text
suggest-hook
suggest-angr
suggest-debug
generate-template
list-templates
```

这说明 BeaconFlow 已经不仅能“看报告”，还能根据已有证据建议下一步使用什么工具。

---

## 3. 当前主要问题

### 3.1 功能已经很多，但入口还不够统一

目前工具数量较多，README 中也暴露了大量命令，例如：

```text
collect_drcov
collect_qemu
qemu_explore
analyze_flow
diff_flow
branch_rank
inspect_block
inspect_function
find_decision_points
trace_compare
input_taint
feedback_explore
normalize_ir
sig_match
summarize_case
wasm_analyze
trace_calls
input_impact
...
```

这些功能对 AI 很有用，但对人类用户来说容易产生一个问题：

```text
我到底第一步该跑哪个？
```

所以后续重点不是再增加 20 个命令，而是把入口收敛成少数几个主命令。

---

### 3.2 本地进度和公开 README 可能不同步

进度文档中写到：

```text
triage-native / triage-qemu / triage-wasm 已完成
README 简化成“先用哪个 playbook”已完成
```

但当前 GitHub README 页面中没有明显检索到 `triage-native` 字样，说明可能存在以下情况之一：

```text
1. 本地代码已经实现，但还没有 push 到 GitHub
2. README 本地已经改了，但公开仓库还没同步
3. 命令存在，但 README 仍以旧的 collect/flow/qemu 工作流为主
4. 文档说完成，但用户打开仓库时仍然看不到最推荐入口
```

这会影响项目展示效果。外部用户或 Codex 直接看 GitHub 时，可能仍然以为 BeaconFlow 主要是底层命令集合，而不是一键 playbook 工具。

---

### 3.3 MCP tools 太多，AI 可能选错工具

MCP 当前工具数量已经很多。工具越多，并不一定越好。

AI Agent 面对几十个工具时，容易出现：

```text
1. 该用 summarize_case，却直接 inspect_block
2. 该先 triage，却直接 trace_compare
3. 该用 qemu_explore，却反复 collect_qemu
4. 该导入外部日志，却重新跑底层采集
5. 该看 ai_digest，却读取完整大 JSON 导致上下文浪费
```

因此 MCP 需要分层暴露或增加工具选择说明。

---

### 3.4 Case workspace 可以继续升级成真正的“总控台”

当前已经有：

```text
init-case
summarize-case
add_metadata_to_case
add_run_to_case
add_report_to_case
add_note_to_case
list_case_runs
list_case_reports
list_case_notes
```

但后续应该让 case workspace 成为主线，而不是辅助功能。

理想状态是：

```text
所有分析结果自动进入 case
所有外部日志自动进入 case
所有 evidence 都能在 case summary 中统一引用
所有 next action 都基于 case 的全局状态生成
```

这样 BeaconFlow 才真正成为 AI 接力分析的中枢。

---

### 3.5 报告还可以更“结论优先”

当前报告已经有 `ai_digest`，但后续还应该继续压缩信息层级。

推荐报告顺序：

```text
1. 一句话结论
2. Top 5 evidence
3. 当前最可信假设
4. 关键函数 / 分支 / 比较点
5. 缺失证据
6. 下一步动作
7. 原始数据索引
```

不要让 AI 或人类一开始就读大量 coverage/block/edge 细节。

---

## 4. 优化总原则

后续开发建议遵循以下原则。

### 4.1 只做 AI 决策需要的功能

每个新功能都要问：

```text
这个功能能不能帮助 AI 更快判断下一步？
```

如果不能，就先不做。

---

### 4.2 不重复造轮子

不建议做：

```text
完整 Frida hook 框架
完整动态污点引擎
完整符号执行器
完整 Android 反编译器
完整 IR 优化器
完整自动反混淆平台
```

建议做：

```text
Frida 模板推荐 + 日志导入 + 证据总结
angr 模板生成 + 结果导入 + 求解证据总结
GDB/x64dbg 断点脚本生成 + 日志导入
JADX/JEB 结果导入 + Java 层可疑函数总结
IDA/Ghidra 注释回写 + 地址上下文整理
```

---

### 4.3 入口少，内部强

用户和 AI 不应该一开始看到几十个命令。

建议主入口变成：

```text
beaconflow triage
beaconflow summarize-case
beaconflow import-evidence
beaconflow suggest-next
beaconflow generate-template
```

底层命令继续保留，但放到 advanced 文档里。

---

### 4.4 报告必须稳定可引用

每个关键证据都应该有：

```text
evidence_id
kind
source_tool
location
summary
confidence
actionability
refs
next_actions
```

AI 在多轮分析中应该能说：

```text
根据 E003 和 E007，下一步应 hook 0x401495 附近的 memcmp。
```

---

## 5. 第一阶段优化：统一入口

优先级：P0 之后的最高优先级。

### 5.1 增加总入口 `beaconflow triage`

目标：用户只需要记住一个命令。

推荐命令：

```bash
beaconflow triage --target ./checker --stdin "AAAA" --format markdown
```

内部自动判断：

```text
PE/ELF x86/x64 可执行文件 → triage-native
LoongArch/MIPS/ARM/AArch64/RISC-V ELF → triage-qemu 或提示 --qemu-arch
WASM → triage-wasm
.so/.dll/.pyd → triage-library
.pyc → triage-pyc，以后实现
APK → apk-native-summary，以后实现
未知格式 → doctor + file identification + next actions
```

输出示例：

```markdown
# BeaconFlow Triage Report

## Verdict
当前目标是 x86_64 ELF，已使用 native workflow。

## Top Findings
1. 疑似 validator：check_flag @ 0x401230
2. 关键比较：memcmp @ 0x401495 比较输入和常量
3. 输入影响：input[0:5] 可能影响 success/failure 分支

## Recommended Next Actions
1. 使用 suggest-hook 生成 memcmp hook 模板
2. 使用 inspect-function 查看 check_flag
3. 使用 flow-diff 对比 wrong/better 输入
```

---

### 5.2 保留专业入口，但降低曝光

底层命令仍保留：

```text
collect
collect-qemu
record-flow
flow
flow-diff
branch-rank
trace-compare
inspect-block
inspect-function
...
```

但 README 第一屏不要优先展示这些。

README 第一屏只展示：

```bash
# 普通二进制
beaconflow triage --target ./checker --stdin "AAAA" --format markdown

# 已经有 case
beaconflow summarize-case ./case_dir --format markdown

# 导入外部日志
beaconflow import-evidence --case ./case_dir --tool frida --input frida.log

# 推荐下一步
beaconflow suggest-next --case ./case_dir --format markdown
```

---

## 6. 第二阶段优化：MCP 工具分层

### 6.1 MCP tools 增加 tier 字段

建议每个 MCP tool 的描述中增加：

```json
{
  "tier": "basic|advanced|expert",
  "when_to_use": "什么时候使用",
  "requires": ["metadata", "coverage", "case"],
  "produces": ["evidence", "report", "template"],
  "preferred_before": [],
  "preferred_after": []
}
```

示例：

```json
{
  "name": "summarize_case",
  "tier": "basic",
  "when_to_use": "当用户问当前分析进度、下一步怎么做、交接给 AI 时优先使用",
  "requires": ["case_dir"],
  "produces": ["case_summary", "recommended_actions"]
}
```

---

### 6.2 MCP 工具分三层

#### Basic：默认推荐给 AI 用

```text
triage_target
summarize_case
suggest_next
inspect_evidence
import_evidence
```

#### Advanced：需要一定上下文时使用

```text
analyze_flow
diff_flow
branch_rank
trace_compare
trace_values
detect_roles
inspect_function
inspect_decision_point
input_impact
feedback_explore
```

#### Expert：底层采集与特殊分析

```text
collect_drcov
collect_qemu
qemu_explore
export_ghidra_metadata
metadata_from_address_log
normalize_ir
sig_match
deflatten_flow
trace_compare_rt
wasm_analyze
```

---

### 6.3 增加 `recommend_tool` 工具

让 AI 不确定时先调用：

```text
recommend_tool(user_goal, target_info, available_files, case_state)
```

返回：

```json
{
  "recommended_tool": "triage_target",
  "reason": "用户还没有 case，也没有 metadata，应该先做一键 triage",
  "fallback_tools": ["doctor", "export_ghidra_metadata"]
}
```

这个工具可以显著减少 AI 乱选工具的问题。

---

## 7. 第三阶段优化：Case workspace 总控台化

### 7.1 所有命令都支持 `--case`

建议所有核心命令统一支持：

```bash
--case ./case_dir
```

例如：

```bash
beaconflow triage --target ./checker --stdin "AAAA" --case ./case_checker
beaconflow import-frida-log ./frida.log --case ./case_checker
beaconflow suggest-hook --case ./case_checker
beaconflow summarize-case ./case_checker --format markdown
```

这样每次运行都会自动写入 case。

---

### 7.2 case 目录建议结构

```text
case_checker/
  case.json
  target/
    target_info.json
    file_hashes.json
  metadata/
    ida_metadata.json
    ghidra_metadata.json
    wasm_metadata.json
  runs/
    run_0001_wrong/
    run_0002_better/
  reports/
    flow_wrong.json
    flow_diff_wrong_better.json
    branch_rank.json
  imports/
    frida_log_0001.json
    gdb_log_0001.json
    angr_result_0001.json
    jadx_summary_0001.json
  evidence/
    evidence_index.json
  notes/
    manual_notes.md
  summary/
    case_summary.md
    ai_handoff.md
```

---

### 7.3 `summarize-case` 应该输出的核心内容

推荐结构：

```markdown
# BeaconFlow Case Summary

## 1. Current Verdict
当前最可信判断。

## 2. Target Overview
- path
- format
- arch
- entry
- hash
- run environment

## 3. Evidence Index
| ID | Kind | Source | Location | Confidence | Summary |

## 4. Best Findings
1. validator candidate
2. key branch
3. runtime compare
4. input influence
5. success/failure split

## 5. Current Hypothesis
当前对程序校验逻辑的推测。

## 6. Missing Evidence
当前还缺什么。

## 7. Recommended Next Actions
按收益排序的下一步操作。

## 8. AI Handoff
给另一个 AI 接力时只需要阅读这一节。
```

---

## 8. 第四阶段优化：Evidence Schema 强化

### 8.1 建议 evidence 基础结构

```json
{
  "id": "E023",
  "kind": "runtime_compare",
  "source_tool": "frida",
  "source_report": "imports/frida_log_0001.json",
  "target": {
    "path": "./checker",
    "format": "ELF",
    "arch": "x86_64"
  },
  "location": {
    "module": "checker",
    "function": "check_flag",
    "address": "0x401495"
  },
  "summary": "memcmp compares transformed input with constant ISCC{",
  "confidence": "high",
  "actionability": "direct",
  "stability": "seen_once",
  "refs": ["0x401495", "run_0001"],
  "recommended_actions": [
    "rerun with prefix ISCC{",
    "inspect caller of memcmp",
    "generate Frida memcmp hook template"
  ]
}
```

---

### 8.2 Evidence 分类

建议至少分以下类型：

```text
coverage_function
coverage_block
flow_edge
flow_diff
branch_decision
runtime_compare
runtime_value
input_influence
function_role
crypto_signature
vm_dispatcher
solver_result
hook_result
debug_log
java_method
native_export
wasm_export
manual_note
```

---

### 8.3 Evidence 质量评分

每条证据不只要 `confidence`，还应该有 `actionability`。

```text
confidence：证据可信不可信
  high
  medium
  low

actionability：证据能不能直接指导下一步
  direct      直接可用，例如 memcmp 泄露 ISCC{
  indirect    间接有用，例如某函数疑似 validator
  weak        仅供参考，例如某块被覆盖
```

示例：

```json
{
  "confidence": "high",
  "actionability": "direct"
}
```

AI 排序时优先看：

```text
high confidence + direct actionability
```

---

## 9. 第五阶段优化：README 重构

### 9.1 README 第一屏建议

当前 README 不应该先放大量命令细节，而应该先回答三个问题：

```text
1. BeaconFlow 是什么？
2. 我第一条命令该跑什么？
3. 它给 AI 什么结果？
```

推荐开头：

```markdown
# BeaconFlow

BeaconFlow is an AI-oriented binary analysis evidence summarizer.

It collects coverage, flow, metadata, hook logs, trace logs, and external tool outputs,
then turns them into compact, structured, AI-readable reports and next-step suggestions.

## Quick Start

### 1. Analyze a native binary

```bash
beaconflow triage --target ./checker --stdin "AAAA" --format markdown
```

### 2. Analyze a non-x86 ELF with QEMU

```bash
beaconflow triage --target ./checker --qemu-arch loongarch64 --stdin "AAAA" --format markdown
```

### 3. Analyze a WASM module

```bash
beaconflow triage --target ./box.wasm --format markdown
```

### 4. Summarize a case for AI handoff

```bash
beaconflow summarize-case ./case_dir --format markdown
```
```

---

### 9.2 README 中间部分

放项目能力图：

```text
Target Binary
    ↓
Metadata Export      Runtime Trace       External Logs
IDA/Ghidra/WASM      drcov/QEMU/Frida    GDB/angr/JADX
    ↓                    ↓                    ↓
              Evidence Normalizer
                    ↓
              Evidence Correlator
                    ↓
              AI Digest / Case Summary
                    ↓
              Next Actions / Templates
```

---

### 9.3 README 后半部分

把高级命令放后面：

```text
Advanced CLI Reference
MCP Configuration
Tool Matrix
Schema Reference
Template Usage
Case Workspace
Troubleshooting
```

避免新用户第一眼被大量命令吓到。

---

## 10. 第六阶段优化：HTML 报告

HTML 报告建议放在 P2 里，但很值得做。

### 10.1 为什么需要 HTML 报告

Markdown 适合 AI 和终端，但 HTML 更适合人类看。

HTML 报告可以提供：

```text
1. evidence 可折叠
2. 函数/地址可点击
3. confidence 颜色标识
4. flow diff 可视化
5. case timeline
6. next actions 面板
7. 原始日志折叠展示
```

---

### 10.2 HTML 报告结构

```text
report.html
├─ Overview
├─ Target Info
├─ Top Findings
├─ Evidence Table
├─ Flow Graph
├─ Branch / Decision Points
├─ Runtime Comparisons
├─ Input Influence
├─ Missing Evidence
├─ Recommended Actions
└─ Raw Artifacts
```

---

### 10.3 技术建议

先不要做复杂前端。

建议第一版：

```text
Python Jinja2 模板
单文件 HTML
内嵌 CSS
不依赖服务器
可直接打开
```

命令：

```bash
beaconflow report-html --case ./case_dir --output report.html
```

---

## 11. 第七阶段优化：Benchmark 和 Release

### 11.1 benchmark cases

当前项目已经有真实 CTF 题测试记录，但建议整理成公开 benchmark 文档。

建议新增：

```text
docs/BENCHMARKS.md
```

内容：

```markdown
# BeaconFlow Benchmarks

## Case 1: simple PE checker
- Target type: PE x64
- Covered features: drcov, flow, diff, decision-points, trace-calls
- Expected result: detects validator and key compare

## Case 2: LoongArch flagchecker
- Target type: LoongArch ELF
- Covered features: qemu collect, address-range, fallback metadata, flow
- Expected result: identifies hot function range and branch points

## Case 3: WASM checker
- Target type: WASM
- Covered features: wasm metadata, role detection, normalize-ir, sig-match
- Expected result: detects dispatcher / transform loop
```

---

### 11.2 release 包

建议开始做正式 release。

最低要求：

```text
1. GitHub tag，例如 v0.1.0
2. CHANGELOG.md
3. README Quick Start 同步
4. pyproject version 同步
5. pip install -e . 测试通过
6. MCP 启动测试通过
7. tests 全部通过
8. docs/BENCHMARKS.md 有最小样例
```

建议命令：

```bash
python -m pytest
python -m beaconflow.cli doctor --format markdown
python -m beaconflow.cli schema --validate examples/report.json
```

---

## 12. 后续功能优先级

### 12.1 最高优先级

| 优先级 | 功能 | 原因 |
|---|---|---|
| P0 | `beaconflow triage` 总入口 | 降低使用成本 |
| P0 | README 第一屏重构 | 提升项目展示效果 |
| P0 | MCP tools 分层 | 减少 AI 选错工具 |
| P0 | Case workspace 自动写入 | 让项目主线更清晰 |
| P0 | evidence schema 强化 | 提高 AI 接力质量 |

---

### 12.2 中优先级

| 优先级 | 功能 | 原因 |
|---|---|---|
| P1 | HTML 报告 | 提升人类可读性 |
| P1 | benchmark cases | 提高可信度 |
| P1 | release 包 | 方便安装和推广 |
| P1 | Android APK native summary | 扩展常见 CTF 场景 |
| P1 | Android Java hook 模板推荐 | 配合 Frida/JADX 使用 |

---

### 12.3 低优先级

| 优先级 | 功能 | 原因 |
|---|---|---|
| P2 | triage-pyc | 有价值，但不是主线 |
| P2 | JEB/JADX 深度导入 | 可后做 |
| P2 | 更复杂的可视化图 | 容易耗时，不如先做 HTML 表格 |
| P2 | 更复杂的 IR 优化 | 偏底层，暂时不要投入过多 |

---

## 13. 不建议做的方向

以下方向短期不要投入：

```text
1. 自研完整 Frida hook 框架
2. 自研动态污点分析引擎
3. 自研符号执行器
4. 自研 Android 反编译器
5. 自研完整 Python bytecode 反编译器
6. 自研大型反混淆平台
7. 复杂 GUI 客户端
8. 过早做云端/平台化
```

原因：

```text
这些方向都会把 BeaconFlow 拉成一个大而重的逆向平台，偏离“AI 证据汇总层”的核心优势。
```

---

## 14. 建议新增文档

建议在 `docs/` 下新增：

```text
docs/
  QUICKSTART.md          # 最短使用说明
  PLAYBOOKS.md           # native/qemu/wasm/library/apk/pyc 工作流
  EVIDENCE_SCHEMA.md     # evidence 结构说明
  AI_DIGEST_SCHEMA.md    # ai_digest 字段说明
  CASE_WORKSPACE.md      # case 目录和 summarize-case 说明
  MCP_TOOLS.md           # MCP tools 分层说明
  TEMPLATE_USAGE.md      # Frida/angr/GDB/x64dbg 模板用法
  BENCHMARKS.md          # 测试样例和效果
  ROADMAP.md             # 后续路线图
```

README 只保留：

```text
1. 项目是什么
2. 快速开始
3. 最小案例
4. 文档入口
5. MCP 配置入口
```

---

## 15. 给 Codex 的开发任务拆分

可以直接把下面任务交给 Codex。

### Task 1：新增统一 triage 入口

```text
目标：新增 beaconflow triage 命令。

要求：
1. 根据 target 文件类型自动分发到 triage-native / triage-qemu / triage-wasm / triage-library。
2. 支持 --stdin、--auto-newline、--case、--format markdown/json。
3. 如果架构无法自动判断，输出明确 next_actions，而不是直接失败。
4. 所有输出必须包含 ai_digest、evidence_refs、missing_evidence、recommended_actions。
5. 增加 tests/test_triage_router.py。
```

---

### Task 2：MCP tools 增加分层 metadata

```text
目标：给 MCP tools/list 输出增加 tier、when_to_use、requires、produces 字段。

要求：
1. basic 工具：triage/summarize_case/suggest_next/import_evidence/inspect_evidence。
2. advanced 工具：flow/diff/branch/trace/role/context/input-impact。
3. expert 工具：collect/qemu/metadata/ir/signature/deflatten/wasm。
4. 不破坏现有 MCP 调用兼容性。
5. 增加一个 recommend_tool 工具，根据用户目标推荐工具。
```

---

### Task 3：case workspace 自动写入

```text
目标：核心 CLI 增加 --case 参数并自动登记 artifact。

要求：
1. triage、import-*、suggest-*、trace-*、flow-* 输出都能写入 case。
2. case 维护 evidence_index.json。
3. summarize-case 能读取所有 evidence 并按 confidence/actionability 排序。
4. 输出 ai_handoff.md，供其他 AI 接力。
```

---

### Task 4：Evidence Schema v2

```text
目标：实现 evidence schema v2。

要求：
1. 每条 evidence 包含 id、kind、source_tool、location、summary、confidence、actionability、stability、refs、recommended_actions。
2. 给旧报告做兼容转换。
3. schema --validate 支持 v1/v2。
4. ai_digest.evidence_refs 引用 evidence_index.json 中的稳定 ID。
```

---

### Task 5：README 重构

```text
目标：重写 README 第一屏。

要求：
1. 第一屏只保留项目定位、Quick Start、三条主路线。
2. 把底层命令移动到 Advanced CLI Reference。
3. 增加 What BeaconFlow Gives AI 一节。
4. 明确说明 BeaconFlow 不替代 IDA/Ghidra/Frida/angr，而是总结它们的证据。
5. 确保 GitHub 公共 README 中能看到 triage-native / triage-qemu / triage-wasm 或统一 triage 入口。
```

---

## 16. 推荐最终路线图

### v0.1.0：可公开使用版本

```text
目标：让外部用户可以一眼看懂并跑起来。

必须完成：
- README Quick Start
- beaconflow triage 总入口
- summarize-case 稳定输出
- evidence schema v2
- MCP tools 分层说明
- benchmarks 文档
- release tag
```

---

### v0.2.0：AI Agent 强化版本

```text
目标：让 Codex / Claude / Cursor Agent 更不容易选错工具。

建议完成：
- recommend_tool
- suggest_next
- ai_handoff.md
- MCP tool metadata
- case 自动写入
- 外部日志统一 import-evidence
```

---

### v0.3.0：多目标扩展版本

```text
目标：扩展 CTF 常见文件类型。

建议完成：
- apk-native-summary
- Android Java hook 模板推荐
- triage-pyc
- HTML report
- JEB/JADX 导入增强
```

---

## 17. 总结

当前 BeaconFlow 的功能已经比较多，下一步最重要的不是继续加底层分析模块，而是：

```text
1. 收敛入口
2. 强化 case workspace
3. 稳定 evidence schema
4. 优化 MCP 工具选择
5. 重构 README 第一屏
6. 做 benchmark 和 release
```

最终目标应该是：

> 用户或 AI 只需要跑一次 `beaconflow triage`，就能得到一份包含关键函数、关键分支、运行时比较、输入影响、缺失证据和下一步动作的 AI 可读报告。

这样 BeaconFlow 的核心价值会更清晰：

```text
不是更多工具，而是更好的证据组织。
不是替代逆向工具，而是让 AI 更会用逆向工具的结果。
```
