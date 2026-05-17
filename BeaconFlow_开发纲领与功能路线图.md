# BeaconFlow 开发纲领与功能路线图

> 本文档用于规划 BeaconFlow 后续开发方向。  
> 核心目标不是继续堆叠大量底层逆向工具，而是把已有工具和外部工具产生的结果整理成 AI Agent 能直接使用的证据报告。

---

## 1. 项目总定位

BeaconFlow 的定位建议调整为：

> **BeaconFlow 是面向 AI Agent 的二进制分析证据汇总层。**

它不应该试图替代：

- IDA
- Ghidra
- Frida
- angr
- Triton
- JADX
- JEB
- GDB / LLDB
- QEMU / DynamoRIO

而应该负责：

```text
收集证据 → 清洗证据 → 关联证据 → 总结证据 → 给出下一步建议
```

也就是说，BeaconFlow 的价值不在于“重新实现所有逆向工具”，而在于让 AI 能够更好地理解这些工具的输出。

---

## 2. 推荐项目描述

英文描述：

```text
BeaconFlow is an AI-oriented binary analysis evidence summarizer.

It collects coverage, flow, metadata, hook logs, trace logs, and external tool outputs,
then turns them into compact, structured, AI-readable reports and next-step suggestions.
```

中文描述：

```text
BeaconFlow 是面向 AI Agent 的二进制分析证据汇总器。

它负责收集覆盖率、执行流、metadata、hook 日志、trace 日志和外部工具输出，
再把这些信息整理成 AI 能直接阅读、引用和继续行动的分析报告。
```

---

## 3. 开发总原则

后续开发应遵循以下原则：

```text
1. 不重复造轮子
2. 优先接入和总结已有工具结果
3. 每个功能都要服务 AI 决策
4. 每份报告都要包含 evidence / confidence / next actions
5. 底层分析能力够用即可，重点是证据关联和解释
```

也就是说：

```text
不优先做：
  自研完整 hook 框架
  自研完整动态污点分析
  自研完整符号执行器
  自研 Android 反编译平台

优先做：
  归一化已有结果
  汇总多种工具证据
  自动生成 AI 可读报告
  自动推荐下一步分析动作
  提供常用工具模板
```

---

## 4. 目标用户

BeaconFlow 主要面向三类用户：

### 4.1 AI Agent

例如：

- Codex
- Claude Desktop
- Cursor Agent
- 自研 MCP Agent
- 其他具备工具调用能力的 AI

AI 使用 BeaconFlow 的核心目的：

```text
快速理解二进制程序当前执行到了哪里；
找出最值得继续分析的函数、分支和比较点；
根据已有证据决定下一步该使用什么工具。
```

### 4.2 CTF / 逆向选手

适合场景：

```text
不知道该看哪个函数
想比较不同输入的执行路径
想知道 wrong / correct 分支差异
想让 AI 接力分析
想快速整理一份逆向分析报告
```

### 4.3 自动化分析流水线

适合场景：

```text
批量运行样本
批量收集覆盖率
批量生成摘要
批量整理 evidence
批量交给 AI 做后续分析
```

---

## 5. 总体架构设计

建议把 BeaconFlow 抽象成五层：

```text
BeaconFlow
├─ 1. Evidence Collectors      证据采集层
├─ 2. Evidence Importers       外部结果导入层
├─ 3. Evidence Normalizers     证据归一化层
├─ 4. Evidence Correlators     证据关联层
└─ 5. AI Summarizers           AI 总结层
```

---

# 6. Evidence Collectors：证据采集层

这一层负责直接采集程序运行和静态分析结果。

当前 BeaconFlow 已经有不少采集能力，例如：

```text
DynamoRIO drcov 覆盖率
QEMU address log
IDA metadata
Ghidra metadata
WASM metadata
Frida trace-calls
Frida trace-compare-rt
flow / flow-diff
branch-rank
decision-points
input-taint
feedback-explore
```

这一层后续不应该无限扩展。  
只需要继续补齐必要的薄适配能力。

## 后续建议

优先补：

```text
.so / .dll / .pyd 的基础识别
Frida 日志导入
angr 输出导入
JADX / JEB 输出导入
GDB / x64dbg 日志导入
```

暂时不建议做：

```text
完整 hook 引擎
完整 taint engine
完整 symbolic execution engine
完整 Android reverse platform
```

---

# 7. Evidence Importers：外部结果导入层

这一层是后续最值得加强的方向之一。

BeaconFlow 不需要重写外部工具，而是应该支持导入外部工具的结果。

## 需要支持导入的结果

```text
IDA 导出的函数、基本块、CFG、伪代码、注释
Ghidra 导出的函数、基本块、CFG、伪代码、引用
Frida hook 日志
angr 求解结果
GDB / LLDB 断点日志
x64dbg trace 日志
JADX / JEB Java 层分析结果
strings / readelf / objdump 输出
QEMU / DynamoRIO trace 结果
```

## 统一导入格式示例

```json
{
  "kind": "runtime_compare",
  "source_tool": "frida",
  "function": "memcmp",
  "caller": "0x401495",
  "lhs": "AAAA",
  "rhs": "ISCC{",
  "length": 5,
  "confidence": "high"
}
```

这样 AI 不需要直接阅读大量原始日志，而是只读 BeaconFlow 的统一 evidence。

---

# 8. Evidence Normalizers：证据归一化层

不同工具输出的地址和上下文不同：

```text
IDA 地址
Ghidra 地址
QEMU address log
drcov module offset
Frida return address
angr basic block address
JADX Java method name
```

BeaconFlow 需要把这些统一成一套结构。

## 推荐统一对象

```text
target
module
function
basic_block
decision_point
runtime_event
input_case
evidence_id
confidence
```

## 推荐基本字段

```json
{
  "target": {
    "path": "./checker",
    "format": "ELF",
    "arch": "x86_64"
  },
  "module": "checker",
  "function": "check_flag",
  "address": "0x401495",
  "kind": "decision_point",
  "confidence": "high"
}
```

这层做好之后，后续支持 `.dll`、`.so`、`.pyd`、`.pyc`、Android、WASM 都会更稳定。

---

# 9. Evidence Correlators：证据关联层

这是 BeaconFlow 最有价值的核心层。

它要把分散的证据关联起来：

```text
某个输入
  → 覆盖了哪些块
  → 进入了哪个函数
  → 触发了哪个分支
  → 调用了哪个 strcmp / memcmp
  → 比较了什么值
  → 哪些输入字节可能影响该分支
  → 下一步应该怎么改输入
```

## 推荐输出

```text
输入 "AAAA" 进入了 check_flag；
在 0x401495 调用了 memcmp；
memcmp 左侧是用户输入，右侧是常量 "ISCC{"；
因此输入前 5 字节很可能应为 "ISCC{"；
建议下一轮输入使用 "ISCC{AAAA" 重新采集 flow。
```

这类总结比单纯输出覆盖率更适合 AI 使用。

---

# 10. AI Summarizers：AI 总结层

这是后续最优先做强的部分。

所有报告都应该包含统一的 AI 摘要字段。

## 推荐统一 ai_digest schema

```json
{
  "ai_digest": {
    "summary": "",
    "top_findings": [],
    "key_functions": [],
    "key_blocks": [],
    "key_decisions": [],
    "runtime_evidence": [],
    "input_influence": [],
    "confidence": "high|medium|low",
    "missing_evidence": [],
    "recommended_actions": [],
    "evidence_refs": []
  }
}
```

## 每份报告都应该回答

```text
1. 当前最重要发现是什么？
2. 哪些函数最可疑？
3. 哪些分支最关键？
4. 哪些比较值被泄露了？
5. 哪些输入影响了路径？
6. 哪些地方证据不足？
7. 下一步建议调用什么工具？
8. 如果交给 AI，AI 应该优先看什么？
```

---

# 11. Evidence ID 机制

建议给每条关键证据分配稳定 ID。

示例：

```text
E001: check_flag covered in all runs
E002: memcmp compares input with "ISCC{"
E003: branch 0x401478 differs between wrong and better input
E004: input[0] likely affects CMP EAX, 0x41
```

这样 AI 和用户可以在多轮分析中引用证据：

```text
根据 E002 和 E003，下一步应该修正输入前缀后重新采集路径。
```

## 推荐 evidence 字段

```json
{
  "id": "E002",
  "kind": "runtime_compare",
  "summary": "memcmp compares input with ISCC{",
  "confidence": "high",
  "source": "frida_trace_calls",
  "refs": ["0x401495"]
}
```

---

# 12. Case Summary：案件总控台

当前 BeaconFlow 已有 case workspace 能力，后续应该把它升级成核心功能。

## 推荐命令

```bash
beaconflow summarize-case ./case_dir --format markdown
```

## 推荐报告结构

```markdown
# BeaconFlow Case Summary

## Target
- Path:
- Format:
- Arch:
- Entry:
- Status:

## Evidence Index
- Metadata:
- Coverage Runs:
- Flow Reports:
- Hook Logs:
- Notes:

## Best Findings
1. 疑似 validator:
2. 关键比较:
3. 输入相关分支:
4. success / failure 分叉:

## Current Hypothesis
当前对程序逻辑的判断。

## Missing Evidence
- 还缺哪些 trace
- 还缺哪些 hook
- 还缺哪些函数上下文

## Recommended Next Actions
1. 下一步看哪个函数
2. 下一步 hook 哪个 API
3. 下一步用 angr 求哪个分支
4. 下一步用 IDA/Ghidra 查看哪个地址
```

---

# 13. 一键工作流 Playbook

现在工具数量较多，用户和 AI 容易不知道从哪里开始。

建议新增一键工作流，而不是继续暴露大量零散命令。

---

## 13.1 triage-native

适用目标：

```text
ELF
PE
普通 x86/x64 可执行文件
```

推荐命令：

```bash
beaconflow triage-native --target ./checker --stdin "AAAA" --format markdown
```

内部流程：

```text
doctor
export metadata
collect drcov
flow
detect-roles
find-decision-points
trace-compare
case-summary
```

输出：

```text
程序概况
覆盖率摘要
可疑函数排名
关键分支
比较证据
下一步建议
```

---

## 13.2 triage-qemu

适用目标：

```text
LoongArch
MIPS
ARM
AArch64
RISC-V
IDA/Ghidra 支持较差的 ELF
```

推荐命令：

```bash
beaconflow triage-qemu   --target ./checker   --qemu-arch loongarch64   --stdin "AAAA"   --address-min 0x220000   --address-max 0x244000   --format markdown
```

输出：

```text
QEMU trace 概况
核心地址范围
可疑函数区间
路径脊柱
输入相关分支
下一步建议
```

---

## 13.3 triage-wasm

适用目标：

```text
WASM 模块
WebAssembly CTF 题
wasm checker
```

推荐命令：

```bash
beaconflow triage-wasm --target ./box.wasm --format markdown
```

内部流程：

```text
export-wasm-metadata
wasm-analyze
detect-roles
sig-match
normalize-ir for top functions
case-summary
```

输出：

```text
导出函数
可疑函数
字符串 / 常量
关键分支
伪代码摘要
下一步建议
```

---

## 13.4 triage-library

适用目标：

```text
.so
.dll
.pyd
```

推荐命令：

```bash
beaconflow triage-library --target ./libcheck.so --format markdown
beaconflow triage-library --target ./check.dll --format markdown
beaconflow triage-library --target ./module.pyd --format markdown
```

功能范围：

```text
识别文件格式
列 imports / exports
识别可疑导出函数
识别 init / entry 函数
生成 loader / harness 建议
推荐 hook 点
推荐 angr 入口
```

不建议一开始做：

```text
复杂 ABI 自动推断
完整参数类型恢复
完整 loader 框架
```

---

# 14. 模板库设计

后续应该维护常用工具模板，而不是重写工具。

建议目录：

```text
templates/
  frida/
  angr/
  gdb/
  x64dbg/
  ida/
  ghidra/
  android/
```

---

## 14.1 Frida 模板

目录：

```text
templates/frida/
  compare_strcmp_memcmp.js
  input_read_recv_scanf.js
  memory_snapshot.js
  jni_getstringutfchars.js
  android_java_string_equals.js
  android_crypto_base64_cipher.js
```

用途：

```text
hook strcmp / memcmp
hook read / recv / scanf
dump 关键 buffer
hook JNI 字符串
hook Android Java check 函数
hook Base64 / Cipher / MessageDigest
```

BeaconFlow 只需要：

```text
推荐模板
填充参数
导入输出
总结证据
```

---

## 14.2 angr 模板

目录：

```text
templates/angr/
  find_avoid_stdin.py
  find_avoid_argv.py
  call_symbol_solve.py
  dll_export_solve.py
  wasm_harness_solve.py
```

BeaconFlow 根据已有 evidence 自动建议：

```text
find 地址
avoid 地址
输入长度
stdin / argv / memory 模型
字符范围约束
```

推荐报告内容：

```text
建议使用 angr：
find = 0x401520
avoid = 0x401560
stdin length = 32

原因：
flow-diff 显示 0x401520 更接近 success 分支；
0x401560 是 failure handler。
```

---

## 14.3 GDB / x64dbg 模板

目录：

```text
templates/gdb/
  break_decision.gdb
  dump_registers.gdb
  watch_buffer.gdb
  dump_memory_range.gdb

templates/x64dbg/
  break_cmp.txt
  log_registers.txt
  trace_until_ret.txt
```

用途：

```text
根据 decision point 自动生成断点脚本
打印寄存器
dump 内存
观察 buffer 修改
```

---

## 14.4 Android 模板

目录：

```text
templates/android/
  jadx_search_check_methods.md
  frida_hook_mainactivity_check.js
  frida_hook_string_equals.js
  frida_hook_getstringutfchars.js
  frida_hook_register_natives.js
```

用途：

```text
搜索 check / verify / encrypt / decrypt 方法
hook Java 层 String.equals
hook MainActivity.check
hook JNI GetStringUTFChars
hook RegisterNatives
```

---

# 15. 适用范围扩展策略

适用范围可以扩，但只做“接入和总结”，不做完整平台。

---

## 15.1 .so / .dll / .pyd

优先级：高。

功能范围：

```text
文件识别
imports / exports 总结
可疑导出函数排名
loader / harness 模板生成
已有 coverage / hook / trace 结果总结
```

### .so

建议支持：

```text
readelf / objdump / Ghidra metadata 导入
exports / imports 总结
dlopen / dlsym harness 模板
```

### .dll

建议支持：

```text
PE exports / imports 总结
ordinal export 标注
LoadLibrary / GetProcAddress harness 模板
x64dbg / Frida hook 建议
```

### .pyd

建议支持：

```text
识别 PyInit_xxx
当作 DLL 分析
生成 Python import harness
总结 native check 函数
```

---

## 15.2 .pyc

优先级：中。

只做总结型能力：

```text
pyc magic 识别
Python 版本提示
dis 反汇编结果导入
code object / consts / names 总结
可疑函数识别
```

推荐命令：

```bash
beaconflow triage-pyc target.pyc --format markdown
```

输出：

```text
Python 版本
顶层 code object
函数名
字符串常量
可疑 compare / hash / base64 / marshal / zlib
建议 uncompyle6 / pycdc / dis
```

不建议现在做完整 Python bytecode CFG 和动态执行追踪。

---

## 15.3 Android

Android 应该分层支持。

### Android Native SO

优先级：中高。

建议支持：

```text
APK 解包
列 lib/arm64-v8a/*.so
识别 JNI 函数名
总结 Java ↔ native 可能关联
推荐 Frida JNI 模板
```

### Android Java / DEX

优先级：后期。

建议支持：

```text
JADX / JEB 输出导入
MainActivity / check / verify / encrypt 方法总结
字符串和 crypto API 总结
Frida Java hook 模板推荐
```

不建议自己写 DEX 反编译器。

---

# 16. Hook、污点分析、符号执行的处理方式

---

## 16.1 Hook

BeaconFlow 不需要开发完整 hook 框架。  
建议使用 Frida/GDB/x64dbg 等外部工具。

BeaconFlow 负责：

```text
提供模板
推荐 hook 点
导入 hook 输出
总结 runtime evidence
```

重点模板：

```text
strcmp / memcmp
read / recv / scanf
memory snapshot
JNI GetStringUTFChars
Android Java String.equals
Base64 / AES / MD5 / SHA / Cipher
```

---

## 16.2 污点分析

不建议开发完整动态污点引擎。

当前可保留轻量级 input-taint，并把它升级为：

```text
input influence summary
```

目标是总结：

```text
输入来自哪里
传到了哪个函数
影响哪个比较
哪个 offset 可能影响哪个分支
置信度是多少
```

示例输出：

```text
input[0] 可能影响 0x401010 的 CMP EAX, 0x41
建议尝试把 input[0] 改成 'A'
confidence: medium
```

---

## 16.3 符号执行

不建议自研符号执行引擎。

BeaconFlow 负责：

```text
生成 angr 任务建议
生成 angr 模板
导入 angr 运行结果
总结 solver evidence
```

推荐功能名：

```text
suggest-angr
import-angr-result
summarize-solver-result
```

---

# 17. 优先级路线图

---

## P0：马上做

```text
1. 统一 ai_digest 字段
2. 强化 summarize-case
3. 所有报告增加 evidence_id
4. 增加 missing_evidence / next_actions
5. 增加 triage-native
6. 增加 triage-qemu
7. 增加 triage-wasm
8. 整理 templates/frida
9. 整理 templates/angr
10. README 简化成“先用哪个 playbook”
```

---

## P1：很值得做

```text
1. import-frida-log
2. import-gdb-log
3. import-angr-result
4. import-jadx-summary
5. triage-library：.so / .dll / .pyd
6. suggest-hook：根据 evidence 推荐 Frida 模板
7. suggest-angr：根据 flow-diff 推荐 find / avoid
8. suggest-debug：根据 decision point 推荐断点脚本
9. function_context 总结升级
10. decision_context 总结升级
```

---

## P2：后面做

```text
1. triage-pyc
2. apk-native-summary
3. JADX / JEB 输出导入
4. Android Java hook 模板推荐
5. HTML 报告
6. IDA / Ghidra 标注脚本生成
7. report schema versioning
8. benchmark cases
9. GitHub Actions CI
10. 发布 release 包
```

---

## P3：暂时不要做

```text
1. 自研完整 Frida hook 框架
2. 自研完整动态污点引擎
3. 自研符号执行器
4. 自研 Android 反编译器
5. 自研复杂 IR 优化器
6. 大规模自动反混淆平台
```

---

# 18. README 建议重构

当前 README 可以保留完整工具说明，但开头应该先给用户三条主路线。

## 推荐开头结构

```markdown
# BeaconFlow

BeaconFlow is an AI-oriented binary analysis evidence summarizer.

## Quick Start

### Native x86/x64
beaconflow triage-native --target ./checker --stdin "AAAA"

### QEMU / non-x86
beaconflow triage-qemu --target ./checker --qemu-arch loongarch64 --stdin "AAAA"

### WASM
beaconflow triage-wasm --target ./box.wasm

## What BeaconFlow Gives AI

- covered functions
- key branches
- runtime comparisons
- path differences
- input influence hints
- recommended next actions
```

完整命令列表放到后面，避免新用户一进来就被大量工具淹没。

---

# 19. 推荐仓库目录调整

建议后续目录结构：

```text
beaconflow/
  collectors/
  importers/
  normalizers/
  correlators/
  summarizers/
  templates/
    frida/
    angr/
    gdb/
    x64dbg/
    ida/
    ghidra/
    android/
  schemas/
  reports/
  mcp/
  cli/
docs/
  ROADMAP.md
  AI_DIGEST_SCHEMA.md
  EVIDENCE_SCHEMA.md
  PLAYBOOKS.md
  TEMPLATE_USAGE.md
```

---

# 20. 最终结论

BeaconFlow 后续最重要的方向不是“继续开发更多底层工具”，而是：

```text
把已有工具和外部工具的结果总结成 AI 能使用的证据报告。
```

最应该优先做：

```text
summarize-case
ai_digest
evidence_id
triage playbooks
templates
external log import
next-action recommendation
```

不应该马上做：

```text
完整 hook
完整污点分析
完整符号执行
完整 Android 平台
```

一句话总结：

> **BeaconFlow 应该成为 AI 逆向分析的证据汇总层，而不是新的 IDA、Frida 或 angr。**

这样项目会更轻、更稳定，也更符合实际使用需求。
