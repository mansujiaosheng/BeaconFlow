# BeaconFlow 当前进展与优化更新路线文档

> 适用对象：BeaconFlow 后续开发者 / AI Coding Agent / 项目维护者  
> 文档目标：总结当前插件实现进展、主要优点、存在问题、优化优先级和后续开发路线。  
> 当前定位：BeaconFlow 不应继续盲目扩展为“大而全逆向平台”，而应稳定为一个面向 AI Agent 的逆向分析证据汇总与决策辅助插件。

---

## 1. 项目当前总体评价

BeaconFlow 当前已经不只是一个简单的 coverage / flow 分析工具，而是逐渐演化成一个面向 AI 逆向分析流程的“证据汇总层”和“分析决策辅助层”。

目前项目已经具备较多能力，包括：

- DynamoRIO drcov 覆盖率采集；
- QEMU address log 采集与跨架构 flow 分析；
- Ghidra / IDA metadata 导出与导入；
- flow / flow-diff / branch-rank / deflatten / recover-state；
- decision point 检测；
- block context / function context；
- role detector；
- sig-match 签名匹配；
- ai_digest / evidence_id / confidence / next_actions；
- Frida runtime trace；
- trace-calls / trace-values / trace-compare-rt；
- import-frida-log / import-gdb-log / import-angr-result / import-jadx-summary；
- suggest-hook / suggest-angr / suggest-debug；
- triage-native / triage-qemu / triage-wasm / triage-pyc；
- WASM parser；
- PYC triage；
- workspace case 管理；
- HTML 报告导出；
- schema 验证；
- benchmark 框架；
- Frida / angr / GDB / x64dbg 模板。

整体来看，BeaconFlow 的功能面已经比较完整。当前最重要的问题不是继续增加大功能，而是要先把已有能力收敛成稳定、清晰、适合 AI 调用的工具链。

---

## 2. 当前完成度评估

| 维度 | 当前评价 | 说明 |
|---|---|---|
| 功能完成度 | 较高 | 已覆盖 native、QEMU、WASM、PYC、runtime trace、外部日志导入等方向 |
| AI Agent 适配度 | 中高 | 已有 ai_digest、evidence_id、confidence、next_actions 等 AI 友好字段 |
| CLI 可用度 | 中高 | CLI 命令丰富，但入口过多，初学者容易迷路 |
| MCP 可用度 | 中等 | MCP 已有不少 tools，但落后于 CLI，部分关键能力没有暴露 |
| 工程稳定性 | 中等偏低 | 部分 triage / benchmark / import 路径存在不一致或潜在崩溃点 |
| 文档完整度 | 高 | README 很长，内容多 |
| 文档易用度 | 中等偏低 | README 过长，不适合作为项目主入口 |
| 发布成熟度 | 偏低 | 打包内容、release 分层、版本策略还需要整理 |

简要判断：

```text
功能已经比较多，但入口、MCP、测试、schema、文档和发布流程还没有完全统一。
```

下一阶段目标应该是：

```text
把已有能力变成稳定、好用、AI 能自动决策调用的工具链。
```

---

## 3. 当前项目主要优点

### 3.1 AI 友好方向正确

BeaconFlow 最有价值的地方不是简单记录“程序跑到了哪些基本块”，而是开始整理出 AI 能直接使用的分析证据。

目前已经具备以下 AI 友好字段或结构：

- `ai_digest`
- `top_findings`
- `recommended_actions`
- `report_confidence`
- `data_quality`
- `evidence_id`
- `missing_evidence`
- `next_actions`

这些字段使 AI 不只是看到原始 trace，而是可以进一步判断：

- 哪些地址值得优先看；
- 哪些结论可信；
- 哪些只是启发式推断；
- 下一步应该 hook、angr、debug，还是继续采集覆盖率；
- 当前缺少哪些证据。

这是 BeaconFlow 和普通 coverage 工具的区别，也是项目最应该继续强化的核心优势。

---

### 3.2 适用范围已经明显扩大

目前 BeaconFlow 已经不局限于 PE / ELF 的基本覆盖率分析，而是逐渐扩展到多种分析对象。

| 目标类型 | 当前状态 | 后续建议 |
|---|---|---|
| PE `.exe` | 支持较完整 | 继续保持 |
| ELF | 支持较完整 | 重点配合 QEMU / GDB / angr |
| `.dll` | 可作为 native 目标识别 | 需要更多真实样本回归测试 |
| `.so` | 可作为 native 目标识别 | 需要增强 Android / Linux 场景支持 |
| `.pyd` | 可作为 native 目标识别 | 可补 Python 扩展模块 triage 说明 |
| LoongArch / MIPS / ARM | 可通过 QEMU address log 支持 | 继续完善 qemu-explore / qemu-triage |
| WASM | 已有 parser / triage / sig-match | 需要统一 schema 和 benchmark |
| `.pyc` | 已有 triage-pyc | 可增加反编译工具建议和 suspicious code object 解释 |
| Android APK | 目前只是间接支持 | 建议新增 APK summary 薄适配 |

后续不建议一下子做完整 APK 逆向平台，而是优先做轻量 summary 和 hook 推荐。

---

### 3.3 “不重复造轮子”的架构方向正确

BeaconFlow 当前没有试图自己实现完整的：

- Frida 框架；
- angr 符号执行器；
- GDB 调试器；
- JADX / JEB 反编译器；
- IDA / Ghidra 替代品。

而是做：

```text
模板生成 + 外部工具结果导入 + 证据结构化 + AI 总结 + 下一步建议
```

这是正确方向。

后续应继续坚持：

```text
BeaconFlow 负责连接工具、整理证据、输出 AI 可读报告，而不是重新实现所有逆向能力。
```

---

## 4. 当前必须修复的问题

### 4.1 P0：`triage-native` 存在导入路径错误

当前 `triage-native` 是很重要的一键入口，但存在明显导入错误。

问题表现类似：

```text
ModuleNotFoundError: No module named 'beaconflow.analysis.coverage'
```

问题位置可能在：

```text
beaconflow/triage.py
```

错误导入类似：

```python
from beaconflow.analysis.coverage import analyze_coverage
from beaconflow.analysis.roles import detect_roles
```

但实际项目中更可能存在的是：

```text
beaconflow/analysis/coverage_mapper.py
beaconflow/analysis/role_detector.py
```

建议修改为更稳定的导入方式：

```python
from beaconflow.analysis.coverage_mapper import analyze_coverage
from beaconflow.analysis.flow import analyze_flow
from beaconflow.analysis.decision_points import find_decision_points
from beaconflow.analysis.role_detector import detect_roles
```

或者在 `beaconflow/analysis/__init__.py` 中统一导出后，再使用：

```python
from beaconflow.analysis import analyze_coverage, analyze_flow, find_decision_points, detect_roles
```

验收标准：

```text
beaconflow triage-native <target> --out <case_dir>
```

在缺少部分外部依赖时，也不应直接崩溃，而应输出 partial report，并在 `missing_evidence` 或 `warnings` 中说明缺失项。

---

### 4.2 P0：CLI 与 MCP 能力不一致

目前 CLI 命令数量明显多于 MCP tools。对于一个面向 AI Agent 的插件来说，这是比较严重的问题。

CLI 有功能但 MCP 没有暴露，会导致：

```text
人类命令行能用，AI Agent 不能自动调用。
```

建议优先补齐以下 MCP tools：

- `suggest-hook`
- `suggest-angr`
- `suggest-debug`
- `generate-template`
- `list-templates`
- `import-frida-log`
- `import-gdb-log`
- `import-angr-result`
- `import-jadx-summary`
- `triage-native`
- `triage-qemu`
- `triage-wasm`
- `triage-pyc`
- `benchmark`
- `schema`
- `to-html`
- `export-annotations`
- `trace-compare-rt`

建议建立统一规则：

```text
每新增一个 CLI 命令：
1. 必须有对应 Python API；
2. 必须判断是否需要暴露给 MCP；
3. 必须有输入输出 schema；
4. 必须有最小测试；
5. 必须在文档中更新。
```

---

### 4.3 P0：triage 系列入口需要最小测试覆盖

当前建议给以下入口全部增加最小测试：

- `triage-native`
- `triage-qemu`
- `triage-wasm`
- `triage-pyc`

测试目标不是验证所有分析结论都完全正确，而是至少保证：

```text
1. 命令能正常运行；
2. 输出目录能创建；
3. 核心 JSON 报告存在；
4. 报告包含 ai_digest / confidence / warnings / artifacts 等基础字段；
5. 缺少外部工具时不会直接崩溃。
```

建议测试 fixture：

```text
tests/fixtures/native/minimal_elf
tests/fixtures/qemu/minimal_trace.log
tests/fixtures/wasm/minimal.wasm
tests/fixtures/pyc/minimal.pyc
```

---

### 4.4 P1：benchmark 字段与实际报告结构需要对齐

当前 benchmark 框架方向是对的，但需要注意以下问题：

- benchmark 不传 `--target` 时容易 skipped，用户可能误以为可直接运行；
- 部分检查字段可能和实际报告结构不一致；
- native benchmark 依赖 `triage-native`，而当前 `triage-native` 有导入 bug；
- WASM benchmark 检查字段需要和 `analyze_wasm` 的真实输出结构对齐；
- benchmark 不应期待某些 triage 阶段没有生成的文件。

建议拆分为两类：

```text
内置 benchmark：
  使用 tests/fixtures 中的最小样本，不需要用户提供 target。

外部 benchmark：
  用户提供真实 CTF / 逆向样本路径。
```

验收标准：

```text
beaconflow benchmark --builtin
```

应该能在干净环境中完成基础测试，并输出清晰结果。

---

## 5. 入口和文档优化建议

### 5.1 当前 CLI 命令过多，需要分层

目前 CLI 命令数量已经较多，对人类用户来说容易造成选择困难。

建议将入口分成三层。

#### 第一层：新人入口

只保留最常用的一键 triage：

```text
beaconflow triage-native
beaconflow triage-qemu
beaconflow triage-wasm
beaconflow triage-pyc
```

#### 第二层：AI Agent 入口

用于 AI 自动读取、总结、决策：

```text
beaconflow summarize-case
beaconflow ai-summary
beaconflow suggest-hook
beaconflow suggest-angr
beaconflow suggest-debug
```

#### 第三层：专家入口

用于细粒度分析和调试：

```text
beaconflow collect
beaconflow flow
beaconflow flow-diff
beaconflow deflatten
beaconflow branch-rank
beaconflow trace-values
beaconflow trace-calls
beaconflow import-*
beaconflow schema
beaconflow benchmark
```

---

### 5.2 README 应该缩短

当前 README 内容较多，适合作为完整手册，但不适合作为项目首页。

建议 README 只保留：

```text
1. 项目定位；
2. 30 秒 quickstart；
3. 我该用哪个命令；
4. 典型工作流；
5. MCP 使用方式；
6. 文档链接。
```

将详细内容拆到 `docs/` 目录：

```text
docs/
  human_quickstart.md
  agent_playbook.md
  cli_cheatsheet.md
  triage_guide.md
  runtime_tracing_guide.md
  importer_guide.md
  template_guide.md
  mcp_guide.md
  report_schema.md
  benchmark_guide.md
```

其中最重要的是：

```text
docs/agent_playbook.md
```

该文档应专门告诉 AI：

```text
看到什么输入，用什么工具；
拿到什么报告，下一步怎么判断；
哪些字段可信；
哪些字段只是启发式；
缺少证据时应该怎么补。
```

---

## 6. 后续功能优化路线

### 6.1 P0：稳定性优先

这一阶段不建议继续新增大功能，而是先修已有能力。

任务清单：

```text
1. 修复 triage-native import bug；
2. 修复 triage-wasm / benchmark 字段不一致问题；
3. 给 triage-native / triage-qemu / triage-wasm / triage-pyc 加最小测试；
4. 确保缺少外部工具时输出 partial report，而不是直接崩溃；
5. schema 验证覆盖主要 report；
6. README 标注哪些功能是 heuristic。
```

验收标准：

```text
pytest
beaconflow triage-native <sample> --out case_native
beaconflow triage-qemu <sample_log> --out case_qemu
beaconflow triage-wasm <sample.wasm> --out case_wasm
beaconflow triage-pyc <sample.pyc> --out case_pyc
```

以上命令至少应全部完成基础输出。

---

### 6.2 P1：补齐 MCP 能力

BeaconFlow 的目标是给 AI Agent 用，因此 MCP 是核心入口之一。

建议优先暴露以下能力：

```text
triage-native
triage-qemu
triage-wasm
triage-pyc
suggest-hook
suggest-angr
suggest-debug
list-templates
generate-template
import-frida-log
import-gdb-log
import-angr-result
import-jadx-summary
schema-validate
to-html
summarize-case
```

每个 MCP tool 应提供：

```text
1. 清晰 description；
2. 参数 schema；
3. 输出 artifact path；
4. warnings；
5. next_actions；
6. 出错时的结构化 error。
```

建议 MCP tool 输出统一格式：

```json
{
  "ok": true,
  "tool": "triage-native",
  "artifacts": [],
  "summary": {},
  "warnings": [],
  "next_actions": []
}
```

---

### 6.3 P1：新增 APK / Android 薄适配

当前 Android 方向还不够完整，但不建议直接做大型 APK 分析平台。

建议新增轻量命令：

```text
beaconflow apk-summary <target.apk> --out <case_dir>
```

或：

```text
beaconflow triage-apk <target.apk> --out <case_dir>
```

输出内容建议包括：

```json
{
  "package": "...",
  "main_activity": "...",
  "permissions": [],
  "native_libs": [],
  "abis": [],
  "interesting_classes": [],
  "jni_methods": [],
  "crypto_apis": [],
  "base64_apis": [],
  "string_compare_apis": [],
  "system_load_library": [],
  "recommended_hooks": []
}
```

可调用或解析的外部工具包括：

- `apktool`
- `jadx`
- `aapt`
- `readelf`
- `nm`
- `strings`
- Frida 模板

目标不是替代 JADX，而是告诉 AI：

```text
这个 APK 应该先看 Java 层还是 native 层？
哪个类最值得看？
哪个 so 最值得 hook？
是否存在 JNI / RegisterNatives / Base64 / AES / String.equals 等关键点？
```

---

### 6.4 P1：增强 Android hook 推荐

当前已有一些 Frida 模板，但建议让 `suggest-hook` 支持 Android 场景。

推荐规则示例：

| 发现内容 | 推荐模板 |
|---|---|
| `Base64.decode` | Android Base64 hook |
| `Cipher.getInstance` | Java Crypto hook |
| `String.equals` | String compare hook |
| `System.loadLibrary` | native library hook |
| `native` 方法 | JNI method hook |
| `RegisterNatives` | RegisterNatives hook |
| `GetStringUTFChars` | JNI string hook |
| suspicious `.so` | Frida native Interceptor 模板 |

输出建议：

```json
{
  "recommended_hooks": [
    {
      "name": "hook_string_equals",
      "reason": "String.equals appears near validation logic",
      "template": "android_string_equals",
      "confidence": 0.78
    }
  ]
}
```

---

### 6.5 P2：增强 schema 和 case 检查

建议新增：

```text
beaconflow schema --validate-all <case_dir>
```

用于检查一个 case 目录下所有报告是否符合 schema。

还可以新增：

```text
beaconflow case-check <case_dir>
```

检查内容：

```text
1. metadata 是否存在；
2. run 信息是否存在；
3. report 是否存在；
4. report 是否包含 ai_digest；
5. report 是否包含 evidence_id；
6. report 是否包含 confidence；
7. artifact path 是否失效；
8. 是否存在过大的 AI 不友好文件；
9. 是否存在 schema 不匹配文件；
10. 是否缺少 next_actions。
```

---

### 6.6 P2：发布包整理

当前开发包中可能包含较多开发缓存或大型第三方文件。正式发布时建议分层打包：

```text
beaconflow-src.zip
  只包含源码、docs、tests、scripts

beaconflow-win-bundle.zip
  源码 + Windows DynamoRIO

beaconflow-linux-bundle.zip
  源码 + Linux DynamoRIO

beaconflow-full-dev.7z
  开发者完整包
```

建议补充：

```text
CHANGELOG.md
MANIFEST.in
pyproject.toml metadata
release checklist
version policy
```

---

## 7. 推荐开发顺序

### 阶段 1：稳定性修复

优先级：最高

```text
1. 修复 triage-native import bug；
2. 修复 triage / benchmark 字段不一致；
3. 给四个 triage 入口加最小测试；
4. 缺依赖时输出 partial report；
5. schema 验证覆盖核心报告。
```

完成标志：

```text
pytest 全部通过；
四个 triage 命令都能在 fixture 上跑通；
benchmark --builtin 能跑通。
```

---

### 阶段 2：MCP 补齐

优先级：高

```text
1. MCP 暴露 suggest-hook / suggest-angr / suggest-debug；
2. MCP 暴露 list-templates / generate-template；
3. MCP 暴露 import-frida-log / import-gdb-log / import-angr-result / import-jadx-summary；
4. MCP 暴露 triage-native / triage-qemu / triage-wasm / triage-pyc；
5. MCP tools/list 中给每个 tool 增加清晰说明。
```

完成标志：

```text
AI Agent 不需要通过 shell 命令，也能完成主要 BeaconFlow 工作流。
```

---

### 阶段 3：入口收敛和文档重构

优先级：高

```text
1. README 缩短；
2. 新增 docs/human_quickstart.md；
3. 新增 docs/agent_playbook.md；
4. 新增 docs/cli_cheatsheet.md；
5. 文档按使用场景组织，而不是简单堆命令列表。
```

完成标志：

```text
新用户可以通过 README 在 5 分钟内知道自己该用哪个命令。
AI Agent 可以通过 agent_playbook 决定下一步调用哪个工具。
```

---

### 阶段 4：Android / APK 薄适配

优先级：中高

```text
1. 新增 apk-summary 或 triage-apk；
2. 增强 import-jadx-summary；
3. suggest-hook 支持 Android Java / JNI 场景；
4. generate-template 增加 RegisterNatives / Java method / native so hook 模板；
5. 输出 recommended_hooks。
```

完成标志：

```text
面对一个 APK，BeaconFlow 可以告诉 AI：
应该先看哪个 Activity、哪个类、哪个 native lib、哪些 Java API、哪些 JNI 方法。
```

---

### 阶段 5：release 工程化

优先级：中

```text
1. 清理打包内容；
2. 分层 release 包；
3. 增加 CHANGELOG；
4. 明确版本号策略；
5. 增加 release checklist。
```

完成标志：

```text
用户可以下载清晰的源码包或平台 bundle，而不是拿到一个混有缓存、构建产物和大型第三方文件的开发压缩包。
```

---

## 8. 建议的新增文档结构

```text
README.md
  项目定位、快速开始、选择指南、文档入口

docs/human_quickstart.md
  给人类用户看的快速上手

docs/agent_playbook.md
  给 AI Agent 看的工具选择和分析决策指南

docs/cli_cheatsheet.md
  CLI 命令速查，按场景分类

docs/mcp_guide.md
  MCP tools、参数、输出说明

docs/triage_guide.md
  triage-native / qemu / wasm / pyc / apk 使用指南

docs/runtime_tracing_guide.md
  Frida / GDB / x64dbg / trace 导入使用说明

docs/importer_guide.md
  import-frida-log / import-gdb-log / import-angr-result / import-jadx-summary

docs/template_guide.md
  generate-template / list-templates / 自定义模板

docs/report_schema.md
  报告字段解释、confidence、evidence_id、warnings、next_actions

docs/benchmark_guide.md
  builtin benchmark 与外部样本 benchmark
```

---

## 9. 给 AI Coding Agent 的直接任务清单

以下任务可以直接交给另一个 AI Coding Agent 执行。

### Task 1：修复 triage-native 导入错误

目标文件：

```text
beaconflow/triage.py
beaconflow/analysis/__init__.py
```

要求：

```text
1. 修复错误 import；
2. 保证 triage_native 可以正常调用；
3. 缺少外部依赖时不崩溃；
4. 输出 warnings；
5. 添加最小测试。
```

---

### Task 2：为 triage 系列增加测试

目标：

```text
tests/test_triage_native.py
tests/test_triage_qemu.py
tests/test_triage_wasm.py
tests/test_triage_pyc.py
```

要求：

```text
1. 使用最小 fixture；
2. 验证命令或核心函数不崩溃；
3. 验证输出 JSON 存在；
4. 验证 ai_digest / warnings / confidence / artifacts 字段存在；
5. 测试缺依赖 partial report 行为。
```

---

### Task 3：补齐 MCP tools

目标文件：

```text
beaconflow/mcp/server.py
```

需要增加或检查：

```text
triage-native
triage-qemu
triage-wasm
triage-pyc
suggest-hook
suggest-angr
suggest-debug
list-templates
generate-template
import-frida-log
import-gdb-log
import-angr-result
import-jadx-summary
schema-validate
to-html
summarize-case
```

要求：

```text
1. 每个 tool 有 description；
2. 每个 tool 有参数 schema；
3. 输出结构统一；
4. 出错时返回结构化 error；
5. 添加最小 MCP tool 测试。
```

---

### Task 4：重构 README 和 docs

目标：

```text
README.md
docs/human_quickstart.md
docs/agent_playbook.md
docs/cli_cheatsheet.md
docs/mcp_guide.md
```

要求：

```text
1. README 缩短到适合作为首页；
2. 增加“我该用哪个命令”选择表；
3. 给 AI Agent 单独写 agent_playbook；
4. CLI 文档按场景分类；
5. 标明 heuristic 与 hard evidence 的区别。
```

---

### Task 5：新增 APK summary 薄适配

新增命令：

```text
beaconflow apk-summary <target.apk> --out <case_dir>
```

或：

```text
beaconflow triage-apk <target.apk> --out <case_dir>
```

输出字段：

```json
{
  "package": "...",
  "main_activity": "...",
  "permissions": [],
  "native_libs": [],
  "abis": [],
  "interesting_classes": [],
  "jni_methods": [],
  "crypto_apis": [],
  "base64_apis": [],
  "string_compare_apis": [],
  "recommended_hooks": [],
  "warnings": [],
  "next_actions": []
}
```

要求：

```text
1. 不要求完整 APK 逆向；
2. 优先解析 manifest、native libs、JADX summary；
3. 输出 hook 建议；
4. 缺少 apktool / jadx / aapt 时给 warning，不直接失败。
```

---

## 10. 最终建议

BeaconFlow 当前最需要的不是继续堆功能，而是做以下事情：

```text
1. 修稳定性；
2. 补 MCP；
3. 收敛入口；
4. 重构文档；
5. 用 schema 和 benchmark 保证输出质量；
6. 轻量补 Android / APK 场景。
```

推荐当前版本的开发主线：

```text
从“功能很多的个人插件”
升级为
“AI 逆向分析工作流工具”。
```

优先级总结：

```text
P0：triage-native bug、triage 测试、benchmark 修复、缺依赖 partial report
P1：MCP 补齐、README 缩短、agent_playbook、新人入口收敛
P2：APK summary、Android hook 推荐、schema validate-all、case-check
P3：release 分层、CHANGELOG、版本策略、打包清理
```

只要先完成 P0 和 P1，BeaconFlow 的可用性和 AI Agent 适配度就会有明显提升。
