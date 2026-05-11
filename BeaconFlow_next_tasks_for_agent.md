# BeaconFlow 下一阶段改进任务单（交给 AI Agent 用）

仓库：<https://github.com/mansujiaosheng/BeaconFlow>

本文档基于当前仓库 README 与目录结构整理，目标是避免重复实现已经完成的功能，把开发重点放在“AI 逆向真正还缺的能力”上。

---

## 0. 当前已有能力，先不要重复实现

当前 BeaconFlow 已经有以下能力，后续开发不要再重复做同类基础功能：

- CLI 入口：`beaconflow.cli`
- MCP Server：`beaconflow.mcp.server`
- IDA headless metadata 导出
- Ghidra / pyghidra metadata 导出
- DynamoRIO drcov 覆盖率采集
- QEMU user-mode 地址日志采集
- `record-flow` 一步采集并生成执行流
- `flow` / `flow-diff` 执行流分析与差异分析
- `diff` 函数级覆盖率差异分析
- `qemu-explore` 多输入探索
- `qemu-explore mutate` 模板变异、seed、positions、alphabet、byte-flip、length 等
- `deflatten` / `deflatten-merge` 反平坦化路径合并
- `recover-state` 状态转移表恢复
- `branch-rank` 输入相关分支排序
- `inspect-block` / `inspect-function` block context 查看
- `find-decision-points` / `inspect-decision-point` 决策点识别
- `detect-roles` / `inspect-role` 函数角色检测
- `role_rules.yaml` 可配置角色规则
- Markdown / JSON 报告输出

当前主要短板不是“路径分析不够”，而是：

> BeaconFlow 能告诉 AI 哪条路径不同、哪个分支值得看，但还不能直接告诉 AI 运行时比较了什么值、哪个输入字节影响了哪个判断、下一步应该如何自动修改输入。

---

## 1. 总体开发原则

请遵守这些约束：

1. 不做 GUI / Web UI。BeaconFlow 是给 AI Agent 和命令行使用的工具。
2. 不把 CTF 题目里的函数名、地址、flag 格式写死。所有目标函数、地址范围、输入格式都必须可配置。
3. 每个新功能同时提供：
   - CLI 子命令
   - Python 内部函数
   - MCP tool，若适合 AI 客户端调用
   - JSON 输出
   - Markdown 输出，若结果需要人或 AI 阅读
   - 单元测试或最小 smoke test
4. 对非 x86 架构不要假设 IDA 可用；优先兼容 QEMU / Ghidra 工作流。
5. 对运行时插桩类能力，先做 MVP，不要一开始追求完整动态污点或完整符号执行。

---

# P0：优先实现

## P0-1. 新增 `doctor` 环境诊断命令

### 目标

快速诊断 BeaconFlow 当前环境是否可用，尤其是 Windows + WSL + QEMU + DynamoRIO + Ghidra + IDA 组合环境。

### 新增命令

```bash
python -m beaconflow.cli doctor
```

可选参数：

```bash
python -m beaconflow.cli doctor --target ./checker --qemu-arch loongarch64
python -m beaconflow.cli doctor --format json
python -m beaconflow.cli doctor --format markdown
```

### 检查内容

至少检查：

- Python 版本是否 >= 3.10
- `beaconflow` 是否能正常 import
- CLI entrypoint 是否可用
- 当前系统类型：Windows / Linux / WSL
- DynamoRIO Windows x64 是否存在
- DynamoRIO Windows x86 是否存在
- DynamoRIO Linux 版是否存在
- `drrun` 是否能执行
- WSL 是否可用
- WSL 内 `qemu-<arch>` 是否存在
- 本机 `qemu-<arch>` 是否存在
- `idat64` / `ida64` 是否在 PATH 中
- `pyghidra` 是否可 import
- Ghidra 环境变量或常见路径是否存在
- MCP server 是否能 import / 启动基本初始化

### 输出示例

```text
# BeaconFlow Doctor

## Core
- [OK] Python 3.12.0
- [OK] beaconflow import
- [OK] CLI entrypoint

## DynamoRIO
- [OK] Windows x64 drrun: third_party/dynamorio/bin64/drrun.exe
- [WARN] Windows x86 drrun not found
- [OK] Linux drrun: third_party/dynamorio_linux/bin64/drrun

## QEMU / WSL
- [OK] WSL available
- [OK] qemu-loongarch64 found in WSL
- [WARN] qemu-aarch64 not found locally

## Ghidra / IDA
- [WARN] idat64 not found in PATH
- [OK] pyghidra importable

## Result
Environment is usable for: qemu-loongarch64, ghidra metadata, drcov x64
```

### 建议文件结构

```text
beaconflow/env/
  __init__.py
  doctor.py
```

或：

```text
beaconflow/diagnostics/
  __init__.py
  doctor.py
```

### CLI 接入位置

在 `beaconflow/cli.py` 中增加 `doctor` subparser。

### MCP 接入

新增 MCP tool：

```text
doctor
```

输入：

```json
{
  "target_path": "optional",
  "qemu_arch": "optional",
  "format": "json"
}
```

### 验收标准

- `python -m beaconflow.cli doctor --format json` 能输出结构化 JSON。
- 不依赖真实 IDA/Ghidra 安装也能运行，只是输出 WARN。
- Windows、Linux、WSL 下都不会异常崩溃。
- 缺少工具时给出明确修复建议。

---

## P0-2. 新增 `trace-calls`：运行时库函数参数提取

### 目标

优先解决 AI 逆向最需要的信息：当程序调用 `strcmp` / `memcmp` / `strncmp` / `strlen` 等函数时，直接抓取运行时参数、返回值和附近调用点。

这比完整动态污点更容易实现，但收益很大。

### 新增命令

```bash
python -m beaconflow.cli trace-calls \
  --target ./checker \
  --stdin "AAAA" \
  --auto-newline \
  --hook strcmp,strncmp,memcmp,strlen \
  --format json
```

可选参数：

```bash
--target ./checker
--args ...
--stdin "..."
--auto-newline
--run-cwd ./case
--timeout 120
--arch x64
--backend frida|dynamorio|auto
--hook strcmp,memcmp,strncmp,strlen
--max-read 128
--output trace_calls.json
--format json|markdown
```

### 第一阶段实现建议

优先用 Frida 实现 MVP，因为：

- 写起来快
- 适合 hook libc / msvcrt 导出函数
- 能直接读函数参数指针内容
- 能拿返回值

先支持：

- Windows x64 PE：`msvcrt.dll` / `ucrtbase.dll` / 目标模块导入
- Linux ELF：`libc.so.6`

后续再考虑 DynamoRIO client。

### 输出 JSON 结构

```json
{
  "target": "./checker",
  "backend": "frida",
  "input": {
    "stdin_preview": "AAAA",
    "args": []
  },
  "events": [
    {
      "index": 0,
      "function": "memcmp",
      "call_site": "0x401234",
      "return_address": "0x401239",
      "args": [
        {
          "name": "arg0",
          "pointer": "0x7fffffffe000",
          "bytes_hex": "41414141",
          "ascii": "AAAA"
        },
        {
          "name": "arg1",
          "pointer": "0x404080",
          "bytes_hex": "49534343",
          "ascii": "ISCC"
        },
        {
          "name": "size",
          "value": 4
        }
      ],
      "return_value": -1,
      "verdict_hint": "not_equal"
    }
  ],
  "summary": {
    "total_events": 1,
    "interesting_events": 1
  }
}
```

### Markdown 输出示例

```markdown
# BeaconFlow Trace Calls

## memcmp @ 0x401234

- return address: `0x401239`
- size: `4`
- arg0: `AAAA`
- arg1: `ISCC`
- result: not equal

AI hint: this call compares runtime input-like bytes with a constant-like buffer.
```

### 需要注意

- 不要默认打印超大内存，`--max-read` 默认 128。
- 不要假设字符串一定以 `\0` 结尾；`memcmp` 必须按 size 读取。
- 如果参数指针不可读，记录错误而不是崩溃。
- 如果无法得到 call_site，至少保留 return_address。
- 对 stripped binary 也要能工作，只要导入函数可 hook。

### 建议文件结构

```text
beaconflow/runtime/
  __init__.py
  trace_calls.py
  frida_trace_calls.py
```

### MCP 接入

新增 MCP tool：

```text
trace_calls
```

### 验收标准

- 能对一个调用 `strcmp(input, "secret")` 的测试程序输出两边字符串。
- 能对一个调用 `memcmp(input, expected, n)` 的测试程序输出 n 字节内容。
- JSON / Markdown 都可用。
- 缺少 Frida 时提示安装：`pip install frida frida-tools`。

---

## P0-3. 新增 `trace-compare`：运行时比较指令值提取

### 目标

对 `cmp` / `test` / 条件跳转附近的运行时寄存器或立即数进行提取，让 AI 知道失败分支到底比较了什么。

当前 `find-decision-points` 能告诉 AI 哪里有判断，但不能告诉 AI 运行时值。`trace-compare` 就是补这一层。

### 新增命令

```bash
python -m beaconflow.cli trace-compare \
  --target ./checker \
  --metadata metadata.json \
  --stdin "AAAA" \
  --focus-function check_flag \
  --format markdown
```

可选参数：

```bash
--target ./checker
--metadata metadata.json
--stdin "..."
--auto-newline
--args ...
--run-cwd ./case
--backend frida|dynamorio|auto
--address 0x401234
--focus-function check_flag
--address-min 0x401000
--address-max 0x402000
--max-events 1000
--format json|markdown
--output trace_compare.json
```

### MVP 实现建议

第一阶段不要做全架构完整模拟。先做 x86/x64：

1. 读取 metadata 中的 block context。
2. 找 `cmp` / `test` / `jcc` 决策点。
3. 使用 Frida 在这些地址插桩。
4. 命中时读取当前寄存器上下文。
5. 尝试解析简单操作数：
   - register vs immediate
   - register vs register
   - register vs memory
   - memory vs immediate
6. 记录是否紧跟 jcc，以及下一步分支地址。

### 输出 JSON 结构

```json
{
  "target": "./checker",
  "backend": "frida",
  "events": [
    {
      "index": 0,
      "address": "0x401236",
      "function": "check_flag",
      "instruction": "cmp al, 0x41",
      "operands": [
        {
          "text": "al",
          "kind": "register",
          "value": 66,
          "hex": "0x42",
          "ascii": "B"
        },
        {
          "text": "0x41",
          "kind": "immediate",
          "value": 65,
          "hex": "0x41",
          "ascii": "A"
        }
      ],
      "near_branch": "jne 0x401260",
      "hint": "left differs from immediate by +1"
    }
  ]
}
```

### Markdown 输出示例

```markdown
# BeaconFlow Trace Compare

## check_flag:0x401236

Instruction: `cmp al, 0x41`

Runtime values:

- `al` = `0x42` (`B`)
- expected immediate = `0x41` (`A`)

Nearby branch: `jne 0x401260`

AI hint: the current byte is one greater than the immediate constant.
```

### 需要注意

- 不要硬编码 `check_flag`，必须通过 `--focus-function` 自定义。
- 不能解析的复杂操作数也要保留原始寄存器快照。
- 缺少 metadata 时允许 `--address` 手动指定地址。
- 第一版可以只支持 x86/x64；对 LoongArch/MIPS/ARM 输出 “not implemented yet”，不要假装支持。

### 验收标准

- 对简单 `if (input[0] == 'A')` 测试程序能输出 `cmp` 两边运行时值。
- 能和 `find-decision-points` 结果联动。
- JSON 输出稳定，便于 AI Agent 读取。

---

# P1：第二阶段实现

## P1-1. 新增 `case workspace`：统一题目工作区

### 目标

当前 BeaconFlow 命令很多，但打题时文件容易散：metadata、runs、reports、candidates、notes 都在不同位置。新增 case workspace，方便 AI Agent 连续分析。

### 新增命令

```bash
python -m beaconflow.cli init-case --target ./checker --arch loongarch64 --case-dir .beaconflow
python -m beaconflow.cli case-status --case-dir .beaconflow
python -m beaconflow.cli run-case --case-dir .beaconflow --stdin "AAAA"
python -m beaconflow.cli summarize-case --case-dir .beaconflow --format markdown
```

### 目录结构

```text
.beaconflow/
  manifest.json
  target/
  metadata/
  runs/
  reports/
  candidates/
  notes/
```

### manifest 示例

```json
{
  "schema_version": 1,
  "target": "./checker",
  "arch": "loongarch64",
  "backend": "qemu",
  "qemu_arch": "loongarch64",
  "metadata_path": "metadata/metadata.json",
  "runs": [],
  "reports": [],
  "created_at": "2026-05-11T00:00:00Z",
  "updated_at": "2026-05-11T00:00:00Z"
}
```

### 设计要求

- 不强制用户使用 workspace，现有命令保持兼容。
- workspace 只是把已有命令串起来。
- AI Agent 可以通过 manifest 找到最近的 metadata、trace、报告。

### MCP 接入

新增 MCP tools：

```text
init_case
case_status
run_case
summarize_case
```

### 验收标准

- 初始化后能创建标准目录和 manifest。
- `run-case` 能调用现有 `collect` 或 `collect-qemu`。
- `case-status` 能列出最近 runs / reports。

---

## P1-2. 新增 `auto-explore-loop`：反馈式多轮输入探索

### 目标

当前 `qemu-explore mutate` 可以生成一批候选并排序，但还不是闭环。新增多轮探索：保留更优输入，继续变异，直到命中 success 或达到轮数。

### 新增命令

```bash
python -m beaconflow.cli auto-explore-loop \
  --target ./checker \
  --qemu-arch loongarch64 \
  --mutate-template "ISCC{%32x}" \
  --rounds 20 \
  --batch-size 64 \
  --keep-top 8 \
  --success-regex "Correct" \
  --failure-regex "Wrong" \
  --format markdown \
  --output auto_explore.md
```

### 核心逻辑

每轮：

1. 从当前 corpus 选择 top seeds。
2. 根据策略生成 batch 输入。
3. 调用现有 `qemu-explore` 运行。
4. 按以下指标排序：
   - success verdict
   - new_blocks_global
   - new_blocks_vs_baseline
   - unique_blocks
   - output_fingerprint 变化
5. 保存 top seeds 到 `candidates/`。
6. 继续下一轮。

### 输出字段

```json
{
  "rounds": [
    {
      "round": 1,
      "best_input": "ISCC{...}",
      "best_score": 123,
      "new_blocks_global": 20,
      "verdict": "failure"
    }
  ],
  "best_candidate": "ISCC{...}",
  "success_found": false
}
```

### 注意

- 这不是完整 fuzzing，不要试图替代 AFL++。
- 重点是“AI 可读、可解释、能接着分析”。
- 必须支持自定义模板，不要写死 flag 格式。

### 验收标准

- 能在 mock 程序上多轮保留路径更优输入。
- 能输出每轮 best candidate。
- 超时、崩溃、重复路径都要记录。

---

## P1-3. 新增 `input-impact`：轻量输入影响分析

### 目标

不做完整 taint，先做黑盒差分输入影响分析：对指定输入的每个位置做扰动，观察哪些分支、块、边发生变化，从而推断“哪个输入字节影响哪个分支”。

### 新增命令

```bash
python -m beaconflow.cli input-impact \
  --target ./checker \
  --qemu-arch loongarch64 \
  --seed "ISCC{00000000000000000000000000000000}" \
  --positions "5:37" \
  --alphabet "0123456789abcdef" \
  --address-min 0x220000 \
  --address-max 0x244000 \
  --format markdown
```

### 实现思路

1. 先跑 seed，得到 baseline flow。
2. 对每个位置做若干字符扰动。
3. 跑 `collect-qemu` 或 `qemu-explore`。
4. 比较 flow / flow-diff。
5. 记录每个输入位置影响的块、边、函数、输出 fingerprint。

### 输出示例

```markdown
# Input Impact Report

## Position 7

Mutations tested: 16

Changed edges:

- `0x22ef68 -> 0x22efa0` affected by chars: `0,1,2,3`
- `0x22ef68 -> 0x22efb0` affected by chars: `a,b,c`

AI hint: position 7 likely participates in a branch condition near `0x22ef68`.
```

### 和 `branch-rank` 的区别

- `branch-rank`：已有 trace 下，哪些分支值得看。
- `input-impact`：主动扰动输入，估计哪个输入位置影响哪个分支。

### 验收标准

- 能输出 position -> changed blocks/edges 映射。
- 能限制位置范围和字符集。
- 能复用现有 qemu-explore / flow-diff 能力。

---

# P2：第三阶段增强

## P2-1. 新增 `decompile-export`：伪代码摘要导出

### 目标

把 Ghidra / IDA 的伪代码转成 AI 更容易读取的 JSON / Markdown，不替代反编译器，只做摘要导出。

### 新增命令

```bash
python -m beaconflow.cli decompile-export \
  --target ./checker \
  --backend ghidra \
  --function check_flag \
  --output decompile_check.json
```

### 输出字段

```json
{
  "function": "check_flag",
  "address": "0x401000",
  "backend": "ghidra",
  "pseudocode": "...",
  "summary": {
    "loops": [],
    "conditions": [],
    "calls": [],
    "constants": []
  }
}
```

### 注意

- 先支持 Ghidra pyghidra。
- IDA Hex-Rays 可选，不要作为硬依赖。
- 没有反编译器时输出明确错误。

---

## P2-2. 新增 `crypto-patterns`：加密 / 编码 / VM 特征细分

### 目标

当前 `detect-roles` 有 `crypto_like`，但粒度较粗。新增细分规则，帮助 AI 快速判断函数可能是 AES、DES、TEA、RC4、Base64、CRC、VM dispatcher 等。

### 新增命令

```bash
python -m beaconflow.cli detect-patterns --metadata metadata.json --format markdown
```

### 建议 pattern 类型

```text
aes_like
des_like
tea_like
xxtea_like
rc4_like
md5_like
sha_like
base64_like
crc_like
xor_loop
substitution_table
vm_dispatcher
bytecode_interpreter
packer_stub
```

### 识别依据

- 常量表
- S-box
- magic number
- 大量位运算
- 特定循环形态
- 高出度 dispatcher
- 间接跳转
- fetch-decode-execute 模式

### 配置文件

```text
beaconflow/analysis/pattern_rules.yaml
```

### 验收标准

- 规则可配置。
- 输出证据，不只输出结论。
- 不要误把所有“大量常量函数”都叫 AES，要给 confidence。

---

## P2-3. MCP Resources：暴露当前 case / report / metadata 资源

### 目标

目前 MCP 主要是 tools。可以增加 resources，让 AI 客户端直接读取当前 case 状态、最新报告、metadata 索引。

### 建议资源 URI

```text
beaconflow://cases/current/manifest
beaconflow://runs/latest/flow
beaconflow://reports/latest
beaconflow://metadata/functions
beaconflow://metadata/decision-points
beaconflow://metadata/roles
```

### 验收标准

- MCP host 能列出 resources。
- 能读取最新 manifest / report。
- 不影响现有 MCP tools。

---

# 任务优先级建议

建议按这个顺序做：

1. `doctor`
2. `trace-calls`
3. `trace-compare`
4. `case workspace`
5. `auto-explore-loop`
6. `input-impact`
7. `decompile-export`
8. `crypto-patterns`
9. MCP Resources

如果只能先做一个，请做：

```text
trace-calls
```

因为它实现难度低、收益高，能直接让 AI 看到 `strcmp/memcmp` 两边实际比较内容。

---

# 最小 PR 拆分建议

## PR 1：doctor

包含：

- `beaconflow/diagnostics/doctor.py`
- CLI `doctor`
- JSON / Markdown formatter
- tests
- README 增加使用示例

## PR 2：trace-calls MVP

包含：

- `beaconflow/runtime/trace_calls.py`
- `beaconflow/runtime/frida_trace_calls.py`
- CLI `trace-calls`
- MCP tool `trace_calls`
- tests：strcmp / memcmp mock 程序
- README 增加使用示例

## PR 3：trace-compare MVP

包含：

- `beaconflow/runtime/trace_compare.py`
- x86/x64 简单 cmp/test 操作数解析
- CLI `trace-compare`
- 和 decision-points 联动
- tests：单字符比较 mock 程序

## PR 4：case workspace

包含：

- `beaconflow/case/manifest.py`
- `init-case`
- `case-status`
- `run-case`
- `summarize-case`
- MCP tools

## PR 5：auto-explore-loop + input-impact

包含：

- 复用现有 qemu-explore
- 多轮 corpus 保存
- position impact 报告

---

# README 更新要求

每个功能完成后，请更新 README：

1. 在功能列表中增加新命令。
2. 在 MCP Tools 表中增加对应 tool。
3. 增加一个最小示例。
4. 在 FAQ 中说明限制，例如：
   - `trace-compare` 第一版只支持 x86/x64。
   - `trace-calls` 需要 Frida。
   - `input-impact` 是黑盒差分，不是完整 taint。

---

# 不建议现在做的事情

下面这些暂时不要优先做：

- 大型 Web UI
- 完整符号执行框架
- 完整动态污点引擎
- 自研反编译器
- 替代 AFL++ 的完整 fuzzing
- 针对某一道 CTF 的硬编码 solver

当前 BeaconFlow 最需要的是把“路径差异”升级成“运行时值与输入影响”。

