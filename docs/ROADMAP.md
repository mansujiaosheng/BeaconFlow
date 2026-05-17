# BeaconFlow Roadmap

本文档是 BeaconFlow 后续开发路线。它不是用户手册，README 不应包含这里的 planned 功能。

## 总体方向

BeaconFlow 的定位：

```text
AI 逆向分析证据中枢
```

不要把 BeaconFlow 做成“大而全逆向平台”。它应该连接 IDA、Ghidra、DynamoRIO、QEMU、Frida、GDB、angr、JADX 等工具，把它们的结果转成 AI 可读的统一证据。

## 当前阶段判断

项目已经具备：

```text
- IDA / Ghidra metadata
- DynamoRIO drcov
- QEMU address log
- flow / flow-diff
- qemu-explore
- decision-points
- detect-roles
- deflatten
- input-taint
- trace-compare / feedback-explore
- WASM metadata
- MCP server
- quickstart-pe / quickstart-qemu / quickstart-flatten
- schema / case-check / html report 基础
```

当前最重要的问题不是继续堆功能，而是：

```text
- 入口太多
- 文档太长
- stable / beta / planned 混在一起
- report schema 需要统一
- CLI / MCP / docs 需要自动对齐
```

## P0：稳定化与收敛

目标：让新用户和 AI Agent 不迷路，让已有功能跑得稳。

### P0.1 README 收敛

任务：

```text
- README 只保留 3 个主入口：
  - quickstart-pe
  - quickstart-qemu
  - quickstart-flatten
- 专家命令只放表格
- planned 功能全部移到 ROADMAP
- beta/experimental 全部移到 EXPERIMENTAL
```

验收：

```text
用户从 README 复制命令可以跑通。
README 不出现尚未实现命令。
```

### P0.2 统一 report schema

任务：

```text
- 所有核心报告加入 schema_version
- 所有报告加入 tool
- 所有报告加入 ai_digest
- 所有报告加入 data_quality
- evidence_refs 必须能指向 evidence
```

验收：

```powershell
python -m beaconflow.cli schema --validate-all reports/
```

能检查并指出错误。

### P0.3 CLI / MCP / docs 自动对齐

任务：

```text
- 建立 CLI/MCP 映射表
- 测试 CLI parser 中的 stable 命令是否在 docs 中出现
- 测试 MCP tools 是否有文档
- 测试 docs 中 stable 命令是否真实存在
```

验收：

```powershell
python -m unittest discover -s tests -p "test_doc_sync*.py"
```

### P0.4 case-check 强化

任务：

```text
case-check 检查：
- 文件是否存在
- metadata/report 是否过期
- schema 是否有效
- QEMU address range 是否过宽
- unmapped events 是否过高
- 是否缺少 ai_digest
- 是否缺少 recommended_actions
```

验收：

```powershell
python -m beaconflow.cli case-check --root D:\case
```

能输出 Markdown/JSON 质量报告。

### P0.5 doctor 强化

任务：

```text
doctor 输出：
- Python 版本
- 是否安装 MCP extra
- 是否能找到 DynamoRIO
- 是否能找到 WSL
- 是否能找到 QEMU
- 是否能找到 IDA/Ghidra/pyghidra
- 当前推荐入口
```

验收：

```powershell
python -m beaconflow.cli doctor --format markdown
```

输出能直接告诉用户下一步跑哪个命令。

## P1：AI 可用性增强

目标：让 AI 看到报告后能直接决定下一步。

### P1.1 recommended_next_command

每个报告都加：

```json
{
  "recommended_actions": [
    {
      "action": "inspect_block",
      "command": "python -m beaconflow.cli inspect-block --metadata metadata.json --address 0x401280 --format markdown",
      "reason": "Right-only block in flow-diff.",
      "confidence": "high"
    }
  ]
}
```

### P1.2 flow-diff 地址范围压缩

任务：

```text
- 把 right-only / left-only blocks 压缩成连续 range
- 输出 top 5 ranges
- 每个 range 给出函数名、块数、边数、推荐动作
```

示例：

```text
0x22ef28-0x22ef68
function: check_flag
reason: only reached by case002
next: inspect-function check_flag
```

### P1.3 inspect-function 增强

任务：

```text
inspect-function 自动附带：
- decision points
- strings
- constants
- calls
- xrefs
- covered blocks
- diff-only blocks
```

### P1.4 qemu-explore 路径雷达

任务：

```text
- 自动展示 best input
- 输出 new_ranges
- 输出 output_fingerprint
- 输出 suspected_success_prefix
- 输出 next_commands
```

### P1.5 markdown-brief 统一

任务：

```text
所有核心命令支持：
--format markdown-brief
```

只输出：

```text
Summary
AI Digest
Data Quality
Top Evidence
Recommended Actions
```

## P2：外部工具桥接

目标：不自研大框架，只做模板生成、日志导入、证据归一化。

### P2.1 suggest-hook

输入：

```text
metadata + decision-points + roles + flow-diff
```

输出：

```text
推荐 hook 点：
- strcmp/memcmp/strncmp
- read/recv/scanf/fgets
- JNI GetStringUTFChars
- Java String.equals
```

### P2.2 generate-template

生成：

```text
- frida-js
- gdb-script
- x64dbg-script
- angr-stub
```

示例：

```powershell
python -m beaconflow.cli generate-template `
  --kind frida-js `
  --metadata metadata.json `
  --function check_flag `
  --output hook_check_flag.js
```

### P2.3 import-frida-log

任务：

```text
导入 Frida 日志，提取：
- 调用函数
- 参数
- 返回值
- buffer dump
- compare result
```

输出统一 report schema。

### P2.4 suggest-angr

任务：

```text
从 flow-diff / decision-points 生成 angr find/avoid 建议。
```

BeaconFlow 不负责保证 angr 求解成功，只给模板和依据。

## P3：目标格式扩展

优先级：

### P3.1 DLL / SO / PYD

理由：

```text
和现有 PE/ELF native 工作流最接近。
```

任务：

```text
- 支持 module 选择
- 支持导出函数入口
- 支持指定 host process
- 支持 loader/harness 模板
```

### P3.2 WASM 增强

任务：

```text
- table/indirect call 摘要
- memory load/store 访问摘要
- wasm control-flow rendering
- wasm function role detector 优化
```

### P3.3 PYC

任务：

```text
- 导入 dis 输出
- code object 层级结构
- constants / names / varnames
- jump target / block 切分
```

注意：不要做完整 Python decompiler，只给 AI 可读结构。

### P3.4 Android native

任务：

```text
- JNI 函数识别
- libxxx.so metadata
- Frida JNI 模板
- JADX 摘要导入
```

### P3.5 Android DEX / Java

原则：

```text
不要自己写 DEX 反编译器。
导入 JADX 输出、smali、method list、字符串、调用图即可。
```

## P4：工程质量

### P4.1 CI 扩展

矩阵：

```text
Ubuntu + Python 3.10 / 3.12
Windows + Python 3.10 / 3.12
```

检查：

```text
- unit tests
- CLI help
- MCP smoke
- schema validate fixtures
- docs sync
```

### P4.2 fixture 分层

```text
tests/fixtures/
  native_pe/
  native_elf/
  qemu_logs/
  wasm/
  reports/
  mcp/
```

### P4.3 文档生成

可选：

```text
从 CLI parser / MCP TOOLS 自动生成 docs/COMMANDS.md
```

避免手写文档过期。

## 不建议做的事

```text
- 不要自己写完整 hook 框架
- 不要自己写完整符号执行引擎
- 不要自己写完整反编译器
- 不要把所有命令都塞进 README
- 不要把 beta/planned 写成 stable
- 不要让报告只有自然语言，没有 evidence
```

## 近期建议版本规划

### v0.2

```text
- README 收敛
- docs 分层
- report schema v1
- case-check 强化
- CLI/MCP/docs 对齐测试
```

### v0.3

```text
- qemu-explore 路径雷达
- flow-diff top ranges
- inspect-function context 增强
- markdown-brief 全覆盖
```

### v0.4

```text
- suggest-hook
- generate-template
- import-frida-log
- import-gdb-log
```

### v0.5

```text
- DLL/SO/PYD harness
- WASM 增强
- Android native/JADX 导入
```
