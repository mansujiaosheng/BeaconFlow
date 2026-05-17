# BeaconFlow 测试结果记录

本文档记录 BeaconFlow 各功能在真实 CTF 题目上的测试结果。

更新日期：2026-05-17

## 1. Triage 工作流测试

### 1.1 triage-native：ISCC2026 re3

- **目标**：`D:\CTF\ISCC2026\re3\target.exe`
- **架构**：x64 PE
- **命令**：
  ```powershell
  python -m beaconflow.cli triage-native --target target.exe --output-dir output --stdin "AAAA"
  ```
- **结果**：
  - ✅ Ghidra metadata 导出成功（102 函数）
  - ✅ drcov 覆盖率采集成功
  - ✅ 覆盖率分析：45/102 函数被覆盖
  - ✅ 执行流分析完成
  - ✅ 决策点检测：6 个 checker_call 类型
  - ✅ 角色检测：check_flag → validator (score: 1.2)
- **下一步建议**：suggest-hook → generate-template → trace-calls

### 1.2 triage-qemu：ACTF2026 flagchecker

- **目标**：`D:\CTF\ACTF2026\flagchecker\flagchecker`
- **架构**：LoongArch ELF（静态链接）
- **命令**：
  ```powershell
  python -m beaconflow.cli triage-qemu --target flagchecker --qemu-arch loongarch64 --output-dir output --stdin "ACTF{00000000000000000000000000000000}" --address-min 0x220000 --address-max 0x244000
  ```
- **结果**：
  - ✅ Ghidra metadata 导出成功（2870 函数）
  - ✅ QEMU trace 采集成功，stdout: "Wrong!"
  - ✅ 执行流分析完成
  - 核心函数范围：0x223560-0x2239a0
- **下一步建议**：qemu-explore 探索更多输入

### 1.3 triage-wasm：ISCC2026 re3-lei box.wasm

- **目标**：`D:\CTF\ISCC2026\re3-lei\box.wasm`
- **架构**：WebAssembly
- **命令**：
  ```powershell
  python -m beaconflow.cli triage-wasm --target box.wasm --output-dir output
  ```
- **结果**：
  - ✅ WASM 分析：112 函数，5 导出，7 导入
  - ✅ WASM metadata 导出成功
  - ✅ sig_match 发现 XOR 解密循环
  - ✅ 角色检测：5 dispatcher，83 transformer
  - f84 有 83 个后继（VM dispatch table）

## 2. 模板库测试

### 2.1 list-templates

- **命令**：`python -m beaconflow.cli list-templates`
- **结果**：✅ 列出 14 个模板（6 Frida + 2 angr + 3 GDB + 3 x64dbg）

### 2.2 generate-template

- **命令**：
  ```powershell
  python -m beaconflow.cli generate-template --template-name compare_strcmp_memcmp --output hook.js
  ```
- **结果**：✅ 生成 hook.js，包含 strcmp/memcmp/strncmp hook 代码

### 2.3 suggest-hook

- **目标**：ISCC2026 re3
- **命令**：
  ```powershell
  python -m beaconflow.cli suggest-hook --decision-points dp.json --roles roles.json
  ```
- **结果**：✅ 3 个推荐
  1. compare_strcmp_memcmp (confidence: high) - checker_call 决策点
  2. input_read_recv_scanf (confidence: medium) - input_handler 角色
  3. memory_snapshot (confidence: low) - crypto_like 角色

### 2.4 suggest-angr

- **命令**：
  ```powershell
  python -m beaconflow.cli suggest-angr --flow-diff diff.json --roles roles.json
  ```
- **结果**：✅ 推荐 find_avoid_stdin 模板，自动填充 find/avoid 地址

### 2.5 suggest-debug

- **目标**：ISCC2026 re3
- **命令**：
  ```powershell
  python -m beaconflow.cli suggest-debug --decision-points dp.json --debugger gdb --output bp.gdb
  ```
- **结果**：✅ 81 个断点，按优先级排序

## 3. 外部工具导入测试

### 3.1 import-frida-log

- **测试数据**：3 个 JSON 行格式事件
- **结果**：✅ 3 事件解析成功，0 错误
  - compare 事件：1
  - input 事件：1
  - memory 事件：1

### 3.2 import-gdb-log

- **测试数据**：2 断点命中 + 4 寄存器 dump
- **结果**：✅ 6 事件解析成功
  - breakpoint 事件：2
  - register 事件：4

### 3.3 import-angr-result

- **测试数据**：JSON 格式 + 文本格式
- **结果**：✅ 两种格式均解析成功

### 3.4 import-jadx-summary

- **测试数据**：JADX 反编译摘要
- **结果**：✅ 解析成功，提取类名和方法签名

## 4. 运行时追踪测试

### 4.1 trace-calls：ISCC2026 re3-lei

- **目标**：`angr_harness.exe`
- **命令**：
  ```powershell
  python -m beaconflow.cli trace-calls --target angr_harness.exe --stdin "AAAA" --hook memcmp --format markdown
  ```
- **关键发现**：✅ 直接暴露 flag 前缀 `ISCC{`
  ```
  memcmp @ 0x2031
  buf2: `ISCC{` (hex: `495343437b`)
  n: 5
  ```

### 4.2 trace-compare-rt

- **目标**：simple_pe.exe
- **命令**：
  ```powershell
  python -m beaconflow.cli trace-compare-rt --target simple_pe.exe --metadata metadata.json --stdin "test"
  ```
- **结果**：✅ 成功提取决策点寄存器值

## 5. 其他功能测试

### 5.1 export-annotations

- **命令**：
  ```powershell
  python -m beaconflow.cli export-annotations --output-dir annotations/ --decision-points dp.json --roles roles.json --format both
  ```
- **结果**：✅ 生成 IDA Python + Ghidra Java 标注脚本

### 5.2 fuzz_corpus

- **命令**：
  ```powershell
  python -m beaconflow.cli corpus-init --corpus-dir corpus/
  python -m beaconflow.cli generate-harness --target target.exe --output harness.c --engine aflpp
  ```
- **结果**：✅ corpus 初始化成功，harness 模板生成成功

### 5.3 dynamorio_custom

- **命令**：
  ```powershell
  python -m beaconflow.cli dr-generate-client --type compare --output dr_compare.cpp
  ```
- **结果**：✅ DynamoRIO 客户端模板生成成功

### 5.4 schemas

- **命令**：
  ```powershell
  python -m beaconflow.cli schema --list
  python -m beaconflow.cli schema --name coverage_report
  ```
- **结果**：✅ 25 种 schema 可用，验证功能正常

## 6. 单元测试

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

- **结果**：17/17 通过

## 7. MCP 工具矩阵测试

- **测试环境**：Windows + Python 3.13
- **测试目标**：
  - `simple_pe.exe`：Ghidra metadata、drcov、flow/diff、deflatten、branch-rank、decision points、Frida runtime trace、input-impact
  - `flagchecker`（LoongArch）：QEMU collect/explore、address-log flow/diff、case workspace
  - `box.wasm`：WASM metadata、WASM triage report、IR、signature、role、pseudo-code
- **结果**：45 个 MCP tools 全部验证通过

## 8. triage-pyc 测试

### 8.1 自建 .pyc 测试

- **目标**：`test_check.pyc`（Python 3.13 编译）
- **源码内容**：包含 `check_flag`、`encrypt_data`、`main` 函数
- **命令**：
  ```powershell
  python -m beaconflow.cli triage-pyc --target test_check.pyc --output-dir output --disassemble
  ```
- **结果**：
  - ✅ Python 版本识别：Python 3.13
  - ✅ magic number：0x0df3
  - ✅ 函数检测：4 个函数（module、check_flag、encrypt_data、main）
  - ✅ 可疑函数：4 个（全部标记）
    - `<module>`：调用可疑函数 check_flag、encrypt_data
    - `check_flag`：常量含 flag/correct/wrong，函数名含 check
    - `encrypt_data`：函数名含 encrypt，调用 b64encode/encode
    - `main`：常量含 flag，调用 check_flag
  - ✅ dis 反汇编：成功输出

## 9. HTML 报告测试

### 9.1 Markdown → HTML

- **输入**：README.md
- **命令**：
  ```powershell
  python -m beaconflow.cli to-html --input README.md --output report.html --title "BeaconFlow README"
  ```
- **结果**：✅ 成功生成带暗色主题样式的 HTML

### 9.2 JSON → HTML

- **输入**：包含 ai_digest 的 JSON 报告
- **命令**：
  ```powershell
  python -m beaconflow.cli to-html --input report.json --input-format json --output report.html
  ```
- **结果**：✅ 成功生成带摘要卡片和 AI Digest 展示的 HTML

### 9.3 --format html

- **命令**：
  ```powershell
  python -m beaconflow.cli analyze --metadata metadata.json --coverage sample.drcov --format html --output report.html
  ```
- **结果**：✅ 所有分析命令支持 html/html-json 格式

## 10. Benchmark Cases 测试

### 10.1 benchmark --list

- **命令**：`python -m beaconflow.cli benchmark --list`
- **结果**：✅ 列出 5 个 benchmark 用例

### 10.2 pyc_check benchmark

- **目标**：test_check.pyc
- **命令**：
  ```powershell
  python -m beaconflow.cli benchmark --run pyc_check --target test_check.pyc --output-dir results
  ```
- **结果**：
  - ✅ passed: 2, failed: 0
  - python_version_detected: true
  - min_suspicious: 4 (≥1)
  - elapsed: 0.01s
