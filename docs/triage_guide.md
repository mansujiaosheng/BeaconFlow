# BeaconFlow Triage 工作流详细指南

本文档详细介绍 BeaconFlow 的三种一键 Triage 工作流，包括使用场景、参数说明、输出解读和实际案例。

## 1. triage-native：PE/ELF 本地分析

### 适用目标

- Windows PE 可执行文件（.exe）
- Linux ELF 可执行文件
- x86/x64 架构的本地目标

### 命令格式

```powershell
python -m beaconflow.cli triage-native --target <目标文件> --output-dir <输出目录> [选项]
```

### 参数说明

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `--target` | 是 | 目标 PE/ELF 二进制文件路径 |
| `--output-dir` | 是 | 所有报告的输出目录 |
| `--stdin` | 否 | 目标程序的 stdin 输入 |
| `--target-args` | 否 | 传递给目标程序的参数列表 |
| `--arch` | 否 | 目标架构，x86 或 x64（默认 x64） |
| `--timeout` | 否 | 每步超时秒数（默认 120） |

### 自动执行流程

```
1. 自动地址范围检测 → detect_executable_address_range()
2. Ghidra metadata 导出 → export_ghidra_metadata()
3. drcov 覆盖率采集 → collect_drcov()
4. 覆盖率分析 → analyze_coverage()
5. 执行流分析 → analyze_flow()
6. 决策点检测 → find_decision_points()
7. 角色检测 → detect_roles()
```

### 输出文件

| 文件 | 说明 |
| --- | --- |
| `metadata.json` | Ghidra 导出的函数/基本块/CFG 信息 |
| `drcov.*.log` | DynamoRIO 采集的覆盖率日志 |
| `coverage.json` / `coverage.md` | 覆盖率分析报告 |
| `flow.json` / `flow.md` | 执行流分析报告 |
| `decision_points.json` / `decision_points.md` | 决策点检测报告 |
| `roles.json` / `roles.md` | 函数角色检测报告 |
| `triage_native.md` | 汇总索引报告 |

### 实际案例：ISCC2026 re3

```powershell
python -m beaconflow.cli triage-native --target D:\CTF\ISCC2026\re3\target.exe --output-dir D:\case\re3_triage --stdin "AAAA"
```

关键输出：

- 覆盖率：102 个函数中覆盖 45 个
- 决策点：发现 6 个 checker_call 类型（strcmp/memcmp + jcc）
- 角色：check_flag 被识别为 validator（score: 1.2）
- 下一步建议：用 suggest-hook 生成 Frida hook 模板

## 2. triage-qemu：QEMU 跨架构分析

### 适用目标

- LoongArch ELF
- MIPS ELF
- ARM/AArch64 ELF
- RISC-V ELF
- IDA 当前环境不支持的目标

### 命令格式

```powershell
python -m beaconflow.cli triage-qemu --target <目标文件> --qemu-arch <架构> --output-dir <输出目录> [选项]
```

### 参数说明

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `--target` | 是 | 目标 ELF 二进制文件路径 |
| `--qemu-arch` | 是 | QEMU 用户态架构名（loongarch64/mips/arm/aarch64） |
| `--output-dir` | 是 | 所有报告的输出目录 |
| `--stdin` | 否 | 目标程序的 stdin 输入 |
| `--address-min` | 否 | 分析地址范围下限 |
| `--address-max` | 否 | 分析地址范围上限 |
| `--timeout` | 否 | 每步超时秒数（默认 120） |

### 自动执行流程

```
1. 自动地址范围检测 → detect_executable_address_range()
2. Ghidra metadata 导出 → export_ghidra_metadata()
3. QEMU trace 采集 → collect_qemu_trace()
4. 执行流分析 → analyze_flow()
```

### 实际案例：ACTF2026 flagchecker

```powershell
python -m beaconflow.cli triage-qemu --target D:\CTF\ACTF2026\flagchecker\flagchecker --qemu-arch loongarch64 --output-dir D:\case\actf_triage --stdin "ACTF{00000000000000000000000000000000}" --address-min 0x220000 --address-max 0x244000
```

关键输出：

- Ghidra 识别 2870 个函数（静态链接）
- QEMU trace 采集成功，stdout 显示 "Wrong!"
- 执行流分析显示核心函数在 0x223560-0x2239a0 范围
- 下一步建议：用 qemu-explore 探索更多输入

## 3. triage-wasm：WebAssembly 分析

### 适用目标

- .wasm 文件
- WebAssembly CTF 题
- wasm checker

### 命令格式

```powershell
python -m beaconflow.cli triage-wasm --target <wasm文件> --output-dir <输出目录>
```

### 参数说明

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `--target` | 是 | 目标 .wasm 文件路径 |
| `--output-dir` | 是 | 所有报告的输出目录 |

### 自动执行流程

```
1. WASM triage 报告 → analyze_wasm()
2. WASM metadata 导出 → wasm_to_metadata()
3. 特征签名匹配 → sig_match()
```

### 实际案例：ISCC2026 re3-lei box.wasm

```powershell
python -m beaconflow.cli triage-wasm --target D:\CTF\ISCC2026\re3-lei\box.wasm --output-dir D:\case\wasm_triage
```

关键输出：

- 112 个函数，5 个导出，7 个导入
- sig_match 发现 XOR 解密循环
- 角色检测：5 个 dispatcher，83 个 transformer
- f84 有 83 个后继（VM dispatch table）
- 下一步建议：用 normalize-ir 分析 XOR 解密函数

## 4. 错误处理

所有 triage 命令在部分步骤失败时会返回 `status: partial`，并在 `errors` 列表中记录失败原因。已成功的步骤结果仍会保存。

常见错误：

| 错误 | 原因 | 解决方案 |
| --- | --- | --- |
| Ghidra metadata 导出失败 | Ghidra 未安装或路径不对 | 设置 GHIDRA_INSTALL_DIR 环境变量 |
| drcov 采集超时 | 目标程序等待输入或死循环 | 提供 --stdin 参数或增大 --timeout |
| QEMU 不可用 | WSL 未安装或 QEMU 不在 PATH | 安装 WSL 和 QEMU |
| WASM 解析失败 | 文件格式不是标准 WASM | 确认文件完整性 |

## 5. 与其他命令配合

Triage 完成后，可以继续使用以下命令深入分析：

```powershell
# 查看可疑函数详情
python -m beaconflow.cli inspect-function --metadata output/metadata.json --name check_flag

# 生成 Frida hook 模板
python -m beaconflow.cli suggest-hook --decision-points output/decision_points.json --roles output/roles.json

# 生成 angr 求解模板
python -m beaconflow.cli suggest-angr --flow-diff output/flow.json --roles output/roles.json

# 生成 GDB 断点脚本
python -m beaconflow.cli suggest-debug --decision-points output/decision_points.json --debugger gdb

# 导入 Frida hook 结果
python -m beaconflow.cli import-frida-log --log frida_output.log

# 生成 IDA/Ghidra 标注脚本
python -m beaconflow.cli export-annotations --output-dir annotations/ --decision-points output/decision_points.json --roles output/roles.json
```
