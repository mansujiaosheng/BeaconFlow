# BeaconFlow 运行时追踪详细指南

本文档详细介绍 BeaconFlow 的运行时追踪功能，包括 trace-calls 和 trace-compare-rt。

## 1. trace-calls：运行时库函数参数提取

### 功能说明

使用 Frida hook 运行时库函数（strcmp/memcmp/strncmp/strlen 等），直接提取参数值和返回值。

### 命令格式

```powershell
python -m beaconflow.cli trace-calls --target <目标文件> [选项]
```

### 参数说明

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `--target` | 是 | 目标可执行文件路径 |
| `--stdin` | 否 | 发送到目标 stdin 的输入 |
| `--hook` | 否 | 要 hook 的函数列表，逗号分隔（默认 strcmp,memcmp,strncmp,strlen） |
| `--timeout` | 否 | 超时秒数（默认 30） |
| `--max-read` | 否 | 最大读取字节数（默认 128） |
| `--format` | 否 | 输出格式 json/markdown（默认 markdown） |

### 支持的 hook 函数

| 函数 | 平台 | 说明 |
| --- | --- | --- |
| `strcmp` | Windows/Linux | 字符串比较 |
| `memcmp` | Windows/Linux | 内存比较 |
| `strncmp` | Windows/Linux | 有限字符串比较 |
| `strlen` | Windows/Linux | 字符串长度 |

Windows 上会自动从 `ucrtbase.dll` 或 `msvcrt.dll` 查找函数地址；Linux 上从 `libc.so.6` 查找。

### CRT 噪声过滤

默认启用 `filter_user_only=true`，只保留主模块（用户代码）调用的库函数，自动过滤 C 运行库初始化时的内部调用。

### 输出示例

```markdown
## Key Comparisons

### strcmp @ 0x1495

- return address: `0x7ff7b5591495`
- result: **not_equal** (return=-1)

- s1: `AAAA` (hex: `41414141`)
- s2: `ISCC{test_flag}` (hex: `495343437b746573745f666c61677d`)

> **AI hint**: this call compares runtime input-like bytes with a constant-like buffer. The values differ.
```

### AI Hint 说明

| Hint | 含义 |
| --- | --- |
| `input-like bytes with a constant-like buffer` | 一侧是用户输入，一侧是常量 |
| `both sides look input-like` | 两侧都像输入数据 |
| `both sides look constant-like` | 两侧都像常量（可能是内部比较） |
| `No strcmp/memcmp comparisons captured` | 未捕获到比较，程序可能使用自定义比较逻辑 |

### 实际案例：ISCC2026 re3-lei

```powershell
python -m beaconflow.cli trace-calls --target angr_harness.exe --stdin "AAAA" --hook memcmp --format markdown
```

关键发现：trace-calls 直接暴露了 flag 前缀 `ISCC{`！

```markdown
### memcmp @ 0x2031

- result: **not_equal** (return=1)
- buf1: `..z..` (hex: `9d0d7abcaf`)
- buf2: `ISCC{` (hex: `495343437b`)
- n: `5`
```

### 依赖

- Frida：`pip install frida frida-tools`
- 仅支持 Windows x64 和 Linux x64

## 2. trace-compare-rt：运行时比较指令值提取

### 功能说明

使用 Frida 在 cmp/test/jcc 决策点插桩，提取运行时寄存器值。与 trace-calls 不同，它 hook 的是汇编级别的比较指令，而非库函数。

### 命令格式

```powershell
python -m beaconflow.cli trace-compare-rt --target <目标文件> [选项]
```

### 参数说明

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `--target` | 是 | 目标可执行文件路径 |
| `--metadata` | 否 | metadata JSON，用于自动找决策点 |
| `--address` | 否 | 手动指定决策点地址，逗号分隔 |
| `--focus-function` | 否 | 聚焦特定函数 |
| `--stdin` | 否 | 发送到目标 stdin 的输入 |
| `--timeout` | 否 | 超时秒数（默认 30） |
| `--format` | 否 | 输出格式 json/markdown（默认 markdown） |

### 使用方式

**方式 1：自动从 metadata 找决策点**

```powershell
python -m beaconflow.cli trace-compare-rt --target checker.exe --metadata metadata.json --stdin "AAAA"
```

**方式 2：手动指定地址**

```powershell
python -m beaconflow.cli trace-compare-rt --target checker.exe --address 0x401234,0x401250 --stdin "AAAA"
```

**方式 3：聚焦特定函数**

```powershell
python -m beaconflow.cli trace-compare-rt --target checker.exe --metadata metadata.json --focus-function check_flag --stdin "AAAA"
```

### 限制

- 仅支持 x86/x64 架构
- 需要 Frida
- 决策点数量过多时可能影响目标程序性能

## 3. 两种运行时追踪的对比

| 特性 | trace-calls | trace-compare-rt |
| --- | --- | --- |
| Hook 对象 | 库函数（strcmp/memcmp 等） | 汇编指令（cmp/test/jcc） |
| 获取内容 | 函数参数和返回值 | 寄存器值 |
| 适用场景 | 程序使用标准库比较 | 程序使用自定义比较逻辑 |
| 架构支持 | Windows/Linux x64 | 仅 x86/x64 |
| 依赖 | Frida | Frida |
| 性能影响 | 低（少量 hook 点） | 中高（每个决策点都插桩） |

### 选择建议

1. 先用 `trace-calls`，大多数 CTF 题使用标准库比较
2. 如果 `trace-calls` 没有捕获到比较，说明程序使用自定义比较逻辑，改用 `trace-compare-rt`
3. 两者可以结合使用：`trace-calls` 获取宏观比较结果，`trace-compare-rt` 获取微观寄存器值
