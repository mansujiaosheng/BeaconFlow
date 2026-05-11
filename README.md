# BeaconFlow

BeaconFlow 是一个面向 AI Agent 的 headless 覆盖率与控制流分析工具。

仓库地址：[https://github.com/mansujiaosheng/BeaconFlow](https://github.com/mansujiaosheng/BeaconFlow)

它的目标不是替代 IDA，而是让 AI 在不打开 IDA 图形界面的情况下，读取 IDA 或 Ghidra 的函数、基本块、CFG 信息，并结合覆盖率数据快速回答：

- 哪些函数被运行过
- 哪些基本块被覆盖
- 程序这一次实际走过的基本块流程
- 实际出现过的基本块转移边
- 哪些函数没有跑到
- 两次运行触发了哪些不同路径
- 在不知道正确输入的情况下，哪些输入触发了更多新路径
- 指定函数/地址范围的执行流分析
- 后续哪些函数值得重点分析或 fuzz

当前版本包含 CLI、MCP Server、IDA headless 导出脚本、Ghidra pyghidra 导出脚本和一个可选 skill。

## 项目结构

```text
beaconflow/
  analysis/      覆盖率映射、覆盖率 diff、控制流分析逻辑
  coverage/      覆盖率文件解析，支持 drcov 和 QEMU 地址日志
  ida/           IDA 导出的 metadata 读取逻辑
  metadata/      从地址日志聚类生成 fallback metadata
  mcp/           MCP stdio server
  reports/       Markdown 报告生成
  cli.py         命令行入口
  models.py      核心数据结构

ida_scripts/
  export_ida_metadata.py   用 idat64 -A 运行的 IDA metadata 导出脚本

ghidra_scripts/
  export_ghidra_metadata.py   用 pyghidra 运行的 Ghidra metadata 导出脚本（支持 PE/ELF/LoongArch 等所有 Ghidra 支持的架构）
  ExportBeaconFlowMetadata.java   Ghidra headless Java 脚本（需要 OSGi，推荐优先使用 pyghidra 方案）
  ExportBeaconFlowMetadata.py    Ghidra headless Python 脚本（需要 PyGhidra，推荐优先使用 pyghidra 方案）

skills/
  beaconflow/SKILL.md      可选的 AI skill 说明
```

## 安装（AI Agent 请直接照做）

### 第一步：确认环境

```powershell
python --version
# 需要 Python 3.10+
```

### 第二步：克隆仓库并安装

```powershell
git clone https://github.com/mansujiaosheng/BeaconFlow.git
cd BeaconFlow
python -m pip install -e .
```

验证安装成功：

```powershell
python -m beaconflow.cli --help
```

如果看到子命令列表（analyze、collect、flow、flow-diff、collect-qemu、qemu-explore 等），说明安装成功。

### 第三步（可选）：安装 MCP 依赖

如果你要作为 MCP Server 使用：

```powershell
python -m pip install -e ".[mcp]"
```

当前 MCP Server 使用轻量 stdio JSON-RPC 实现，不强依赖 `mcp` 包。

### 第四步：验证

运行自测试：

```powershell
python tests\smoke_beaconflow.py
```

成功时输出包含 `"covered_functions": 1, "total_functions": 1`。

## 环境要求

- Python 3.10+
- IDA Pro（需能使用 `idat64` 或 `ida64 -A`），用于导出 metadata
- DynamoRIO `drcov`（仓库已内置 Windows 版和 Linux 版，路径 `third_party/dynamorio` 和 `third_party/dynamorio_linux`）
- 可选：QEMU user-mode（Windows 上通过 WSL 使用），用于非 x86 架构目标
- 可选：Ghidra + pyghidra，用于 IDA 不支持的架构（如 LoongArch）导出 metadata
- 可选：WSL（Windows Subsystem for Linux），用于在 Windows 上运行 ELF 目标的 drcov

可选：

- 支持 MCP 的 AI 客户端，例如 Codex、Claude Desktop 或其他 MCP host

## 两种工作流

BeaconFlow 支持两种核心工作流，取决于目标架构和可用工具：

### 工作流 A：IDA/Ghidra + DynamoRIO（x86/x64 目标）

适用于 IDA 或 Ghidra 能打开的目标。先用 IDA headless 或 Ghidra pyghidra 导出 metadata，再用 DynamoRIO 采集覆盖率。**支持 PE 和 ELF 目标**——ELF 文件在 Windows 上通过 WSL 自动运行 Linux 版 DynamoRIO。

### 工作流 B：QEMU 地址日志（LoongArch/MIPS/ARM 等非 x86 目标）

适用于 IDA 当前环境打不开的目标。用 QEMU user-mode 生成执行地址日志，BeaconFlow 从日志自动聚类生成 fallback metadata。

两种工作流共享同一套 `flow`、`flow-diff`、`analyze` 分析命令。

此外，Ghidra + pyghidra 可以作为 metadata 导出的替代方案（工作流 A/B 的增强），支持 IDA 不支持的架构。

---

## 工作流 A：IDA + DynamoRIO

### 导出 IDA metadata

BeaconFlow 不直接依赖 IDA UI。先用 IDA headless 模式导出函数、基本块和 CFG 信息：

```powershell
idat64 -A -S"ida_scripts/export_ida_metadata.py metadata.json" target.exe
```

如果 `idat64` 不在 `PATH` 里，请使用完整路径：

```powershell
& "C:\Program Files\IDA Professional 9.0\idat64.exe" -A -S"ida_scripts/export_ida_metadata.py metadata.json" target.exe
```

### 采集 drcov 覆盖率

使用内置 DynamoRIO。**支持 PE 和 ELF 目标**——ELF 文件在 Windows 上自动通过 WSL 运行 Linux 版 DynamoRIO：

```powershell
# PE 目标（Windows 原生）
python -m beaconflow.cli collect --target target.exe --output-dir runs -- arg1 arg2

# ELF 目标（自动通过 WSL 运行）
python -m beaconflow.cli collect --target target_elf --output-dir runs -- arg1
```

如果目标从 stdin 读取输入：

```powershell
python -m beaconflow.cli collect --target target.exe --stdin "ISCC{test}`n" --output-dir runs
```

`--auto-newline` 可以自动给 stdin 追加换行符：

```powershell
python -m beaconflow.cli collect --target target.exe --stdin "ISCC{test}" --auto-newline --output-dir runs
```

指定运行目录、32 位目标或自定义 drrun：

```powershell
python -m beaconflow.cli collect --target target.exe --run-cwd D:\case --output-dir runs -- arg1
python -m beaconflow.cli collect --arch x86 --target target32.exe --output-dir runs -- arg1
python -m beaconflow.cli collect --drrun "D:\DynamoRIO\bin64\drrun.exe" --target target.exe --output-dir runs
```

超时控制（默认 120 秒）：

```powershell
python -m beaconflow.cli collect --target target.exe --timeout 60 --output-dir runs
```

collect 命令返回 JSON 格式的运行结果，包含 `log_path`、`returncode`、`stdout`、`stderr`、`backend`（`windows-native`、`wsl`、`linux-native`）。

### 一步运行并记录执行流

```powershell
python -m beaconflow.cli record-flow --metadata metadata.json --target target.exe --output-dir runs --output flow.json -- input.bin
```

这个命令会：用 DynamoRIO 跑一遍目标 → 生成 drcov → 映射到 IDA metadata → 输出执行流报告。

Markdown 输出：

```powershell
python -m beaconflow.cli record-flow --metadata metadata.json --target target.exe --output-dir runs --format markdown --output flow.md -- input.bin
```

给 AI 使用时，推荐优先读取 `ai_report` 中的 `how_to_use`、`function_order_text`、`execution_spine_preview`、`dispatcher_candidates`、`branch_points`、`join_points`、`loop_like_edges`、`next_steps`。

---

## 工作流 B：QEMU 地址日志

当目标不是 Windows/PE，或者当前机器上的 IDA 不支持该架构时，使用 QEMU user-mode 采集执行路径。

### 单次 QEMU trace 采集

```powershell
python -m beaconflow.cli collect-qemu --target D:\case\flagchecker --qemu-arch loongarch64 --output-dir runs --stdin "ACTF{00000000000000000000000000000000}" --auto-newline --name wrong
```

参数说明：

- `--target`：目标二进制文件路径
- `--qemu-arch`：QEMU 用户态架构名，如 `loongarch64`、`mips`、`arm`、`aarch64`
- `--trace-mode`：QEMU `-d` 参数，默认 `in_asm`；需要精确执行次数时用 `exec,nochain`
- `--stdin`：发送到目标 stdin 的文本
- `--auto-newline`：自动给 stdin 追加换行符（很多程序需要换行才能读取输入）
- `--run-cwd`：目标程序的运行目录
- `--timeout`：超时秒数，默认 120

Windows 上如果本地没有 QEMU，BeaconFlow 会自动检测 WSL 中的 QEMU 并通过 WSL 运行。

返回结果包含：

```json
{
  "log_path": "runs/wrong.in_asm.qemu.log",
  "command": ["wsl", "--cd", "/mnt/d/case", "--", "qemu-loongarch64", "-D", "...", "-d", "in_asm", "..."],
  "returncode": 0,
  "stdout": "Enter the flag: Wrong!\n",
  "stderr": "",
  "backend": "wsl"
}
```

### 多输入路径探索（qemu-explore）

**核心场景**：你不知道正确输入是什么，但想看哪些输入触发了不同的执行路径。

```powershell
python -m beaconflow.cli qemu-explore `
  --target D:\case\flagchecker `
  --qemu-arch loongarch64 `
  --stdin "ACTF{00000000000000000000000000000000}" `
  --stdin "ACTF{ffffffffffffffffffffffffffffffff}" `
  --stdin "ACTF{1234567890abcdef1234567890abcdef}" `
  --auto-newline `
  --failure-regex "Wrong" `
  --success-regex "Correct" `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --gap 0x200 `
  --jobs 3 `
  --format markdown `
  --output explore_report.md
```

参数说明：

- `--stdin`：可重复，每个是一组测试输入
- `--stdin-file`：可重复，从文件读取测试输入
- `--auto-newline`：自动给每个 stdin 追加换行符
- `--failure-regex` / `--success-regex`：根据 stdout/stderr 匹配判定 success/failure
- `--address-min` / `--address-max`：只分析此地址范围内的 trace 事件
- `--gap`：地址聚类间隔，超过此间隔会拆分为不同函数区段
- `--jobs`：并行 QEMU worker 数量，默认全部并行
- `--timeout`：每个 QEMU 实例的超时秒数

输出示例（ACTF flagchecker 实测）：

```markdown
# BeaconFlow QEMU Explore

## Runs

| Case | Verdict | Return | Unique Blocks | New vs Baseline | New Global | Output | Stdin |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| `case000` | `failure` | 0 | 5260 | 0 | 5260 | `df8cb67d5caed483` | `ACTF{00000000...}` |
| `case001` | `failure` | 0 | 5263 | 25 | 25 | `df8cb67d5caed483` | `ACTF{12345678...}` |
| `case002` | `success` | 0 | 5422 | 201 | 192 | `fdcac192c6ce6d5b` | `ACTF{fce553ec...}` |

## AI Notes

- Inputs with nonzero `New vs Baseline` reached code not seen by case000; inspect those first.
- Different output fingerprints with no path novelty usually mean data-state differences, not control-flow differences.
```

**解读**：case002 的 `New vs Baseline` 是 201，远超其他失败输入的 25。即使不知道正确 flag，AI 也能判断"这个输入触发了大量新路径，值得重点分析"。

### 从地址日志生成 metadata

如果没有 IDA metadata，可以从 QEMU 地址日志聚类生成 fallback metadata：

```powershell
python -m beaconflow.cli metadata-from-address-log `
  --address-log wrong.log correct.log `
  --input-path D:\case\flagchecker `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --gap 0x200 `
  --name-prefix trace `
  --output trace_metadata.json
```

### 分析单次路径

```powershell
python -m beaconflow.cli flow `
  --metadata trace_metadata.json `
  --address-log correct.log `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --format markdown `
  --output correct_flow.md
```

使用 `--from` 和 `--to` 指定函数名或地址范围，聚焦分析特定区间：

```powershell
# 从 main 函数开始统计
python -m beaconflow.cli flow --metadata metadata.json --coverage drcov.log --from main --format markdown

# 从 check_flag 到 main 的地址范围
python -m beaconflow.cli flow --metadata metadata.json --coverage drcov.log --from check_flag --to main --format markdown

# 使用十六进制地址指定范围
python -m beaconflow.cli flow --metadata metadata.json --address-log correct.log --from 0x223560 --to 0x2239a0 --format markdown
```

`--from` 和 `--to` 支持函数名（如 `main`、`check_flag`）或十六进制地址（如 `0x401000`）。当使用函数名时，`--from` 使用函数的起始地址，`--to` 使用函数的结束地址。

### 对比两次路径

```powershell
python -m beaconflow.cli flow-diff `
  --metadata trace_metadata.json `
  --left-address-log wrong.log `
  --right-address-log correct.log `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --format markdown `
  --output wrong_vs_correct.md
```

`flow-diff` 的 Markdown 报告会优先输出连续地址范围，例如 `0x22ef28-0x22ef68`，方便 AI 先定位"正确路径多跑了哪几段"，再回到反汇编里细看。

### 反平坦化分析

`deflatten` 命令从执行流中自动识别并移除 dispatcher 块，重建真实控制流边。**跑一遍程序，就能知道哪些块是真实逻辑、哪些是 dispatcher 噪音**。

```powershell
# 基本用法：对 drcov 覆盖率做反平坦化
python -m beaconflow.cli deflatten --metadata metadata.json --coverage drcov.log --focus-function main --format markdown

# 对 QEMU 地址日志做反平坦化
python -m beaconflow.cli deflatten `
  --metadata flagchecker_metadata.json `
  --address-log correct.in_asm.qemu.log `
  --address-min 0x220000 --address-max 0x244000 `
  --from 0x223560 --to 0x2239a0 `
  --format markdown

# 调整 dispatcher 识别阈值
python -m beaconflow.cli deflatten --metadata metadata.json --coverage drcov.log `
  --dispatcher-min-hits 3 --dispatcher-min-pred 3 --dispatcher-min-succ 3 `
  --format markdown
```

`deflatten` 的 Markdown 报告包含：
- **Summary**：原始块数、dispatcher 块数、真实块数、真实边数
- **Dispatcher Blocks**：被移除的 dispatcher 块列表
- **Real Execution Spine**：去掉 dispatcher 后的干净执行流
- **Real Branch Points**：真实分支点（if/else、循环）
- **Real Edges**：重建的控制流边（A -> B，不是 A -> dispatcher -> B）

#### 实际案例：ACTF flagchecker（LoongArch 平坦化）

```powershell
# 1. 导出 Ghidra metadata
python ghidra_scripts\export_ghidra_metadata.py flagchecker flagchecker_metadata.json

# 2. 采集 QEMU trace
python -m beaconflow.cli collect-qemu --target flagchecker --qemu-arch loongarch64 `
  --stdin "ACTF{fce553ec44532f11ff209e1213c92acd}" --auto-newline --output-dir runs

# 3. 反平坦化分析
python -m beaconflow.cli deflatten `
  --metadata flagchecker_metadata.json `
  --address-log runs/case000.in_asm.qemu.log `
  --address-min 0x220000 --address-max 0x244000 `
  --from 0x223560 --to 0x2239a0 `
  --format markdown --output deflatten_report.md
```

结果：**31 个原始块 → 12 个 dispatcher 块被移除 → 19 个真实块 + 18 条真实边**。执行流从 `0x2239a0 -> 0x223780 -> 0x223560` 三个函数的调用关系清晰可见。

#### 反平坦化工作原理

1. **识别 dispatcher**：高频执行 + 多前驱/多后继的块被标记为 dispatcher
2. **过滤 dispatcher**：从执行流中移除 dispatcher 块
3. **重建真实边**：如果原始流是 `A -> dispatcher -> B`，则真实边是 `A -> B`
4. **输出干净执行流**：只包含真实块和真实边的执行脊柱

#### 局限

- 一次运行只覆盖一条路径，需要多次运行（不同输入）才能还原完整 CFG
- 不提供状态变量值（需要更丰富的 trace，如寄存器/内存值）
- dispatcher 识别基于启发式，可能误判（可调整 `--dispatcher-min-hits` 等阈值）

### 合并多次反平坦化结果（deflatten-merge）

`deflatten-merge` 命令合并多次 `deflatten` 的结果，还原完整的真实 CFG。**跑多遍程序（不同输入），合并后就能看到所有可能的分支路径**。

```powershell
# 合并多个 drcov 覆盖率
python -m beaconflow.cli deflatten-merge `
  --metadata metadata.json `
  --coverage runs/drcov.input_ab.log runs/drcov.input_cd.log runs/drcov.input_x.log `
  --label AB_input CD_input X_input `
  --focus-function check `
  --format markdown

# 合并多个 QEMU 地址日志
python -m beaconflow.cli deflatten-merge `
  --metadata flagchecker_metadata.json `
  --address-log runs/correct.log runs/wrong.log `
  --label correct wrong `
  --address-min 0x220000 --address-max 0x244000 `
  --format markdown
```

参数说明：

- `--coverage`：两个或多个 drcov 日志文件（不同输入产生的）
- `--address-log`：两个或多个 QEMU 地址日志文件
- `--label`：为每个覆盖率文件指定标签（按顺序对应），可重复
- 其他参数与 `deflatten` 相同

`deflatten-merge` 的 Markdown 报告包含：

- **Summary**：合并的 trace 数量、真实块/边总数、分支点、汇合点
- **Per-Trace Summary**：每个 trace 的原始块、dispatcher 块、真实块/边数
- **Branch Points**：真实 CFG 中的分支点（出度 > 1）
- **Merge Points**：真实 CFG 中的汇合点（入度 > 1）
- **Common Path**：所有 trace 都覆盖的边（输入无关的公共路径）
- **Input-Dependent Path**：仅部分 trace 覆盖的边（输入相关的关键分支）

#### 实际案例：多输入合并还原完整 CFG

```powershell
# 1. 用不同输入采集覆盖率
python -m beaconflow.cli collect --target target.exe --stdin "ABxx" --auto-newline --output-dir runs --name input_ab
python -m beaconflow.cli collect --target target.exe --stdin "CDxx" --auto-newline --output-dir runs --name input_cd
python -m beaconflow.cli collect --target target.exe --stdin "Xxxx" --auto-newline --output-dir runs --name input_x

# 2. 合并反平坦化结果
python -m beaconflow.cli deflatten-merge `
  --metadata metadata.json `
  --coverage runs/drcov.input_ab.log runs/drcov.input_cd.log runs/drcov.input_x.log `
  --label AB_input CD_input X_input `
  --focus-function check `
  --format markdown
```

结果示例：

```markdown
## Summary
- Total traces merged: 3
- Total real blocks (union): 9
- Total real edges (union): 9
- Common edges (all traces): 1
- Input-dependent edges: 8

## Branch Points (Real CFG)
- check:0x140001478 -> [check:0x140001483, check:0x1400014a0] (2 successors)
- check:0x1400014a0 -> [check:0x1400014ab, check:0x1400014c8] (2 successors)

## Common Path (All Traces)
- check:0x140001450 -> check:0x140001478 hits=3 covered_by=3/3

## Input-Dependent Path (Key Branches)
- check:0x140001478 -> check:0x140001483 hits=1 covered_by=1/3
- check:0x140001478 -> check:0x1400014a0 hits=2 covered_by=2/3
```

**解读**：`0x140001478` 是第一个分支点（2 个后继），`0x1400014a0` 是第二个分支点。公共路径只有入口到第一个判断，其余 8 条边都是输入相关的——这正是还原完整 CFG 所需的信息。

### 状态变量恢复（recover-state）

`recover-state` 命令从多次执行 trace 中恢复状态转移表，帮助理解平坦化控制流中状态变量的行为。

在平坦化控制流中，dispatcher 通过一个"状态变量"来决定跳转到哪个真实块。`recover-state` 通过观察"真实块 → dispatcher → 真实块"的链路，推断：

- **确定性转移**：真实块 A 之后 dispatcher 总是跳到 B → A 设置状态变量为固定值
- **输入相关转移**：真实块 A 之后 dispatcher 有时跳到 B 有时跳到 C → 状态变量取决于输入条件

```powershell
# 用 drcov 覆盖率
python -m beaconflow recover-state `
  --metadata metadata.json `
  --coverage runs/drcov.input_ab.log runs/drcov.input_cd.log runs/drcov.input_x.log `
  --label AB --label CD --label X `
  --focus-function check `
  --format markdown

# 用 QEMU 地址日志
python -m beaconflow recover-state `
  --metadata flagchecker_metadata.json `
  --address-log runs/correct.log runs/wrong.log `
  --label correct --label wrong `
  --address-min 0x220000 --address-max 0x244000 `
  --format markdown
```

报告中的关键部分：

- **Branch Blocks**：状态变量决策点，列出每个分支块的所有后继及覆盖情况
- **Deterministic Transitions**：确定性转移（状态变量 = 常量），这些边在所有输入下都走
- **Input-Dependent Transitions**：输入相关转移（状态变量 = 分支条件），这些是还原逻辑的关键
- **State Transition Table**：紧凑的状态转移矩阵，显示每个分支点在不同 trace 输入下的后继选择

**如何使用**：
1. 对 Branch Blocks 中的每个块，在 IDA/Ghidra 中打开，找到比较指令
2. 确定性转移对应的真实块中，状态变量被赋值为常量
3. 输入相关转移对应的真实块中，状态变量由条件分支设置
4. 在 dispatcher 块中找到状态变量与常量的比较，将常量映射到后继真实块

---

## Ghidra + pyghidra 导出 metadata

当 IDA 不支持目标架构（如 LoongArch），或者不想依赖 IDA 时，可以用 Ghidra + pyghidra 导出 metadata。导出的 JSON 格式与 IDA 导出完全兼容，可以直接用于 `flow`、`flow-diff`、`analyze` 等命令。

### 安装 pyghidra

```powershell
pip install pyghidra
```

需要 JDK 17+（Ghidra 12 要求）和 Ghidra 安装目录。

### 导出 metadata

```powershell
python ghidra_scripts\export_ghidra_metadata.py <binary_path> [output.json]
```

示例：

```powershell
# 导出 ELF metadata
python ghidra_scripts\export_ghidra_metadata.py target_elf metadata.json

# 导出 PE metadata
python ghidra_scripts\export_ghidra_metadata.py target.exe metadata.json

# 导出 LoongArch ELF metadata
python ghidra_scripts\export_ghidra_metadata.py flagchecker flagchecker_metadata.json
```

如果 Ghidra 不在默认路径 `D:\TOOL\ghidra_12.0.4_PUBLIC`，可以通过环境变量指定：

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.0.4_PUBLIC"
python ghidra_scripts\export_ghidra_metadata.py target.exe metadata.json
```

### 与工作流 B 结合

导出 Ghidra metadata 后，可以替代 fallback metadata，获得更精确的函数名和基本块信息：

```powershell
# 1. 用 Ghidra 导出 metadata（替代 metadata-from-address-log）
python ghidra_scripts\export_ghidra_metadata.py flagchecker flagchecker_metadata.json

# 2. 用 QEMU 采集覆盖率
python -m beaconflow.cli collect-qemu --target flagchecker --qemu-arch loongarch64 --stdin "test" --auto-newline --output-dir runs

# 3. 用 Ghidra metadata + QEMU trace 分析执行流
python -m beaconflow.cli flow --metadata flagchecker_metadata.json --address-log runs/case000.in_asm.qemu.log --address-min 0x220000 --address-max 0x244000 --format markdown
```

### 为什么用 pyghidra 而不是 analyzeHeadless

Ghidra 12.0.4 的 `analyzeHeadless.bat` 在某些环境下存在 OSGi Felix 初始化失败的问题，导致 Java/Python 脚本无法运行。pyghidra 通过 JPype 直接调用 Ghidra Java API，完全绕过 OSGi，更加稳定可靠。

### 已验证的架构

| 架构 | 格式 | 测试结果 |
| --- | --- | --- |
| x86_64 | ELF | ✅ 28 函数（simple_flagchecker） |
| x86_64 | PE | ✅ 102 函数（simple_pe） |
| LoongArch | ELF | ✅ 2870 函数（ACTF flagchecker，静态链接） |

---

## 通用分析命令

以下命令在两种工作流中通用。

### 分析单次覆盖率

```powershell
python -m beaconflow.cli analyze --metadata metadata.json --coverage sample.drcov --format markdown
```

### 恢复执行流

```powershell
python -m beaconflow.cli flow --metadata metadata.json --coverage sample.drcov --output flow.json
```

输出包含：

- `ai_report`：给 AI 直接阅读的执行流摘要、关键块、平坦化提示和下一步建议
- `function_order`：按首次出现顺序进入过的函数
- `flow`：按顺序压缩后的基本块流程
- `transitions`：实际出现过的基本块转移边和次数
- `hot_blocks`：命中次数最多的基本块

只看某个函数：

```powershell
python -m beaconflow.cli flow --metadata metadata.json --coverage sample.drcov --focus-function _main --format markdown
```

### 比较两次执行流

```powershell
python -m beaconflow.cli flow-diff --metadata metadata.json --left wrong.drcov.log --right correct.drcov.log --format markdown
```

输出包含：

- 只在左侧运行出现的基本块和转移边
- 只在右侧运行出现的基本块和转移边
- 命中次数不同的基本块
- 连续地址范围压缩（如 `0x22ef28-0x22ef68`）

### 比较两次覆盖率（函数级）

```powershell
python -m beaconflow.cli diff --metadata metadata.json --left input_a.drcov --right input_b.drcov
```

---

## 完整案例：ACTF flagchecker（LoongArch）

目标：一个 LoongArch 架构的 flagchecker，IDA 当前环境无法打开，不知道正确输入。

### 步骤 0（可选）：用 Ghidra 导出 metadata

如果有 Ghidra，可以导出更精确的 metadata（含函数名和基本块信息），替代 fallback metadata：

```powershell
pip install pyghidra
python ghidra_scripts\export_ghidra_metadata.py D:\CTF\ACTF2026\flagchecker\flagchecker flagchecker_metadata.json
```

### 步骤 1：用 qemu-explore 探索多个输入

```powershell
python -m beaconflow.cli qemu-explore `
  --target D:\CTF\ACTF2026\flagchecker\flagchecker `
  --qemu-arch loongarch64 `
  --stdin "ACTF{00000000000000000000000000000000}" `
  --stdin "ACTF{1234567890abcdef1234567890abcdef}" `
  --stdin "ACTF{fce553ec44532f11ff209e1213c92acd}" `
  --auto-newline `
  --failure-regex "Wrong" `
  --success-regex "Correct" `
  --address-min 0x220000 --address-max 0x244000 --gap 0x200 `
  --jobs 3 --format markdown --output explore_report.md
```

### 步骤 2：阅读报告，找到路径差异最大的输入

报告显示 case002（`ACTF{fce553ec...}`）比基线多了 201 个新块，且被判定为 success。

### 步骤 3：用 flow-diff 精确定位差异

使用 Ghidra metadata（如果已导出）：

```powershell
python -m beaconflow.cli flow-diff `
  --metadata flagchecker_metadata.json `
  --left-address-log explore_dir/case000.in_asm.qemu.log `
  --right-address-log explore_dir/case002.in_asm.qemu.log `
  --address-min 0x220000 --address-max 0x244000 `
  --format markdown --output wrong_vs_correct.md
```

或使用 fallback metadata：

```powershell
python -m beaconflow.cli flow-diff `
  --metadata explore_dir/qemu_explore_metadata.json `
  --left-address-log explore_dir/case000.in_asm.qemu.log `
  --right-address-log explore_dir/case002.in_asm.qemu.log `
  --address-min 0x220000 --address-max 0x244000 `
  --format markdown --output wrong_vs_correct.md
```

### 步骤 4：根据 diff 结果定位关键代码

diff 报告显示正确路径独有的块范围：

```text
actf_005_22e2a0:0x22ef28-0x22ef68  blocks=16
actf_005_22e2a0:0x22efb0-0x22f000  blocks=20
actf_005_22e2a0:0x22f338-0x22f394  blocks=23
actf_005_22e2a0:0x22f3a0-0x22f3c8  blocks=10
```

错误路径独有的块范围：

```text
actf_005_22e2a0:0x22ef68-0x22efa0  blocks=14
actf_005_22e2a0:0x22f3c8-0x22f3d4  blocks=3
```

AI 可以直接去反汇编中查看这些地址范围的逻辑，判断校验条件。

---

## MCP 使用

### 启动 MCP Server

```powershell
python -m beaconflow.mcp.server
```

安装后也可以使用：

```powershell
beaconflow-mcp
```

### MCP 客户端配置

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "python",
      "args": ["-m", "beaconflow.mcp.server"],
      "cwd": "D:\\BeaconFlow"
    }
  }
}
```

如果客户端找不到 Python，使用完整路径：

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "C:\\Users\\YourName\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
      "args": ["-m", "beaconflow.mcp.server"],
      "cwd": "D:\\BeaconFlow"
    }
  }
}
```

### 当前 MCP Tools

| 工具 | 用途 |
| --- | --- |
| `collect_drcov` | 用 DynamoRIO 采集 drcov 覆盖率 |
| `collect_qemu` | 用 QEMU 采集单次执行 trace |
| `qemu_explore` | 多输入并行探索，分类 verdict，排名路径新颖性 |
| `analyze_coverage` | 分析 drcov 覆盖率 |
| `analyze_flow` | 恢复有序执行流 |
| `record_flow` | 一步运行并返回执行流 |
| `diff_coverage` | 函数级覆盖率对比 |
| `diff_flow` | 块级/边级执行流对比 |
| `metadata_from_address_log` | 从地址日志聚类生成 fallback metadata |

### `collect_drcov`

```json
{
  "target_path": "D:\\case\\target.exe",
  "target_args": ["input.bin"],
  "output_dir": "D:\\case\\runs",
  "arch": "x64",
  "stdin": "test_input",
  "auto_newline": false,
  "run_cwd": "D:\\case"
}
```

返回：`{"coverage_path": "D:\\case\\runs\\drcov.target.exe.1234.0000.log"}`

### `collect_qemu`

```json
{
  "target_path": "D:\\case\\flagchecker",
  "qemu_arch": "loongarch64",
  "trace_mode": "in_asm",
  "stdin": "ACTF{00000000000000000000000000000000}",
  "auto_newline": true,
  "output_dir": "D:\\case\\runs",
  "timeout": 120
}
```

返回：

```json
{
  "log_path": "D:\\case\\runs\\case000.in_asm.qemu.log",
  "command": ["wsl", "--cd", "/mnt/d/case", "--", "qemu-loongarch64", ...],
  "returncode": 0,
  "stdout": "Enter the flag: Wrong!\n",
  "stderr": "",
  "backend": "wsl"
}
```

### `qemu_explore`

```json
{
  "target_path": "D:\\case\\flagchecker",
  "qemu_arch": "loongarch64",
  "stdin_cases": [
    "ACTF{00000000000000000000000000000000}",
    "ACTF{1234567890abcdef1234567890abcdef}",
    "ACTF{fce553ec44532f11ff209e1213c92acd}"
  ],
  "auto_newline": true,
  "failure_regex": "Wrong",
  "success_regex": "Correct",
  "address_min": "0x220000",
  "address_max": "0x244000",
  "gap": "0x200",
  "jobs": 3,
  "format": "markdown"
}
```

返回包含 summary 和每个 case 的 verdict、unique_blocks、new_blocks_vs_baseline、new_blocks_global、output_fingerprint。

### `analyze_flow`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "coverage_path": "D:\\case\\runs\\drcov.target.exe.1234.0000.log",
  "max_events": 0,
  "format": "json"
}
```

也支持 `address_log_path` 代替 `coverage_path`：

```json
{
  "metadata_path": "D:\\case\\trace_metadata.json",
  "address_log_path": "D:\\case\\qemu_correct.log",
  "address_min": "0x220000",
  "address_max": "0x244000",
  "format": "markdown"
}
```

### `record_flow`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "target_path": "D:\\case\\target.exe",
  "target_args": ["input.bin"],
  "output_dir": "D:\\case\\runs",
  "arch": "x64",
  "max_events": 0,
  "format": "json"
}
```

### `analyze_coverage`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "coverage_path": "D:\\case\\sample.drcov",
  "format": "markdown"
}
```

### `diff_coverage`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "left_coverage_path": "D:\\case\\input_a.drcov",
  "right_coverage_path": "D:\\case\\input_b.drcov"
}
```

### `diff_flow`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "left_address_log_path": "D:\\case\\wrong.log",
  "right_address_log_path": "D:\\case\\correct.log",
  "address_min": "0x220000",
  "address_max": "0x244000",
  "format": "markdown"
}
```

也支持 `left_coverage_path` / `right_coverage_path` 代替地址日志。

### `metadata_from_address_log`

```json
{
  "address_log_paths": ["D:\\case\\wrong.log", "D:\\case\\correct.log"],
  "output_path": "D:\\case\\trace_metadata.json",
  "input_path": "D:\\case\\flagchecker",
  "address_min": "0x220000",
  "address_max": "0x244000",
  "gap": "0x200",
  "name_prefix": "trace_region"
}
```

---

## 自测试

```powershell
python tests\smoke_beaconflow.py
```

成功时输出：

```text
{
  "covered_functions": 1,
  "total_functions": 1,
  "covered_basic_blocks": 1,
  "total_basic_blocks": 1
}
```

## Skill 使用

仓库里带了一个可选 skill：`skills/beaconflow/SKILL.md`。它告诉 AI 遇到覆盖率、控制流、路径 diff、反平坦化辅助分析时应该怎么调用 BeaconFlow。

如果你的 AI 客户端支持 skills，可以把 `skills/beaconflow` 复制或链接到对应的 skills 目录。核心分析仍然建议通过 MCP 调用完成。

## 常见问题

### BeaconFlow 需要打开 IDA 界面吗？

不需要。使用 `idat64 -A` 或 `ida64 -A` 即可在 headless 模式导出 metadata。

### IDA 不支持目标架构怎么办？

使用 QEMU 地址日志工作流。用 `collect-qemu` 或 `qemu-explore` 采集执行路径，用 `metadata-from-address-log` 生成 fallback metadata，然后用同样的 `flow`、`flow-diff` 命令分析。

如果有 Ghidra，可以用 `ghidra_scripts/export_ghidra_metadata.py` 导出更精确的 metadata（含函数名和基本块信息），替代 fallback metadata。

### 只给 drcov 文件能分析吗？

不够。`drcov` 里主要是模块和基本块偏移，BeaconFlow 还需要 IDA 导出的函数和 CFG 信息（或从地址日志生成的 fallback metadata），才能告诉 AI 这些覆盖率对应哪些函数和基本块。

### 不知道正确输入怎么办？

用 `qemu-explore`。给它多个候选输入，它会：
1. 并行运行所有输入
2. 根据 `--success-regex` / `--failure-regex` / exit code 分类 verdict
3. 计算每个输入相比基线的新增块数（`new_blocks_vs_baseline`）
4. 按 output fingerprint 分组

新增块数最多的输入最可能触发了不同的校验路径，值得重点分析。

### QEMU trace 的 hit count 准确吗？

`-d in_asm` 更像翻译块日志，hit count 不应当当作精确循环次数。需要精确执行次数时用 `-d exec,nochain`。

**两种 trace 模式对比**：

| 模式 | 命令参数 | 记录内容 | 粒度 | 日志大小 | 适用场景 |
| --- | --- | --- | --- | --- | --- |
| `in_asm` | `-d in_asm` | 基本块首次翻译 | 粗（每块一次） | 小 | 快速浏览执行流、函数级分析 |
| `exec,nochain` | `-d exec,nochain` | 每条指令每次执行 | 细（每条指令每次） | 大 | 反平坦化、dispatcher 识别、精确 hit count |

`exec,nochain` 精确模式的优势：
- 记录 dispatcher 块的每次执行（而非仅首次翻译），使 dispatcher 识别更准确
- 提供精确的 hit count，可以判断循环次数
- 对于 `deflatten`、`deflatten-merge`、`recover-state` 等反平坦化命令，推荐使用 `exec,nochain` 模式

```powershell
# 使用 exec,nochain 精确模式采集
python -m beaconflow collect-qemu --target ./flagchecker --qemu-arch loongarch64 --trace-mode exec,nochain --stdin "test" --output-dir runs --name precise
```

### Ghidra headless 的 OSGi 报错怎么办？

Ghidra 12.0.4 的 `analyzeHeadless.bat` 在某些环境下（如 JDK 版本不匹配、OSGi 缓存权限问题）会报 OSGi Felix 初始化失败。推荐使用 `pyghidra` 方案（`ghidra_scripts/export_ghidra_metadata.py`），它通过 JPype 直接调用 Ghidra Java API，完全绕过 OSGi。

### Ghidra 导出的 metadata 和 IDA 导出的有什么区别？

格式完全兼容。Ghidra 导出的 JSON 可以直接用于 `load_metadata`、`flow`、`flow-diff`、`analyze` 等所有命令。区别在于 Ghidra 可能识别出不同的函数名和基本块划分（特别是对 LoongArch 等新架构），但结构一致。

### 能做反平坦化吗？

当前版本提供覆盖率和 CFG 映射基础，`ai_report` 中已包含 dispatcher 候选、branch/join 点、loop 边等提示。反平坦化建议下一步增加 state variable 候选识别和基于多输入的真实路径过滤。

## 后续开发方向

- 增加 trace 文件解析和 `analyze_trace`
- 增加函数调用顺序统计
- 增加 IDA metadata 缓存
- 增加 HTML 报告
- 增加对 Frida/Pin/Tenet trace 的读取
- 增加 Ghidra MCP 集成（通过 Ghidra MCP Server 直接获取 metadata，无需 pyghidra）
- 增加状态变量恢复（从 dispatcher 块中提取 state variable 值）
- 增加 IDA/Ghidra 补丁脚本输出（自动标注真实块和 dispatcher 块）
- 增加多 trace 合并（合并多次运行的 deflatten 结果，还原完整 CFG）✅ 已完成

## 致谢

BeaconFlow 的设计参考了 IDA 覆盖率插件 Lighthouse 的思路，并沿用了覆盖率分析中常见的 DynamoRIO/drcov 工作流。项目内置的第三方组件许可证见：

```text
third_party/dynamorio/License.txt
third_party/dynamorio/ACKNOWLEDGEMENTS
```
