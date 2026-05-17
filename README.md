# BeaconFlow

BeaconFlow 是一个面向 AI Agent 的 headless 覆盖率与控制流分析工具。

仓库地址：<https://github.com/mansujiaosheng/BeaconFlow>

它的目标不是替代 IDA，而是让 AI 在不打开 IDA 图形界面的情况下，读取 IDA 或 Ghidra 的函数、基本块、CFG 信息，并结合覆盖率数据快速回答：

- 哪些函数被运行过
- 哪些基本块被覆盖
- 程序这一次实际走过的基本块流程
- 实际出现过的基本块转移边
- 哪些函数没有跑到
- 两次运行触发了哪些不同路径
- 在不知道正确输入的情况下，哪些输入触发了更多新路径
- 哪些分支最可能受输入影响，应该优先回到反汇编里看比较条件
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

如果要验证 MCP server 本身，可以再跑：

```powershell
python -m beaconflow.cli doctor --format markdown
python -m beaconflow.mcp.server
```

`doctor` 中 MCP 依赖显示 OK 时，说明 `python -m pip install -e ".[mcp]"` 已安装；当前 stdio server 即使没有 `mcp` 包也能启动，但安装 extra 可以避免环境检查警告。

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

## 一键工作流（Quickstart）

如果你只是想先得到可读报告，不想在几十个命令里选择入口，优先使用 quickstart 命令。

### PE / Windows 可执行文件

```powershell
python -m beaconflow.cli quickstart-pe `
  --target D:\case\target.exe `
  --output-dir D:\case\beacon_quick `
  -- arg1 arg2
```

输出目录会包含 Ghidra metadata、drcov run、coverage JSON/Markdown、flow JSON/Markdown 和 `quickstart-pe.md` 索引。

### QEMU / 非 x86 ELF

```powershell
python -m beaconflow.cli quickstart-qemu `
  --target D:\case\flagchecker `
  --qemu-arch loongarch64 `
  --output-dir D:\case\beacon_qemu `
  --stdin "ACTF{test}" `
  --stdin "ACTF{00000000000000000000000000000000}" `
  --auto-newline `
  --failure-regex "Wrong" `
  --address-min 0x220000 --address-max 0x244000 `
  --format markdown
```

输出目录会包含 QEMU logs、fallback metadata、path novelty 报告和 `quickstart-qemu.md` 索引。

### 控制流平坦化

```powershell
python -m beaconflow.cli quickstart-flatten `
  --metadata D:\case\metadata.json `
  --address-log D:\case\wrong.in_asm.qemu.log `
  --address-min 0x220000 --address-max 0x244000 `
  --output-dir D:\case\beacon_flatten
```

输出目录会包含 deflatten JSON/Markdown 和 `quickstart-flatten.md` 索引。

## 报告置信度

带 AI Digest 的报告会同时输出 `report_confidence`：

- `level`：`high` / `medium` / `low`
- `score`：0-100
- `basis`：支持当前置信度的证据，例如高 mapping ratio、可靠覆盖率来源
- `limitations`：限制条件，例如 QEMU `in_asm` 只代表 translation log、deflatten/branch-rank 属于启发式排序
- `recommendation`：Agent 下一步该如何使用该报告

规则上，DynamoRIO drcov + 高映射率通常是高置信；QEMU `in_asm`、反平坦化、分支排序、taint/value 推断会自动降级，防止 AI 把启发式结论当成事实。

***

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

给 AI 使用时，推荐优先读取顶层 `ai_digest` 和 `data_quality`：

- `ai_digest.top_findings`：当前报告最值得看的证据点
- `ai_digest.recommended_actions`：下一步可执行动作，例如打开反汇编地址或重新采集 `exec,nochain`
- `ai_digest.evidence_refs`：可引用的证据 ID
- `data_quality.hit_count_precision`：判断 hit count 是否可信
- `data_quality.recommended_recollection`：需要重新采集时的建议

需要更多上下文时，再读取 `ai_report` 中的 `how_to_use`、`function_order_text`、`execution_spine_preview`、`dispatcher_candidates`、`branch_points`、`join_points`、`loop_like_edges`、`next_steps`。

***

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

### 自定义输入搜索（qemu-explore mutate）

**核心场景**：你知道大致输入结构，但不知道哪些字符、字段或参数会触发新路径。可以让 BeaconFlow 自动生成候选输入，再按路径新颖性排序。它不限定 CTF flag 格式，也可以用于 token、license、命令行参数、协议字段、表单文本等输入。

```powershell
python -m beaconflow.cli qemu-explore `
  --target D:\case\flagchecker `
  --qemu-arch loongarch64 `
  --mutate-template "token=%16x&mode=%4s" `
  --mutate-template "license:%32x" `
  --strategy byte-flip `
  --mutate-limit 200 `
  --keep-top 20 `
  --auto-newline `
  --failure-regex "Wrong" `
  --address-min 0x220000 --address-max 0x244000 `
  --format markdown `
  --output explore_mutate_report.md
```

`--mutate-template` 会把 `token=%16x&mode=%4s` 变成 `token=0000000000000000&mode=AAAA` 作为 seed，并且只变异占位符对应的字符，不会破坏固定文本。这个参数可以重复，用来同时探索多个可能输入结构。`--mutate-format` 仍可作为兼容别名使用。

如果你已经有一个完整 seed，只想指定部分位置变异：

```powershell
python -m beaconflow.cli qemu-explore `
  --target D:\case\checker `
  --qemu-arch aarch64 `
  --mutate-template "ignored" `
  --mutate-seed "login=admin&pin=0000" `
  --mutate-positions "16:20" `
  --mutate-alphabet "0123456789"
```

`--mutate-positions` 使用 0-based 位置，支持 `0,3,8-15` 或 Python 风格半开区间 `8:16`。内置策略包括 `byte-flip`、`length` 和 `all`。

如果需要精确循环次数、dispatcher hit count 或 timing/path oracle，请使用 `--trace-mode exec,nochain`。默认 `in_asm` 更适合快速路径探索，hit count 只能当翻译日志证据。

对静态链接或运行库噪声很大的 ELF，务必优先加 `--address-min` / `--address-max` 限定目标代码范围。实测 LoongArch 静态题目如果不限定范围，`qemu-explore` 会把运行库地址也拿去聚类和差分，后处理可能非常慢；限定到题目核心范围后，同一批输入可在十几秒内完成。

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

### 压缩已有报告给 AI

完整 JSON 报告可能很大。可以用 `ai-summary` 把已有报告压缩成只包含摘要、数据质量、关键发现和下一步动作的版本：

```powershell
python -m beaconflow.cli ai-summary --input branch_rank.json --format markdown
```

输出会保留 `summary`、`data_quality` 和 `ai_digest`。适合 MCP/Agent 先读摘要，再按 `evidence_id` 回到完整报告里查细节。

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
  --dispatcher-mode strict `
  --dispatcher-min-hits 3 --dispatcher-min-pred 3 --dispatcher-min-succ 3 `
  --format markdown
```

`--dispatcher-mode` 可选：

- `strict`（默认）：必须同时满足高频、多前驱、多后继，优先避免把热点循环、状态机、VM/事件分发器误删。
- `balanced`：仍要求较强 CFG 形态，但比 strict 更容易选出候选。
- `aggressive`：接近早期启发式，适合典型 CFF 快速探索，但更容易误判热点块。

`deflatten` 的 Markdown 报告包含：

- **Summary**：原始块数、dispatcher 块数、真实块数、真实边数
- **Dispatcher Blocks**：被移除的 dispatcher 块列表
- **Dispatcher Candidates**：候选块、置信度、是否被选中，以及低置信候选的误判警告
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

1. **识别 dispatcher**：默认 strict 模式只把高频且同时具备多前驱/多后继形态的块标记为 dispatcher
2. **过滤 dispatcher**：从执行流中移除 dispatcher 块
3. **重建真实边**：如果原始流是 `A -> dispatcher -> B`，则真实边是 `A -> B`
4. **输出干净执行流**：只包含真实块和真实边的执行脊柱

#### 局限

- 一次运行只覆盖一条路径，需要多次运行（不同输入）才能还原完整 CFG
- 不提供状态变量值（需要更丰富的 trace，如寄存器/内存值）
- dispatcher 识别仍基于启发式，可能误判；默认 `--dispatcher-mode strict` 会降低热点循环/状态机误判，必要时可调整 `--dispatcher-mode` 和 `--dispatcher-min-*` 阈值

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
- `--label`：为每个覆盖率文件指定标签（按顺序对应），支持空格分隔或重复指定：`--label A B C` 或 `--label A --label B --label C`
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

### 输入相关分支排序（branch-rank）

`branch-rank` 把 CTF flagchecker 最关心的问题单独抽出来：哪些分支最可能被输入控制，哪个分支最像 check fail / check pass。

```powershell
python -m beaconflow.cli branch-rank `
  --metadata trace_metadata.json `
  --bad-address-log wrong.log `
  --better-address-log almost.log `
  --good-address-log correct.log `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --top 10 `
  --format markdown `
  --output branch_rank.md
```

参数说明：

- `--top N`：Markdown 报告中只显示前 N 个排名分支（默认 10，设为 0 显示全部）
- `--format`：支持 `json`、`markdown`、`markdown-brief`（精简模式，只输出摘要+关键信息）

报告会优先排序：

- baseline 没走过、better/good 走到的新边
- across traces 出现多个后继的块
- 只在 good trace 出现的边
- hit count 随输入变化明显的块（`in_asm` 下只作为弱证据）

它不会直接恢复比较表达式，但能先回答“AI 下一步最该看哪个分支点”。

***

## Ghidra + pyghidra 导出 metadata

当 IDA 不支持目标架构（如 LoongArch），或者不想依赖 IDA 时，可以用 Ghidra + pyghidra 导出 metadata。导出的 JSON 格式与 IDA 导出完全兼容，可以直接用于 `flow`、`flow-diff`、`analyze` 等命令。

### 安装 pyghidra

```powershell
pip install pyghidra
```

需要 JDK 17+（Ghidra 12 要求）和 Ghidra 安装目录。

### 导出 metadata

```powershell
python -m beaconflow.cli export-ghidra-metadata --target <binary_path> --output metadata.json
```

示例：

```powershell
# 导出 ELF metadata
python -m beaconflow.cli export-ghidra-metadata --target target_elf --output metadata.json

# 导出 PE metadata
python -m beaconflow.cli export-ghidra-metadata --target target.exe --output metadata.json

# 导出 LoongArch ELF metadata
python -m beaconflow.cli export-ghidra-metadata --target flagchecker --output flagchecker_metadata.json
```

如果 Ghidra 不在默认路径 `D:\TOOL\ghidra_12.0.4_PUBLIC`，可以通过环境变量指定：

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.0.4_PUBLIC"
python -m beaconflow.cli export-ghidra-metadata --target target.exe --output metadata.json
```

`export-ghidra-metadata` 默认使用 `pyghidra`，避免 Ghidra 12.x 的 `analyzeHeadless` Java/Python 脚本加载问题。如需保留旧的 headless 脚本路径，可以显式指定：

```powershell
python -m beaconflow.cli export-ghidra-metadata --backend headless --target target.exe --output metadata.json
```

### 与工作流 B 结合

导出 Ghidra metadata 后，可以替代 fallback metadata，获得更精确的函数名和基本块信息：

```powershell
# 1. 用 Ghidra 导出 metadata（替代 metadata-from-address-log）
python -m beaconflow.cli export-ghidra-metadata --target flagchecker --output flagchecker_metadata.json

# 2. 用 QEMU 采集覆盖率
python -m beaconflow.cli collect-qemu --target flagchecker --qemu-arch loongarch64 --stdin "test" --auto-newline --output-dir runs

# 3. 用 Ghidra metadata + QEMU trace 分析执行流
python -m beaconflow.cli flow --metadata flagchecker_metadata.json --address-log runs/case000.in_asm.qemu.log --address-min 0x220000 --address-max 0x244000 --format markdown
```

### 为什么用 pyghidra 而不是 analyzeHeadless

Ghidra 12.0.4 的 `analyzeHeadless.bat` 在某些环境下存在 OSGi Felix 初始化失败的问题，导致 Java/Python 脚本无法运行。pyghidra 通过 JPype 直接调用 Ghidra Java API，完全绕过 OSGi，更加稳定可靠。

### 已验证的架构

| 架构          | 格式    | 测试结果                                     |
| ----------- | ----- | ---------------------------------------- |
| x86\_64     | ELF   | ✅ 28 函数（simple\_flagchecker）             |
| x86\_64     | PE    | ✅ 102 函数（simple\_pe）                     |
| LoongArch   | ELF   | ✅ 2870 函数（ACTF flagchecker，静态链接）         |
| WebAssembly | .wasm | ✅ 112 函数（ISCC2026 box.wasm，纯 Python 解析器） |

***

## WebAssembly (WASM) 支持

BeaconFlow 内置纯 Python WASM 解析器，无需安装额外依赖即可从 `.wasm` 文件提取函数、基本块、指令和导出信息。

### 导出 WASM metadata

```powershell
python -m beaconflow.cli export-wasm-metadata --target box.wasm --output box_metadata.json
```

输出示例：

```json
{
  "format": "wasm",
  "functions": 112,
  "basic_blocks": 2463,
  "exports": 5,
  "imports": 7
}
```

### 分析 WASM 程序

导出 metadata 后，所有分析命令都可以使用：

```powershell
# 角色检测 - 自动定位 dispatcher、validator 等关键函数
python -m beaconflow.cli detect-roles --metadata box_metadata.json --format markdown

# 伪代码摘要 - 理解函数逻辑
python -m beaconflow.cli decompile-function --metadata box_metadata.json --name main --format markdown

# 统一 IR - 跨架构指令归一化（支持 WASM 指令）
python -m beaconflow.cli normalize-ir --metadata box_metadata.json --name f1 --format markdown
```

IR 输出示例（XOR 解密循环）：

```
  ASSIGN       0x10                  // i32.const 0x10
  BINARY_XOR                         // i32.xor
  STORE        offset=0              // i32.store8 offset=0
  ASSIGN       0x30                  // i32.const 0x30
  COMPARE                            // i32.ne
  BRANCH       loop_back 0           // br_if 0
```

### WASM 解析器特性

- 纯 Python 实现，无需外部依赖
- 解析 WASM 二进制格式（type/import/function/export/code/data 段）
- 自动提取函数名（从 export 段）和导入函数名
- 基本块分割（基于 block/loop/if/br/br\_if/br\_table 指令）
- 提取每条指令的操作码、操作数和立即数
- 输出格式与 IDA/Ghidra 导出的 metadata 完全兼容

> **提示**：Ghidra 12.0.4 不内置 WASM 支持，因此 `export-ghidra-metadata` 无法处理 `.wasm` 文件。请使用 `export-wasm-metadata` 命令。

***

## 通用分析命令

以下命令在两种工作流中通用。

所有分析命令的 `--format` 参数支持三种格式：

- `json`（默认）：完整结构化 JSON，适合程序化处理
- `markdown`：完整 Markdown 报告，包含所有详细列表
- `markdown-brief`：精简 Markdown 报告，只输出摘要 + AI Digest + 关键发现（Top 5-10），适合 AI Agent 快速阅读

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

### 查看基本块上下文

当 metadata 中包含 block context（由 Ghidra/IDA 导出器自动提取）时，可以查看单个基本块的详细信息：

```powershell
# 查看某个基本块的指令、调用、字符串、常量等
python -m beaconflow.cli inspect-block --metadata metadata.json --address 0x1400014c7

# 查看某个函数的所有基本块及其上下文
python -m beaconflow.cli inspect-function --metadata metadata.json --name check_flag
# 或按地址查找
python -m beaconflow.cli inspect-function --metadata metadata.json --address 0x140001460
```

输出包含：

- `instructions`：块内反汇编指令
- `calls`：块内调用的函数名
- `strings`：块内引用的字符串常量
- `constants`：块内使用的立即数
- `data_refs`：块内引用的数据地址
- `code_refs`：块内引用的代码地址
- `predecessors`：前驱块地址
- `successors`：后继块地址

> **提示**：block context 在 Ghidra/IDA 导出时默认启用。使用 `--no-context` 可跳过（加快导出速度）。

### 查找决策点（Decision Points）

`find-decision-points` 命令从 metadata 的 block context 中自动识别关键判断点，并按 AI 优先级排序。**让 AI 不只看到分支地址，还能直接看到"这里做了什么判断"**。

```powershell
# 查找所有决策点
python -m beaconflow.cli find-decision-points --metadata metadata.json --format markdown

# 只查找某个函数中的决策点
python -m beaconflow.cli find-decision-points --metadata metadata.json --focus-function check_flag --format markdown

# 精简模式（只显示 critical/high 优先级）
python -m beaconflow.cli find-decision-points --metadata metadata.json --format markdown-brief

# 输出到文件
python -m beaconflow.cli find-decision-points --metadata metadata.json --format json --output decision_points.json
```

识别的决策点类型：

| 类型             | 模式                           | AI 优先级   | 说明                   |
| -------------- | ---------------------------- | -------- | -------------------- |
| `checker_call` | `strcmp/memcmp/strlen + jcc` | critical | 字符串/内存比较后的条件分支       |
| `jump_table`   | `JMP [reg]` / `SHL+ADD+JMP`  | high     | switch/jump table 分发 |
| `cmp_jcc`      | `CMP + JZ/JNE/...`           | medium   | 比较后条件分支              |
| `test_jcc`     | `TEST + JZ/JNE/...`          | medium   | 位测试后条件分支             |
| `cmovcc`       | `CMOVE/CMOVNE/...`           | low      | 条件移动（数据选择）           |
| `setcc`        | `SETNE/SETZ/...`             | low      | 条件置位（标志转布尔）          |

输出示例：

```markdown
# BeaconFlow Decision Points

- Total decision points: 6
- Critical: 0 | High: 2 | Medium: 2 | Low: 2
- Focus function: <none>

## HIGH Priority (2)

- `check_flag:0x401010` type=`test_jcc`
  - call: `strcmp()`
  - compare: `TEST EAX, EAX`
  - branch: `JNE 0x401040`
  - reason: Bit test (TEST) followed by conditional branch
  - successors: `0x401020`
  - taken: `0x401040`
```

### 检查单个决策点

`inspect-decision-point` 命令查看某个地址的决策点详情：

```powershell
python -m beaconflow.cli inspect-decision-point --metadata metadata.json --address 0x401010
```

输出包含决策点类型、优先级、比较/分支指令、后继块、以及关联的 block context（指令、调用、字符串等）。

> **提示**：Decision Points 依赖 block context 中的指令信息。使用 Ghidra/IDA 导出 metadata 时默认包含 context。

### 检测函数角色（Candidate Role Detector）

`detect-roles` 命令通过可配置规则自动推断函数在程序中的角色，让 AI 不需要逐个分析函数就能快速定位关键逻辑。

```powershell
# 检测所有函数角色
python -m beaconflow.cli detect-roles --metadata metadata.json --format markdown

# 只检测某个函数
python -m beaconflow.cli detect-roles --metadata metadata.json --focus-function check_flag --format json

# 使用自定义规则文件
python -m beaconflow.cli detect-roles --metadata metadata.json --rules my_rules.yaml

# 设置最低分数阈值
python -m beaconflow.cli detect-roles --metadata metadata.json --min-score 0.5
```

支持的角色类型：

| 角色                    | 说明      | 识别依据                                                        |
| --------------------- | ------- | ----------------------------------------------------------- |
| `validator`           | 核心校验函数  | 名称含 check/verify/validate + 有 decision points + 调用 strcmp 等 |
| `crypto_like`         | 加解密函数   | 名称含 encrypt/decrypt/hash + 大量位运算 + 常量 + 循环                  |
| `input_handler`       | 输入处理函数  | 名称含 read/input + 调用 scanf/recv 等 I/O 函数                     |
| `dispatcher`          | 状态分发函数  | 名称含 dispatch/handler + 多后继 + jump table                     |
| `success_handler`     | 成功输出函数  | 名称含 success/pass + 调用 printf/puts                           |
| `failure_handler`     | 失败输出函数  | 名称含 fail/error/deny + 调用 printf/puts                        |
| `anti_debug`          | 反调试函数   | 名称含 debug/ptrace + 调用调试检测 API                               |
| `transformer`         | 数据变换函数  | 名称含 transform/encode + 无 decision points + 有循环              |
| `input_normalizer`    | 输入标准化函数 | 名称含 normalize/trim + 在输入后调用                                 |
| `state_update`        | 状态更新函数  | 名称含 update/set\_state + 在分发后调用                              |
| `runtime_init`        | 运行时初始化  | 名称含 init/setup/main + 调用多个函数                                |
| `unknown_interesting` | 有趣的未知函数 | 有 decision points + 有常量                                     |

输出示例：

```markdown
# BeaconFlow Candidate Role Detection

- Total candidates: 6
- High confidence: 4 | Medium: 2 | Low: 0

## HIGH Confidence (4)

### `check_flag` → `validator` (score: 1.2)
- Name matches patterns: check
- Contains decision points (cmp/test+jcc, cmovcc, setcc)
- Calls string comparison: strcmp

**Recommended actions:**
- Trace input data flow into this function
- Compare path differences between correct/wrong inputs
- Inspect string comparison arguments for expected values
```

### 检查单个函数角色

`inspect-role` 命令查看某个函数的角色详情：

```powershell
# 按函数名查看
python -m beaconflow.cli inspect-role --metadata metadata.json --name check_flag

# 按地址查看
python -m beaconflow.cli inspect-role --metadata metadata.json --address 0x401000
```

输出包含角色、置信度、分数、证据、匹配规则、推荐操作和关联信息。

### 自定义角色规则

角色检测使用 YAML 配置文件，默认内置在 `beaconflow/analysis/role_rules.yaml`。可以通过 `--rules` 参数指定自定义规则：

```yaml
roles:
  validator:
    name_patterns:
      - "check"
      - "verify"
    positive_features:
      - "has_decision_points"
      - "calls_string_compare"
    negative_features:
      - "runtime_noise"
    score_weight: 1.2
```

> **提示**：Role Detector 依赖 block context 中的指令和调用信息。使用 Ghidra/IDA 导出 metadata 时默认包含 context。

### 检测比较值追踪（Value Trace）

`trace-values` 命令从 metadata 的 block context 中提取关键比较点的寄存器/内存/比较值信息，让 AI 不只知道"哪个块被执行"，还知道关键比较点发生了什么。

```powershell
# 基本用法（仅从 metadata 提取比较语义）
python -m beaconflow.cli trace-values --metadata metadata.json --format markdown

# 结合覆盖率数据推断分支结果
python -m beaconflow.cli trace-values --metadata metadata.json --coverage drcov.log --format markdown

# 结合 QEMU 地址日志推断分支结果
python -m beaconflow.cli trace-values --metadata metadata.json --address-log trace.log --format markdown

# 聚焦某个函数
python -m beaconflow.cli trace-values --metadata metadata.json --focus-function check_flag --format json

# 简洁模式
python -m beaconflow.cli trace-values --metadata metadata.json --format markdown-brief
```

输出示例：

```markdown
# BeaconFlow Value Trace

- Total compare events: 5
- Immediate compares: 3
- Input sites: 1
- Dispatcher states: 0

## Input Sites

- `check_flag:0x401020` call=`scanf` type=`stdio`

## Immediate Compares (Key Check Points)

*These compare instructions use an immediate value as the right operand, making them the most actionable check points for AI analysis.*

- `check_flag:0x401000` `CMP EAX, 0x41` type=`cmp` branch=`fail`
  - left=`EAX` right=`0x41`
```

> **提示**：`Immediate Compares` 是最有价值的输出——右操作数是常量，AI 可以直接判断"输入应该接近这个值"。结合覆盖率数据时，`branch_result` 会显示 `taken`/`fallthrough`/`fail`，帮助 AI 理解比较是否成功。

### 比较语义提取（Trace Compare）

`trace-compare` 命令专门提取程序中的"输入校验点"，输出结构化的比较语义信息。与 `trace-values` 不同，它更聚焦于比较的语义分类（cmp\_imm/cmp\_reg/test/strcmp/memcmp/switch），并区分成功/失败的比较。

```powershell
# 基本用法
python -m beaconflow.cli trace-compare --metadata metadata.json --format markdown

# 结合覆盖率数据推断比较结果
python -m beaconflow.cli trace-compare --metadata metadata.json --coverage drcov.log --format markdown

# 聚焦某个函数
python -m beaconflow.cli trace-compare --metadata metadata.json --focus-function check_flag --format json
```

输出示例：

```markdown
# BeaconFlow Trace Compare

- Total compare points: 5
- Failed compares (not_equal): 2
- Passed compares (equal): 1

## Compare Types

- `cmp_imm`: 2
- `strcmp`: 1
- `test`: 1
- `switch`: 1

## Failed Compares (Input Check Failures)

- `check_flag:0x401000` type=`cmp_imm` left=`EAX` right=`0x41`
- `check_flag:0x401010` type=`strcmp` left=`arg1` right=`arg2`
```

> **提示**：`Failed Compares` 是最有价值的输出——AI 可以直接看到哪些比较失败了，从而知道"失败原因"。对于 `cmp_imm` 类型，`right` 字段是常量，AI 可以直接判断输入应该匹配什么值。

### 环境诊断（Doctor）

`doctor` 命令检查 BeaconFlow 的所有依赖项是否可用，减少环境问题带来的使用成本。

```powershell
# 检查所有依赖
python -m beaconflow.cli doctor

# 检查特定 QEMU 架构
python -m beaconflow.cli doctor --qemu-arch loongarch64

# 检查目标文件是否存在
python -m beaconflow.cli doctor --target ./challenge.elf

# JSON 格式输出
python -m beaconflow.cli doctor --format json
```

输出示例：

```markdown
# BeaconFlow Doctor

- OK: 5
- FAIL: 1
- WARN: 3

[OK] Python: Python 3.12.0
[OK] beaconflow: beaconflow 0.1.0 importable
[WARN] IDA: IDA idat64 not in PATH
[OK] pyghidra: pyghidra installed
[OK] Ghidra: Ghidra found (C:\ghidra)
[FAIL] drrun x64: drrun x64 not found
[WARN] qemu-loongarch64: qemu-loongarch64 not found
[OK] WSL: WSL available
[OK] MCP: mcp package installed

## Action Required

- **drrun x64**: drrun x64 not found
```

> **提示**：`FAIL` 项表示必需依赖缺失，需要安装。`WARN` 项表示可选依赖未安装，相关功能不可用但不影响核心功能。

### 输入污点分析（Input Taint）

`input-taint` 命令从输入点（read/recv/scanf）出发，通过寄存器传递链追踪到比较/分支点，输出"输入偏移 → 分支"的映射。让 AI 知道"第 N 个字节影响了哪个分支"。

```powershell
# 基本用法
python -m beaconflow.cli input-taint --metadata metadata.json --format markdown

# 聚焦某个函数
python -m beaconflow.cli input-taint --metadata metadata.json --focus-function check_flag --format json
```

输出示例：

```markdown
# BeaconFlow Input Taint Analysis

- Input sources: 1
- Compare sinks: 1
- Taint edges: 1
- Input→Branch mappings: 1

## Input Sources

- `check_flag:0x401000` call=`scanf` type=`stdio` → `RAX`

## Input → Branch Mappings

- `check_flag:0x401000` → `0x401010` reg=`EBX` conf=`high`
  - source: `scanf` → sink: `CMP EBX, 0x41` left=`EBX` right=`0x41`
```

> **提示**：`Input → Branch Mappings` 是最有价值的输出——它告诉 AI 哪些输入字节影响了哪个分支决策。`confidence=high` 表示传播路径短（≤3步），结果可靠；`confidence=low` 表示路径长（≥7步），可能存在误报。

### 反馈式输入探索（Feedback Auto-Explore）

`feedback-explore` 命令根据 `trace-compare` 的失败比较结果，自动生成输入修改方案。支持多轮迭代探索策略。

```powershell
# 基本用法（自动运行 trace-compare 并生成修改方案）
python -m beaconflow.cli feedback-explore --metadata metadata.json --format markdown

# 提供当前输入文件（用于生成修改后的输入）
python -m beaconflow.cli feedback-explore --metadata metadata.json --input-file input.bin --format json

# 聚焦某个函数
python -m beaconflow.cli feedback-explore --metadata metadata.json --focus-function check_flag --format markdown
```

输出示例：

```markdown
# BeaconFlow Feedback Auto-Explore

- Status: plan_generated
- Total failed compares: 2
- Total patches: 2
- High confidence: 1
- Medium confidence: 1
- Total rounds: 2

## Round 1: immediate_fix

**Strategy**: Fix immediate value compares (cmp_imm) where the expected value is known.

| Offset | Suggested Value | Size | Compare | Confidence | Reason |
|--------|----------------|------|---------|------------|--------|
| 0 | `0x41` | 1 | `0x401000`: `CMP EAX, 0x41` | `high` | cmp_imm: make EAX == 0x41 |

## Round 2: string_compare

**Strategy**: Fix string/memory compares. Need to determine expected buffer content.
```

> **提示**：Round 1（immediate\_fix）是最可操作的——直接将输入字节设置为期望的立即数值。Round 2 和 Round 3 需要更多分析。应用补丁后，重新运行程序并使用 `trace-compare` 检查更多比较是否通过。

### 伪代码摘要导出（Decompile Function）

`decompile-function` 命令从 metadata 的 block context 中生成函数级别的伪代码摘要，让 AI 不需要完整反编译也能理解函数逻辑。

```powershell
# 按函数名导出伪代码
python -m beaconflow.cli decompile-function --metadata metadata.json --name check_flag --format markdown

# 按地址导出伪代码
python -m beaconflow.cli decompile-function --metadata metadata.json --address 0x401000 --format markdown
```

输出示例：

````markdown
# Function: check_flag

- Address: `0x401000`
- Size: 48 bytes
- Blocks: 3
- Signature: `int check_flag(arg0)`

## Pseudo Code

```c
int check_flag(arg0) {
  // entry block
  EBP = ESP;
  call scanf;
  compare(EAX, 0x41);
  if (not_equal) goto 0x401020;

  // bb_10:
  call printf;
  EAX = 0;
  return;

  // bb_20:
  call printf;
  EAX = 1;
  return;
}
````

````

> **提示**：伪代码摘要基于 block context 中的指令信息生成，不需要 IDA/Ghidra 完整反编译。对于理解函数逻辑、识别关键比较和调用关系非常有用。结合 `trace-values` 和 `trace-compare` 可以获得更完整的分析。

### 统一中间表示（Normalized IR）

`normalize-ir` 命令将不同架构的指令统一为一种 IR（中间表示），使后续分析不依赖具体架构。支持 x86/x64、ARM/AArch64、MIPS、LoongArch、RISC-V。

```powershell
# 按函数名转换
python -m beaconflow.cli normalize-ir --metadata metadata.json --name check_flag --format markdown

# 按地址转换
python -m beaconflow.cli normalize-ir --metadata metadata.json --address 0x401000 --format json
````

输出示例：

```markdown
# Normalized IR: check_flag

- Address: `0x401000`
- Blocks: 2
- Operations: {'ASSIGN': 2, 'CALL': 2, 'COMPARE': 1, 'BRANCH': 1, 'RETURN': 1}

## bb_0 (`0x401000`)

```

ASSIGN       EBP ESP              // MOV EBP, ESP
CALL         scanf                // CALL scanf
COMPARE      EAX 0x41             // CMP EAX, 0x41
BRANCH       not\_equal 0x401020   // JNE 0x401020

```
```

> **提示**：IR 将不同架构的指令统一为 ASSIGN/LOAD/STORE/COMPARE/BRANCH/CALL/RETURN/BINARY 等操作，使 AI 可以用统一的方式分析不同架构的程序。`XOR reg, reg` 会被自动优化为 `ASSIGN reg, 0`。

### 特征签名匹配（Signature Match）

`sig-match` 命令在 metadata 中匹配 crypto/VM/packer/anti-debug 特征签名，让 AI 能自动识别程序中使用的加密算法、虚拟机保护、加壳和反调试技术。

```powershell
# 基本用法
python -m beaconflow.cli sig-match --metadata metadata.json --format markdown

# 使用自定义特征库
python -m beaconflow.cli sig-match --metadata metadata.json --sig-library my_sigs.yaml --format json

# 输出到文件
python -m beaconflow.cli sig-match --metadata metadata.json --format markdown --output sig_report.md
```

输出示例：

```markdown
# BeaconFlow Signature Match

- Total matches: 5
- By category: {'crypto': 3, 'vm': 1, 'anti_debug': 1}

## CRYPTO

- `aes_encrypt:0x401000` `aes` confidence=`high`
  - name_match:aes_encrypt
  - const:0x63
  - insn:SHL ECX, 4

## VM

- `vm_dispatch:0x403000` `generic_vm` confidence=`medium`
  - name_match:vm_dispatch
  - insn:JMP [EAX+ECX*4]

## ANTI_DEBUG

- `check_debug:0x405000` `windows` confidence=`high`
  - api:IsDebuggerPresent
  - api:GetTickCount
```

识别的签名类型：

| 类别          | 签名                                                   | 说明         |
| ----------- | ---------------------------------------------------- | ---------- |
| crypto      | aes, des, rc4, tea, chacha20, sm4, hash, base64, crc | 加密/哈希/编码算法 |
| crypto      | tea\_cross\_block, chacha20\_cross\_block, ...       | 跨 block 函数级加密识别（XXTEA/BTEA 等 delta 常量分散在多个 block 时自动聚合匹配） |
| iat\_hook   | iat\_hook                                             | IAT Hook 检测（间接跳转、蹦床跳转、IAT 覆写等，适用于 EzHook 类型题目） |
| vm          | generic\_vm, vm\_stack                               | 虚拟机解释器特征   |
| packer      | upx, generic\_packer, packer\_ids                    | 加壳/解壳特征    |
| anti\_debug | windows, linux, generic                              | 反调试技术      |

> **提示**：`confidence=high` 表示匹配到 2 个以上证据（名称+常量+指令），可信度高；`confidence=medium` 表示只有 1 个证据，需要进一步确认。自定义特征库使用 YAML 格式，参考内置的 `beaconflow/analysis/sig_library.yaml`。

### 案例工作区（Case Workspace）

Case Workspace 让一个 CTF 题目或分析目标形成稳定工作区，方便 AI Agent 多轮分析而不需要每次重新猜路径、目标文件、trace 文件、metadata 文件位置。

```powershell
# 初始化工作区
python -m beaconflow.cli init-case --target ./flagchecker --arch loongarch64 --backend qemu

# 添加 metadata 文件
python -m beaconflow.cli add-metadata --name ghidra --path metadata.json --description "Ghidra metadata"

# 添加运行记录
python -m beaconflow.cli add-run --name case001 --stdin-preview "AAAA" --verdict failure --returncode 1

# 添加分析报告
python -m beaconflow.cli add-report --name flow_report --path flow.md --type flow --description "执行流分析"

# 添加笔记（AI Agent 记录分析发现）
python -m beaconflow.cli add-note --title "Round 1" --content "Found AES at 0x401000, TEA at 0x402000"

# 查看工作区状态
python -m beaconflow.cli summarize-case --format markdown

# 列出运行记录/报告/笔记
python -m beaconflow.cli list-runs
python -m beaconflow.cli list-reports
python -m beaconflow.cli list-notes

# 删除工作区
python -m beaconflow.cli destroy-case
```

工作区目录结构：

```text
.case/
  manifest.json   # 工作区清单（目标、架构、运行记录、报告、笔记）
  target          # 目标二进制文件（拷贝或符号链接）
  metadata/       # 元数据 JSON 文件
  runs/           # 运行/trace 结果
  reports/        # 分析报告
  notes/          # 用户/AI 笔记
```

manifest.json 示例：

```json
{
  "target": "./flagchecker",
  "arch": "loongarch64",
  "backend": "qemu",
  "metadata": {"ghidra": {"path": "metadata/ghidra.json"}},
  "runs": [{"name": "case001", "verdict": "failure", "stdin_preview": "AAAA"}],
  "reports": [],
  "notes": [{"title": "Round 1", "content": "Found AES at 0x401000"}]
}
```

> **提示**：AI Agent 可以在多轮分析中持续围绕同一个 case 工作。每轮分析后用 `add-note` 记录发现，用 `add-run` 记录运行结果，用 `summarize-case` 快速回顾进度。

### 运行时库函数追踪（trace-calls）

`trace-calls` 命令使用 Frida hook 运行时库函数调用（strcmp/memcmp/strncmp/strlen 等），直接提取参数值和返回值，让 AI 能看到比较了什么。

```powershell
# 追踪 strcmp/memcmp 调用
python -m beaconflow.cli trace-calls --target ./checker --stdin "AAAA" --hook strcmp,memcmp --format markdown

# 只 hook 指定函数
python -m beaconflow.cli trace-calls --target ./checker --stdin "test" --hook strcmp --format json

# 自定义超时和最大读取字节数
python -m beaconflow.cli trace-calls --target ./checker --stdin "AAAA" --timeout 60 --max-read 256
```

输出示例：

```markdown
## Key Comparisons

### strcmp @ 0x1495

- return address: `0x7ff7b5591495`
- result: **not_equal** (return=-1)

- s1: `AAAA` (hex: `41414141`)
- s2: `ISCC{test_flag}` (hex: `495343437b746573745f666c61677d`)

> **AI hint**: this call compares runtime input-like bytes with a constant-like buffer. The values differ.
```

> **提示**：`trace-calls` 需要 Frida（`pip install frida frida-tools`）。支持 Windows x64（ucrtbase.dll/msvcrt.dll）和 Linux（libc.so.6）。当 `verdict_hint` 为 `not_equal` 时，AI 可以直接看到期望值，从而构造正确输入。
>
> **重要**：`trace-calls` 默认启用 `filter_user_only=true`，只保留主模块（用户代码）调用的库函数，自动过滤 CRT/运行库内部噪声（如 C 运行库初始化时的内部 `memcmp` 调用）。如果需要查看所有调用（包括库内部调用），设置 `filter_user_only=false`。结果中还包含 `ai_hints` 字段，提供方向性建议，例如"未捕获到 strcmp/memcmp 比较，程序可能使用自定义比较逻辑"。

### 运行时比较指令追踪（trace-compare-rt）

`trace-compare-rt` 命令使用 Frida 在 cmp/test/jcc 决策点插桩，提取运行时寄存器值。

```powershell
# 自动从 metadata 找决策点
python -m beaconflow.cli trace-compare-rt --target ./checker --metadata metadata.json --stdin "AAAA" --format markdown

# 手动指定地址
python -m beaconflow.cli trace-compare-rt --target ./checker --address 0x401234,0x401250 --stdin "AAAA"

# 聚焦特定函数
python -m beaconflow.cli trace-compare-rt --target ./checker --metadata metadata.json --focus-function check_flag --stdin "AAAA"
```

> **提示**：`trace-compare-rt` 当前仅支持 x86/x64 架构。需要 Frida。

***

## 完整案例：ACTF flagchecker（LoongArch）

目标：一个 LoongArch 架构的 flagchecker，IDA 当前环境无法打开，不知道正确输入。

### 步骤 0（可选）：用 Ghidra 导出 metadata

如果有 Ghidra，可以导出更精确的 metadata（含函数名和基本块信息），替代 fallback metadata：

```powershell
pip install pyghidra
python -m beaconflow.cli export-ghidra-metadata --target D:\CTF\ACTF2026\flagchecker\flagchecker --output flagchecker_metadata.json
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

***

## 真实 CTF 题目验证

以下示例使用真实 CTF 题目验证 BeaconFlow 各项功能的实际效果。

### 示例 1：drink\_tea.exe（Newstar2024 - TEA 加密识别）

```powershell
# 1. 用 Ghidra 导出 metadata
python -m beaconflow.cli export-ghidra-metadata --target drink_tea.exe --output tea_metadata.json

# 2. 特征签名匹配 - 自动识别 TEA 加密
python -m beaconflow.cli sig-match --metadata tea_metadata.json --format markdown
```

sig-match 输出关键发现：

```markdown
## CRYPTO

- `0x140001180:0x140001236` `tea` confidence=`high`
  - insn:SHL EAX, 0x4
  - insn:SHR ECX, 0x5
  - insn:SHL EAX, 0x4
  - insn:SHR ECX, 0x5
```

```powershell
# 3. 统一 IR 转换 - 查看 TEA 函数的跨架构 IR
python -m beaconflow.cli normalize-ir --metadata tea_metadata.json --name "0x140001180" --format markdown
```

IR 输出清晰展示 TEA 算法结构：

```
  BINARY_SHL   EAX 0x4               // SHL EAX, 0x4
  BINARY_ADD   EAX dword             // ADD EAX, dword ptr [RSP + 0x14]
  BINARY_SHR   ECX 0x5               // SHR ECX, 0x5
  BINARY_XOR   EAX ECX               // XOR EAX, ECX
```

常量 `0x9e3779b9`（TEA delta）也被成功提取。

### 示例 2：vm.exe（Reverse - VM 虚拟机题）

```powershell
# 1. 导出 metadata
python -m beaconflow.cli export-ghidra-metadata --target vm.exe --output vm_metadata.json

# 2. 角色检测 - 自动定位关键函数
python -m beaconflow.cli detect-roles --metadata vm_metadata.json --format markdown
```

detect-roles 输出：

```markdown
## Roles Summary

- `validator`: 48 function(s)
- `crypto_like`: 5 function(s)
- `dispatcher`: 2 function(s)
- `input_handler`: 2 function(s)
```

### 示例 3：begin.exe（Newstar2024 - 入门 RE 题）

```powershell
# 1. 导出 metadata
python -m beaconflow.cli export-ghidra-metadata --target begin.exe --output begin_metadata.json

# 2. 伪代码摘要 - 不需要完整反编译也能理解 main 函数
python -m beaconflow.cli decompile-function --metadata begin_metadata.json --name main --format markdown
```

decompile-function 输出：

```c
int main(arg0) {
  RBP = RSP;
  RSP -= 0x20;
  call 0x00401750;
  RAX = 0x6320756f592c4b4f;    // "OK, you c"
  MOV qword ptr [0x00403010], RAX;
  RAX = 0x6b63696c63206e61;    // "an click"
  // ... 字符串拼接
  EAX = 0x0;
  return;
}
```

### 示例 4：完整 Case Workspace 工作流

```powershell
# 1. 初始化工作区
python -m beaconflow.cli init-case --target drink_tea.exe --arch x64 --backend qemu

# 2. 添加 metadata
python -m beaconflow.cli add-metadata --name ghidra --path tea_metadata.json --description "Ghidra metadata"

# 3. 运行签名匹配并保存报告
python -m beaconflow.cli sig-match --metadata tea_metadata.json --format markdown --output sig_report.md
python -m beaconflow.cli add-report --name sig_match --path sig_report.md --type sig-match --description "签名匹配报告"

# 4. 记录分析发现
python -m beaconflow.cli add-note --title "Round 1" --content "TEA encryption at 0x140001180, validator at 0x1400012e0 calls memcmp"

# 5. 查看工作区状态
python -m beaconflow.cli summarize-case --format markdown
```

summarize-case 输出：

```markdown
# BeaconFlow Case Workspace

- **Target**: `drink_tea.exe`
- **Arch**: `x64`

## Metadata (1)
- `ghidra.json`

## Reports (1)
- sig-match: 1

## Notes (1)
```

### 示例 5：ISCC2026 re3-lei（WASM + trace-calls）

```powershell
# 1. 导出 WASM metadata
python -m beaconflow.cli export-wasm-metadata --target box.wasm --output box_metadata.json

# 2. 角色检测 - 发现 VM dispatcher
python -m beaconflow.cli detect-roles --metadata box_metadata.json --format markdown
# → 5 dispatchers, 83 transformers, f84 has 83 successors (VM dispatch table)

# 3. IR 转换 - 分析 XOR 解密循环
python -m beaconflow.cli normalize-ir --metadata box_metadata.json --name f1 --format markdown
# → i32.xor with 0x10, loop 0x30 times

# 4. trace-calls - 直接捕获 flag 前缀
python -m beaconflow.cli trace-calls --target angr_harness.exe --stdin "AAAA" --hook memcmp --format markdown
```

trace-calls 输出：

```markdown
## Key Comparisons

### memcmp @ 0x2031

- result: **not_equal** (return=1)
- buf1: `..z..` (hex: `9d0d7abcaf`)
- buf2: `ISCC{` (hex: `495343437b`)
- n: `5`

> **AI hint**: this call compares runtime input-like bytes with a constant-like buffer. The values differ.
```

> **关键发现**：trace-calls 直接暴露了 flag 前缀 `ISCC{`！AI 可以立即知道输入格式和部分期望值。

***

## MCP 使用

### 启动 MCP Server

```powershell
python -m beaconflow.mcp.server
```

安装后也可以使用：

```powershell
beaconflow-mcp
```

MCP 启动路径不会自动输出更新提醒，避免污染 stdio JSON-RPC；需要检查版本时，请显式调用 `check_update` tool 或 CLI `doctor`。

### MCP 验证记录

2026-05-17 在 Windows + Python 3.13 环境中验证过 MCP tools 的 `tools/list` 和代表性 `tools/call`；随后 MCP 侧补齐了 `wasm_analyze`，当前共 45 个 tools：

- `D:\project\BeaconFlow\tests\fixtures\simple_pe.exe`：覆盖 Ghidra metadata、drcov、flow/diff、deflatten、branch-rank、decision points、Frida runtime trace、input-impact。
- `D:\CTF\ACTF2026\flagchecker\flagchecker`：覆盖 LoongArch QEMU collect/explore、address-log flow/diff、case workspace。
- `D:\CTF\ISCC2026\qu\re3-lei\box.wasm`：覆盖 WASM metadata、WASM triage report、IR、signature、role、pseudo-code。

生成的矩阵结果示例在 `D:\project\test4\mcp_runs_final\tool_matrix_summary.json`。对大型静态 ELF，MCP 版 `qemu_explore` 同样建议传入 `address_min` / `address_max`，否则后处理可能被运行库日志拖慢。

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


### 完整 MCP 配置指南（AI Agent 请仔细阅读）

以下是一份生产级 MCP 配置，包含所有推荐参数。**AI Agent 在配置时应参照此模板**：

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "C:\\Users\\YourName\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
      "args": ["-m", "beaconflow.mcp.server"],
      "timeout": 1800,
      "env": {
        "GHIDRA_INSTALL_DIR": "D:\\TOOL\\ghidra_12.0.4_PUBLIC",
        "GHIDRA_HOME": "D:\\TOOL\\ghidra_12.0.4_PUBLIC",
        "IDA_PATH": "D:\\TOOL\\ida_9.2"
      },
      "autoApprove": [
        "analyze_coverage", "diff_coverage", "analyze_flow", "diff_flow",
        "metadata_from_address_log", "record_flow", "collect_drcov",
        "collect_qemu", "qemu_explore", "export_ghidra_metadata",
        "deflatten_flow", "deflatten_merge", "recover_state_transitions",
        "branch_rank", "ai_summary", "inspect_block", "inspect_function",
        "find_decision_points", "inspect_decision_point", "detect_roles",
        "inspect_role", "trace_values", "trace_compare", "doctor",
        "input_taint", "feedback_explore", "decompile_function",
        "normalize_ir", "sig_match", "init_case", "summarize_case",
        "add_metadata_to_case", "add_run_to_case", "add_report_to_case",
        "add_note_to_case", "list_case_runs", "list_case_reports",
        "list_case_notes", "export_wasm_metadata", "wasm_analyze", "trace_calls",
        "auto_explore_loop", "input_impact", "check_update"
      ],
      "alwaysAllow": [
        "analyze_coverage", "diff_coverage", "analyze_flow", "diff_flow",
        "metadata_from_address_log", "record_flow", "collect_drcov",
        "collect_qemu", "qemu_explore", "export_ghidra_metadata",
        "deflatten_flow", "deflatten_merge", "recover_state_transitions",
        "branch_rank", "ai_summary", "inspect_block", "inspect_function",
        "find_decision_points", "inspect_decision_point", "detect_roles",
        "inspect_role", "trace_values", "trace_compare", "doctor",
        "input_taint", "feedback_explore", "decompile_function",
        "normalize_ir", "sig_match", "init_case", "summarize_case",
        "add_metadata_to_case", "add_run_to_case", "add_report_to_case",
        "add_note_to_case", "list_case_runs", "list_case_reports",
        "list_case_notes", "export_wasm_metadata", "wasm_analyze", "trace_calls",
        "auto_explore_loop", "input_impact", "check_update"
      ]
    }
  }
}
```

**配置要点**：

1. **`command`**：必须指向安装了 beaconflow 的 Python 解释器完整路径
2. **`timeout`**：建议 1800 秒（30 分钟），Ghidra 导出和 QEMU 探索可能耗时较长
3. **`env`**：必须设置以下环境变量，否则 Ghidra/IDA 相关功能无法找到安装路径：
   - `GHIDRA_INSTALL_DIR` / `GHIDRA_HOME`：Ghidra 安装目录（两者设一个即可，推荐都设）
   - `IDA_PATH`：IDA Pro 安装目录
4. **`autoApprove` / `alwaysAllow`**：建议全部添加，BeaconFlow 的工具都是只读分析型，不会修改目标文件

### 环境变量设置（AI Agent 请先执行）

在配置 MCP 之前，需要先设置系统环境变量。**Windows PowerShell 管理员模式**：

```powershell
# 设置 Ghidra 路径（替换为你的实际安装路径）
[Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", "D:\TOOL\ghidra_12.0.4_PUBLIC", "User")
[Environment]::SetEnvironmentVariable("GHIDRA_HOME", "D:\TOOL\ghidra_12.0.4_PUBLIC", "User")

# 设置 IDA 路径
[Environment]::SetEnvironmentVariable("IDA_PATH", "D:\TOOL\ida_9.2", "User")

# 将 IDA 和 Ghidra 添加到 PATH（可选，方便命令行直接调用）
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
[Environment]::SetEnvironmentVariable("PATH", "D:\TOOL\ida_9.2;D:\TOOL\ghidra_12.0.4_PUBLIC\support;$userPath", "User")
```

**Linux/macOS**：

```bash
# 添加到 ~/.bashrc 或 ~/.zshrc
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC
export GHIDRA_HOME=/opt/ghidra_12.0.4_PUBLIC
export IDA_PATH=/opt/ida-9.2
export PATH="$IDA_PATH:$GHIDRA_HOME/support:$PATH"
```

> **重要**：设置环境变量后需要重启 IDE/终端才能生效。MCP 配置中的 `env` 字段可以作为备选方案，但系统环境变量优先级更高。

### 与其他 MCP 服务器协同配置

BeaconFlow 通常与以下 MCP 服务器配合使用，建议一起配置：

| MCP 服务器 | 用途 | 配置示例 |
|-----------|------|---------|
| **ida-pro-mcp** | IDA Pro 实时反编译/重命名/类型操作 | `"command": "python", "args": ["-m", "ida_pro_mcp.server", "--ida-rpc", "http://127.0.0.1:13337"]` |
| **ghidra** | Ghidra 实时反编译/重命名 | `"command": "python", "args": ["bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:8080/"]` |
| **jeb** | JEB Android 反编译 | `"command": "uv", "args": ["run", "--directory", "D:\\TOOL\\JEB-MCP", "server.py"]` |
| **jadx** | JADX Android 反编译 | `"command": "uv", "args": ["run", "--directory", "D:\\TOOL\\jadx-mcp-server", "python", "jadx_mcp_server.py"]` |
| **x64dbg** | x64dbg 动态调试 | `"url": "http://127.0.0.1:50300/sse"` |

**典型工作流**：

1. **BeaconFlow** 做 headless 覆盖率/控制流/签名分析（不需要打开 GUI）
2. **IDA/Ghidra MCP** 做实时反编译和交互式分析（需要打开 GUI 并启动 MCP 插件）
3. **x64dbg MCP** 做动态调试（需要运行 x64dbg 并启动 MCP 插件）

三者互补：BeaconFlow 擅长批量分析和路径探索，IDA/Ghidra MCP 擅长单点深挖，x64dbg 擅长运行时断点调试。
### 当前 MCP Tools

| 工具                          | 用途                                                         |
| --------------------------- | ---------------------------------------------------------- |
| `collect_drcov`             | 用 DynamoRIO 采集 drcov 覆盖率                                   |
| `collect_qemu`              | 用 QEMU 采集单次执行 trace                                        |
| `qemu_explore`              | 多输入并行探索，分类 verdict，排名路径新颖性                                 |
| `analyze_coverage`          | 分析 drcov 覆盖率                                               |
| `analyze_flow`              | 恢复有序执行流                                                    |
| `record_flow`               | 一步运行并返回执行流                                                 |
| `diff_coverage`             | 函数级覆盖率对比                                                   |
| `diff_flow`                 | 块级/边级执行流对比                                                 |
| `metadata_from_address_log` | 从地址日志聚类生成 fallback metadata                                |
| `branch_rank`               | 对 bad/better/good trace 排名输入相关分支点                          |
| `inspect_block`             | 查看单个基本块的详细上下文（指令、调用、字符串等）                                  |
| `inspect_function`          | 查看函数及其所有基本块的详细上下文                                          |
| `find_decision_points`      | 查找并优先排序决策点（cmp+jcc、checker calls、cmovcc、setcc、jump tables） |
| `inspect_decision_point`    | 查看单个决策点的详细信息                                               |
| `detect_roles`              | 检测函数角色（validator、crypto、dispatcher、input\_handler 等）       |
| `inspect_role`              | 查看单个函数的角色详情                                                |
| `trace_values`              | 追踪关键比较点的寄存器/内存/比较值                                         |
| `trace_compare`             | 提取比较语义（cmp/strcmp/memcmp/switch）                           |
| `doctor`                    | 环境诊断                                                       |
| `input_taint`               | 轻量污点分析：输入字节到分支的追踪                                          |
| `feedback_explore`          | 反馈式输入探索：自动生成输入修改方案                                         |
| `decompile_function`        | 伪代码摘要导出                                                    |
| `normalize_ir`              | 统一中间表示（跨架构指令归一化）                                           |
| `sig_match`                 | 特征签名匹配（crypto/VM/packer/anti-debug）                        |
| `init_case`                 | 初始化案例工作区                                                   |
| `summarize_case`            | 汇总案例工作区状态                                                  |
| `add_metadata_to_case`      | 向工作区添加 metadata 文件                                         |
| `add_run_to_case`           | 向工作区添加运行记录                                                 |
| `add_report_to_case`        | 向工作区添加分析报告                                                 |
| `add_note_to_case`          | 向工作区添加笔记                                                   |
| `list_case_runs`            | 列出工作区中的运行记录                                                |
| `list_case_reports`         | 列出工作区中的报告                                                  |
| `list_case_notes`           | 列出工作区中的笔记                                                  |
| `export_wasm_metadata`      | 从 WASM 文件导出 metadata（纯 Python 解析器）                         |
| `wasm_analyze`              | 生成 WASM triage 报告（imports/exports/strings/data/functions）       |
| `trace_calls`               | 运行时库函数参数提取（Frida hook strcmp/memcmp/strlen 等），默认过滤 CRT 噪声 |
| `auto_explore_loop`         | 多轮反馈式输入探索，保留更优输入并持续变异                               |
| `input_impact`              | 黑盒差分输入影响分析，逐位扰动观察输出变化                               |
| `check_update`              | 检查 GitHub 是否有新版本（非强制，1 小时缓存）                           |
| `trace_compare_rt`          | 运行时比较指令值提取（Frida hook cmp/test/jcc）                        |

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

返回包含 summary 和每个 case 的 verdict、unique\_blocks、new\_blocks\_vs\_baseline、new\_blocks\_global、output\_fingerprint。

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

### `inspect_block`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "address": "0x1400014c7",
  "format": "markdown"
}
```

返回指定基本块的完整上下文：指令、调用、字符串、常量、数据/代码引用、前驱/后继。

### `inspect_function`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "name": "check_flag",
  "format": "markdown"
}
```

或按地址查找：

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "address": "0x140001460",
  "format": "markdown"
}
```

返回函数及其所有基本块的完整上下文。

### `find_decision_points`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "focus_function": "check_flag",
  "format": "json"
}
```

返回所有决策点，按 AI 优先级排序（critical > high > medium > low）。每个决策点包含类型、比较/分支指令、调用函数、后继块、优先级和原因。

### `inspect_decision_point`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "address": "0x401010",
  "format": "markdown"
}
```

返回指定地址的决策点详情，包含类型、优先级、比较/分支指令、后继块和关联的 block context。

### `detect_roles`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "focus_function": "check_flag",
  "min_score": 0.1,
  "format": "json"
}
```

返回所有函数的角色检测结果，按分数降序排列。每个结果包含角色、置信度、分数、证据、匹配规则和推荐操作。

### `inspect_role`

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "function_name": "check_flag",
  "format": "markdown"
}
```

返回指定函数的角色详情，包含角色、置信度、证据、推荐操作和关联信息。

***

## 自测试

```powershell
python tests\smoke_beaconflow.py
python -m unittest discover -s tests -p "test*.py"
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

`-d in_asm` 更像翻译块日志，hit count 不应当当作精确循环次数。BeaconFlow 在 `in_asm` 模式下会将报告中的 "hits" 标注为 "translations"（翻译次数），以避免误解。需要精确执行次数时用 `-d exec,nochain`。

**两种 trace 模式对比**：

| 模式             | 命令参数              | 记录内容     | 粒度        | 日志大小 | 适用场景                            |
| -------------- | ----------------- | -------- | --------- | ---- | ------------------------------- |
| `in_asm`       | `-d in_asm`       | 基本块首次翻译  | 粗（每块一次）   | 小    | 快速浏览执行流、函数级分析                   |
| `exec,nochain` | `-d exec,nochain` | 每条指令每次执行 | 细（每条指令每次） | 大    | 反平坦化、dispatcher 识别、精确 hit count |

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

### Ghidra 导出时出现 "Module manifest file error" 警告怎么办？

如果安装了 GhidraMCP 扩展，Ghidra 12 可能会报 `Module manifest file error` 警告。这是因为 GhidraMCP 的 `Module.manifest` 格式不符合 Ghidra 12 的要求。修复方法：

```powershell
# 找到 GhidraMCP 的 Module.manifest 文件
# 通常在 <GHIDRA_INSTALL_DIR>/Ghidra/Extensions/GhidraMCP/Module.manifest
# 将内容替换为：
#   MODULE FILE LICENSE: lib/GhidraMCP.jar Apache License 2.0
```

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
