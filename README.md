# BeaconFlow

BeaconFlow 是一个面向 AI Agent 的 headless IDA 覆盖率与控制流分析工具。

它的目标不是替代 IDA，而是让 AI 在不打开 IDA 图形界面的情况下，读取 IDA 的函数、基本块、CFG 信息，并结合 `drcov` 覆盖率文件快速回答：

- 哪些函数被运行过
- 哪些基本块被覆盖
- 程序这一次实际走过的基本块流程
- 实际出现过的基本块转移边
- 哪些函数没有跑到
- 两次运行触发了哪些不同路径
- 后续哪些函数值得重点分析或 fuzz

当前版本包含 CLI、MCP Server、IDA headless 导出脚本和一个可选 skill。

## 项目结构

```text
beaconflow/
  analysis/      覆盖率映射、覆盖率 diff、后续控制流分析逻辑
  coverage/      覆盖率文件解析，目前支持 DynamoRIO drcov
  ida/           IDA 导出的 metadata 读取逻辑
  mcp/           MCP stdio server
  reports/       Markdown 报告生成
  cli.py         命令行入口
  models.py      核心数据结构

ida_scripts/
  export_ida_metadata.py   用 idat64 -A 运行的 IDA metadata 导出脚本

skills/
  beaconflow/SKILL.md      可选的 AI skill 说明
```

## 环境要求

- Python 3.10 或更高版本
- IDA Pro，需能使用 `idat64` 或 `ida64 -A`
- DynamoRIO `drcov` 覆盖率文件，或兼容 drcov 格式的覆盖率文件

仓库已内置一份 Windows 版 DynamoRIO/drcov，路径为：

```text
third_party/dynamorio
```

对应许可证文件保留在：

```text
third_party/dynamorio/License.txt
third_party/dynamorio/ACKNOWLEDGEMENTS
```

可选：

- 支持 MCP 的 AI 客户端，例如 Codex、Claude Desktop 或其他 MCP host

## 安装

在项目根目录执行：

```powershell
python -m pip install -e .
```

如果你要作为 MCP Server 使用，也可以安装 MCP 依赖：

```powershell
python -m pip install -e ".[mcp]"
```

当前 MCP Server 使用的是轻量 stdio JSON-RPC 实现，不强依赖 `mcp` 包；后续如果改成官方 SDK，可以直接复用这个 optional dependency。

## 第一步：导出 IDA metadata

BeaconFlow 不直接依赖 IDA UI。你需要先用 IDA headless 模式导出函数、基本块和 CFG 信息：

```powershell
idat64 -A -S"ida_scripts/export_ida_metadata.py metadata.json" target.exe
```

如果 `idat64` 不在 `PATH` 里，请使用完整路径，例如：

```powershell
& "C:\Program Files\IDA Professional 9.0\idat64.exe" -A -S"ida_scripts/export_ida_metadata.py metadata.json" target.exe
```

导出的 `metadata.json` 大致包含：

```json
{
  "input_path": "target.exe",
  "image_base": "0x140001000",
  "functions": [
    {
      "name": "sub_140001000",
      "start": "0x140001000",
      "end": "0x140001050",
      "blocks": [
        {
          "start": "0x140001000",
          "end": "0x140001020",
          "succs": ["0x140001030"]
        }
      ]
    }
  ]
}
```

## 第二步：准备覆盖率文件

当前支持 DynamoRIO `drcov` 文件。示例：

```powershell
drrun.exe -t drcov -dump_text -- target.exe input.bin
```

如果使用 BeaconFlow 内置的 DynamoRIO，可以直接执行：

```powershell
python -m beaconflow.cli collect --target target.exe --output-dir runs -- input.bin
```

生成后会输出 drcov 日志路径，例如：

```text
runs\drcov.target.exe.1234.0000.log
```

不同 DynamoRIO 版本输出路径可能不同，常见文件名类似：

```text
drcov.target.exe.<pid>.<tid>.log
```

只要文件是 drcov 格式，就可以交给 BeaconFlow 分析。

BeaconFlow 会保留 drcov BB Table 中记录的基本块顺序，用于恢复“这一次运行实际走过的流程”。这对控制流平坦化很有用：AI 可以先看真实执行流和真实转移边，减少静态 CFG 里大量未走路径的干扰。

注意：当前执行流来自 drcov 记录的基本块序列，适合做路径还原、覆盖路径筛选、平坦化 dispatcher 观察。若后续需要寄存器值、内存值或分支条件，需要再接入更强的 trace，例如 Tenet trace、Frida stalker、Pin 或 DynamoRIO 自定义插桩。

## CLI 使用

### 采集 drcov 覆盖率

使用内置 DynamoRIO：

```powershell
python -m beaconflow.cli collect --target target.exe --output-dir runs -- arg1 arg2
```

指定 32 位目标：

```powershell
python -m beaconflow.cli collect --arch x86 --target target32.exe --output-dir runs -- arg1
```

指定自定义 `drrun.exe`：

```powershell
python -m beaconflow.cli collect --drrun "D:\DynamoRIO\bin64\drrun.exe" --target target.exe --output-dir runs -- arg1
```

### 分析单次覆盖率

输出 JSON：

```powershell
python -m beaconflow.cli analyze --metadata metadata.json --coverage sample.drcov
```

输出 Markdown 报告：

```powershell
python -m beaconflow.cli analyze --metadata metadata.json --coverage sample.drcov --format markdown
```

写入文件：

```powershell
python -m beaconflow.cli analyze --metadata metadata.json --coverage sample.drcov --format markdown --output report.md
```

也可以使用安装后的命令：

```powershell
beaconflow analyze --metadata metadata.json --coverage sample.drcov --format markdown
```

### 恢复一次运行的执行流

如果已经有 drcov 文件：

```powershell
python -m beaconflow.cli flow --metadata metadata.json --coverage sample.drcov --output flow.json
```

输出里包含：

- `ai_report`：给 AI 直接阅读的执行流摘要、关键块、平坦化提示和下一步建议
- `function_order`：这一次运行中按首次出现顺序进入过的函数
- `flow`：按顺序压缩后的基本块流程
- `transitions`：实际出现过的基本块转移边和次数
- `hot_blocks`：命中次数最多的基本块

默认会记录完整流程。如果只想预览前 N 个流程事件，可以加：

```powershell
--max-events 500
```

### 一步运行程序并记录流程

```powershell
python -m beaconflow.cli record-flow --metadata metadata.json --target target.exe --output-dir runs --output flow.json -- input.bin
```

这个命令会：

1. 用内置 DynamoRIO/drcov 跑一遍目标程序
2. 生成 drcov 文件
3. 立即映射到 IDA metadata
4. 输出这一次真实走过的函数、基本块和转移边

这就是给 AI 解决平坦化时用的核心入口。AI 可以先看 `flow.json`，只分析真实路径，再回到 IDA metadata 中定位相关函数和块。

如果想让结果更适合直接阅读，可以输出 Markdown：

```powershell
python -m beaconflow.cli record-flow --metadata metadata.json --target target.exe --output-dir runs --format markdown --output flow.md -- input.bin
```

给 AI 使用时，推荐优先读取：

```text
ai_report.how_to_use
ai_report.function_order_text
ai_report.execution_spine_preview
ai_report.dispatcher_candidates
ai_report.branch_points
ai_report.join_points
ai_report.loop_like_edges
ai_report.next_steps
```

完整的 `flow` 和 `transitions` 作为定位细节使用，不建议一开始就让 AI 从完整列表里人工归纳。

### 比较两次运行

```powershell
python -m beaconflow.cli diff --metadata metadata.json --left input_a.drcov --right input_b.drcov
```

这个命令用于回答：

- A 输入跑到了哪些函数，B 没跑到
- B 输入跑到了哪些函数，A 没跑到
- 两个输入共同覆盖了哪些函数

## 自测试

仓库提供了一个 smoke 测试脚本，会自动完成以下事情：

1. 使用 MinGW 编译 `tests/fixtures/simple_pe.c` 生成一个最小 Windows PE
2. 使用本仓库内置的 DynamoRIO `drrun.exe -t drcov` 运行这个 PE 并生成真实 drcov
3. 构造最小 metadata，并用 BeaconFlow 验证覆盖率命中
4. 恢复本次运行的基本块执行流，并验证真实转移边

执行：

```powershell
python tests\smoke_beaconflow.py
```

成功时会看到类似输出：

```text
{
  "covered_functions": 1,
  "total_functions": 1,
  "covered_basic_blocks": 1,
  "total_basic_blocks": 1
}
```

测试生成物位于：

```text
tests/fixtures/simple_pe.exe
tests/fixtures/simple_pe.drcov.log
tests/fixtures/simple_pe.metadata.json
tests/fixtures/simple_pe.flow.metadata.json
```

这些文件默认被 `.gitignore` 忽略。

## MCP 使用

启动 MCP Server：

```powershell
python -m beaconflow.mcp.server
```

安装后也可以使用：

```powershell
beaconflow-mcp
```

当前 MCP tools：

- `collect_drcov`
- `analyze_coverage`
- `analyze_flow`
- `record_flow`
- `diff_coverage`

### `collect_drcov`

参数：

```json
{
  "target_path": "D:\\project\\case\\target.exe",
  "target_args": ["input.bin"],
  "output_dir": "D:\\project\\case\\runs",
  "arch": "x64"
}
```

返回：

```json
{
  "coverage_path": "D:\\project\\case\\runs\\drcov.target.exe.1234.0000.log"
}
```

### `analyze_flow`

参数：

```json
{
  "metadata_path": "D:\\project\\case\\metadata.json",
  "coverage_path": "D:\\project\\case\\runs\\drcov.target.exe.1234.0000.log",
  "max_events": 0,
  "format": "json"
}
```

返回这一次运行中目标模块的有序基本块流程、函数首次出现顺序、热块和实际转移边。

### `record_flow`

参数：

```json
{
  "metadata_path": "D:\\project\\case\\metadata.json",
  "target_path": "D:\\project\\case\\target.exe",
  "target_args": ["input.bin"],
  "output_dir": "D:\\project\\case\\runs",
  "arch": "x64",
  "max_events": 0,
  "format": "json"
}
```

这是推荐给 AI 使用的入口：跑一次程序并直接返回执行流报告。

如果 MCP 客户端更适合读取自然语言报告，把 `format` 改成：

```json
{
  "format": "markdown"
}
```

### `analyze_coverage`

参数：

```json
{
  "metadata_path": "D:\\project\\case\\metadata.json",
  "coverage_path": "D:\\project\\case\\sample.drcov",
  "format": "markdown"
}
```

返回内容包括：

- 覆盖函数数量
- 总函数数量
- 覆盖基本块数量
- 总基本块数量
- 已覆盖函数列表
- 未覆盖函数列表
- 每个函数的基本块覆盖比例

### `diff_coverage`

参数：

```json
{
  "metadata_path": "D:\\project\\case\\metadata.json",
  "left_coverage_path": "D:\\project\\case\\input_a.drcov",
  "right_coverage_path": "D:\\project\\case\\input_b.drcov"
}
```

返回内容包括：

- 左侧覆盖摘要
- 右侧覆盖摘要
- 只在左侧运行中覆盖的函数
- 只在右侧运行中覆盖的函数
- 两侧都覆盖的函数

## MCP 客户端配置示例

不同 AI 客户端的配置文件位置不一样，但 MCP server 配置通常长这样：

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "python",
      "args": [
        "-m",
        "beaconflow.mcp.server"
      ],
      "cwd": "D:\\project\\控制流分析AI版"
    }
  }
}
```

如果你已经执行过 `python -m pip install -e .`，也可以配置为：

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "beaconflow-mcp",
      "args": [],
      "cwd": "D:\\project\\控制流分析AI版"
    }
  }
}
```

如果客户端启动时找不到 Python 或包，优先使用完整路径：

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "C:\\Users\\YourName\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
      "args": [
        "-m",
        "beaconflow.mcp.server"
      ],
      "cwd": "D:\\project\\控制流分析AI版"
    }
  }
}
```

## Skill 使用

仓库里带了一个可选 skill：

```text
skills/beaconflow/SKILL.md
```

它不是核心能力，只是告诉 AI 遇到覆盖率、控制流、路径 diff、反平坦化辅助分析时应该怎么调用 BeaconFlow。

如果你的 AI 客户端支持 skills，可以把 `skills/beaconflow` 复制或链接到对应的 skills 目录。核心分析仍然建议通过 MCP 调用完成。

## 常见问题

### BeaconFlow 需要打开 IDA 界面吗？

不需要。使用 `idat64 -A` 或 `ida64 -A` 即可在 headless 模式导出 metadata。

### 只给 drcov 文件能分析吗？

不够。`drcov` 里主要是模块和基本块偏移，BeaconFlow 还需要 IDA 导出的函数和 CFG 信息，才能告诉 AI 这些覆盖率对应哪些函数和基本块。

### 能分析运行顺序吗？

当前可以基于 drcov BB Table 恢复一次运行中观察到的基本块顺序，并输出实际转移边。它适合回答“这次到底走过哪些流程”。

如果要进一步知道寄存器值、内存值、状态变量值、分支条件，则需要后续新增更强的 trace 后端。

### 能做反平坦化吗？

当前版本提供覆盖率和 CFG 映射基础。反平坦化建议下一步增加：

- dispatcher 候选识别
- state variable 候选识别
- 多输入 coverage diff
- 基于 `record-flow` 的真实路径过滤
- basic-block trace 运行状态恢复
- flattened CFG 还原报告

## 后续开发方向

- 增加 trace 文件解析和 `analyze_trace`
- 增加函数调用顺序统计
- 增加反平坦化候选检测
- 增加 IDA metadata 缓存
- 增加 HTML 报告
- 增加对 Frida/Pin/Tenet trace 的读取

## 致谢

BeaconFlow 的设计参考了 IDA 覆盖率插件 Lighthouse 的思路，并沿用了覆盖率分析中常见的 DynamoRIO/drcov 工作流。项目内置的第三方组件许可证见：

```text
third_party/dynamorio/License.txt
third_party/dynamorio/ACKNOWLEDGEMENTS
```
