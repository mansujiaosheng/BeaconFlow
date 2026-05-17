# BeaconFlow API 使用与开发文档

面向两类人：

- 对接方：把 BeaconFlow 接入 Codex、Claude Desktop、自研 Agent、脚本流水线。
- 开发方：给 BeaconFlow 增加新的 CLI/MCP 工具、分析模块或报告输出。

当前验证环境：`D:\project\BeaconFlow`，Python 3.13，2026-05-17 已完成 MCP tools 的矩阵测试；当前 MCP 暴露 45 个 tools。

## 1. 安装与启动

```powershell
cd D:\project\BeaconFlow
python -m pip install -e ".[mcp]"
python -m beaconflow.cli doctor --format markdown
```

启动 MCP server：

```powershell
python -m beaconflow.mcp.server
```

安装后也可以：

```powershell
beaconflow-mcp
```

MCP server 是 stdio JSON-RPC，每行一个 JSON request，每行一个 JSON response。
启动路径不会自动打印更新提醒；需要版本检查时显式调用 `check_update`，避免污染 stdio 协议流。

## 2. MCP 对接协议

### 初始化

请求：

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

典型响应：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}, "resources": {}},
    "serverInfo": {"name": "beaconflow", "version": "0.1.0"}
  }
}
```

### 列工具

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

响应里的 `result.tools[]` 来自 `beaconflow\mcp\server.py` 的 `TOOLS` 字典。每个工具包含：

- `name`
- `description`
- `inputSchema`

对接方应优先使用 `inputSchema.required` 和 `properties` 自动生成表单或参数校验，不要硬编码旧参数名。

### 调工具

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "analyze_flow",
    "arguments": {
      "metadata_path": "D:\\case\\metadata.json",
      "coverage_path": "D:\\case\\run.drcov.log",
      "format": "markdown"
    }
  }
}
```

响应格式统一为：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {"type": "text", "text": "..."}
    ]
  }
}
```

`text` 可能是 Markdown，也可能是 JSON 字符串，取决于工具和 `format` 参数。Agent 侧建议先尝试按 JSON 解析，失败时按 Markdown 处理。

## 3. 客户端配置示例

```json
{
  "mcpServers": {
    "beaconflow": {
      "command": "python",
      "args": ["-m", "beaconflow.mcp.server"],
      "cwd": "D:\\project\\BeaconFlow",
      "timeout": 1800,
      "env": {
        "GHIDRA_INSTALL_DIR": "D:\\TOOL\\ghidra_12.0.4_PUBLIC",
        "GHIDRA_HOME": "D:\\TOOL\\ghidra_12.0.4_PUBLIC",
        "JAVA_HOME": "C:\\Program Files\\Java\\jdk-24"
      }
    }
  }
}
```

如果客户端找不到 `python`，把 `command` 改成完整路径，例如：

```json
"command": "C:\\Program Files\\Python313\\python.exe"
```

## 4. 常用工具分组

### 环境与更新

| Tool | 用途 |
| --- | --- |
| `doctor` | 检查 Python、BeaconFlow、IDA、Ghidra、DynamoRIO、QEMU、WSL、MCP、PyYAML |
| `check_update` | 检查 GitHub 是否有新版本；网络不可达时不应视为失败 |

### Metadata

| Tool | 用途 |
| --- | --- |
| `export_ghidra_metadata` | 用 Ghidra/pyghidra 导出函数、基本块、CFG metadata |
| `export_wasm_metadata` | 用纯 Python 解析 WASM metadata |
| `wasm_analyze` | 生成 WASM triage 报告：imports、exports、strings、data segments、function summaries |
| `metadata_from_address_log` | 从 QEMU address log 聚类生成 fallback metadata |

### 覆盖率与执行流

| Tool | 用途 |
| --- | --- |
| `collect_drcov` | Windows PE 或 WSL ELF 的 DynamoRIO drcov 采集 |
| `record_flow` | 采集 drcov 并直接输出 flow |
| `analyze_coverage` | drcov 到函数/基本块覆盖率映射 |
| `diff_coverage` | 两个 drcov 覆盖率差分 |
| `analyze_flow` | drcov 或 QEMU address log 到有序执行流 |
| `diff_flow` | 两条执行流的 block/edge 差分 |

### QEMU 探索

| Tool | 用途 |
| --- | --- |
| `collect_qemu` | 单个输入的 QEMU user-mode trace |
| `qemu_explore` | 多输入并行 trace、verdict 分类、路径新颖性排序 |

大型静态 ELF 必须优先传 `address_min` / `address_max`，否则会把运行库和启动代码纳入聚类，后处理可能非常慢。

### 反平坦化与分支排序

| Tool | 用途 |
| --- | --- |
| `deflatten_flow` | 单 trace 识别 dispatcher，恢复真实执行边 |
| `deflatten_merge` | 合并多 trace 的反平坦化结果 |
| `recover_state_transitions` | 从多 trace 恢复 state transition 表 |
| `branch_rank` | 用 bad/better/good trace 排序输入相关分支 |

`branch_rank` 参数不是 `coverage_paths` 风格。必须给基线：

```json
{
  "metadata_path": "D:\\case\\metadata.json",
  "bad_coverage_path": "D:\\case\\wrong.drcov.log",
  "better_coverage_paths": ["D:\\case\\almost.drcov.log"],
  "good_coverage_paths": ["D:\\case\\correct.drcov.log"],
  "format": "markdown"
}
```

QEMU log 对应参数是 `bad_address_log_path`、`better_address_log_paths`、`good_address_log_paths`。

### 静态理解

| Tool | 用途 |
| --- | --- |
| `inspect_block` | 查看一个基本块的指令、调用、常量、引用、前后继 |
| `inspect_function` | 查看一个函数及全部基本块 |
| `find_decision_points` | 找 cmp/test/call/jump-table 等决策点 |
| `inspect_decision_point` | 深入一个决策点 |
| `detect_roles` | 识别 validator、crypto、dispatcher、handler 等函数角色 |
| `inspect_role` | 查看某函数角色证据 |
| `trace_values` | 从 metadata/coverage 推断 compare/value 证据 |
| `analyze_compare` | 静态比较语义分析 |
| `input_taint` | 轻量输入到分支的静态 taint |
| `feedback_explore` | 基于失败 compare 生成输入修改建议 |
| `decompile_function` | 基于 metadata 生成伪代码摘要 |
| `normalize_ir` | 生成架构无关 IR |
| `sig_match` | crypto/VM/packer/anti-debug 签名匹配 |
| `ai_summary` | 压缩大型 JSON 报告供 Agent 快读 |

### Runtime Frida

| Tool | 用途 |
| --- | --- |
| `trace_calls` | hook `strcmp/memcmp/strncmp/strlen` 等库函数 |
| `trace_compare` | x86/x64 运行时 cmp/test/jcc 寄存器值跟踪 |

注意：CLI 里运行时 compare 命令叫 `trace-compare-rt`，MCP tool 名是 `trace_compare`；静态 compare MCP tool 是 `analyze_compare`。

### Case Workspace

| Tool | 用途 |
| --- | --- |
| `init_case` | 初始化 `.case` 工作区 |
| `add_metadata_to_case` | 加 metadata |
| `add_run_to_case` | 加运行/trace |
| `add_report_to_case` | 加报告 |
| `add_note_to_case` | 加分析笔记 |
| `summarize_case` | 汇总工作区 |
| `list_case_runs` | 列 run |
| `list_case_reports` | 列 report |
| `list_case_notes` | 列 note |

## 5. Python API 用法

BeaconFlow 内部模块可以直接被 Python 调用。适合写测试、批处理或构建自己的服务层。

### 分析 drcov

```python
from beaconflow.ida import load_metadata
from beaconflow.coverage import load_drcov
from beaconflow.analysis import analyze_coverage, analyze_flow

metadata = load_metadata(r"D:\case\metadata.json")
coverage = load_drcov(r"D:\case\run.drcov.log")

coverage_report = analyze_coverage(metadata, coverage)
flow_report = analyze_flow(metadata, coverage)
```

### 分析 QEMU address log

```python
from beaconflow.ida import load_metadata
from beaconflow.coverage import load_address_log
from beaconflow.analysis import analyze_flow

metadata = load_metadata(r"D:\case\metadata.json")
trace = load_address_log(
    r"D:\case\wrong.in_asm.qemu.log",
    min_address=int("0x220000", 16),
    max_address=int("0x244000", 16),
)

report = analyze_flow(metadata, trace)
```

### 导出 Ghidra metadata

```python
from beaconflow.ghidra import export_ghidra_metadata

result = export_ghidra_metadata(
    target=r"D:\case\target.exe",
    output=r"D:\case\metadata.json",
    backend="pyghidra",
    timeout=600,
)
```

### 采集覆盖率

```python
from beaconflow.coverage.runner import collect_drcov

result = collect_drcov(
    target=r"D:\case\target.exe",
    output_dir=r"D:\case\runs",
    target_args=["beta"],
    arch="x64",
)
print(result.log_path)
```

### 通过 MCP 函数本地调用

开发测试时可直接调用 `_call_tool`，不必启动子进程：

```python
from beaconflow.mcp.server import _call_tool

res = _call_tool("doctor", {"format": "markdown"})
print(res["content"][0]["text"])
```

这是内部测试方式，不建议第三方长期依赖 `_call_tool` 私有函数；正式对接应走 JSON-RPC。

## 6. CLI 与 MCP 的对应关系

CLI 用短横线，MCP 用下划线：

| CLI | MCP |
| --- | --- |
| `quickstart-pe` | CLI only |
| `quickstart-qemu` | CLI only |
| `quickstart-flatten` | CLI only |
| `analyze` | `analyze_coverage` |
| `diff` | `diff_coverage` |
| `flow` | `analyze_flow` |
| `flow-diff` | `diff_flow` |
| `collect` | `collect_drcov` |
| `collect-qemu` | `collect_qemu` |
| `qemu-explore` | `qemu_explore` |
| `metadata-from-address-log` | `metadata_from_address_log` |
| `export-ghidra-metadata` | `export_ghidra_metadata` |
| `export-wasm-metadata` | `export_wasm_metadata` |
| `wasm-analyze` | `wasm_analyze` |
| `find-decision-points` | `find_decision_points` |
| `trace-compare` | `analyze_compare` |
| `trace-compare-rt` | `trace_compare` |
| `init-case` | `init_case` |
| `add-metadata` | `add_metadata_to_case` |
| `add-run` | `add_run_to_case` |
| `add-report` | `add_report_to_case` |
| `add-note` | `add_note_to_case` |

Quickstart 命令是面向人和 Agent 的高层编排入口，会在输出目录生成多个底层报告；MCP 侧仍保持工具粒度，方便客户端按步骤组合。

## 7. 开发目录结构

核心目录：

```text
beaconflow/
  analysis/      分析逻辑：flow、diff、deflatten、IR、roles、taint、compare
  coverage/      drcov/QEMU 采集与解析
  ghidra/        Ghidra metadata/decompile 封装
  ida/           metadata schema 加载与保存
  metadata/      address log fallback metadata
  mcp/server.py  MCP tool schema、调度、stdio JSON-RPC
  reports/       Markdown 报告渲染
  runtime/       Frida runtime tracing
  cli.py         argparse CLI 入口
  workspace.py   case workspace
```

## 8. 新增一个 MCP 工具

建议步骤：

1. 在合适模块里实现纯 Python 函数，返回 `dict`，不要直接 print。
2. 在 `beaconflow\reports` 增加 Markdown renderer，复杂报告要包含 `summary`、`data_quality`、`ai_digest` 或可读的 top findings。
3. 在 `beaconflow\cli.py` 增加 CLI 子命令，保证命令行能独立跑。
4. 在 `beaconflow\mcp\server.py` 的 `TOOLS` 增加 schema。
5. 在 `_call_tool` 增加分支，把 JSON 参数转换为内部函数调用。
6. 增加或更新 `tests`，至少覆盖一个成功路径和一个参数错误路径。
7. 跑 smoke 和 MCP 单工具调用。

MCP tool 分支返回值应使用 `_tool_result(...)`：

```python
if name == "new_tool":
    result = new_tool_impl(arguments["target_path"])
    if arguments.get("format") == "markdown":
        return _tool_result(new_tool_to_markdown(result))
    return _tool_result(result)
```

schema 示例：

```python
"new_tool": {
    "description": "Short action-oriented description.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target_path": {"type": "string"},
            "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"}
        },
        "required": ["target_path"]
    }
}
```

## 9. 测试建议

基础验证：

```powershell
python -m beaconflow.cli --help
python -m beaconflow.cli doctor --format markdown
python tests\smoke_beaconflow.py
```

MCP 协议 smoke：

```powershell
$req = @(
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
) -join "`n"
$req + "`n" | python -m beaconflow.mcp.server
```

单工具调用 smoke：

```powershell
@'
from beaconflow.mcp.server import _call_tool
res = _call_tool("doctor", {"format": "markdown"})
print(res["content"][0]["text"])
'@ | python -
```

完整矩阵测试可参考：

`D:\project\test4\mcp_runs_final\tool_matrix_summary.json`

## 10. 对接方错误处理建议

- 如果 `tools/call` 返回 JSON-RPC `error`，视为协议或未捕获异常。
- 如果 `result.content[0].text` 是 `# Error` 或包含 `{"status":"error"}`，视为业务失败。
- 对 `check_update` 的网络失败只做 warning，不阻塞主流程。
- 优先读取 `report_confidence`。`level=medium/low` 时只能把报告当作 triage 排序，关键结论必须回到反汇编、伪代码或更强 trace 交叉验证。
- 对 QEMU `in_asm` 报告，必须检查 `data_quality.hit_count_precision`；值为 `translation-log` 时，不要把 hit count 当精确循环次数。
- 对大型 address log，优先检查 `summary.auto_address_range` 或手工传 `address_min/address_max`，再做 `qemu_explore`、`metadata_from_address_log`、`diff_flow`。`qemu_explore` 和 `metadata_from_address_log` 默认会从 ELF executable `PT_LOAD` 段自动推断范围；如果静态库代码仍太多，客户端应提示用户手工收窄。
- 对 Frida 工具，零事件不一定是失败，可能是目标没调用被 hook 函数、地址不对或进程过快退出。

## 11. 推荐的 Agent 工作流

1. `doctor` 检查环境。
2. 生成或加载 metadata：Ghidra/IDA/WASM/address-log fallback。
3. 采集一条 baseline：`collect_drcov` 或 `collect_qemu`。
4. `analyze_flow` 看实际执行流。
5. 多输入时跑 `diff_flow` 或 `qemu_explore`。
6. 对可疑函数跑 `inspect_function`、`find_decision_points`、`analyze_compare`、`normalize_ir`、`sig_match`。
7. 对平坦化目标跑 `deflatten_flow`、`deflatten_merge`、`recover_state_transitions`。
8. 用 `init_case` / `add_note_to_case` 持久化中间证据。

## 12. 开发与 CI

提交前至少运行：

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m beaconflow.cli --help
python tests\smoke_beaconflow.py
```

CI 在 `.github/workflows/ci.yml` 中定义：

- Ubuntu/Windows x Python 3.10/3.12：安装 `.[mcp]`、`compileall`、单元测试、CLI help。
- Windows smoke：安装 MinGW，运行 `tests\smoke_beaconflow.py`，覆盖 PE 生成、DynamoRIO drcov、coverage/flow 分析。

新增 MCP 工具或报告字段时，同步更新 `TOOLS` schema、CLI parser、README/API 文档，并在 `tests/test_core.py` 增加 schema 或 report shape 断言。
