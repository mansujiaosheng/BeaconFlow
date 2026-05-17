# BeaconFlow 函数参考文档

> 本文档列出 BeaconFlow 所有公开 API 函数的名称、输入、输出和作用，用于统一命名、防止开发混乱。

---

## 1. Triage 入口（beaconflow/triage.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `triage` | `target_path: str\|Path, output_dir: str\|Path, stdin: str\|None=None, target_args: list\|None=None, qemu_arch: str\|None=None, arch: str\|None=None, timeout: int=120, disassemble: bool=False` | `dict[str, Any]` | 统一 triage 入口：自动检测文件类型（PE/ELF/WASM/PYC/APK）并分发到对应工作流 |
| `triage_native` | `target_path: str\|Path, output_dir: str\|Path, stdin: str\|None=None, target_args: list\|None=None, arch: str="x64", timeout: int=120` | `dict[str, Any]` | 一键 PE/ELF 本地分析：Ghidra metadata + drcov + coverage + flow + decision_points + roles |
| `triage_qemu` | `target_path: str\|Path, output_dir: str\|Path, qemu_arch: str="arm", stdin_cases: list\|None=None, timeout: int=120` | `dict[str, Any]` | 一键 QEMU 远程分析：Ghidra metadata + QEMU trace + flow + branch_rank |
| `triage_wasm` | `target_path: str\|Path, output_dir: str\|Path` | `dict[str, Any]` | 一键 WASM 分析：WASM metadata + decision_points + sig_match |
| `triage_pyc` | `target_path: str\|Path, output_dir: str\|Path, disassemble: bool=False` | `dict[str, Any]` | 一键 Python .pyc 分析：magic 识别 + dis 反汇编 + code object 总结 + 可疑函数识别 |
| `triage_apk` | `target_path: str\|Path, output_dir: str\|Path` | `dict[str, Any]` | 一键 Android APK 分析：AXML manifest 解析 + native libs 检测 + JADX summary 导入 + hook 推荐 |
| `_detect_target_type` | `target: Path` | `dict[str, Any]` | 检测目标文件类型和架构（PE/ELF/WASM/PYC/APK），返回 type/arch/bits/endian 等信息 |
| `_parse_axml_manifest` | `data: bytes` | `dict[str, Any]` | 解析 Android 二进制 XML (AXML) 格式的 AndroidManifest.xml，提取 package/permissions/main_activity |

### triage 输出统一格式

```json
{
  "status": "ok" | "partial" | "error",
  "target": "文件路径",
  "artifacts": {"名称": "文件路径", ...},
  "errors": ["错误信息", ...],
  "next_steps": ["建议操作", ...]
}
```

---

## 2. Benchmark 测试（beaconflow/benchmark.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `run_builtin_benchmarks` | `output_dir: str\|Path\|None=None` | `dict[str, Any]` | 运行内置 benchmark（无需外部目标），测试模板库/导入器/Schema/文件检测/HTML/建议引擎 |
| `run_benchmark` | `case_name: str, target_path: str\|Path\|None=None, output_dir: str\|Path\|None=None` | `dict[str, Any]` | 运行单个 benchmark 用例（需要外部目标文件） |
| `run_all_benchmarks` | `targets: dict\|None=None, output_dir: str\|Path\|None=None` | `dict[str, Any]` | 运行所有 benchmark 用例 |
| `list_benchmarks` | 无 | `dict[str, Any]` | 列出所有 benchmark 用例定义 |

### benchmark 输出格式

```json
{
  "status": "ok" | "partial",
  "checks": {"检查项": bool, ...},
  "errors": [],
  "passed": 8,
  "failed": 0,
  "total_checks": 8
}
```

---

## 3. 模板与建议（beaconflow/templates.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `suggest_hook` | `metadata_path: str\|Path\|None=None, decision_points_result: dict\|None=None, roles_result: dict\|None=None, trace_compare_result: dict\|None=None, target_type: str="native", apk_summary: dict\|None=None` | `dict[str, Any]` | 根据分析证据推荐 Frida hook 模板，支持 Android APK 场景 |
| `suggest_angr` | `flow_diff_result: dict\|None=None, roles_result: dict\|None=None, decision_points_result: dict\|None=None, branch_rank_result: dict\|None=None` | `dict[str, Any]` | 根据分析证据推荐 angr 求解参数和脚本 |
| `suggest_debug` | `decision_points_result: dict\|None=None, roles_result: dict\|None=None, trace_compare_result: dict\|None=None, debugger: str="gdb"` | `dict[str, Any]` | 根据分析证据推荐 GDB/x64dbg 断点脚本 |
| `generate_template` | `template_name: str, output_path: str\|Path, params: dict\|None=None` | `dict[str, Any]` | 生成指定模板文件，替换 %KEY% 占位符 |
| `list_templates` | `category: str\|None=None` | `dict[str, Any]` | 列出所有可用模板（可按 frida/angr/gdb/x64dbg 分类过滤） |

---

## 4. 外部工具导入（beaconflow/importers.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `import_frida_log` | `log_path: str\|Path, metadata_path: str\|Path\|None=None` | `dict[str, Any]` | 导入 Frida hook 输出日志（JSON 行格式和 Frida CLI 输出格式） |
| `import_gdb_log` | `log_path: str\|Path, metadata_path: str\|Path\|None=None` | `dict[str, Any]` | 导入 GDB 调试日志（断点命中、寄存器 dump、内存 dump） |
| `import_angr_result` | `result_path: str\|Path, metadata_path: str\|Path\|None=None` | `dict[str, Any]` | 导入 angr 求解结果（JSON 和文本格式，自动搜索 flag 模式） |
| `import_jadx_summary` | `summary_path: str\|Path, metadata_path: str\|Path\|None=None` | `dict[str, Any]` | 导入 JADX 反编译摘要（JSON 格式） |

### importers 输出统一格式

```json
{
  "status": "ok" | "partial" | "error",
  "source": "frida|gdb|angr|jadx",
  "total_events": 0,
  "evidence": [...],
  "warnings": []
}
```

---

## 5. Case Workspace 管理（beaconflow/workspace.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `init_case` | `target: str, arch: str="x64", backend: str="qemu", root: str\|None=None, overwrite: bool=False` | `dict[str, Any]` | 初始化分析案例工作区（.case/ 目录） |
| `summarize_case` | `root: str\|None=None` | `dict[str, Any]` | 汇总工作区状态（metadata/runs/reports/notes 数量和摘要） |
| `add_metadata` | `name: str, path: str, description: str="", root: str\|None=None` | `dict[str, Any]` | 向工作区添加 metadata 文件记录 |
| `add_run` | `name: str, path: str\|None=None, stdin_preview: str\|None=None, verdict: str\|None=None, returncode: int\|None=None, notes: str="", root: str\|None=None` | `dict[str, Any]` | 向工作区添加运行记录 |
| `add_report` | `name: str, path: str, report_type: str="", description: str="", root: str\|None=None` | `dict[str, Any]` | 向工作区添加分析报告记录 |
| `add_note` | `content: str, title: str="", root: str\|None=None` | `dict[str, Any]` | 向工作区添加笔记（AI Agent 交接用） |
| `list_runs` | `root: str\|None=None` | `dict[str, Any]` | 列出工作区中的所有运行记录 |
| `list_reports` | `root: str\|None=None` | `dict[str, Any]` | 列出工作区中的所有报告 |
| `list_notes` | `root: str\|None=None` | `dict[str, Any]` | 列出工作区中的所有笔记 |
| `case_check` | `root: str\|None=None` | `dict[str, Any]` | 对工作区进行全面质量检查（10项检查：metadata/runs/reports/ai_digest/evidence_id/confidence/target/large_files/schema/next_actions） |

---

## 6. 分析引擎（beaconflow/analysis/）

### 6.0 Schema 验证（beaconflow/schemas.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `validate_report` | `report: dict, schema_name: str` | `list[str]` | 验证报告是否符合指定 schema，返回错误列表 |
| `validate_report_strict` | `report: dict, schema_name: str` | `dict[str, Any]` | 严格验证报告，返回包含 valid/error_count/errors 的结构化结果 |
| `validate_all_reports` | `directory: str\|Path, recursive: bool=True` | `dict[str, Any]` | 批量验证目录下所有 JSON 报告文件，自动检测 schema 名称 |
| `list_schemas` | 无 | `list[str]` | 列出所有可用 schema 名称 |
| `get_schema` | `name: str` | `dict[str, Any]` | 获取指定 schema 的 JSON Schema 定义 |

### 6.1 覆盖率分析（coverage_mapper.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `analyze_coverage` | `metadata: ProgramMetadata, coverage: CoverageData` | `dict[str, Any]` | 将 drcov 覆盖率块映射到函数/基本块，统计已覆盖和未覆盖函数 |
| `diff_coverage` | `metadata: ProgramMetadata, left: CoverageData, right: CoverageData` | `dict[str, Any]` | 对比两次覆盖率数据的差异 |

### 6.2 执行流分析（flow.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `analyze_flow` | `metadata: ProgramMetadata, coverage: CoverageData, max_events: int=0, focus_function: str\|None=None` | `dict[str, Any]` | 将 drcov 基本块表映射为有序执行流报告 |
| `diff_flow` | `metadata: ProgramMetadata, left: CoverageData, right: CoverageData, focus_function: str\|None=None` | `dict[str, Any]` | 对比两次执行流的差异 |
| `rank_input_branches` | `metadata: ProgramMetadata, coverages: list[CoverageData], labels: list\|None=None, roles: list\|None=None, focus_function: str\|None=None` | `dict[str, Any]` | 排序最可能受输入影响的分支点 |
| `deflatten_flow` | `metadata: ProgramMetadata, coverage: CoverageData, focus_function: str\|None=None, dispatcher_min_hits: int=2, dispatcher_min_pred: int=2, dispatcher_min_succ: int=2, dispatcher_mode: str="strict"` | `dict[str, Any]` | 反控制流平坦化：过滤 dispatcher 块，重建真实控制流边 |
| `deflatten_merge` | `metadata: ProgramMetadata, coverages: list[CoverageData], labels: list\|None=None, ...` | `dict[str, Any]` | 合并多次 deflatten 结果，还原完整真实 CFG |
| `recover_state_transitions` | `metadata: ProgramMetadata, coverages: list[CoverageData], labels: list\|None=None, ...` | `dict[str, Any]` | 从多次 trace 中恢复状态转移表 |

### 6.3 决策点检测（decision_points.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `find_decision_points` | `metadata: ProgramMetadata, focus_function: str\|None=None` | `list[dict[str, Any]]` | 查找所有决策点（cmp+jcc、test+jcc、checker call、cmovcc、setcc、jump table） |

### 6.4 角色检测（role_detector.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `detect_roles` | `metadata: ProgramMetadata, rules_path: str\|None=None, focus_function: str\|None=None, min_score: float=0.1` | `list[RoleCandidate]` | 推断函数角色（validator、crypto_like、input_handler、dispatcher 等） |

### 6.5 签名匹配（sig_matcher.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `match_signatures` | `metadata: ProgramMetadata, sig_library_path: str\|None=None` | `dict[str, Any]` | 识别 crypto/VM/packer/anti-debug 特征（AES/DES/RC4/TEA/Base64/CRC 等） |

### 6.6 反编译（decompile_function.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `decompile_function` | `metadata: ProgramMetadata, function_name: str\|None=None, function_address: int\|None=None` | `dict[str, Any]` | 从 block context 生成函数级伪代码摘要 |

### 6.7 IR 归一化（normalized_ir.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `normalize_to_ir` | `metadata: ProgramMetadata, function_name: str\|None=None, function_address: int\|None=None` | `dict[str, Any]` | 将多架构指令统一为 IR（ASSIGN/LOAD/STORE/COMPARE/BRANCH/CALL/RETURN/BINARY） |

### 6.8 值追踪（value_trace.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `analyze_value_trace` | `metadata: ProgramMetadata, executed_addrs: set[int]\|None=None, focus_function: str\|None=None` | `dict[str, Any]` | 追踪关键比较点的寄存器/内存/比较值，推断分支结果 |

### 6.9 比较语义（trace_compare.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `analyze_trace_compare` | `metadata: ProgramMetadata, executed_addrs: set[int]\|None=None, focus_function: str\|None=None` | `dict[str, Any]` | 提取输入校验点的比较语义（cmp/strcmp/memcmp/strlen/jump table） |

### 6.10 污点分析（input_taint.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `analyze_input_taint` | `metadata: ProgramMetadata, focus_function: str\|None=None` | `dict[str, Any]` | 轻量污点分析：追踪输入字节到分支决策的传播路径 |

### 6.11 反馈探索（feedback_explore.py）

| 函数名 | 输入 | 输出 | 作用 |
|--------|------|------|------|
| `feedback_auto_explore` | `metadata: ProgramMetadata, trace_compare_result: dict, current_input: bytes\|None=None, input_offset_base: int=0` | `dict[str, Any]` | 根据失败比较结果自动建议输入修改方案 |

---

## 7. MCP 工具映射（beaconflow/mcp/server.py）

MCP 工具名与 Python 函数的对应关系：

| MCP 工具名 | Python 函数 | 层级 |
|------------|------------|------|
| `triage_target` | `triage_auto()` | Basic |
| `suggest_hook` | `suggest_hook()` | Basic |
| `suggest_angr` | `suggest_angr()` | Basic |
| `suggest_debug` | `suggest_debug()` | Basic |
| `list_templates` | `list_templates()` | Basic |
| `generate_template` | `generate_template()` | Basic |
| `import_frida_log` | `import_frida_log()` | Basic |
| `import_gdb_log` | `import_gdb_log()` | Basic |
| `import_angr_result` | `import_angr_result()` | Basic |
| `import_jadx_summary` | `import_jadx_summary()` | Basic |
| `analyze_coverage` | `analyze_coverage()` | Advanced |
| `analyze_flow` | `analyze_flow()` | Advanced |
| `find_decision_points` | `find_decision_points()` | Advanced |
| `detect_roles` | `detect_roles()` | Advanced |
| `sig_match` | `match_signatures()` | Expert |
| `deflatten_flow` | `deflatten_flow()` | Advanced |
| `deflatten_merge` | `deflatten_merge()` | Advanced |
| `branch_rank` | `rank_input_branches()` | Advanced |
| `schema_validate` | `validate_report_strict()` | Advanced |
| `schema_validate_all` | `validate_all_reports()` | Advanced |
| `case_check` | `ws_case_check()` | Advanced |
| `to_html` | `markdown_to_html()` / `json_to_html()` | Advanced |
| `benchmark` | `run_builtin_benchmarks()` / `run_benchmark()` | Expert |

---

## 8. 数据类型说明

| 类型名 | 模块 | 说明 |
|--------|------|------|
| `ProgramMetadata` | `beaconflow.ida` | 程序元数据：函数列表、基本块、CFG、字符串等 |
| `CoverageData` | `beaconflow.coverage` | 覆盖率数据：drcov 或 QEMU address log 解析后的基本块命中信息 |
| `RoleCandidate` | `beaconflow.analysis.role_detector` | 角色检测结果：function_name, address, role, score, confidence, evidence |

---

## 9. 命名约定

- **triage_\*** : 一键分析入口，自动完成多步骤工作流
- **analyze_\*** : 分析函数，输入 metadata + coverage，输出结构化报告
- **diff_\*** : 对比函数，输入两组数据，输出差异报告
- **find_\*** : 搜索函数，输入 metadata，输出列表
- **detect_\*** : 检测函数，输入 metadata，输出检测结果
- **match_\*** : 匹配函数，输入 metadata，输出匹配结果
- **suggest_\*** : 建议函数，输入分析结果，输出推荐方案
- **import_\*** : 导入函数，输入外部日志路径，输出结构化证据
- **generate_\*** : 生成函数，输入模板名+参数，输出文件
- **list_\*** : 列表函数，输出可用选项
- **run_\*** : 运行函数，执行实际操作
- **add_\*** : 添加函数，向 workspace 添加记录
- **validate_\*** : 验证函数，检查报告或目录是否符合 schema
- **case_check** : 工作区质量检查函数，综合检查工作区完整性和 AI 友好度
