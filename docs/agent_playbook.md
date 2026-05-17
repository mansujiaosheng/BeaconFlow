# AI Agent 工具选择与分析决策指南

> **本文档面向 AI Agent**，用于指导 Agent 在逆向分析任务中如何根据输入类型选择工具、如何根据分析结果做出下一步决策。

---

## 1. 工作流决策树

收到新的分析目标后，按以下路径选择入口工具：

```
拿到新目标
  │
  ▼
triage_target（自动检测文件类型与架构）
  │
  ├── PE / ELF x86/x64 ──────► triage_native
  ├── ELF 非 x86 ────────────► triage_qemu
  ├── WASM ──────────────────► triage_wasm
  ├── PYC ───────────────────► triage_pyc
  └── APK ───────────────────► import_jadx_summary + suggest_hook
```

**要点：**
- `triage_target` 是通用入口，会自动判断文件类型并返回初步分类结果。
- 对于 APK，需先调用 `import_jadx_summary` 导入 Java 层反编译摘要，再调用 `suggest_hook` 生成 Hook 建议，两者配合使用。
- 非 x86 架构的 ELF（如 ARM、MIPS）必须走 `triage_qemu` 路径，因为需要 QEMU 模拟执行。

---

## 2. 分析后决策

`triage_*` 返回结果后，根据返回内容决定下一步动作：

```
triage 结果 status=ok
  │
  ▼
查看 roles 和 decision_points 字段
  │
  ├── 发现 validator（校验/验证逻辑）
  │     └── ► trace_calls / trace_compare 获取运行时值
  │
  ├── 发现 crypto_like（疑似加密算法）
  │     └── ► sig_match 识别具体算法
  │
  └── 发现 dispatcher（控制流分发器/平坦化）
        └── ► deflatten_flow 反平坦化
```

**要点：**
- `roles` 字段标识函数在程序中扮演的角色（如 validator、crypto_like、dispatcher）。
- `decision_points` 字段指出需要进一步分析的关键决策位置。
- 三种角色对应三种不同的深入分析策略，不要混淆。

---

## 3. 证据可信度说明

分析过程中产生的证据分为不同可信度等级，决策时需加以区分：

| 证据类型 | 可信度 | 说明 |
|----------|--------|------|
| `coverage` / `flow` | **Hard Evidence（硬证据）** | 来自实际执行数据（如 DynamoRIO、QEMU 追踪），反映程序真实运行行为 |
| `roles` / `sig_match` | **Heuristic（启发式推断）** | 基于模式匹配和经验规则推断，存在误判可能 |
| `ai_digest.confidence` | **显式可信度** | `ai_digest` 中的 `confidence` 字段直接反映该条分析结论的可信程度 |

**决策原则：**
- 以 hard evidence 为基础构建分析结论。
- heuristic 结论需与 hard evidence 交叉验证后再采纳。
- 当 `confidence` 较低时，应主动补证而非直接采信。

---

## 4. 缺少证据时的补证策略

当分析过程中发现证据不足，按以下策略补充：

| 缺失证据 | 补证工具 | 说明 |
|----------|----------|------|
| 缺 `coverage`（执行覆盖率） | `collect_drcov` / `collect_qemu` | x86/x64 用 `collect_drcov`，其他架构用 `collect_qemu` |
| 缺 runtime 值（运行时数据） | `trace_calls` / `trace_compare` | 追踪函数调用参数和返回值，或对比两次执行的差异 |
| 缺约束求解 | `suggest_angr` + `import_angr_result` | 先用 `suggest_angr` 生成求解建议，执行后用 `import_angr_result` 导入结果 |

**补证流程：**
1. 识别当前分析链中缺失的证据类型。
2. 选择对应的补证工具执行。
3. 将新证据与已有结论交叉验证。
4. 根据验证结果更新分析结论。

---

## 5. MCP 工具分层使用指南

MCP 工具按使用频率和场景分为三层，Agent 应优先使用低层工具，按需升级到高层工具。

### Basic 层（21 个工具）

**日常分析优先使用。** 覆盖文件加载、基础分诊、字符串搜索、函数列表、交叉引用等常见操作。

典型场景：
- 加载二进制文件并获取基本信息
- 搜索关键字符串和函数
- 查看函数列表与调用关系
- 获取基本覆盖率数据

### Advanced 层（27 个工具）

**深入分析时使用。** 包括符号执行、Hook 注入、追踪对比、签名匹配、反平坦化等高级功能。

典型场景：
- 识别加密算法（`sig_match`）
- 控制流反平坦化（`deflatten_flow`）
- 运行时值追踪与对比（`trace_calls` / `trace_compare`）
- 覆盖率采集（`collect_drcov` / `collect_qemu`）
- 约束求解建议（`suggest_angr`）

### Expert 层（11 个工具）

**特殊场景使用。** 涉及自定义脚本注入、底层内存操作、特殊格式处理等。

典型场景：
- 注入自定义分析脚本
- 处理非标准二进制格式
- 需要直接操作进程内存的场景

**使用原则：**
- 能用 Basic 解决的不升级到 Advanced。
- 能用 Advanced 解决的不升级到 Expert。
- 每次升级工具层级时，需明确说明为什么低层工具不够用。

---

## 6. 典型 CTF 逆向工作流示例

### 场景 A：x86 ELF 逆向（含加密校验）

```
步骤 1: triage_target → 识别为 ELF x86_64
步骤 2: triage_native → 获取函数列表、字符串、roles
步骤 3: 发现 roles 中有 crypto_like
步骤 4: sig_match → 识别为 AES-ECB
步骤 5: 发现 roles 中有 validator
步骤 6: trace_calls → 获取 AES 输入/输出的运行时值
步骤 7: 根据运行时值还原密钥，解密 flag
```

### 场景 B：ARM ELF 逆向（含控制流平坦化）

```
步骤 1: triage_target → 识别为 ELF ARM
步骤 2: triage_qemu → 获取基本信息和覆盖率
步骤 3: 发现 roles 中有 dispatcher
步骤 4: deflatten_flow → 反平坦化恢复原始控制流
步骤 5: 分析恢复后的控制流，定位关键校验逻辑
步骤 6: trace_calls → 获取校验函数的运行时参数
步骤 7: 根据参数推导 flag
```

### 场景 C：APK 逆向（Java + JNI 混合）

```
步骤 1: triage_target → 识别为 APK
步骤 2: import_jadx_summary → 导入 Java 层反编译摘要
步骤 3: suggest_hook → 生成 Hook 建议列表
步骤 4: 分析 Java 层逻辑，定位 JNI 调用点
步骤 5: triage_native → 分析 JNI .so 文件
步骤 6: 发现 roles 中有 validator
步骤 7: trace_calls → 获取 JNI 函数运行时值
步骤 8: 结合 Java 层和 JNI 层结果还原 flag
```

### 场景 D：WASM 逆向

```
步骤 1: triage_target → 识别为 WASM
步骤 2: triage_wasm → 获取函数列表和导出信息
步骤 3: 分析关键导出函数逻辑
步骤 4: trace_calls → 获取运行时调用序列和参数
步骤 5: 根据调用序列还原算法逻辑
步骤 6: 实现等价算法，求解 flag
```

### 场景 E：PYC 逆向

```
步骤 1: triage_target → 识别为 PYC
步骤 2: triage_pyc → 反编译获取 Python 源码
步骤 3: 分析源码中的校验逻辑
步骤 4: 如有运行时依赖，trace_calls 获取动态值
步骤 5: 根据逻辑直接求解或编写脚本求解
```

---

## 附录：决策速查表

| 输入/发现 | 动作 |
|-----------|------|
| 新文件 | `triage_target` |
| PE/ELF x86/x64 | `triage_native` |
| ELF 非 x86 | `triage_qemu` |
| WASM | `triage_wasm` |
| PYC | `triage_pyc` |
| APK | `import_jadx_summary` + `suggest_hook` |
| 发现 validator | `trace_calls` / `trace_compare` |
| 发现 crypto_like | `sig_match` |
| 发现 dispatcher | `deflatten_flow` |
| 缺 coverage | `collect_drcov` / `collect_qemu` |
| 缺 runtime 值 | `trace_calls` / `trace_compare` |
| 缺约束求解 | `suggest_angr` + `import_angr_result` |
