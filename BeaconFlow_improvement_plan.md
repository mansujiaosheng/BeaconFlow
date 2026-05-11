# BeaconFlow 改进建议总结

## 项目现状判断

BeaconFlow 目前已经不是简单的覆盖率工具，而是一个面向 AI Agent 的二进制分析辅助框架。

当前已经具备的核心能力包括：

- Headless 元数据导出
- 函数、基本块、CFG 信息整理
- 覆盖率映射
- 执行流分析
- 多输入路径 diff
- QEMU trace
- 多输入探索与路径新颖性排序
- 反控制流平坦化辅助
- basic block context
- decision point 分析
- role detector
- branch-rank
- MCP 工具接口

因此，下一阶段不建议继续只堆“覆盖率统计”，而应该重点增强：

> 动态值、输入影响、比较语义、自动探索闭环。

目标是让 BeaconFlow 从：

```text
这个输入多走了哪些块
```

升级成：

```text
这个输入在哪个比较点失败，失败原因是什么，哪个输入字节影响了这个分支，下一步应该怎么改输入。
```

---

# P0：最优先改进

## 1. 增加 value_trace：寄存器 / 内存 / 比较值追踪

### 目标

让 AI 不只知道“哪个块被执行”，还知道关键比较点发生了什么。

例如：

```text
0x40123a cmp eax, 0x41
eax = 0x42
branch = fail
input_offset = 3
```

### 需要记录的内容

- cmp / test / sub 等比较指令
- jcc 条件跳转结果
- strcmp / strncmp / memcmp 参数
- read / recv / scanf / fgets 等输入来源
- 关键 dispatcher 块的状态变量

### 预期效果

AI 可以直接判断：

```text
第 4 个输入字符导致比较失败，它应该接近 0x41。
```

### 可选工具

- DynamoRIO client
- QEMU plugin / QEMU gdbstub
- Frida Stalker
- Intel Pin
- Unicorn
- Triton
- angr

---

## 2. 增加 trace_compare：比较语义提取

### 目标

专门提取程序中的“输入校验点”。

例如：

```json
{
  "addr": "0x401300",
  "type": "memcmp",
  "arg1": "input+8",
  "arg2": "table+0x20",
  "length": 16,
  "result": "not_equal"
}
```

### 重点识别

- cmp reg, imm
- cmp reg, reg
- test reg, reg
- strcmp
- strncmp
- memcmp
- strlen
- switch / jump table

### 预期效果

AI 可以从“路径失败”进一步知道“失败原因”。

例如：

```text
程序在 0x401300 调用了 memcmp，比较 input[8:24] 和常量表，长度 16，结果失败。
```

---

## 3. 增加 doctor 环境诊断命令

### 目标

减少环境问题带来的使用成本。

BeaconFlow 依赖项比较多，建议增加：

```bash
python -m beaconflow.cli doctor
```

### 检查内容

- Python 版本
- beaconflow 是否可 import
- IDA / idat64 是否可用
- Ghidra / pyghidra 是否可用
- DynamoRIO / drrun 是否可用
- QEMU user-mode 是否可用
- WSL 是否可用
- 目标架构对应的 QEMU 是否存在
- MCP 配置是否正常

### 示例输出

```text
[OK] Python 3.12
[OK] beaconflow import
[OK] drrun x64 found
[FAIL] drrun x86 not found
[OK] WSL available
[OK] qemu-loongarch64 found
[WARN] pyghidra not installed
[WARN] IDA idat64 not in PATH
```

### 可扩展命令

```bash
beaconflow doctor --target ./flagchecker --qemu-arch loongarch64
```

---

# P1：第二阶段改进

## 4. 增加 input_taint：输入到分支的轻量污点分析

### 目标

判断哪些输入字节影响了哪些分支。

### 输出示例

```text
branch 0x140012340 depends on input[5]
branch 0x140012380 depends on input[6:10]
memcmp at 0x140013000 compares input[8:16] with table[0x140040000]
```

### 和 branch-rank 的区别

```text
branch-rank：告诉 AI 先看哪个分支
input-taint：告诉 AI 哪些输入字节影响这个分支
```

### 可选工具

- Triton
- angr
- Miasm
- PANDA
- DynamoRIO 自写轻量 taint
- QEMU 插桩

---

## 5. 增加 feedback auto-explore：反馈式输入探索

### 目标

把已有的多输入 mutate 能力升级成自动循环探索。

### 工作流

```text
1. 跑一批输入
2. 统计路径新颖性
3. 选择更优输入
4. 基于更优输入继续变异
5. 保留新路径
6. 多轮循环
```

### 建议命令

```bash
beaconflow auto-explore \
  --target ./chall \
  --seed ./seeds \
  --rounds 20 \
  --strategy coverage-guided
```

### 目标

不是完全替代 AFL++，而是做一个 AI 友好的轻量路径探索器。

### 可选工具

- AFL++ QEMU mode
- AFL++ Frida mode
- LibAFL
- 自写 lightweight feedback loop

---

## 6. 增加 decompile-function：伪代码摘要导出

### 目标

让 AI 不只看汇编和 block context，还能看到更接近源码的函数逻辑。

### 输出示例

```json
{
  "function": "check_flag",
  "pseudocode_summary": "...",
  "important_locals": ["i", "state", "buf"],
  "conditions": [
    "if len != 32 -> fail",
    "if transform(buf[i]) != table[i] -> fail"
  ]
}
```

### 建议支持

- decompile-function
- decompile-block
- export-pseudocode
- summarize-function

### 可选工具

- Ghidra Decompiler API
- IDA Hex-Rays
- Binary Ninja MLIL
- RetDec
- angr decompiler

### 推荐优先级

优先支持 Ghidra，因为它对 headless 自动化和多架构支持比较友好。

---

# P2：泛化和增强能力

## 7. 增加 normalized IR：统一中间表示

### 目标

减少 AI 被不同架构汇编细节干扰的问题。

例如不同架构的比较指令：

```text
x86: cmp eax, 0x10
ARM: cmp r0, #0x10
LoongArch: sltui ...
```

可以统一成：

```json
{
  "op": "compare",
  "left": "input_byte[3]",
  "right": 16,
  "predicate": "eq"
}
```

### 可选 IR

- Ghidra P-code
- angr VEX
- Binary Ninja MLIL
- Capstone + 自定义归一化

### 适用场景

- LoongArch
- MIPS
- ARM
- x86 / x64
- RISC-V
- WebAssembly

---

## 8. 扩展 crypto / VM / packer 特征库

### 目标

在现有 role detector 基础上，把 crypto_like 进一步细分。

### 建议识别类型

```text
aes_like
des_like
tea_like
rc4_like
md5_like
sha_like
base64_like
crc_like
xor_loop
substitution_table
vm_dispatcher
bytecode_interpreter
packer_stub
```

### 识别依据

- 常量表
- S-box
- magic number
- 大量位运算
- 大量查表
- 高出度 dispatcher
- fetch-decode-execute 解释器结构
- 自修改 / 解包行为

### 可选工具 / 规则形式

- capa-style rule
- YARA
- Ghidra constants scan
- 自定义 signature YAML

---

## 9. 增加 case workspace / manifest

### 目标

让一个 CTF 题目或一个分析目标形成稳定工作区，方便 AI Agent 多轮分析。

### 建议目录结构

```text
.case/
  manifest.json
  target
  metadata/
  runs/
  reports/
  notes/
```

### 建议命令

```bash
beaconflow init-case --target ./flagchecker --arch loongarch64
beaconflow run-case --stdin "AAAA"
beaconflow summarize-case
```

### manifest 示例

```json
{
  "target": "./flagchecker",
  "arch": "loongarch64",
  "backend": "qemu",
  "metadata": "metadata/ghidra.json",
  "runs": [],
  "reports": []
}
```

### 预期效果

AI 不需要每次重新猜路径、目标文件、trace 文件、metadata 文件位置，可以持续围绕同一个 case 工作。

---

# 推荐开发顺序

## 第一批：最值得先做

```text
1. trace-values：关键比较点寄存器 / 内存值
2. trace-compare：strcmp / memcmp / cmp / test 参数提取
3. doctor：环境诊断
```

## 第二批：增强自动分析能力

```text
4. input-taint：输入字节影响分支
5. feedback auto-explore：多轮路径探索
6. decompile-function：Ghidra / IDA 伪代码摘要
```

## 第三批：增强泛化能力

```text
7. normalized IR / P-code
8. crypto / VM / packer 规则库
9. case workspace / manifest
```

---

# 最终目标

BeaconFlow 的下一阶段目标应该是：

```text
从“路径覆盖率分析工具”升级为“AI 逆向决策辅助工具”。
```

也就是让 AI 能够回答：

```text
哪里失败？
为什么失败？
哪个输入字节导致失败？
应该优先改哪个输入？
下一轮该怎么探索？
```

理想输出应该类似：

```text
输入在 0x22ef68 失败。
失败原因：input[7] 与常量 0x41 比较不等。
good trace 走向 0x22efb0，wrong trace 走向 0x22efa0。
建议优先变异 input[7]，候选字符集为 printable / hex / base64。
```

这才是 BeaconFlow 对 AI 解二进制题最有价值的方向。
