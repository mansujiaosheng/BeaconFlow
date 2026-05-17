# BeaconFlow Experimental Features

本文档记录 beta / experimental 能力、适用场景、误报风险和推荐使用方式。

README 主流程只放 stable 功能。本文件中的能力可以使用，但不要把结果当成确定事实。

## 状态说明

| 状态 | 含义 |
|---|---|
| beta | 功能可用，但参数、输出字段或边界行为可能调整 |
| experimental | 启发式较强，容易受样本、架构、编译器影响 |
| planned | 设计中，未保证代码存在 |

## 1. qemu-explore

状态：beta

用途：

```text
在不知道正确输入时，用多组 stdin / 文件输入跑 QEMU trace，
按照新 basic block / 新 transition / 输出特征对输入排序。
```

适合：

```text
- LoongArch / MIPS / ARM / AArch64 CTF checker
- 正确输入未知但能判断 Wrong/Correct
- 想找到更接近成功路径的输入
```

风险：

```text
- QEMU in_asm 是 translation log，不等于精确动态执行次数
- 静态链接 ELF 如果不限制 address range，会混入大量运行库地址
- 新路径不一定代表更接近正确答案，也可能只是错误处理路径
```

推荐：

```powershell
python -m beaconflow.cli qemu-explore `
  --target D:\case\flagchecker `
  --qemu-arch loongarch64 `
  --stdin "ACTF{00000000000000000000000000000000}" `
  --stdin "ACTF{ffffffffffffffffffffffffffffffff}" `
  --auto-newline `
  --failure-regex "Wrong" `
  --success-regex "Correct" `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --format markdown `
  --output explore.md
```

AI 使用建议：

```text
先看 New vs Baseline / New Global 最高的输入，
再对这些输入做 flow-diff，
最后 inspect-block / inspect-function。
```

## 2. deflatten

状态：beta / experimental，取决于样本

用途：

```text
从实际执行流中识别 dispatcher、loop-like edge、join point，
辅助恢复控制流平坦化后的真实路径。
```

风险：

```text
- dispatcher 判断是启发式
- 大 switch、解释器、VM dispatcher 可能和混淆 dispatcher 混淆
- QEMU in_asm 下 hit count 不精确
```

推荐使用：

```powershell
python -m beaconflow.cli deflatten `
  --metadata metadata.json `
  --address-log case000.in_asm.qemu.log `
  --address-min 0x220000 `
  --address-max 0x244000 `
  --dispatcher-mode balanced `
  --format markdown `
  --output deflatten.md
```

AI 使用建议：

```text
不要直接相信 dispatcher_candidates。
必须回到 IDA/Ghidra 检查：
- 是否有状态变量
- 是否有 switch/jump table
- 是否有循环回到同一个调度块
- 是否存在真实业务分支被误判
```

## 3. detect-roles

状态：beta

用途：

```text
给函数打角色标签，如 validator、dispatcher、transformer、decoder、wrapper、io。
```

风险：

```text
- 依赖静态特征和 CFG 特征
- 小函数、内联函数、符号缺失时容易误判
- VM / parser / switch-heavy 代码会影响角色分数
```

推荐：

```powershell
python -m beaconflow.cli detect-roles `
  --metadata metadata.json `
  --format markdown `
  --output roles.md
```

AI 使用建议：

```text
把 roles 当作排序线索，不要当作事实。
validator/dispatcher 高分函数优先 inspect-function。
```

## 4. decision-points

状态：beta

用途：

```text
找 cmp/test/jcc、strcmp/memcmp、长度检查、switch 等决策点。
```

风险：

```text
- 静态决策点不一定被当前输入执行
- 一些编译器优化后的条件不容易直接识别
- 间接跳转和异常流可能漏报
```

推荐：

```powershell
python -m beaconflow.cli decision-points `
  --metadata metadata.json `
  --focus-function check_flag `
  --format markdown `
  --output decision_points.md
```

AI 使用建议：

```text
优先结合 flow / flow-diff：
只看“当前执行过”或“左右输入有差异”的决策点。
```

## 5. input-taint

状态：experimental

用途：

```text
从 read/recv/scanf/fgets 等输入源出发，
通过简化寄存器/数据流传播到 cmp/test/branch，
输出“输入影响哪个分支”的启发式映射。
```

风险：

```text
- 不是完整污点分析
- 内存别名、指针、结构体、循环传播容易漏
- 编译优化会改变寄存器传播形态
- 低置信度结果必须人工复查
```

推荐：

```powershell
python -m beaconflow.cli input-taint `
  --metadata metadata.json `
  --focus-function check_flag `
  --format markdown `
  --output input_taint.md
```

AI 使用建议：

```text
只把 high confidence 的 mapping 当作优先分析线索。
medium/low 只能用于提示可能关系。
```

## 6. trace-compare

状态：experimental

用途：

```text
比较运行时比较指令或比较函数的失败点，
例如 cmp imm、strcmp、memcmp、strncmp。
```

风险：

```text
- 依赖 runtime trace 或静态近似
- 如果没有真实运行时值，只能给低置信度推测
- 字节序、宽度、符号扩展可能造成误读
```

推荐输出应包含：

```text
- compare address
- left value
- right value
- width
- source input
- confidence
- suggested patch/input change
```

AI 使用建议：

```text
trace-compare 的 patch 建议不能直接当 flag。
应先用新输入复跑 qemu-explore / flow-diff 验证路径变化。
```

## 7. feedback-explore

状态：experimental

用途：

```text
根据 trace-compare 的失败比较自动生成输入修改方案，
用于多轮探索。
```

风险：

```text
- 如果比较点不是目标校验核心，会朝错误方向修改
- 如果输入经过 hash/crypto/压缩，直接 patch 字节无效
- 多轮探索可能陷入局部路径
```

推荐：

```powershell
python -m beaconflow.cli feedback-explore `
  --metadata metadata.json `
  --input-file input.bin `
  --focus-function check_flag `
  --format markdown `
  --output feedback.md
```

AI 使用建议：

```text
每一轮必须重新采集 trace。
不能只根据一次 feedback 结论继续脑补。
```

## 8. WASM 支持

状态：beta

用途：

```text
纯 Python 解析 .wasm，导出函数、基本块、导入导出、指令。
```

适合：

```text
- CTF WASM checker
- 浏览器/Node wasm 逻辑分析
- 快速给 AI 生成 function/IR 摘要
```

风险：

```text
- 不是完整 wasm decompiler
- 高级语言结构恢复有限
- 间接调用表、复杂控制流、内存模型需要人工复查
```

推荐：

```powershell
python -m beaconflow.cli export-wasm-metadata --target box.wasm --output box_metadata.json
python -m beaconflow.cli detect-roles --metadata box_metadata.json --format markdown
python -m beaconflow.cli normalize-ir --metadata box_metadata.json --name main --format markdown
```

## 9. Runtime / Frida 相关能力

状态：planned / experimental，按具体脚本标记

BeaconFlow 不应该自研完整 Frida 框架。推荐方向：

```text
1. 根据 decision-points / roles 推荐 hook 点
2. 生成 Frida/GDB/x64dbg/angr 模板
3. 导入外部工具日志
4. 转成统一 evidence/report
```

优先模板：

```text
- strcmp / strncmp / memcmp
- strlen / strcmp-like checker
- read / recv / scanf / fgets
- JNI GetStringUTFChars
- Java String.equals / compareTo
- Android Base64 / Cipher / MessageDigest
```

## 10. planned：外部工具桥接

建议后续新增：

```text
suggest-hook
generate-template
import-frida-log
import-gdb-log
suggest-angr
import-angr-result
export-annotations
```

这些能力进入 README 前必须满足：

```text
- 有最小测试
- 有 schema
- 有 data_quality
- 有失败样例说明
- 有可复现 demo
```
