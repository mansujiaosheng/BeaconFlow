# BeaconFlow 外部工具输出导入详细指南

本文档详细介绍如何将外部工具的输出导入 BeaconFlow，统一成 AI 可读的证据格式。

## 1. import-frida-log：导入 Frida hook 日志

### 支持的日志格式

1. **JSON 行格式**：每行一个 JSON 对象（Frida `-o` 输出或 `send()` + `--message-log`）
2. **Frida CLI 输出格式**：`<序号> message: <JSON>`

### 命令格式

```powershell
python -m beaconflow.cli import-frida-log --log <日志文件> [--metadata metadata.json]
```

### 参数说明

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `--log` | 是 | Frida 输出日志文件路径 |
| `--metadata` | 否 | metadata JSON，用于地址关联 |

### 输出结构

```json
{
  "status": "ok",
  "total_events": 15,
  "parse_errors": 0,
  "type_counts": {
    "compare": 8,
    "input": 3,
    "memory": 4
  },
  "compare_events": 8,
  "compares": [
    {
      "type": "compare",
      "function": "strcmp",
      "left": "AAAA",
      "right": "ISCC{test_flag}",
      "caller": "0x401495",
      "result": "not_equal"
    }
  ],
  "input_events": 3,
  "inputs": [
    {
      "type": "input",
      "function": "scanf",
      "data": "AAAA",
      "caller": "0x401050"
    }
  ]
}
```

### 事件分类规则

| 事件类型 | 匹配规则 | 说明 |
| --- | --- | --- |
| `compare` | function 含 strcmp/memcmp/strncmp | 字符串/内存比较事件 |
| `input` | function 含 read/recv/scanf/fgets | 输入事件 |
| `memory` | type 含 memory/snapshot/dump | 内存操作事件 |
| `crypto` | function 含 encrypt/decrypt/hash | 加解密事件 |
| `jni` | function 含 JNI/GetStringUTF | JNI 调用事件 |
| `other` | 其他 | 未分类事件 |

### 使用示例

```powershell
# 1. 用 Frida 运行 hook
frida -l hook.js -o frida_output.log target.exe

# 2. 导入日志
python -m beaconflow.cli import-frida-log --log frida_output.log

# 3. 结合 metadata 分析
python -m beaconflow.cli import-frida-log --log frida_output.log --metadata metadata.json
```

## 2. import-gdb-log：导入 GDB 调试日志

### 支持的日志格式

1. **GDB 日志格式**：`set logging on` 输出
2. **断点命中记录**：`Breakpoint N, 0x... in func ()`
3. **寄存器 dump**：`EAX=0x... EBX=0x...` 格式
4. **内存 dump**：`0xAddr: 0xVal` 格式

### 命令格式

```powershell
python -m beaconflow.cli import-gdb-log --log <日志文件> [--metadata metadata.json]
```

### 输出结构

```json
{
  "status": "ok",
  "total_events": 10,
  "parse_errors": 0,
  "type_counts": {
    "breakpoint": 4,
    "register": 4,
    "memory": 2
  },
  "breakpoint_hits": 4,
  "breakpoints": [
    {
      "type": "breakpoint",
      "number": 1,
      "address": "0x401010",
      "function": "check_flag"
    }
  ],
  "register_dumps": 4,
  "registers": [
    {
      "type": "register",
      "EAX": "0x41",
      "EBX": "0x0",
      "ECX": "0x7ffe1234",
      "EDX": "0x0"
    }
  ]
}
```

### 使用示例

```powershell
# 1. 用 GDB 运行断点脚本
gdb -x bp.gdb ./target

# 2. 导入日志
python -m beaconflow.cli import-gdb-log --log gdb.txt
```

## 3. import-angr-result：导入 angr 求解结果

### 支持的结果格式

1. **JSON 格式**：angr `simgr.found` 序列化输出
2. **文本格式**：angr 打印的求解结果

### 命令格式

```powershell
python -m beaconflow.cli import-angr-result --result <结果文件> [--metadata metadata.json]
```

### 输出结构

```json
{
  "status": "ok",
  "format": "json",
  "solutions": [
    {
      "input_bytes": [0x49, 0x53, 0x43, 0x43],
      "input_text": "ISCC",
      "find_address": "0x401520",
      "avoid_address": "0x401560"
    }
  ],
  "total_solutions": 1
}
```

### 使用示例

```powershell
# 1. 运行 angr 求解
python solve.py target.exe > angr_result.json

# 2. 导入结果
python -m beaconflow.cli import-angr-result --result angr_result.json
```

## 4. import-jadx-summary：导入 JADX 反编译摘要

### 支持的格式

1. **JADX 文本输出**：`jadx -d output app.apk` 生成的 Java 源码摘要
2. **方法列表**：JADX 导出的方法签名列表

### 命令格式

```powershell
python -m beaconflow.cli import-jadx-summary --summary <摘要文件>
```

### 输出结构

```json
{
  "status": "ok",
  "classes": 15,
  "methods": 42,
  "suspicious_methods": [
    {
      "class": "com.example.MainActivity",
      "method": "checkFlag",
      "suspicion": "check/verify in method name"
    }
  ],
  "crypto_usages": [
    {
      "class": "com.example.CryptoUtils",
      "method": "encrypt",
      "algorithm": "AES"
    }
  ]
}
```

### 使用示例

```powershell
# 1. 用 JADX 反编译
jadx -d jadx_output app.apk

# 2. 提取摘要
find jadx_output -name "*.java" | head -20 > jadx_summary.txt

# 3. 导入摘要
python -m beaconflow.cli import-jadx-summary --summary jadx_summary.txt
```

## 5. 统一证据格式

所有导入工具的输出都遵循统一的证据格式：

```json
{
  "kind": "runtime_compare",
  "source_tool": "frida",
  "function": "strcmp",
  "caller": "0x401495",
  "lhs": "AAAA",
  "rhs": "ISCC{test_flag}",
  "length": 5,
  "confidence": "high"
}
```

这样 AI 不需要直接阅读大量原始日志，而是只读 BeaconFlow 的统一 evidence。

## 6. 与建议引擎配合

导入结果后，可以与建议引擎配合，形成闭环：

```
suggest-hook → 生成模板 → 运行外部工具 → import-* → 总结证据 → suggest-angr/suggest-debug
```

完整工作流示例：

```powershell
# 1. Triage
python -m beaconflow.cli triage-native --target checker.exe --output-dir output

# 2. 推荐 hook
python -m beaconflow.cli suggest-hook --decision-points output/decision_points.json --roles output/roles.json

# 3. 生成并运行 hook
python -m beaconflow.cli generate-template --template-name compare_strcmp_memcmp --output hook.js
frida -l hook.js -o frida_output.log checker.exe

# 4. 导入 hook 结果
python -m beaconflow.cli import-frida-log --log frida_output.log

# 5. 根据结果推荐 angr
python -m beaconflow.cli suggest-angr --flow-diff output/flow.json --roles output/roles.json

# 6. 生成并运行 angr
python -m beaconflow.cli generate-template --template-name find_avoid_stdin --output solve.py --params FIND_ADDR=0x401520,AVOID_ADDR=0x401560
python solve.py checker.exe > angr_result.json

# 7. 导入 angr 结果
python -m beaconflow.cli import-angr-result --result angr_result.json
```
