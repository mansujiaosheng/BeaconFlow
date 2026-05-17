# BeaconFlow 模板库与建议引擎详细指南

本文档详细介绍 BeaconFlow 的模板库系统和三个建议引擎的使用方法。

## 1. 模板库概述

BeaconFlow 不自研 hook/符号执行/调试框架，遵循"推荐模板 → 填充参数 → 导入输出 → 总结证据"的原则。

### 模板分类

| 类别 | 模板数量 | 说明 |
| --- | --- | --- |
| Frida/compare | 1 | 字符串/内存比较 hook |
| Frida/input | 1 | 输入函数 hook |
| Frida/memory | 1 | 内存快照 |
| Frida/android | 3 | JNI/Java/Crypto hook |
| angr/solve | 2 | stdin/argv 符号执行 |
| GDB/breakpoint | 1 | 决策点断点 |
| GDB/register | 1 | 寄存器 dump |
| GDB/watchpoint | 1 | 内存写监视 |
| x64dbg/breakpoint | 1 | 比较指令断点 |
| x64dbg/register | 1 | 寄存器日志 |
| x64dbg/trace | 1 | 函数返回追踪 |

### 列出所有模板

```powershell
python -m beaconflow.cli list-templates
```

输出示例：

```
Frida Templates:
  compare_strcmp_memcmp  [compare]  Hook strcmp/memcmp/strncmp，提取比较双方内容和调用点
  input_read_recv_scanf  [input]    Hook read/recv/scanf/fgets，捕获输入数据
  memory_snapshot        [memory]   在指定地址 dump 内存快照
  jni_getstringutfchars  [android]  Hook JNI GetStringUTFChars
  android_string_equals  [android]  Hook String.equals/compareTo
  android_crypto_base64_cipher [android] Hook Base64/Cipher/MessageDigest

angr Templates:
  find_avoid_stdin       [solve]    stdin 模式求解：指定 find/avoid 地址
  find_avoid_argv        [solve]    argv 模式求解：指定 find/avoid 地址

GDB Templates:
  break_decision         [breakpoint] 决策点断点脚本
  dump_registers         [register]   寄存器 dump
  watch_buffer           [watchpoint] 内存写监视

x64dbg Templates:
  break_cmp              [breakpoint] 比较指令断点
  log_registers          [register]   寄存器日志
  trace_until_ret        [trace]      追踪到函数返回
```

## 2. 生成模板文件

### 基本用法

```powershell
python -m beaconflow.cli generate-template --template-name <模板名> --output <输出文件>
```

### 参数替换

模板中包含 `{{参数名}}` 形式的占位符，可以通过 `--params` 替换：

```powershell
python -m beaconflow.cli generate-template --template-name compare_strcmp_memcmp --output hook.js --params MAX_READ=64
```

### 各模板参数说明

#### compare_strcmp_memcmp

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `MAX_READ` | 128 | 最大读取字节数 |

生成的 Frida 脚本会 hook `strcmp`、`memcmp`、`strncmp`，输出比较双方内容和调用点。

#### input_read_recv_scanf

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `MAX_READ` | 256 | 最大读取字节数 |

#### memory_snapshot

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `SNAPSHOT_ADDR` | 0x0 | dump 起始地址 |
| `SNAPSHOT_SIZE` | 256 | dump 大小 |

#### find_avoid_stdin

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `FIND_ADDR` | 0x0 | 目标地址（success 路径） |
| `AVOID_ADDR` | 0x0 | 避免地址（failure 路径） |
| `INPUT_LEN` | 32 | 输入长度 |

#### break_decision

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `BREAKPOINTS` | 无 | 断点地址列表 |

## 3. 建议引擎

### suggest-hook：推荐 Frida hook 模板

根据分析证据（决策点、角色、比较值）推荐合适的 Frida hook 模板。

```powershell
# 基本用法
python -m beaconflow.cli suggest-hook --decision-points dp.json --roles roles.json

# 使用 trace-compare 结果
python -m beaconflow.cli suggest-hook --decision-points dp.json --roles roles.json --trace-compare tc.json

# 指定目标类型
python -m beaconflow.cli suggest-hook --decision-points dp.json --target-type android
```

输出结构：

```json
{
  "status": "ok",
  "suggestions": [
    {
      "template_name": "compare_strcmp_memcmp",
      "confidence": "high",
      "reason": "Found checker_call decision points",
      "evidence": ["check_flag:0x401010 calls strcmp"],
      "params": {"MAX_READ": 128}
    }
  ]
}
```

推荐逻辑：

| 证据 | 推荐模板 | 置信度 |
| --- | --- | --- |
| checker_call 决策点 | compare_strcmp_memcmp | high |
| input_handler 角色 | input_read_recv_scanf | medium |
| crypto_like 角色 | memory_snapshot | medium |
| Android 目标 + JNI | jni_getstringutfchars | high |
| Android 目标 + Java check | android_string_equals | high |

### suggest-angr：推荐 angr 求解模板

根据 flow-diff 和角色分析结果推荐 angr 的 find/avoid 地址。

```powershell
python -m beaconflow.cli suggest-angr --flow-diff diff.json --roles roles.json
```

输出结构：

```json
{
  "status": "ok",
  "suggestions": [
    {
      "template_name": "find_avoid_stdin",
      "confidence": "high",
      "params": {
        "FIND_ADDR": "0x401520",
        "AVOID_ADDR": "0x401560",
        "INPUT_LEN": 32
      },
      "reason": "success_handler at 0x401520, failure_handler at 0x401560"
    }
  ]
}
```

推荐逻辑：

| 证据 | 推荐模板 | 参数来源 |
| --- | --- | --- |
| success_handler 角色 | find_avoid_stdin | find = success_handler 地址 |
| failure_handler 角色 | find_avoid_stdin | avoid = failure_handler 地址 |
| input_handler 角色 | find_avoid_stdin | INPUT_LEN 从 trace 推断 |

### suggest-debug：推荐调试器断点脚本

根据决策点分析结果推荐 GDB 或 x64dbg 断点脚本。

```powershell
# 推荐 GDB 断点脚本
python -m beaconflow.cli suggest-debug --decision-points dp.json --debugger gdb --output bp.gdb

# 推荐 x64dbg 断点脚本
python -m beaconflow.cli suggest-debug --decision-points dp.json --debugger x64dbg --output bp.txt
```

输出结构：

```json
{
  "status": "ok",
  "debugger": "gdb",
  "breakpoint_count": 81,
  "output_file": "bp.gdb",
  "breakpoints": [
    {
      "address": "0x401010",
      "type": "checker_call",
      "priority": "critical",
      "commands": ["printf \"strcmp at %p\\n\", $pc"]
    }
  ]
}
```

## 4. 典型工作流

### 场景 1：Native CTF 题

```powershell
# 1. Triage
python -m beaconflow.cli triage-native --target checker.exe --output-dir output

# 2. 根据证据推荐 hook
python -m beaconflow.cli suggest-hook --decision-points output/decision_points.json --roles output/roles.json

# 3. 生成 hook 脚本
python -m beaconflow.cli generate-template --template-name compare_strcmp_memcmp --output hook.js

# 4. 运行 hook（使用 Frida CLI）
frida -l hook.js checker.exe

# 5. 导入 hook 结果
python -m beaconflow.cli import-frida-log --log frida_output.log
```

### 场景 2：Android CTF 题

```powershell
# 1. Triage
python -m beaconflow.cli suggest-hook --decision-points dp.json --target-type android

# 2. 生成 Android hook
python -m beaconflow.cli generate-template --template-name jni_getstringutfchars --output jni_hook.js

# 3. 运行 hook
frida -U -l jni_hook.js com.example.app
```

### 场景 3：符号执行求解

```powershell
# 1. 分析路径差异
python -m beaconflow.cli flow-diff --metadata metadata.json --left wrong.drcov --right almost.drcov

# 2. 推荐 angr 参数
python -m beaconflow.cli suggest-angr --flow-diff diff.json --roles roles.json

# 3. 生成 angr 脚本
python -m beaconflow.cli generate-template --template-name find_avoid_stdin --output solve.py --params FIND_ADDR=0x401520,AVOID_ADDR=0x401560

# 4. 运行 angr
python solve.py target.exe

# 5. 导入求解结果
python -m beaconflow.cli import-angr-result --result angr_output.json
```
