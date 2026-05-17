# BeaconFlow Case Workspace 详细指南

本文档详细介绍 BeaconFlow 的 Case Workspace 功能，帮助 AI Agent 在多轮分析中持续围绕同一个目标工作。

## 1. 概述

Case Workspace 让一个 CTF 题目或分析目标形成稳定工作区，方便 AI Agent 多轮分析而不需要每次重新猜路径、目标文件、trace 文件、metadata 文件位置。

## 2. 命令列表

| 命令 | 用途 |
| --- | --- |
| `init-case` | 初始化工作区 |
| `summarize-case` | 汇总工作区状态 |
| `add-metadata` | 添加 metadata 文件 |
| `add-run` | 添加运行记录 |
| `add-report` | 添加分析报告 |
| `add-note` | 添加分析笔记 |
| `list-runs` | 列出运行记录 |
| `list-reports` | 列出分析报告 |
| `list-notes` | 列出分析笔记 |
| `destroy-case` | 删除工作区 |

## 3. 工作区目录结构

```
.case/
  manifest.json   # 工作区清单（目标、架构、运行记录、报告、笔记）
  target          # 目标二进制文件（拷贝或符号链接）
  metadata/       # 元数据 JSON 文件
  runs/           # 运行/trace 结果
  reports/        # 分析报告
  notes/          # 用户/AI 笔记
```

## 4. 典型工作流

### 4.1 初始化工作区

```powershell
python -m beaconflow.cli init-case --target ./flagchecker --arch loongarch64 --backend qemu
```

输出：

```json
{
  "status": "ok",
  "case_dir": ".case",
  "target": "./flagchecker",
  "arch": "loongarch64",
  "backend": "qemu"
}
```

### 4.2 添加 metadata

```powershell
python -m beaconflow.cli add-metadata --name ghidra --path metadata.json --description "Ghidra metadata"
```

### 4.3 添加运行记录

```powershell
python -m beaconflow.cli add-run --name case001 --stdin-preview "AAAA" --verdict failure --returncode 1
python -m beaconflow.cli add-run --name case002 --stdin-preview "ISCC{test}" --verdict success --returncode 0
```

### 4.4 添加分析报告

```powershell
python -m beaconflow.cli add-report --name flow_report --path flow.md --type flow --description "执行流分析"
python -m beaconflow.cli add-report --name sig_report --path sig.md --type sig-match --description "签名匹配"
```

### 4.5 添加笔记

```powershell
python -m beaconflow.cli add-note --title "Round 1" --content "Found AES at 0x401000, TEA at 0x402000"
python -m beaconflow.cli add-note --title "Round 2" --content "trace-calls exposed flag prefix ISCC{"
```

### 4.6 查看工作区状态

```powershell
python -m beaconflow.cli summarize-case --format markdown
```

输出：

```markdown
# BeaconFlow Case Workspace

- **Target**: `./flagchecker`
- **Arch**: `loongarch64`
- **Backend**: `qemu`

## Metadata (1)
- `ghidra.json` - Ghidra metadata

## Runs (2)
- case001: failure (stdin="AAAA", rc=1)
- case002: success (stdin="ISCC{test}", rc=0)

## Reports (2)
- flow: 1
- sig-match: 1

## Notes (2)
- Round 1: Found AES at 0x401000, TEA at 0x402000
- Round 2: trace-calls exposed flag prefix ISCC{
```

### 4.7 列出详细记录

```powershell
python -m beaconflow.cli list-runs
python -m beaconflow.cli list-reports
python -m beaconflow.cli list-notes
```

## 5. AI Agent 多轮分析示例

### Round 1：初始 Triage

```powershell
# 初始化
python -m beaconflow.cli init-case --target drink_tea.exe --arch x64 --backend dynamorio

# Triage
python -m beaconflow.cli triage-native --target drink_tea.exe --output-dir output

# 保存结果
python -m beaconflow.cli add-metadata --name ghidra --path output/metadata.json
python -m beaconflow.cli add-report --name triage --path output/triage_native.md --type triage
python -m beaconflow.cli add-note --title "Round 1" --content "TEA encryption at 0x140001180, validator at 0x1400012e0 calls memcmp"
```

### Round 2：深入分析

```powershell
# 签名匹配
python -m beaconflow.cli sig-match --metadata output/metadata.json --format markdown --output sig_report.md

# 保存结果
python -m beaconflow.cli add-report --name sig_match --path sig_report.md --type sig-match
python -m beaconflow.cli add-note --title "Round 2" --content "Confirmed TEA: SHL+SHR+XOR pattern with delta 0x9e3779b9"
```

### Round 3：运行时追踪

```powershell
# trace-calls
python -m beaconflow.cli trace-calls --target drink_tea.exe --stdin "AAAA" --format markdown --output trace_report.md

# 保存结果
python -m beaconflow.cli add-report --name trace_calls --path trace_report.md --type trace-calls
python -m beaconflow.cli add-run --name trace001 --stdin-preview "AAAA" --verdict failure
python -m beaconflow.cli add-note --title "Round 3" --content "memcmp compares input with encrypted flag, need to reverse TEA"
```

### Round 4：求解

```powershell
# 推荐 angr 参数
python -m beaconflow.cli suggest-angr --flow-diff output/flow.json --roles output/roles.json

# 生成求解脚本
python -m beaconflow.cli generate-template --template-name find_avoid_stdin --output solve.py --params FIND_ADDR=0x140001520,AVOID_ADDR=0x140001560

# 保存结果
python -m beaconflow.cli add-note --title "Round 4" --content "angr solve succeeded, flag = ISCC{xxx}"
```

## 6. manifest.json 格式

```json
{
  "target": "./flagchecker",
  "arch": "loongarch64",
  "backend": "qemu",
  "created": "2026-05-17T10:00:00",
  "metadata": {
    "ghidra": {
      "path": "metadata/ghidra.json",
      "description": "Ghidra metadata",
      "added": "2026-05-17T10:05:00"
    }
  },
  "runs": [
    {
      "name": "case001",
      "verdict": "failure",
      "stdin_preview": "AAAA",
      "returncode": 1,
      "added": "2026-05-17T10:10:00"
    }
  ],
  "reports": [
    {
      "name": "flow_report",
      "path": "reports/flow.md",
      "type": "flow",
      "description": "执行流分析",
      "added": "2026-05-17T10:15:00"
    }
  ],
  "notes": [
    {
      "title": "Round 1",
      "content": "Found AES at 0x401000",
      "added": "2026-05-17T10:20:00"
    }
  ]
}
```
