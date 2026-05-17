"""
外部工具输出导入 - Frida / GDB / angr / JADX。

BeaconFlow 不自研这些工具，只负责导入它们的输出并关联已有分析证据。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def import_frida_log(
    log_path: str | Path,
    metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """导入 Frida hook 输出日志。

    支持两种格式：
    1. JSON 行格式（每行一个 send() 输出的 JSON）
    2. Frida CLI 输出格式（含 "message": 前缀）
    """
    log = Path(log_path)
    if not log.exists():
        return {"status": "error", "error": f"log file not found: {log}"}

    content = log.read_text(encoding="utf-8", errors="replace")
    events: list[dict[str, Any]] = []
    parse_errors = 0

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # 格式1: 纯 JSON 行
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "payload" in obj:
                    payload = obj["payload"]
                    if isinstance(payload, dict):
                        events.append(payload)
                    else:
                        events.append({"raw": str(payload)})
                else:
                    events.append(obj)
                continue
            except json.JSONDecodeError:
                pass

        # 格式2: Frida CLI 输出 "message: ..."
        m = re.match(r'^\d+\s+message:\s*(.+)$', line)
        if m:
            try:
                obj = json.loads(m.group(1))
                if "payload" in obj:
                    payload = obj["payload"]
                    if isinstance(payload, dict):
                        events.append(payload)
                    else:
                        events.append({"raw": str(payload)})
                else:
                    events.append(obj)
                continue
            except json.JSONDecodeError:
                pass

        # 格式3: 简单文本行
        if "strcmp" in line or "memcmp" in line or "strncmp" in line:
            events.append({"type": "compare", "raw": line})
        elif "read" in line or "recv" in line or "scanf" in line:
            events.append({"type": "input", "raw": line})
        elif "GetStringUTFChars" in line or "String.equals" in line:
            events.append({"type": "android", "raw": line})
        else:
            parse_errors += 1

    # 按类型分类统计
    type_counts: dict[str, int] = {}
    for ev in events:
        t = ev.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    # 提取比较事件
    compare_events: list[dict[str, Any]] = []
    for ev in events:
        t = ev.get("type", "")
        if t in ("strcmp", "memcmp", "strncmp", "String.equals", "String.compareTo"):
            compare_events.append({
                "type": t,
                "left": ev.get("left", ev.get("this", "")),
                "right": ev.get("right", ev.get("other", "")),
                "result": ev.get("result", ev.get("return_value", "")),
                "caller": ev.get("caller", ""),
            })

    # 提取输入事件
    input_events: list[dict[str, Any]] = []
    for ev in events:
        t = ev.get("type", "")
        if t in ("read", "recv", "scanf", "fgets", "GetStringUTFChars"):
            input_events.append({
                "type": t,
                "data": ev.get("data", ev.get("value", "")),
                "length": ev.get("length", 0),
            })

    return {
        "status": "ok",
        "total_events": len(events),
        "parse_errors": parse_errors,
        "type_counts": type_counts,
        "compare_events": len(compare_events),
        "compares": compare_events[:50],
        "input_events": len(input_events),
        "inputs": input_events[:20],
    }


def import_gdb_log(
    log_path: str | Path,
    metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """导入 GDB 调试日志。

    支持解析：
    1. GDB 断点命中日志
    2. 寄存器 dump
    3. 内存 dump
    """
    log = Path(log_path)
    if not log.exists():
        return {"status": "error", "error": f"log file not found: {log}"}

    content = log.read_text(encoding="utf-8", errors="replace")

    breakpoints_hit: list[dict[str, Any]] = []
    register_dumps: list[dict[str, Any]] = []
    memory_dumps: list[dict[str, Any]] = []

    # 解析断点命中
    bp_pattern = re.compile(
        r'(?:Breakpoint|hit)\s+\d+.*?(?:at|address)\s+(0x[0-9a-fA-F]+)',
        re.IGNORECASE
    )
    for m in bp_pattern.finditer(content):
        breakpoints_hit.append({"address": m.group(1)})

    # 解析寄存器值
    reg_pattern = re.compile(
        r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|rip|eax|ebx|ecx|edx)\s+(0x[0-9a-fA-F]+)',
        re.IGNORECASE
    )
    current_regs: dict[str, str] = {}
    for m in reg_pattern.finditer(content):
        reg = m.group(1).lower()
        val = m.group(2)
        current_regs[reg] = val
    if current_regs:
        register_dumps.append(current_regs)

    # 解析内存 dump
    mem_pattern = re.compile(r'(0x[0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s*)+)')
    for m in mem_pattern.finditer(content):
        memory_dumps.append({"address": m.group(1), "hex": m.group(2).strip()})

    return {
        "status": "ok",
        "breakpoints_hit": len(breakpoints_hit),
        "bp_details": breakpoints_hit[:30],
        "register_dumps": len(register_dumps),
        "regs": register_dumps[:5],
        "memory_dumps": len(memory_dumps),
        "mem_details": memory_dumps[:10],
    }


def import_angr_result(
    result_path: str | Path,
    metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """导入 angr 求解结果。

    支持格式：
    1. JSON（angr 脚本输出）
    2. 文本（包含 flag/flag{ 等模式）
    """
    result_file = Path(result_path)
    if not result_file.exists():
        return {"status": "error", "error": f"result file not found: {result_file}"}

    content = result_file.read_text(encoding="utf-8", errors="replace")

    # 尝试 JSON 解析
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            solution = data.get("solution", "")
            status = data.get("status", "unknown")
            return {
                "status": "ok",
                "angr_status": status,
                "solution": solution,
                "raw": data,
            }
    except json.JSONDecodeError:
        pass

    # 文本模式：搜索 flag 模式
    flag_patterns = [
        re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
        re.compile(r'CTF\{[^}]+\}', re.IGNORECASE),
        re.compile(r'[A-Za-z0-9_]{20,}'),
    ]

    found_flags: list[str] = []
    for pattern in flag_patterns:
        for m in pattern.finditer(content):
            found_flags.append(m.group(0))

    return {
        "status": "ok",
        "angr_status": "text_output",
        "solutions_found": len(found_flags),
        "solutions": found_flags[:10],
        "raw_preview": content[:2000],
    }


def import_jadx_summary(
    summary_path: str | Path,
    metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """导入 JADX 反编译摘要。

    支持 JSON 格式的 JADX 输出。
    """
    summary = Path(summary_path)
    if not summary.exists():
        return {"status": "error", "error": f"summary file not found: {summary}"}

    content = summary.read_text(encoding="utf-8", errors="replace")

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        data = {"raw_text": content[:5000]}

    # 提取关键信息
    classes: list[str] = []
    methods: list[str] = []
    strings: list[str] = []

    if isinstance(data, dict):
        classes = data.get("classes", [])
        methods = data.get("methods", [])
        strings = data.get("strings", [])
        if not classes and "class_names" in data:
            classes = data["class_names"]

    # 从文本中提取
    if not strings and isinstance(content, str):
        str_pattern = re.compile(r'"([^"]{4,})"')
        strings = list(set(m.group(1) for m in str_pattern.finditer(content)))[:100]

    return {
        "status": "ok",
        "class_count": len(classes),
        "method_count": len(methods),
        "string_count": len(strings),
        "classes": classes[:50],
        "methods": methods[:50],
        "strings": strings[:50],
    }
