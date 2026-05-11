"""
运行时比较指令值提取 - 基于 Frida。

在 cmp/test/jcc 决策点插桩，
读取运行时寄存器上下文和操作数值，
让 AI 知道失败分支到底比较了什么值。

当前仅支持 x86/x64 架构。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

try:
    import frida
except ImportError:
    frida = None


def _parse_metadata_decision_points(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """从 metadata 中提取决策点（cmp/test 指令地址）。"""
    points = []
    for func in metadata.get("functions", []):
        func_name = func.get("name", "")
        for block in func.get("blocks", []):
            ctx = block.get("context", {})
            instructions = ctx.get("instructions", [])
            for i, insn in enumerate(instructions):
                insn_lower = insn.lower().strip()
                if insn_lower.startswith("cmp ") or insn_lower.startswith("test "):
                    block_start = block.get("start", "0x0")
                    points.append({
                        "address": block_start,
                        "function": func_name,
                        "instruction": insn.strip(),
                    })
    return points


def _build_frida_script(
    addresses: list[str],
    focus_function: str | None = None,
    max_events: int = 1000,
    image_base: str = "0x0",
) -> str:
    """构建 Frida 脚本来 hook 比较指令地址。"""
    addr_list = json.dumps(addresses)

    return r"""
"use strict";

var addresses = """ + addr_list + r""";
var maxEvents = """ + str(max_events) + r""";
var imageBase = ptr(""" + json.dumps(image_base) + r""");
var events = [];
var eventCount = 0;

function addEvent(evt) {
    if (eventCount >= maxEvents) return;
    eventCount++;
    send(JSON.stringify({type: "event", data: evt}));
}

// 解析 x86/x64 操作数
function parseOperand(text, ctx) {
    var result = {text: text, kind: "unknown", value: null, hex: null, ascii: null};

    // 立即数
    var immMatch = text.match(/^(0x[0-9a-f]+|-?\d+)$/i);
    if (immMatch) {
        result.kind = "immediate";
        var val = parseInt(text, text.startsWith("0x") ? 16 : 10);
        result.value = val;
        result.hex = "0x" + val.toString(16);
        if (val >= 0x20 && val <= 0x7e) {
            result.ascii = String.fromCharCode(val);
        }
        return result;
    }

    // 寄存器
    var regMap = {
        "rax": "rax", "rbx": "rbx", "rcx": "rcx", "rdx": "rdx",
        "rsi": "rsi", "rdi": "rdi", "rbp": "rbp", "rsp": "rsp",
        "r8": "r8", "r9": "r9", "r10": "r10", "r11": "r11",
        "r12": "r12", "r13": "r13", "r14": "r14", "r15": "r15",
        "eax": "eax", "ebx": "ebx", "ecx": "ecx", "edx": "edx",
        "esi": "esi", "edi": "edi", "ebp": "ebp", "esp": "esp",
        "ax": "ax", "bx": "bx", "cx": "cx", "dx": "dx",
        "al": "al", "bl": "bl", "cl": "cl", "dl": "dl",
        "ah": "ah", "bh": "bh", "ch": "ch", "dh": "dh",
        "r8d": "r8d", "r9d": "r9d", "r10d": "r10d", "r11d": "r11d",
        "r12d": "r12d", "r13d": "r13d", "r14d": "r14d", "r15d": "r15d",
    };

    var regLower = text.toLowerCase().replace(/^\[|\]$/g, "");
    if (regMap[regLower]) {
        result.kind = "register";
        try {
            var val = this.context[regLower];
            if (val) {
                var numVal = val.toInt32 !== undefined ? val.toInt32() : 0;
                result.value = numVal;
                result.hex = "0x" + (numVal >>> 0).toString(16);
                if (numVal >= 0x20 && numVal <= 0x7e) {
                    result.ascii = String.fromCharCode(numVal);
                }
            }
        } catch(e) {}
        return result;
    }

    // 内存操作数 [reg+offset]
    var memMatch = text.match(/^\[(.+)\]$/i);
    if (memMatch) {
        result.kind = "memory";
        try {
            var addrStr = memMatch[1].toLowerCase().replace(/\s/g, "");
            // 简单处理 [reg+0xoffset]
            var parts = addrStr.split("+");
            var baseReg = parts[0];
            var offset = parts.length > 1 ? parseInt(parts[1], 16) : 0;
            var baseVal = this.context[baseReg];
            if (baseVal) {
                var addr = baseVal.add(offset);
                var byteVal = addr.readU8();
                result.value = byteVal;
                result.hex = "0x" + byteVal.toString(16);
                if (byteVal >= 0x20 && byteVal <= 0x7e) {
                    result.ascii = String.fromCharCode(byteVal);
                }
            }
        } catch(e) {}
        return result;
    }

    return result;
}

// 在指定地址插桩（RVA + 运行时 image base）
for (var i = 0; i < addresses.length; i++) {
    (function(addrStr) {
        try {
            var rva = ptr(addrStr);
            var hookAddr = imageBase.add(rva);
            Interceptor.attach(hookAddr, {
                onEnter: function(args) {
                    try {
                        var ctx = this.context;
                        var evt = {
                            address: addrStr,
                            event_index: eventCount,
                            registers: {}
                        };

                        // 保存关键寄存器
                        var regNames = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
                        for (var j = 0; j < regNames.length; j++) {
                            try {
                                var rv = ctx[regNames[j]];
                                if (rv) {
                                    evt.registers[regNames[j]] = "0x" + rv.toString(16);
                                }
                            } catch(e2) {}
                        }

                        addEvent(evt);
                    } catch(e) {}
                }
            });
        } catch(e) {}
    })(addresses[i]);
}
"""


def trace_compare(
    target: str,
    metadata: dict[str, Any] | None = None,
    metadata_path: str | None = None,
    stdin_data: str | None = None,
    auto_newline: bool = True,
    args: list[str] | None = None,
    run_cwd: str | None = None,
    focus_function: str | None = None,
    addresses: list[str] | None = None,
    address_min: str | None = None,
    address_max: str | None = None,
    max_events: int = 1000,
    timeout: int = 30,
) -> dict[str, Any]:
    """使用 Frida 在比较指令处插桩，提取运行时寄存器值。

    参数:
        target: 目标可执行文件路径
        metadata: metadata 字典
        metadata_path: metadata JSON 文件路径
        stdin_data: 标准输入数据
        focus_function: 聚焦函数名
        addresses: 手动指定的地址列表
        max_events: 最大事件数
        timeout: 超时时间（秒）
    """
    if frida is None:
        return {
            "status": "error",
            "message": "Frida 未安装。请运行: pip install frida frida-tools",
        }

    target_path = Path(target).resolve()
    if not target_path.exists():
        return {
            "status": "error",
            "message": f"目标文件不存在: {target_path}",
        }

    # 收集决策点地址
    hook_addresses: list[str] = []
    image_base = "0x0"

    if addresses:
        hook_addresses = addresses
    else:
        if metadata is None and metadata_path:
            try:
                metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                return {"status": "error", "message": f"无法读取 metadata: {e}"}

        if metadata:
            # 从 metadata 提取 image base
            image_base = metadata.get("image_base", "0x0")
            if isinstance(image_base, int):
                image_base = hex(image_base)

            points = _parse_metadata_decision_points(metadata)
            for p in points:
                if focus_function and p["function"] != focus_function:
                    continue
                addr = p["address"]
                if address_min:
                    try:
                        if int(addr, 16) < int(address_min, 16):
                            continue
                    except ValueError:
                        pass
                if address_max:
                    try:
                        if int(addr, 16) > int(address_max, 16):
                            continue
                    except ValueError:
                        pass
                hook_addresses.append(addr)

    if not hook_addresses:
        return {
            "status": "no_points",
            "message": "没有找到决策点。请提供 --metadata 或 --address 参数。",
        }

    frida_script = _build_frida_script(
        hook_addresses,
        focus_function=focus_function,
        max_events=max_events,
        image_base=image_base,
    )

    collected_data: dict[str, Any] = {}
    result_events: list[dict[str, Any]] = []
    pid = None

    try:
        spawn_args = [str(target_path)]
        if args:
            spawn_args.extend(args)

        pid = frida.spawn(spawn_args)
        session = frida.attach(pid)

        def on_message(message, data):
            nonlocal result_events
            if message["type"] == "send":
                try:
                    payload = json.loads(message["payload"])
                    if isinstance(payload, dict) and payload.get("type") == "event":
                        result_events.append(payload["data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            elif message["type"] == "error":
                import logging
                logging.warning("Frida 脚本错误: %s", message.get("description", ""))

        script = session.create_script(frida_script)
        script.on("message", on_message)
        script.load()

        if stdin_data and auto_newline and not stdin_data.endswith("\n"):
            stdin_data += "\n"

        frida.resume(pid)

        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):
                break

    except frida.ProcessNotFoundError:
        return {"status": "error", "message": f"无法附加到进程: {target_path}"}
    except frida.TransportError:
        pass
    except Exception as e:
        return {"status": "error", "message": f"Frida 错误: {e}"}
    finally:
        if pid is not None:
            try:
                os.kill(pid, 9)
            except (ProcessLookupError, PermissionError):
                pass

    events = result_events

    return {
        "status": "ok",
        "target": str(target_path),
        "backend": "frida",
        "arch": "x64",
        "input": {
            "stdin_preview": (stdin_data or "")[:64],
            "args": args or [],
        },
        "hooked_addresses": len(hook_addresses),
        "events": events,
        "summary": {
            "total_events": len(events),
        },
    }


def trace_compare_to_markdown(result: dict[str, Any]) -> str:
    """将 trace-compare 结果转为 Markdown 格式。"""
    if result.get("status") == "error":
        return f"# Trace Compare Error\n\n{result.get('message', '')}\n"

    if result.get("status") == "no_points":
        return f"# Trace Compare\n\nNo decision points found. {result.get('message', '')}\n"

    lines = [
        "# BeaconFlow Trace Compare",
        "",
        f"- **Target**: `{result.get('target', '')}`",
        f"- **Backend**: `{result.get('backend', '')}`",
        f"- **Arch**: `{result.get('arch', '')}`",
        f"- **Hooked addresses**: {result.get('hooked_addresses', 0)}",
        "",
    ]

    events = result.get("events", [])
    if events:
        lines.append("## Events")
        lines.append("")
        for evt in events:
            addr = evt.get("address", "?")
            idx = evt.get("event_index", "?")
            lines.append(f"### Event {idx} @ `{addr}`")
            lines.append("")
            regs = evt.get("registers", {})
            if regs:
                lines.append("Registers:")
                for reg, val in regs.items():
                    lines.append(f"- `{reg}` = `{val}`")
            lines.append("")
    else:
        lines.append("No events captured. The target may not have reached the hooked addresses.")
        lines.append("")

    summary = result.get("summary", {})
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total events: {summary.get('total_events', 0)}")
    lines.append("")

    return "\n".join(lines)
