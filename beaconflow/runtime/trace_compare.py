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
import platform
import time
from pathlib import Path
from typing import Any

try:
    import frida
except ImportError:
    frida = None


def _parse_metadata_decision_points(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """从 metadata 中提取决策点（cmp/test 指令地址）。

    尝试从 context.instructions 中计算每条 cmp/test 指令的精确地址。
    由于 metadata 中没有每条指令的精确地址，这里使用块起始地址作为近似。
    """
    points = []
    seen_addrs = set()
    for func in metadata.get("functions", []):
        func_name = func.get("name", "")
        for block in func.get("blocks", []):
            ctx = block.get("context", {})
            instructions = ctx.get("instructions", [])
            block_start = block.get("start", "0x0")
            for i, insn in enumerate(instructions):
                insn_lower = insn.lower().strip()
                if insn_lower.startswith("cmp ") or insn_lower.startswith("test "):
                    # 使用块起始地址作为 hook 点（精确指令地址不可用）
                    addr = block_start
                    if addr not in seen_addrs:
                        seen_addrs.add(addr)
                        points.append({
                            "address": addr,
                            "function": func_name,
                            "instruction": insn.strip(),
                        })
    return points


def _get_target_module_hint() -> str:
    """获取目标模块名提示，用于Frida定位正确的模块基址。
    
    返回空字符串让Frida自动选择最大的非系统模块。
    """
    return ""


def _build_frida_script(
    addresses: list[str],
    focus_function: str | None = None,
    max_events: int = 1000,
    image_base: str = "0x0",
) -> str:
    """构建 Frida 脚本来 hook 比较指令地址。"""
    addr_list = json.dumps(addresses)
    module_hint = _get_target_module_hint()

    # 构建模块查找代码
    if module_hint:
        module_finder = f"Process.findModuleByName('{module_hint}')"
    else:
        # 自动选择：排除系统DLL，选择最大的用户模块
        module_finder = """(function() {
            var mods = Process.enumerateModules();
            // 跳过ntdll, kernel32, kernelbase等系统模块
            var sysPrefixes = ['ntdll', 'kernel32', 'kernelbase', 'msvcrt', 'ucrtbase',
                               'user32', 'gdi32', 'advapi32', 'ole32', 'shell32',
                               'combase', 'rpcrt4', 'msvcrt', 'vcruntime', 'api-ms-',
                               'crypt32', 'ws2_32', 'secur32', 'dbghelp', 'frida'];
            for (var i = 0; i < mods.length; i++) {
                var name = mods[i].name.toLowerCase();
                var isSys = false;
                for (var j = 0; j < sysPrefixes.length; j++) {
                    if (name.startsWith(sysPrefixes[j])) { isSys = true; break; }
                }
                if (!isSys && mods[i].size > 10000) return mods[i];
            }
            return mods[0];
        })()"""

    return r"""
"use strict";

var addresses = """ + addr_list + r""";
var maxEvents = """ + str(max_events) + r""";
// 使用目标模块基址（ASLR 兼容）
var mod = """ + module_finder + r""";
var imageBase = mod ? mod.base : Process.enumerateModules()[0].base;
var events = [];
var eventCount = 0;

function addEvent(evt) {
    if (eventCount >= maxEvents) return;
    eventCount++;
    send(JSON.stringify({type: "event", data: evt}));
}

// 读取寄存器值（支持64/32/16/8位）
function readReg(ctx, name) {
    try {
        var val = ctx[name];
        if (val) {
            if (typeof val.toInt32 === 'function') {
                return {hex: "0x" + val.toString(16), signed: val.toInt32(), unsigned: val.toUInt32()};
            }
            return {hex: "0x" + val.toString(16), signed: 0, unsigned: 0};
        }
    } catch(e) {}
    return null;
}

// 尝试读取指针指向的字符串
function tryReadString(ptr_val, maxLen) {
    maxLen = maxLen || 64;
    try {
        if (ptr_val && typeof ptr_val.readUtf8String === 'function') {
            return ptr_val.readUtf8String(maxLen);
        }
    } catch(e) {}
    return null;
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
                            registers: {},
                            compare_hints: []
                        };

                        // 保存关键寄存器
                        var regNames = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                       "rsp", "rbp"];
                        for (var j = 0; j < regNames.length; j++) {
                            var regVal = readReg(ctx, regNames[j]);
                            if (regVal) {
                                evt.registers[regNames[j]] = regVal.hex;
                                // 如果值在可打印ASCII范围内，添加提示
                                var v = regVal.unsigned & 0xFF;
                                if (v >= 0x20 && v <= 0x7e) {
                                    evt.compare_hints.push(regNames[j] + ".low=0x" + v.toString(16) + "('" + String.fromCharCode(v) + "')");
                                }
                            }
                        }

                        // 尝试读取常见比较寄存器对指向的字符串
                        var ptrRegs = ["rcx", "rdx", "r8", "r9", "rsi", "rdi"];
                        for (var k = 0; k < ptrRegs.length; k++) {
                            try {
                                var p = ctx[ptrRegs[k]];
                                if (p) {
                                    var s = tryReadString(p, 64);
                                    if (s && s.length > 0 && s.length < 64) {
                                        evt.compare_hints.push(ptrRegs[k] + "->'" + s.substring(0, 48) + "'");
                                    }
                                }
                            } catch(e3) {}
                        }

                        addEvent(evt);
                    } catch(e) {}
                }
            });
        } catch(e) {
            // hook地址无效，跳过
        }
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
            image_base_val = metadata.get("image_base", "0x0")
            if isinstance(image_base_val, int):
                image_base_val = hex(image_base_val)
            image_base = image_base_val

            points = _parse_metadata_decision_points(metadata)
            image_base_int = int(image_base, 16) if image_base else 0
            for p in points:
                if focus_function and p["function"] != focus_function:
                    continue
                addr = p["address"]
                addr_int = int(addr, 16)
                if address_min:
                    try:
                        if addr_int < int(address_min, 16):
                            continue
                    except ValueError:
                        pass
                if address_max:
                    try:
                        if addr_int > int(address_max, 16):
                            continue
                    except ValueError:
                        pass
                # metadata 中的地址可能是绝对地址，需要转为 RVA
                if image_base_int and addr_int >= image_base_int:
                    rva = addr_int - image_base_int
                    hook_addresses.append(hex(rva))
                else:
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
    proc = None
    pid = None

    try:
        spawn_args = [str(target_path)]
        if args:
            spawn_args.extend(args)

        import subprocess as sp
        proc = sp.Popen(
            spawn_args,
            stdin=sp.PIPE,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            cwd=run_cwd,
        )
        pid = proc.pid

        import time as _time
        _time.sleep(0.3)

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

        _time.sleep(0.2)

        if stdin_data:
            if auto_newline and not stdin_data.endswith("\n"):
                stdin_data += "\n"
            try:
                proc.stdin.write(stdin_data.encode())
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
        else:
            try:
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass

        try:
            proc.wait(timeout=timeout)
        except sp.TimeoutExpired:
            proc.kill()
            proc.wait()

    except frida.ProcessNotFoundError:
        return {"status": "error", "message": f"无法附加到进程: {target_path}"}
    except frida.TransportError:
        pass
    except Exception as e:
        return {"status": "error", "message": f"Frida 错误: {e}"}
    finally:
        if proc is not None:
            try:
                proc.kill()
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
