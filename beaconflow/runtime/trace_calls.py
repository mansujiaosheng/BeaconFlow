"""
运行时库函数参数提取 - 基于 Frida。

Hook strcmp/memcmp/strncmp/strlen 等函数，
提取运行时参数、返回值和调用点信息，
让 AI 能直接看到比较了什么值。

支持:
  - Windows x64 PE: msvcrt.dll / ucrtbase.dll
  - Linux ELF: libc.so.6
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_DEFAULT_HOOKS = "strcmp,strncmp,memcmp,strlen,strcpy,strncpy,sprintf,printf,puts,gets,fgets,fread,fwrite,scanf,sscanf"

_FRIDA_SCRIPT_TEMPLATE = r"""
"use strict";

// 默认 hook 列表
var hookNames = %HOOK_NAMES%;
var maxRead = %MAX_READ%;
var maxEvents = %MAX_EVENTS%;
var filterUserOnly = %FILTER_USER_ONLY%;

var events = [];
var eventCount = 0;

// 主模块基址和大小，用于判断 call_site 是否属于用户代码
var mainModule = Process.enumerateModules()[0];
var mainBase = mainModule.base;
var mainEnd = mainModule.base.add(mainModule.size);

function isUserAddress(addr) {
    try {
        return addr.compare(mainBase) >= 0 && addr.compare(mainEnd) < 0;
    } catch(e) {
        return false;
    }
}

// 读取内存为 hex + ascii
function readMem(ptr, size) {
    var result = {hex: "", ascii: ""};
    try {
        var buf = ptr.readByteArray(size);
        if (buf) {
            var arr = new Uint8Array(buf);
            var hexParts = [];
            var asciiParts = [];
            for (var i = 0; i < arr.length; i++) {
                hexParts.push(("0" + arr[i].toString(16)).slice(-2));
                if (arr[i] >= 0x20 && arr[i] <= 0x7e) {
                    asciiParts.push(String.fromCharCode(arr[i]));
                } else {
                    asciiParts.push(".");
                }
            }
            result.hex = hexParts.join("");
            result.ascii = asciiParts.join("");
        }
    } catch (e) {
        result.hex = "unreadable";
        result.ascii = "";
    }
    return result;
}

// 读取字符串（遇到 \0 截断，使用 readByteArray 避免 UTF-8 解码错误）
function readStr(ptr, maxLen) {
    try {
        var result = {hex: "", ascii: ""};
        var buf = ptr.readByteArray(maxLen);
        if (buf) {
            var arr = new Uint8Array(buf);
            var hexParts = [];
            var asciiParts = [];
            for (var i = 0; i < arr.length; i++) {
                if (arr[i] === 0) break;
                hexParts.push(("0" + arr[i].toString(16)).slice(-2));
                if (arr[i] >= 0x20 && arr[i] <= 0x7e) {
                    asciiParts.push(String.fromCharCode(arr[i]));
                } else {
                    asciiParts.push(".");
                }
            }
            result.hex = hexParts.join("");
            result.ascii = asciiParts.join("");
        }
        return result;
    } catch (e) {
        return {hex: "unreadable", ascii: ""};
    }
}

// Windows 和 Linux 的 libc 模块名
var libcModules = [];
if (Process.platform === "windows") {
    libcModules = ["ucrtbase.dll", "msvcrt.dll", "api-ms-win-crt-string-l1-1-0.dll",
                   "api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-filesystem-l1-1-0.dll"];
} else {
    libcModules = ["libc.so.6", "libc.musl-x86_64.so.1", "libc.so"];
}

function findExport(funcName) {
    for (var i = 0; i < libcModules.length; i++) {
        try {
            var mod = Process.getModuleByName(libcModules[i]);
            var addr = mod.getExportByName(funcName);
            if (addr) return addr;
        } catch(e) {}
    }
    return null;
}

function addEvent(evt) {
    if (eventCount >= maxEvents) return;
    eventCount++;
    send(JSON.stringify({type: "event", data: evt}));
}

// Hook strcmp
function hook_strcmp() {
    var addr = findExport("strcmp");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var s0 = readStr(this.arg0, maxRead);
            var s1 = readStr(this.arg1, maxRead);
            var rv = retval.toInt32();
            addEvent({
                function: "strcmp",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "s1", pointer: "0x" + this.arg0.toString(16), ascii: s0.ascii, bytes_hex: s0.hex},
                    {name: "s2", pointer: "0x" + this.arg1.toString(16), ascii: s1.ascii, bytes_hex: s1.hex}
                ],
                return_value: rv,
                verdict_hint: rv === 0 ? "equal" : "not_equal"
            });
        }
    });
}

// Hook strncmp
function hook_strncmp() {
    var addr = findExport("strncmp");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2].toInt32();
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var n = this.arg2;
            var s0 = readMem(this.arg0, Math.min(n, maxRead));
            var s1 = readMem(this.arg1, Math.min(n, maxRead));
            var rv = retval.toInt32();
            addEvent({
                function: "strncmp",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "s1", pointer: "0x" + this.arg0.toString(16), ascii: s0.ascii, bytes_hex: s0.hex},
                    {name: "s2", pointer: "0x" + this.arg1.toString(16), ascii: s1.ascii, bytes_hex: s1.hex},
                    {name: "n", value: n}
                ],
                return_value: rv,
                verdict_hint: rv === 0 ? "equal" : "not_equal"
            });
        }
    });
}

// Hook memcmp
function hook_memcmp() {
    var addr = findExport("memcmp");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2].toInt32();
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var n = this.arg2;
            var s0 = readMem(this.arg0, Math.min(n, maxRead));
            var s1 = readMem(this.arg1, Math.min(n, maxRead));
            var rv = retval.toInt32();
            addEvent({
                function: "memcmp",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "buf1", pointer: "0x" + this.arg0.toString(16), ascii: s0.ascii, bytes_hex: s0.hex},
                    {name: "buf2", pointer: "0x" + this.arg1.toString(16), ascii: s1.ascii, bytes_hex: s1.hex},
                    {name: "n", value: n}
                ],
                return_value: rv,
                verdict_hint: rv === 0 ? "equal" : "not_equal"
            });
        }
    });
}

// Hook strlen
function hook_strlen() {
    var addr = findExport("strlen");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var len = retval.toInt32();
            var s = readStr(this.arg0, Math.min(len + 1, maxRead));
            addEvent({
                function: "strlen",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "s", pointer: "0x" + this.arg0.toString(16), ascii: s.ascii, bytes_hex: s.hex}
                ],
                return_value: len,
                verdict_hint: "length=" + len
            });
        }
    });
}

// Hook printf
function hook_printf() {
    var addr = findExport("printf");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var fmt = readStr(this.arg0, maxRead);
            addEvent({
                function: "printf",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "fmt", pointer: "0x" + this.arg0.toString(16), ascii: fmt.ascii, bytes_hex: fmt.hex}
                ],
                return_value: retval.toInt32(),
                verdict_hint: "output"
            });
        }
    });
}

// Hook puts
function hook_puts() {
    var addr = findExport("puts");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var s = readStr(this.arg0, maxRead);
            addEvent({
                function: "puts",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "s", pointer: "0x" + this.arg0.toString(16), ascii: s.ascii, bytes_hex: s.hex}
                ],
                return_value: retval.toInt32(),
                verdict_hint: "output"
            });
        }
    });
}

// Hook gets
function hook_gets() {
    var addr = findExport("gets");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var s = readStr(this.arg0, maxRead);
            addEvent({
                function: "gets",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "buf", pointer: "0x" + this.arg0.toString(16), ascii: s.ascii, bytes_hex: s.hex}
                ],
                return_value: retval.toInt32(),
                verdict_hint: "input"
            });
        }
    });
}

// Hook fgets
function hook_fgets() {
    var addr = findExport("fgets");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.arg1 = args[1].toInt32();
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            if (!retval.isNull()) {
                var s = readStr(this.arg0, Math.min(this.arg1, maxRead));
                addEvent({
                    function: "fgets",
                    call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                    return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                    args: [
                        {name: "buf", pointer: "0x" + this.arg0.toString(16), ascii: s.ascii, bytes_hex: s.hex},
                        {name: "size", value: this.arg1}
                    ],
                    return_value: 0,
                    verdict_hint: "input"
                });
            }
        }
    });
}

// Hook scanf
function hook_scanf() {
    var addr = findExport("scanf");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var fmt = readStr(this.arg0, maxRead);
            addEvent({
                function: "scanf",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "fmt", pointer: "0x" + this.arg0.toString(16), ascii: fmt.ascii, bytes_hex: fmt.hex}
                ],
                return_value: retval.toInt32(),
                verdict_hint: "input"
            });
        }
    });
}

// Hook sscanf
function hook_sscanf() {
    var addr = findExport("sscanf");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.retAddr = this.returnAddress;
            this.isUserCall = !filterUserOnly || isUserAddress(this.retAddr);
        },
        onLeave: function(retval) {
            if (!this.isUserCall) return;
            var src = readStr(this.arg0, maxRead);
            var fmt = readStr(this.arg1, maxRead);
            addEvent({
                function: "sscanf",
                call_site: this.retAddr ? "0x" + this.retAddr.sub(mainBase).toString(16) : "unknown",
                return_address: this.retAddr ? "0x" + this.retAddr.toString(16) : "unknown",
                args: [
                    {name: "src", pointer: "0x" + this.arg0.toString(16), ascii: src.ascii, bytes_hex: src.hex},
                    {name: "fmt", pointer: "0x" + this.arg1.toString(16), ascii: fmt.ascii, bytes_hex: fmt.hex}
                ],
                return_value: retval.toInt32(),
                verdict_hint: "input"
            });
        }
    });
}

// 安装 hooks
var hookMap = {
    "strcmp": hook_strcmp,
    "strncmp": hook_strncmp,
    "memcmp": hook_memcmp,
    "strlen": hook_strlen,
    "printf": hook_printf,
    "puts": hook_puts,
    "gets": hook_gets,
    "fgets": hook_fgets,
    "scanf": hook_scanf,
    "sscanf": hook_sscanf,
};

for (var i = 0; i < hookNames.length; i++) {
    var name = hookNames[i];
    if (hookMap[name]) {
        try {
            hookMap[name]();
        } catch(e) {}
    }
}

// 进程退出时不需要额外处理，事件已经实时发送
"""


def trace_calls(
    target: str,
    stdin_data: str | None = None,
    args: list[str] | None = None,
    auto_newline: bool = True,
    run_cwd: str | None = None,
    timeout: int = 30,
    hook: str | None = None,
    max_read: int = 128,
    max_events: int = 1000,
    filter_user_only: bool = True,
) -> dict[str, Any]:
    """使用 Frida hook 运行时库函数，提取参数和返回值。

    参数:
        target: 目标可执行文件路径
        stdin_data: 标准输入数据
        args: 命令行参数
        auto_newline: 是否自动在 stdin 末尾添加换行
        run_cwd: 运行工作目录
        timeout: 超时时间（秒）
        hook: 要 hook 的函数列表（逗号分隔）
        max_read: 最大读取字节数
        max_events: 最大事件数
        filter_user_only: 是否只保留用户代码（主模块）调用的函数，过滤 CRT 噪声
    """
    try:
        import frida
    except ImportError:
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

    hook_names = (hook or _DEFAULT_HOOKS).split(",")
    hook_names = [h.strip() for h in hook_names if h.strip()]

    frida_script = _FRIDA_SCRIPT_TEMPLATE
    frida_script = frida_script.replace("%HOOK_NAMES%", json.dumps(hook_names))
    frida_script = frida_script.replace("%MAX_READ%", str(max_read))
    frida_script = frida_script.replace("%MAX_EVENTS%", str(max_events))
    frida_script = frida_script.replace("%FILTER_USER_ONLY%", "true" if filter_user_only else "false")

    result_events: list[dict] = []
    proc = None
    pid = None

    try:
        spawn_args = [str(target_path)]
        if args:
            spawn_args.extend(args)

        # 使用 subprocess 启动进程以便传递 stdin
        import subprocess
        proc = subprocess.Popen(
            spawn_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=run_cwd,
        )
        pid = proc.pid

        # 等待进程启动
        import time
        time.sleep(0.3)

        # 附加 Frida
        session = frida.attach(pid)

        def on_message(message, data):
            if message["type"] == "send":
                try:
                    payload = json.loads(message["payload"])
                    if isinstance(payload, dict) and payload.get("type") == "event":
                        result_events.append(payload["data"])
                except (json.JSONDecodeError, TypeError):
                    pass

        script = session.create_script(frida_script)
        script.on("message", on_message)
        script.load()

        # 等待 hooks 生效
        time.sleep(0.2)

        # 发送 stdin 数据
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

        # 等待进程完成
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    except frida.ProcessNotFoundError:
        return {
            "status": "error",
            "message": f"无法附加到进程: {target_path}",
        }
    except frida.TransportError:
        pass
    except Exception as e:
        return {
            "status": "error",
            "message": f"Frida 错误: {e}",
        }
    finally:
        if proc is not None:
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError):
                pass

    events = result_events
    interesting = [e for e in events if e.get("function") in ("strcmp", "strncmp", "memcmp")]
    not_equal = [e for e in interesting if e.get("verdict_hint") == "not_equal"]
    equal = [e for e in interesting if e.get("verdict_hint") == "equal"]
    input_events = [e for e in events if e.get("verdict_hint") == "input"]
    output_events = [e for e in events if e.get("verdict_hint") == "output"]

    ai_hints = []
    if not_equal:
        ai_hints.append(f"发现 {len(not_equal)} 次不相等比较，说明程序对输入进行了校验且当前输入未通过")
    if equal:
        equal_funcs = set(e.get("function", "") for e in equal)
        # 检查相等比较是否只出现在非核心函数中
        equal_args = []
        for e in equal:
            for a in e.get("args", []):
                ascii_val = a.get("ascii", "")
                if ascii_val and len(ascii_val) > 2:
                    equal_args.append(ascii_val)
        if equal_args:
            ai_hints.append(f"发现 {len(equal)} 次相等比较，比较值为: {', '.join(equal_args[:5])}，可能是状态判断而非输入校验")
        else:
            ai_hints.append(f"发现 {len(equal)} 次相等比较，可能是部分校验通过或常量比较")
    if not interesting and events:
        has_input = any(e.get("verdict_hint") == "input" for e in events)
        has_output = any(e.get("verdict_hint") == "output" for e in events)
        if has_input and has_output:
            ai_hints.append("程序有输入输出但未捕获到 strcmp/memcmp 比较，核心校验很可能使用自定义比较逻辑（逐字节异或、查表、内联比较等），建议结合 trace_compare 或静态分析定位校验函数")
        elif has_output:
            ai_hints.append("程序有输出但未捕获到 strcmp/memcmp 比较，可能使用自定义比较逻辑或逐字节校验，建议使用 trace_compare 在分支地址设断点")
        else:
            ai_hints.append("未捕获到 strcmp/memcmp 比较，程序可能使用自定义比较逻辑（如逐字节异或、查表等）")
    if not events:
        ai_hints.append("未捕获到任何库函数调用，程序可能使用内联函数（MSVC 内联 strcmp/memcmp）或静态链接，建议使用 trace_compare 或 DynamoRIO 覆盖率分析")

    summary = {
        "total_events": len(events),
        "interesting_events": len(interesting),
        "not_equal_comparisons": len(not_equal),
        "equal_comparisons": len(equal),
        "input_events": len(input_events),
        "output_events": len(output_events),
        "filter_user_only": filter_user_only,
    }

    return {
        "status": "ok",
        "target": str(target_path),
        "backend": "frida",
        "input": {
            "stdin_preview": (stdin_data or "")[:64],
            "args": args or [],
        },
        "events": events,
        "ai_hints": ai_hints,
        "summary": summary,
    }


def trace_calls_to_markdown(result: dict[str, Any]) -> str:
    """将 trace-calls 结果转为 Markdown 格式。"""
    if result.get("status") == "error":
        return f"# Trace Calls Error\n\n{result.get('message', '')}\n"

    lines = [
        "# BeaconFlow Trace Calls",
        "",
        f"- **Target**: `{result.get('target', '')}`",
        f"- **Backend**: `{result.get('backend', '')}`",
        f"- **Input**: `{result.get('input', {}).get('stdin_preview', '')}`",
        "",
    ]

    events = result.get("events", [])
    summary = result.get("summary", {})

    interesting = [e for e in events if e.get("function") in ("strcmp", "strncmp", "memcmp")]
    other = [e for e in events if e.get("function") not in ("strcmp", "strncmp", "memcmp")]

    if interesting:
        lines.append("## Key Comparisons")
        lines.append("")
        for evt in interesting:
            func = evt.get("function", "?")
            call_site = evt.get("call_site", "?")
            verdict = evt.get("verdict_hint", "?")
            ret_val = evt.get("return_value", "?")

            lines.append(f"### {func} @ {call_site}")
            lines.append("")
            lines.append(f"- return address: `{evt.get('return_address', '?')}`")
            lines.append(f"- result: **{verdict}** (return={ret_val})")
            lines.append("")

            for arg in evt.get("args", []):
                name = arg.get("name", "?")
                if "value" in arg:
                    lines.append(f"- {name}: `{arg['value']}`")
                else:
                    ascii_val = arg.get("ascii", "")
                    hex_val = arg.get("bytes_hex", "")
                    ptr = arg.get("pointer", "")
                    if ascii_val:
                        lines.append(f"- {name}: `{ascii_val}` (hex: `{hex_val}`)")
                    else:
                        lines.append(f"- {name}: ptr=`{ptr}` hex=`{hex_val}`")

            if verdict == "not_equal":
                lines.append("")
                lines.append("> **AI hint**: this call compares runtime input-like bytes with a constant-like buffer. The values differ.")

            lines.append("")

    if other:
        lines.append("## Other Events")
        lines.append("")
        for evt in other:
            func = evt.get("function", "?")
            call_site = evt.get("call_site", "?")
            verdict = evt.get("verdict_hint", "?")
            args_str = []
            for arg in evt.get("args", []):
                if "value" in arg:
                    args_str.append(f"{arg['name']}={arg['value']}")
                elif arg.get("ascii"):
                    args_str.append(f"{arg['name']}=`{arg['ascii']}`")
            lines.append(f"- **{func}** @ {call_site}: {', '.join(args_str)} [{verdict}]")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total events: {summary.get('total_events', 0)}")
    lines.append(f"- Interesting (strcmp/memcmp): {summary.get('interesting_events', 0)}")
    lines.append(f"- Not-equal comparisons: {summary.get('not_equal_comparisons', 0)}")
    lines.append(f"- Equal comparisons: {summary.get('equal_comparisons', 0)}")
    lines.append(f"- Input events: {summary.get('input_events', 0)}")
    lines.append(f"- Output events: {summary.get('output_events', 0)}")
    lines.append(f"- Filter user-only: {summary.get('filter_user_only', True)}")
    lines.append("")

    ai_hints = result.get("ai_hints", [])
    if ai_hints:
        lines.append("## AI Analysis")
        lines.append("")
        for hint in ai_hints:
            lines.append(f"- {hint}")
        lines.append("")

    return "\n".join(lines)
