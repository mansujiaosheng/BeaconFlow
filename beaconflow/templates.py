"""
模板库与建议引擎 - Frida / angr / GDB / x64dbg 模板推荐。

BeaconFlow 不自研 hook/符号执行/调试框架，
只负责：推荐模板 → 填充参数 → 导入输出 → 总结证据。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


TEMPLATES_DIR = Path(__file__).parent / "templates"


# ─── Frida 模板 ───────────────────────────────────────────────

FRIDA_TEMPLATES: dict[str, dict[str, str]] = {
    "compare_strcmp_memcmp": {
        "name": "compare_strcmp_memcmp",
        "description": "Hook strcmp/memcmp/strncmp，提取比较双方内容和调用点",
        "category": "compare",
        "code": r"""
"use strict";

var maxRead = %MAX_READ%;

function hexdump_short(ptr, len) {
    try {
        var buf = ptr.readUtf8String(Math.min(len, maxRead));
        return buf || "<null>";
    } catch(e) {
        try {
            return hexdump(ptr, {length: Math.min(len, maxRead)});
        } catch(e2) {
            return "<unreadable>";
        }
    }
}

// hook strcmp
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        var left = args[0].readUtf8String();
        var right = args[1].readUtf8String();
        var caller = this.returnAddress;
        send({type: "strcmp", left: left, right: right, caller: caller.toString()});
    }
});

// hook memcmp
Interceptor.attach(Module.findExportByName(null, "memcmp"), {
    onEnter: function(args) {
        var len = args[2].toInt32();
        var left = hexdump_short(args[0], len);
        var right = hexdump_short(args[1], len);
        var caller = this.returnAddress;
        send({type: "memcmp", left: left, right: right, length: len, caller: caller.toString()});
    }
});

// hook strncmp
Interceptor.attach(Module.findExportByName(null, "strncmp"), {
    onEnter: function(args) {
        var len = args[2].toInt32();
        var left = args[0].readUtf8String(len);
        var right = args[1].readUtf8String(len);
        var caller = this.returnAddress;
        send({type: "strncmp", left: left, right: right, length: len, caller: caller.toString()});
    }
});
""",
    },
    "input_read_recv_scanf": {
        "name": "input_read_recv_scanf",
        "description": "Hook read/recv/scanf/fgets，捕获输入数据和来源",
        "category": "input",
        "code": r"""
"use strict";

var maxRead = %MAX_READ%;

// hook read
Interceptor.attach(Module.findExportByName(null, "read"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var n = retval.toInt32();
        if (n > 0) {
            try {
                var data = this.buf.readUtf8String(Math.min(n, maxRead));
                send({type: "read", fd: this.fd, length: n, data: data, caller: this.returnAddress.toString()});
            } catch(e) {}
        }
    }
});

// hook recv
Interceptor.attach(Module.findExportByName(null, "recv"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var n = retval.toInt32();
        if (n > 0) {
            try {
                var data = this.buf.readUtf8String(Math.min(n, maxRead));
                send({type: "recv", fd: this.fd, length: n, data: data, caller: this.returnAddress.toString()});
            } catch(e) {}
        }
    }
});

// hook scanf
Interceptor.attach(Module.findExportByName(null, "scanf"), {
    onEnter: function(args) {
        var fmt = args[0].readUtf8String();
        send({type: "scanf", format: fmt, caller: this.returnAddress.toString()});
    }
});

// hook fgets
Interceptor.attach(Module.findExportByName(null, "fgets"), {
    onEnter: function(args) {
        this.buf = args[0];
        this.len = args[1].toInt32();
    },
    onLeave: function(retval) {
        if (!retval.isNull()) {
            try {
                var data = this.buf.readUtf8String();
                send({type: "fgets", data: data, caller: this.returnAddress.toString()});
            } catch(e) {}
        }
    }
});
""",
    },
    "memory_snapshot": {
        "name": "memory_snapshot",
        "description": "在指定地址 dump 内存快照",
        "category": "memory",
        "code": r"""
"use strict";

// 用法: 修改 TARGET_ADDR 和 SIZE 后运行
var TARGET_ADDR = ptr("%TARGET_ADDR%");
var SIZE = %SIZE%;

function dumpMemory(addr, size) {
    try {
        var bytes = addr.readByteArray(size);
        var hex = "";
        var view = new Uint8Array(bytes);
        for (var i = 0; i < view.length; i++) {
            hex += ("0" + view[i].toString(16)).slice(-2) + " ";
            if ((i + 1) % 16 === 0) hex += "\n";
        }
        send({type: "memory_snapshot", address: addr.toString(), size: size, hex: hex});
    } catch(e) {
        send({type: "memory_snapshot_error", address: addr.toString(), error: e.toString()});
    }
}

dumpMemory(TARGET_ADDR, SIZE);
""",
    },
    "jni_getstringutfchars": {
        "name": "jni_getstringutfchars",
        "description": "Hook JNI GetStringUTFChars，捕获 Java 层传递给 native 的字符串",
        "category": "android",
        "code": r"""
"use strict";

Java.perform(function() {
    var env = Java.vm.getEnv();
    var GetStringUTFChars = new NativeFunction(
        Module.findExportByName("libart.so", "_ZN3art3JNI12GetStringUTFCharsEP7_JNIEnvP8_jstringPh"),
        "pointer", ["pointer", "pointer", "pointer"]
    );

    // 更通用的方式：hook JNI RegisterNatives
    var jniEnvPtr = Java.vm.tryGetEnv();
    if (jniEnvPtr) {
        var vtable = jniEnvPtr.readPointer();
        // GetStringUTFChars 是 JNI 函数表第 169 项
        var fnPtr = vtable.add(169 * Process.pointerSize).readPointer();
        Interceptor.attach(fnPtr, {
            onEnter: function(args) {
                this.jstring = args[1];
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    try {
                        var str = retval.readUtf8String();
                        send({type: "GetStringUTFChars", value: str, caller: this.returnAddress.toString()});
                    } catch(e) {}
                }
            }
        });
    }
});
""",
    },
    "android_string_equals": {
        "name": "android_string_equals",
        "description": "Hook Android Java String.equals，捕获字符串比较",
        "category": "android",
        "code": r"""
"use strict";

Java.perform(function() {
    var StringClass = Java.use("java.lang.String");

    StringClass.equals.implementation = function(other) {
        var result = this.equals(other);
        var thisStr = this.toString();
        var otherStr = other ? other.toString() : "null";
        if (thisStr.length < 200 && otherStr.length < 200) {
            send({type: "String.equals", this: thisStr, other: otherStr, result: result});
        }
        return result;
    };

    StringClass.compareTo.implementation = function(other) {
        var result = this.compareTo(other);
        var thisStr = this.toString();
        var otherStr = other ? other.toString() : "null";
        if (thisStr.length < 200 && otherStr.length < 200) {
            send({type: "String.compareTo", this: thisStr, other: otherStr, result: result});
        }
        return result;
    };
});
""",
    },
    "android_crypto_base64_cipher": {
        "name": "android_crypto_base64_cipher",
        "description": "Hook Android Base64/Cipher/MessageDigest，捕获加解密和哈希",
        "category": "android",
        "code": r"""
"use strict";

Java.perform(function() {
    // Base64
    var Base64 = Java.use("android.util.Base64");
    Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
        var result = this.encodeToString(input, flags);
        send({type: "Base64.encode", output: result});
        return result;
    };
    Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
        var result = this.decode(str, flags);
        send({type: "Base64.decode", input: str});
        return result;
    };

    // Cipher
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        var algo = this.getAlgorithm();
        var mode = this.opmode.value;
        send({type: "Cipher.doFinal", algorithm: algo, mode: mode === 1 ? "ENCRYPT" : "DECRYPT",
              inputLen: input ? input.length : 0, outputLen: result ? result.length : 0});
        return result;
    };

    // MessageDigest
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload('[B').implementation = function(input) {
        var result = this.digest(input);
        var algo = this.getAlgorithm();
        var hex = "";
        for (var i = 0; i < result.length; i++) {
            hex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
        }
        send({type: "MessageDigest.digest", algorithm: algo, inputLen: input.length, hash: hex});
        return result;
    };
});
""",
    },
}


# ─── angr 模板 ────────────────────────────────────────────────

ANGR_TEMPLATES: dict[str, dict[str, str]] = {
    "find_avoid_stdin": {
        "name": "find_avoid_stdin",
        "description": "angr stdin 模式求解：指定 find/avoid 地址",
        "category": "solve",
        "code": r"""
import angr
import claripy
import sys

def solve_stdin(target_path, find_addr, avoid_addr=None, stdin_len=32):
    proj = angr.Project(target_path, auto_load_libs=False)
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(stdin_len)]
    flag = claripy.Concat(*flag_chars)

    state = proj.factory.entry_state(
        stdin=angr.SimFile("/dev/stdin", content=flag),
    )

    # 添加可打印字符约束
    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = proj.factory.simulation_manager(state)

    find = int(find_addr, 16) if isinstance(find_addr, str) else find_addr
    avoid = []
    if avoid_addr:
        if isinstance(avoid_addr, list):
            avoid = [int(a, 16) if isinstance(a, str) else a for a in avoid_addr]
        else:
            avoid = [int(avoid_addr, 16) if isinstance(avoid_addr, str) else avoid_addr]

    simgr.explore(find=find, avoid=avoid)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        return {"status": "ok", "solution": solution.decode("latin-1"), "address": hex(find)}
    else:
        return {"status": "no_solution", "active": len(simgr.active), "deadended": len(simgr.deadended)}

if __name__ == "__main__":
    result = solve_stdin(
        target_path="%TARGET_PATH%",
        find_addr="%FIND_ADDR%",
        avoid_addr=%AVOID_ADDR%,
        stdin_len=%STDIN_LEN%,
    )
    print(result)
""",
    },
    "find_avoid_argv": {
        "name": "find_avoid_argv",
        "description": "angr argv 模式求解：输入通过命令行参数传入",
        "category": "solve",
        "code": r"""
import angr
import claripy

def solve_argv(target_path, find_addr, avoid_addr=None, arg_len=32):
    proj = angr.Project(target_path, auto_load_libs=False)
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(arg_len)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(0, 8)])

    state = proj.factory.entry_state(args=[target_path, flag])

    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    simgr = proj.factory.simulation_manager(state)

    find = int(find_addr, 16) if isinstance(find_addr, str) else find_addr
    avoid = []
    if avoid_addr:
        if isinstance(avoid_addr, list):
            avoid = [int(a, 16) if isinstance(a, str) else a for a in avoid_addr]
        else:
            avoid = [int(avoid_addr, 16) if isinstance(avoid_addr, str) else avoid_addr]

    simgr.explore(find=find, avoid=avoid)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        return {"status": "ok", "solution": solution.rstrip(b"\x00").decode("latin-1"), "address": hex(find)}
    else:
        return {"status": "no_solution", "active": len(simgr.active), "deadended": len(simgr.deadended)}

if __name__ == "__main__":
    result = solve_argv(
        target_path="%TARGET_PATH%",
        find_addr="%FIND_ADDR%",
        avoid_addr=%AVOID_ADDR%,
        arg_len=%STDIN_LEN%,
    )
    print(result)
""",
    },
}


# ─── GDB / x64dbg 模板 ───────────────────────────────────────

GDB_TEMPLATES: dict[str, dict[str, str]] = {
    "break_decision": {
        "name": "break_decision",
        "description": "在决策点地址设置断点，打印寄存器",
        "category": "breakpoint",
        "code": r"""
# BeaconFlow GDB 断点脚本 - 自动生成
# 在 GDB 中: source break_decision.gdb

%BREAKPOINTS%

define print_regs_at_bp
    printf "=== Hit breakpoint at %p ===\n", $pc
    info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11
    x/4i $pc
end
""",
    },
    "dump_registers": {
        "name": "dump_registers",
        "description": "在指定地址打印所有通用寄存器",
        "category": "register",
        "code": r"""
# BeaconFlow GDB 寄存器 dump 脚本
# 在 GDB 中: source dump_registers.gdb

define dump_all_regs
    printf "RAX=0x%016lx RBX=0x%016lx RCX=0x%016lx RDX=0x%016lx\n", $rax, $rbx, $rcx, $rdx
    printf "RSI=0x%016lx RDI=0x%016lx RBP=0x%016lx RSP=0x%016lx\n", $rsi, $rdi, $rbp, $rsp
    printf "R8 =0x%016lx R9 =0x%016lx R10=0x%016lx R11=0x%016lx\n", $r8, $r9, $r10, $r11
    printf "RIP=0x%016lx RFLAGS=0x%016lx\n", $rip, $eflags
end
""",
    },
    "watch_buffer": {
        "name": "watch_buffer",
        "description": "监视指定内存地址的写入",
        "category": "watchpoint",
        "code": r"""
# BeaconFlow GDB watchpoint 脚本
# 修改 BUFFER_ADDR 和 SIZE 后运行

set pagination off
set print elements 0

define watch_buffer
    # 设置硬件写断点
    watch *(char*)%BUFFER_ADDR%
end

define dump_buffer
    x/%SIZE%s %BUFFER_ADDR%
end
""",
    },
}

X64DBG_TEMPLATES: dict[str, dict[str, str]] = {
    "break_cmp": {
        "name": "break_cmp",
        "description": "在比较指令处设置条件断点",
        "category": "breakpoint",
        "code": r"""
// BeaconFlow x64dbg 断点脚本 - 自动生成
// 在 x64dbg 命令行中逐行执行

%BREAKPOINTS%
""",
    },
    "log_registers": {
        "name": "log_registers",
        "description": "在断点处记录寄存器值",
        "category": "register",
        "code": r"""
// BeaconFlow x64dbg 寄存器日志脚本
// 在 x64dbg 命令行中逐行执行

// 设置日志格式
SetLogConditional "RAX={rax} RBX={rbx} RCX={rcx} RDX={rdx} RSI={rsi} RDI={rdi} RBP={rbp} RSP={rsp} RIP={rip}"
""",
    },
    "trace_until_ret": {
        "name": "trace_until_ret",
        "description": "追踪执行直到函数返回",
        "category": "trace",
        "code": r"""
// BeaconFlow x64dbg 追踪脚本
// 追踪当前函数直到 ret

TraceIntoConditional "cip != ret"
""",
    },
}


# ─── suggest-hook：根据 evidence 推荐 Frida 模板 ─────────────

def suggest_hook(
    metadata_path: str | Path | None = None,
    decision_points_result: dict[str, Any] | None = None,
    roles_result: dict[str, Any] | None = None,
    trace_compare_result: dict[str, Any] | None = None,
    target_type: str = "native",
) -> dict[str, Any]:
    """根据已有分析证据推荐 Frida hook 模板。"""
    recommendations: list[dict[str, Any]] = []
    reasons: list[str] = []

    if roles_result:
        for cand in roles_result.get("candidates", []):
            role = cand.get("role", "")
            if role == "validator":
                recommendations.append({
                    "template": "compare_strcmp_memcmp",
                    "priority": "high",
                    "reason": f"检测到 validator 函数 {cand.get('function', '?')}，hook 比较函数可泄露 flag",
                    "address": cand.get("address"),
                })
                reasons.append(f"validator at {cand.get('address', '?')}")
            elif role == "crypto_like":
                recommendations.append({
                    "template": "memory_snapshot",
                    "priority": "medium",
                    "reason": f"检测到 crypto 函数 {cand.get('function', '?')}，可在加解密前后 dump 内存",
                    "address": cand.get("address"),
                })
            elif role == "input_handler":
                recommendations.append({
                    "template": "input_read_recv_scanf",
                    "priority": "high",
                    "reason": f"检测到 input_handler {cand.get('function', '?')}，hook 输入函数可确认输入格式",
                    "address": cand.get("address"),
                })

    if trace_compare_result:
        has_strcmp_like = False
        for cmp in trace_compare_result.get("compares", []):
            cmp_type = cmp.get("type", "")
            if "strcmp" in cmp_type or "memcmp" in cmp_type or "strncmp" in cmp_type:
                has_strcmp_like = True
                break
        if has_strcmp_like:
            recommendations.append({
                "template": "compare_strcmp_memcmp",
                "priority": "high",
                "reason": "检测到 strcmp/memcmp 类比较，hook 可获取运行时比较值",
            })
            reasons.append("strcmp/memcmp detected in trace_compare")

    if decision_points_result:
        dp_count = len(decision_points_result.get("decision_points", []))
        critical_dps = [dp for dp in decision_points_result.get("decision_points", []) if dp.get("ai_priority") == "critical"]
        if critical_dps:
            recommendations.append({
                "template": "memory_snapshot",
                "priority": "medium",
                "reason": f"检测到 {len(critical_dps)} 个关键决策点，可在这些地址 dump 内存",
            })

    if target_type == "android":
        recommendations.append({
            "template": "jni_getstringutfchars",
            "priority": "high",
            "reason": "Android 目标，hook JNI GetStringUTFChars 可捕获 Java→native 字符串",
        })
        recommendations.append({
            "template": "android_string_equals",
            "priority": "high",
            "reason": "Android 目标，hook String.equals 可捕获 Java 层字符串比较",
        })
        recommendations.append({
            "template": "android_crypto_base64_cipher",
            "priority": "medium",
            "reason": "Android 目标，hook Base64/Cipher/MessageDigest 可捕获加解密",
        })

    if not recommendations:
        recommendations.append({
            "template": "compare_strcmp_memcmp",
            "priority": "medium",
            "reason": "无明确证据时，默认推荐 hook 比较函数作为起点",
        })

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for r in recommendations:
        if r["template"] not in seen:
            seen.add(r["template"])
            unique.append(r)

    return {
        "status": "ok",
        "recommendations": unique,
        "reasons": reasons,
        "available_templates": list(FRIDA_TEMPLATES.keys()),
    }


# ─── suggest-angr：根据 flow-diff 推荐 find / avoid ──────────

def suggest_angr(
    flow_diff_result: dict[str, Any] | None = None,
    roles_result: dict[str, Any] | None = None,
    decision_points_result: dict[str, Any] | None = None,
    branch_rank_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """根据已有分析证据推荐 angr 求解参数。"""
    find_addrs: list[str] = []
    avoid_addrs: list[str] = []
    reasons: list[str] = []

    if roles_result:
        for cand in roles_result.get("candidates", []):
            role = cand.get("role", "")
            addr = cand.get("address", "")
            if role == "success_handler" and addr:
                find_addrs.append(addr)
                reasons.append(f"success_handler at {addr} → find")
            elif role == "failure_handler" and addr:
                avoid_addrs.append(addr)
                reasons.append(f"failure_handler at {addr} → avoid")

    if flow_diff_result:
        only_right = flow_diff_result.get("only_right_blocks", [])
        only_left = flow_diff_result.get("only_left_blocks", [])
        for blk in only_right[:3]:
            if isinstance(blk, dict):
                addr = blk.get("address", blk.get("block_start", ""))
            elif isinstance(blk, str):
                addr = blk
            else:
                continue
            if addr and addr not in find_addrs:
                find_addrs.append(addr)
                reasons.append(f"only_right block {addr} → find candidate")
        for blk in only_left[:3]:
            if isinstance(blk, dict):
                addr = blk.get("address", blk.get("block_start", ""))
            elif isinstance(blk, str):
                addr = blk
            else:
                continue
            if addr and addr not in avoid_addrs:
                avoid_addrs.append(addr)
                reasons.append(f"only_left block {addr} → avoid candidate")

    if branch_rank_result:
        for br in branch_rank_result.get("ranked_branches", []):
            if br.get("score", 0) > 0.8:
                addr = br.get("block", "")
                if addr and addr not in find_addrs:
                    find_addrs.append(addr)
                    reasons.append(f"high-score branch {addr} → find candidate")

    template = "find_avoid_stdin"
    if not find_addrs:
        reasons.append("未找到明确的 find/avoid 地址，建议先用 flow-diff 或 detect-roles 分析")

    return {
        "status": "ok",
        "find": find_addrs[:5],
        "avoid": avoid_addrs[:5],
        "template": template,
        "reasons": reasons,
        "stdin_len_hint": 32,
        "available_templates": list(ANGR_TEMPLATES.keys()),
    }


# ─── suggest-debug：根据 decision point 推荐断点脚本 ──────────

def suggest_debug(
    decision_points_result: dict[str, Any] | None = None,
    roles_result: dict[str, Any] | None = None,
    trace_compare_result: dict[str, Any] | None = None,
    debugger: str = "gdb",
) -> dict[str, Any]:
    """根据已有分析证据推荐 GDB/x64dbg 断点脚本。"""
    breakpoints: list[dict[str, Any]] = []
    reasons: list[str] = []

    if decision_points_result:
        for dp in decision_points_result.get("decision_points", []):
            addr = dp.get("address", "")
            priority = dp.get("ai_priority", "medium")
            dp_type = dp.get("type", "")
            reason = dp.get("reason", "")
            if priority in ("critical", "high"):
                breakpoints.append({
                    "address": addr,
                    "type": dp_type,
                    "priority": priority,
                    "reason": reason,
                })
                reasons.append(f"{priority} decision at {addr}: {reason}")

    if roles_result:
        for cand in roles_result.get("candidates", []):
            role = cand.get("role", "")
            addr = cand.get("address", "")
            if role in ("validator", "crypto_like", "input_handler") and addr:
                breakpoints.append({
                    "address": addr,
                    "type": f"role:{role}",
                    "priority": "high",
                    "reason": f"{role} function",
                })
                reasons.append(f"{role} at {addr}")

    if trace_compare_result:
        for cmp in trace_compare_result.get("compares", [])[:5]:
            addr = cmp.get("addr", cmp.get("address", ""))
            if addr:
                breakpoints.append({
                    "address": addr,
                    "type": "compare",
                    "priority": "medium",
                    "reason": f"{cmp.get('type', 'compare')} at {addr}",
                })

    bp_lines: list[str] = []
    for bp in breakpoints:
        addr = bp.get("address", "")
        if not addr:
            continue
        try:
            addr_int = int(addr, 16) if addr.startswith("0x") else int(addr)
        except ValueError:
            continue
        if debugger == "gdb":
            bp_lines.append(f"b *0x{addr_int:x}")
            bp_lines.append(f"commands {len(bp_lines) // 2 + 1}")
            bp_lines.append("  printf \"Hit at %p\\n\", $pc")
            bp_lines.append("  info registers rax rbx rcx rdx rsi rdi")
            bp_lines.append("  continue")
            bp_lines.append("end")
        else:
            bp_lines.append(f"bp 0x{addr_int:x}")

    script_content = ""
    if debugger == "gdb":
        template = GDB_TEMPLATES.get("break_decision", {})
        code = template.get("code", "")
        script_content = code.replace("%BREAKPOINTS%", "\n".join(bp_lines))
    else:
        template = X64DBG_TEMPLATES.get("break_cmp", {})
        code = template.get("code", "")
        script_content = code.replace("%BREAKPOINTS%", "\n".join(bp_lines))

    return {
        "status": "ok",
        "debugger": debugger,
        "breakpoint_count": len(breakpoints),
        "breakpoints": breakpoints[:20],
        "reasons": reasons,
        "script_content": script_content,
    }


# ─── 模板生成入口 ─────────────────────────────────────────────

def generate_template(
    template_name: str,
    output_path: str | Path,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """生成指定模板文件，替换参数占位符。"""
    all_templates = {**FRIDA_TEMPLATES, **ANGR_TEMPLATES, **GDB_TEMPLATES, **X64DBG_TEMPLATES}
    tmpl = all_templates.get(template_name)
    if not tmpl:
        return {
            "status": "error",
            "error": f"unknown template: {template_name}",
            "available": list(all_templates.keys()),
        }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    code = tmpl["code"]
    if params:
        for key, value in params.items():
            code = code.replace(f"%{key}%", str(value))

    out.write_text(code.strip() + "\n", encoding="utf-8")

    return {
        "status": "ok",
        "template_name": template_name,
        "output_path": str(out),
        "category": tmpl.get("category", ""),
        "description": tmpl.get("description", ""),
    }


def list_templates(category: str | None = None) -> dict[str, Any]:
    """列出所有可用模板。"""
    all_templates = {**FRIDA_TEMPLATES, **ANGR_TEMPLATES, **GDB_TEMPLATES, **X64DBG_TEMPLATES}
    result = {}
    for name, tmpl in all_templates.items():
        if category and tmpl.get("category") != category:
            continue
        result[name] = {
            "description": tmpl.get("description", ""),
            "category": tmpl.get("category", ""),
        }
    return {"status": "ok", "templates": result}
