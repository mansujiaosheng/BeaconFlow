"""
DynamoRIO 自定义 Instrumentation 支持。

BeaconFlow 不自己实现完整的 DynamoRIO 插件框架，而是负责：
1. 提供常用 DynamoRIO 客户端模板（C 代码）
2. 管理和运行自定义 instrumentation
3. 导入自定义 trace 结果并关联分析
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def find_drrun() -> str | None:
    """查找 DynamoRIO drrun 可执行文件。"""
    for name in ("drrun", "drrun.exe"):
        candidate = shutil.which(name)
        if candidate:
            return candidate

    dr_home = os.environ.get("DYNAMORIO_HOME") or os.environ.get("DYNAMORIO_ROOT")
    if dr_home:
        drrun = Path(dr_home) / "bin64" / "drrun.exe"
        if drrun.exists():
            return str(drrun)
        drrun = Path(dr_home) / "bin32" / "drrun.exe"
        if drrun.exists():
            return str(drrun)

    for root in [Path("C:/"), Path("D:/"), Path("D:/TOOL")]:
        if not root.exists():
            continue
        for candidate in root.glob("DynamoRIO*"):
            drrun = candidate / "bin64" / "drrun.exe"
            if drrun.exists():
                return str(drrun)

    return None


def generate_client_template(
    output_path: str | Path,
    template_type: str = "compare_trace",
) -> dict[str, Any]:
    """生成 DynamoRIO 客户端 C 代码模板。"""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    templates = {
        "compare_trace": _compare_trace_template,
        "memory_trace": _memory_trace_template,
        "call_trace": _call_trace_template,
        "register_trace": _register_trace_template,
    }

    generator = templates.get(template_type)
    if not generator:
        return {
            "status": "error",
            "error": f"unknown template type: {template_type}",
            "available_types": list(templates.keys()),
        }

    code = generator()
    out.write_text(code, encoding="utf-8")

    return {
        "status": "ok",
        "client_path": str(out),
        "template_type": template_type,
        "compile_hint": _compile_hint_client(out.stem),
    }


def _compile_hint_client(name: str) -> str:
    dr_home = os.environ.get("DYNAMORIO_HOME", "/path/to/DynamoRIO")
    return f"cl /I\"{dr_home}/include\" /LD /Fe{name}.dll {name}.c /link \"{dr_home}/lib64/release/dynamorio.lib\""


def _compare_trace_template() -> str:
    return """\
// DynamoRIO 客户端: 比较指令追踪
// 追踪 CMP/TEST 等比较指令的操作数和结果
// 编译: 参见 compile_hint

#include "dr_api.h"
#include "drmgr.h"
#include <stdio.h>

static file_t log_file;

static void event_exit(void) {
    dr_fprintf(log_file, "# Compare trace end\\n");
    dr_close_file(log_file);
    drmgr_exit();
}

// 在比较指令之前插入的分析函数
static void pre_cmp(void *drcontext, int cmp_type, opnd_t left, opnd_t right) {
    reg_t left_val = 0, right_val = 0;
    void *tag = drmgr_get_current_tag(drcontext);
    app_pc pc = dr_fragment_app_pc(tag);

    if (opnd_is_reg(left)) {
        left_val = reg_get_value(opnd_get_reg(left), drcontext);
    } else if (opnd_is_immed(left)) {
        left_val = opnd_get_immed_int(left);
    }

    if (opnd_is_reg(right)) {
        right_val = reg_get_value(opnd_get_reg(right), drcontext);
    } else if (opnd_is_immed(right)) {
        right_val = opnd_get_immed_int(right);
    }

    dr_fprintf(log_file, "CMP type=%d addr=%p left=0x%lx right=0x%lx\\n",
               cmp_type, pc, left_val, right_val);
}

// 指令插桩回调
static dr_emit_flags_t event_app_instruction(
    void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
    bool for_trace, bool translating, void *user_data)
{
    int cmp_type = 0;
    if (instr_is_cmp(instr)) {
        cmp_type = 1; // CMP
    } else if (instr_get_opcode(instr) == OP_test) {
        cmp_type = 2; // TEST
    } else {
        return DR_EMIT_DEFAULT;
    }

    opnd_t left = instr_get_src(instr, 0);
    opnd_t right = instr_get_src(instr, 1);

    dr_insert_clean_call(drcontext, bb, instr, pre_cmp, false,
                         3, OPND_CREATE_INT32(cmp_type), left, right);

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    drmgr_init();
    log_file = dr_open_file("compare_trace.log", DR_FILE_WRITE_OVERWRITE);
    dr_fprintf(log_file, "# BeaconFlow Compare Trace\\n");
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
"""


def _memory_trace_template() -> str:
    return """\
// DynamoRIO 客户端: 内存访问追踪
// 追踪所有内存读写操作
// 编译: 参见 compile_hint

#include "dr_api.h"
#include "drmgr.h"
#include <stdio.h>

static file_t log_file;

static void event_exit(void) {
    dr_fprintf(log_file, "# Memory trace end\\n");
    dr_close_file(log_file);
    drmgr_exit();
}

static void pre_mem_access(app_pc pc, void *addr, bool is_write, size_t size) {
    dr_fprintf(log_file, "MEM addr=%p pc=%p %s size=%zu\\n",
               addr, pc, is_write ? "WRITE" : "READ", size);
}

static dr_emit_flags_t event_app_instruction(
    void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
    bool for_trace, bool translating, void *user_data)
{
    if (!instr_reads_memory(instr) && !instr_writes_memory(instr))
        return DR_EMIT_DEFAULT;

    for (int i = 0; i < instr_num_srcs(instr); i++) {
        opnd_t op = instr_get_src(instr, i);
        if (opnd_is_memory_reference(op)) {
            dr_insert_clean_call(drcontext, bb, instr, pre_mem_access, false,
                                 4, OPND_CREATE_INTPTR((ptr_int_t)dr_fragment_app_pc(tag)),
                                 opnd_create_far_base_disp(opnd_get_base(op), DR_REG_NULL, DR_REG_NULL, 0, opnd_get_disp(op)),
                                 OPND_CREATE_INT32(0), OPND_CREATE_INT32(opnd_get_size(op)));
        }
    }

    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd_t op = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(op)) {
            dr_insert_clean_call(drcontext, bb, instr, pre_mem_access, false,
                                 4, OPND_CREATE_INTPTR((ptr_int_t)dr_fragment_app_pc(tag)),
                                 opnd_create_far_base_disp(opnd_get_base(op), DR_REG_NULL, DR_REG_NULL, 0, opnd_get_disp(op)),
                                 OPND_CREATE_INT32(1), OPND_CREATE_INT32(opnd_get_size(op)));
        }
    }

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    drmgr_init();
    log_file = dr_open_file("memory_trace.log", DR_FILE_WRITE_OVERWRITE);
    dr_fprintf(log_file, "# BeaconFlow Memory Trace\\n");
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
"""


def _call_trace_template() -> str:
    return """\
// DynamoRIO 客户端: 函数调用追踪
// 追踪 CALL/RET 指令
// 编译: 参见 compile_hint

#include "dr_api.h"
#include "drmgr.h"
#include <stdio.h>

static file_t log_file;
static int call_depth = 0;

static void event_exit(void) {
    dr_fprintf(log_file, "# Call trace end\\n");
    dr_close_file(log_file);
    drmgr_exit();
}

static void pre_call(app_pc target) {
    dr_fprintf(log_file, "CALL depth=%d target=%p\\n", call_depth, target);
    call_depth++;
}

static void post_call(app_pc target) {
    call_depth--;
    dr_fprintf(log_file, "RET  depth=%d from=%p\\n", call_depth, target);
}

static dr_emit_flags_t event_app_instruction(
    void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
    bool for_trace, bool translating, void *user_data)
{
    if (instr_is_call(instr)) {
        opnd_t target = instr_get_target(instr);
        if (opnd_is_pc(target)) {
            dr_insert_clean_call(drcontext, bb, instr, pre_call, false,
                                 1, OPND_CREATE_INTPTR((ptr_int_t)opnd_get_pc(target)));
        }
    } else if (instr_is_return(instr)) {
        dr_insert_clean_call(drcontext, bb, instr, post_call, false,
                             1, OPND_CREATE_INTPTR((ptr_int_t)dr_fragment_app_pc(tag)));
    }
    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    drmgr_init();
    log_file = dr_open_file("call_trace.log", DR_FILE_WRITE_OVERWRITE);
    dr_fprintf(log_file, "# BeaconFlow Call Trace\\n");
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
"""


def _register_trace_template() -> str:
    return """\
// DynamoRIO 客户端: 寄存器值追踪
// 在关键比较点追踪寄存器值
// 编译: 参见 compile_hint

#include "dr_api.h"
#include "drmgr.h"
#include <stdio.h>

static file_t log_file;

static void event_exit(void) {
    dr_fprintf(log_file, "# Register trace end\\n");
    dr_close_file(log_file);
    drmgr_exit();
}

static void log_regs_at_cmp(void *drcontext, app_pc pc) {
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    dr_fprintf(log_file, "REGS pc=%p rax=0x%lx rbx=0x%lx rcx=0x%lx rdx=0x%lx "
               "rsi=0x%lx rdi=0x%lx rbp=0x%lx rsp=0x%lx "
               "r8=0x%lx r9=0x%lx r10=0x%lx r11=0x%lx\\n",
               pc,
               mc.rax, mc.rbx, mc.rcx, mc.rdx,
               mc.rsi, mc.rdi, mc.rbp, mc.rsp,
               mc.r8, mc.r9, mc.r10, mc.r11);
}

static dr_emit_flags_t event_app_instruction(
    void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
    bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_cmp(instr) && instr_get_opcode(instr) != OP_test)
        return DR_EMIT_DEFAULT;

    dr_insert_clean_call(drcontext, bb, instr, log_regs_at_cmp, false,
                         2, OPND_CREATE_INTPTR((ptr_int_t)dr_fragment_app_pc(tag)));

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    drmgr_init();
    log_file = dr_open_file("register_trace.log", DR_FILE_WRITE_OVERWRITE);
    dr_fprintf(log_file, "# BeaconFlow Register Trace\\n");
    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
"""


def run_custom_client(
    target_path: str | Path,
    client_path: str | Path,
    drrun_path: str | None = None,
    arch: str = "x64",
    target_args: list[str] | None = None,
    stdin: str | None = None,
    run_cwd: str | None = None,
    timeout: int = 120,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """运行 DynamoRIO 自定义客户端。"""
    drrun = drrun_path or find_drrun()
    if not drrun:
        return {"status": "error", "error": "drrun not found. Set DYNAMORIO_HOME or pass --drrun-path."}

    target = Path(target_path)
    client = Path(client_path)
    out = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="beaconflow_dr_"))
    out.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        return {"status": "error", "error": f"target not found: {target}"}
    if not client.exists():
        return {"status": "error", "error": f"client not found: {client}"}

    cmd = [
        str(drrun),
        "-client", str(client), "0",
        "-logdir", str(out),
    ]

    if arch == "x86":
        cmd.append("-32")
    else:
        cmd.append("-64")

    cmd.append("--")
    cmd.append(str(target))
    if target_args:
        cmd.extend(target_args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=run_cwd,
            input=stdin,
        )
        return {
            "status": "ok",
            "returncode": proc.returncode,
            "stdout": proc.stdout[-2000:] if len(proc.stdout) > 2000 else proc.stdout,
            "stderr": proc.stderr[-2000:] if len(proc.stderr) > 2000 else proc.stderr,
            "output_dir": str(out),
            "command": cmd,
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"timeout after {timeout}s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def import_custom_trace(
    trace_path: str | Path,
    trace_type: str = "compare_trace",
    metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """导入自定义 DynamoRIO 客户端产生的 trace 日志。"""
    trace = Path(trace_path)
    if not trace.exists():
        return {"status": "error", "error": f"trace file not found: {trace}"}

    content = trace.read_text(encoding="utf-8", errors="replace")
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]

    if trace_type == "compare_trace":
        return _parse_compare_trace(lines, metadata_path)
    elif trace_type == "call_trace":
        return _parse_call_trace(lines, metadata_path)
    elif trace_type == "memory_trace":
        return _parse_memory_trace(lines, metadata_path)
    elif trace_type == "register_trace":
        return _parse_register_trace(lines, metadata_path)
    else:
        return {
            "status": "ok",
            "trace_type": trace_type,
            "total_lines": len(lines),
            "raw_preview": content[:2000],
        }


def _parse_compare_trace(lines: list[str], metadata_path: str | Path | None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "CMP":
            continue
        entry: dict[str, Any] = {"raw": line}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                entry[k] = v
        events.append(entry)

    return {
        "status": "ok",
        "trace_type": "compare_trace",
        "total_events": len(events),
        "events": events[:500],
    }


def _parse_call_trace(lines: list[str], metadata_path: str | Path | None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        entry: dict[str, Any] = {"raw": line, "type": parts[0]}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                entry[k] = v
        events.append(entry)

    return {
        "status": "ok",
        "trace_type": "call_trace",
        "total_events": len(events),
        "events": events[:500],
    }


def _parse_memory_trace(lines: list[str], metadata_path: str | Path | None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "MEM":
            continue
        entry: dict[str, Any] = {"raw": line}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                entry[k] = v
        events.append(entry)

    return {
        "status": "ok",
        "trace_type": "memory_trace",
        "total_events": len(events),
        "events": events[:500],
    }


def _parse_register_trace(lines: list[str], metadata_path: str | Path | None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != "REGS":
            continue
        entry: dict[str, Any] = {"raw": line}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                entry[k] = v
        events.append(entry)

    return {
        "status": "ok",
        "trace_type": "register_trace",
        "total_events": len(events),
        "events": events[:500],
    }
