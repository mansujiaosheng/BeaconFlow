from __future__ import annotations

import json
import os
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ida
import ida_kernwin
import ida_nalt
import ida_name
import ida_ua
import ida_xref
import idautils


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _image_base() -> int:
    get_imagebase = getattr(ida_nalt, "get_imagebase", None)
    if get_imagebase:
        return int(get_imagebase())
    return int(ida_ida.inf_get_min_ea())


def _extract_block_context(func_start, block_start, block_end, succs_list, all_block_starts):
    instructions = []
    calls = []
    strings = []
    constants = []
    data_refs = []
    code_refs = []

    ea = block_start
    while ea < block_end:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            ea += 1
            continue

        mnemonic = ida_ua.print_insn_mnem(ea)
        disasm = ida_ua.generate_disasm_line(ea, 0)
        if disasm:
            instructions.append(disasm.strip())

        for xref in idautils.XrefsFrom(ea, 0):
            target = xref.to
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                fname = ida_name.get_ea_name(target)
                calls.append(fname if fname else _hex(target))
            elif xref.type in (ida_xref.dr_O, ida_xref.dr_W, ida_xref.dr_R, ida_xref.dr_T):
                str_val = ida_bytes.get_strlit_contents(target, -1, ida_bytes.STRTYPE_C)
                if str_val:
                    try:
                        strings.append(str_val.decode("utf-8", errors="replace")[:200])
                    except Exception:
                        strings.append(_hex(target))
                else:
                    data_refs.append(_hex(target))
            elif xref.type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F):
                if target not in all_block_starts:
                    code_refs.append(_hex(target))

        for i in range(insn.nops):
            op = insn.ops[i]
            if op.type == ida_ua.o_void:
                break
            if op.type in (ida_ua.o_imm,):
                val = op.value
                if 1 <= val <= 0xFFFF and val not in constants:
                    constants.append(val)

        ea += length

    pred_list = []
    for xref in idautils.XrefsTo(block_start, 0):
        if xref.type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_F):
            pred_list.append(_hex(xref.frm))

    context = {}
    if instructions:
        context["instructions"] = instructions
    if calls:
        context["calls"] = list(dict.fromkeys(calls))
    if strings:
        context["strings"] = list(dict.fromkeys(strings))
    if constants:
        context["constants"] = [_hex(c) for c in constants[:20]]
    if data_refs:
        context["data_refs"] = list(dict.fromkeys(data_refs))
    if code_refs:
        context["code_refs"] = list(dict.fromkeys(code_refs))
    if pred_list:
        context["predecessors"] = list(dict.fromkeys(pred_list))
    if succs_list:
        context["successors"] = succs_list
    return context


def export_metadata(output_path: str, with_context: bool = True) -> None:
    ida_auto.auto_wait()
    functions = []

    for index in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(index)
        if not func:
            continue

        flowchart = ida_gdl.FlowChart(func)
        blocks = []
        block_start_set = set()

        for block in flowchart:
            succs = [_hex(succ.start_ea) for succ in block.succs()]
            blocks.append(
                {
                    "start": _hex(block.start_ea),
                    "end": _hex(block.end_ea),
                    "succs": succs,
                }
            )
            block_start_set.add(block.start_ea)

        if with_context:
            for block_info in blocks:
                start_ea = int(block_info["start"], 16)
                end_ea = int(block_info["end"], 16)
                ctx = _extract_block_context(
                    func.start_ea, start_ea, end_ea,
                    block_info["succs"], block_start_set,
                )
                if ctx:
                    block_info["context"] = ctx

        functions.append(
            {
                "name": ida_name.get_ea_name(func.start_ea) or _hex(func.start_ea),
                "start": _hex(func.start_ea),
                "end": _hex(func.end_ea),
                "blocks": blocks,
            }
        )

    data = {
        "input_path": ida_nalt.get_input_file_path(),
        "image_base": _hex(_image_base()),
        "functions": functions,
    }

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) >= 2 else os.environ.get("BEACONFLOW_IDA_METADATA_OUT")
    if not output_path:
        raise SystemExit("usage: export_ida_metadata.py <output.json> or set BEACONFLOW_IDA_METADATA_OUT")
    no_ctx = os.environ.get("BEACONFLOW_IDA_NO_CONTEXT", "").lower() in ("1", "true", "yes")
    export_metadata(output_path, with_context=not no_ctx)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
