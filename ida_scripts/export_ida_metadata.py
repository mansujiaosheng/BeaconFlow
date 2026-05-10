from __future__ import annotations

import json
import os
import sys

import ida_auto
import ida_funcs
import ida_gdl
import ida_ida
import ida_kernwin
import ida_nalt
import ida_name


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _image_base() -> int:
    get_imagebase = getattr(ida_nalt, "get_imagebase", None)
    if get_imagebase:
        return int(get_imagebase())
    return int(ida_ida.inf_get_min_ea())


def export_metadata(output_path: str) -> None:
    ida_auto.auto_wait()
    functions = []

    for index in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(index)
        if not func:
            continue

        flowchart = ida_gdl.FlowChart(func)
        blocks = []
        for block in flowchart:
            blocks.append(
                {
                    "start": _hex(block.start_ea),
                    "end": _hex(block.end_ea),
                    "succs": [_hex(succ.start_ea) for succ in block.succs()],
                }
            )

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
    export_metadata(output_path)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
