# Export BeaconFlow metadata from Ghidra headless mode
#
# Usage:
#   analyzeHeadless <project_dir> <project_name> \
#     -import <binary> \
#     -postScript ExportBeaconFlowMetadata.py <output.json> \
#     -deleteProject
#
# Or on Windows:
#   analyzeHeadless.bat <project_dir> <project_name> \
#     -import <binary> \
#     -postScript ExportBeaconFlowMetadata.py <output.json> \
#     -deleteProject
#
# The output JSON is compatible with BeaconFlow's load_metadata() and
# has the same schema as the IDA export_ida_metadata.py output:
#
#   {
#     "input_path": "...",
#     "image_base": "0x...",
#     "functions": [
#       {
#         "name": "func_name",
#         "start": "0x...",
#         "end": "0x...",
#         "blocks": [
#           { "start": "0x...", "end": "0x...", "succs": ["0x..."] }
#         ]
#       }
#     ]
#   }

from __future__ import print_function

import json
import os
import sys

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor


def _hex(value):
    return "0x{:x}".format(value)


def _get_image_base(program):
    return program.getImageBase().getOffset()


def _get_input_path(program):
    path = program.getExecutablePath()
    if path:
        return path
    return program.getName()


def _get_function_name(function, program):
    name = function.getName()
    if name and not name.startswith("FUN_"):
        return name
    return _hex(function.getEntryPoint().getOffset())


def _get_blocks_and_succs(function, block_model, program):
    entry = function.getEntryPoint()
    body = function.getBody()
    monitor = ConsoleTaskMonitor()

    blocks = []
    addr_to_block = {}

    code_blocks = block_model.getCodeBlocksContaining(body, monitor)
    while code_blocks.hasNext():
        cb = code_blocks.next()
        start = cb.getMinAddress().getOffset()
        end = cb.getMaxAddress().getOffset() + 1
        addr_to_block[start] = cb
        blocks.append({
            "start": _hex(start),
            "end": _hex(end),
            "succs": []
        })

    for block_info in blocks:
        start_offset = int(block_info["start"], 16)
        cb = addr_to_block.get(start_offset)
        if cb is None:
            continue
        dest_iter = cb.getDestinations(monitor)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            dest_block = dest.getDestinationBlock()
            succ_start = dest_block.getMinAddress().getOffset()
            block_info["succs"].append(_hex(succ_start))

    return blocks


def export_metadata(output_path):
    program = getCurrentProgram()
    listing = program.getListing()
    fm = program.getFunctionManager()
    block_model = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()

    functions = []
    func_iter = fm.getFunctions(True)
    for function in func_iter:
        blocks = _get_blocks_and_succs(function, block_model, program)
        functions.append({
            "name": _get_function_name(function, program),
            "start": _hex(function.getEntryPoint().getOffset()),
            "end": _hex(function.getBody().getMaxAddress().getOffset() + 1),
            "blocks": blocks,
        })

    data = {
        "input_path": _get_input_path(program),
        "image_base": _hex(_get_image_base(program)),
        "functions": functions,
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print("[BeaconFlow] Exported {} functions to {}".format(len(functions), output_path))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: ExportBeaconFlowMetadata.py <output.json>")
    export_metadata(sys.argv[1])
