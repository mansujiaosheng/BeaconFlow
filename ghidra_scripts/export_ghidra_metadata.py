"""
使用 pyghidra headless 导出 BeaconFlow metadata。

不依赖 Ghidra OSGi，直接通过 JPype 调用 Ghidra Java API。

用法:
    python export_ghidra_metadata.py <binary_path> [output.json]

环境变量:
    GHIDRA_INSTALL_DIR  Ghidra 安装目录（默认 D:\\TOOL\\ghidra_12.0.4_PUBLIC）
"""

import json
import os
import sys


def _hex(value):
    return "0x{:x}".format(value)


def export_metadata(binary_path, output_path=None):
    import pyghidra

    ghidra_dir = os.environ.get(
        "GHIDRA_INSTALL_DIR", r"D:\TOOL\ghidra_12.0.4_PUBLIC"
    )
    pyghidra.start(install_dir=ghidra_dir)

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    with pyghidra.open_program(binary_path) as api:
        program = api.getCurrentProgram()
        fm = program.getFunctionManager()
        block_model = BasicBlockModel(program)
        monitor = ConsoleTaskMonitor()

        functions = []
        for function in fm.getFunctions(True):
            entry = function.getEntryPoint()
            body = function.getBody()

            name = function.getName()
            if not name or name.startswith("FUN_"):
                name = _hex(entry.getOffset())

            blocks = []
            addr_to_block = {}
            code_blocks = block_model.getCodeBlocksContaining(body, monitor)
            while code_blocks.hasNext():
                cb = code_blocks.next()
                start = cb.getMinAddress().getOffset()
                end = cb.getMaxAddress().getOffset() + 1
                addr_to_block[start] = cb
                blocks.append({"start": _hex(start), "end": _hex(end), "succs": []})

            for block_info in blocks:
                start_offset = int(block_info["start"], 16)
                cb = addr_to_block.get(start_offset)
                if cb is None:
                    continue
                dest_iter = cb.getDestinations(monitor)
                while dest_iter.hasNext():
                    dest = dest_iter.next()
                    succ_start = dest.getDestinationBlock().getMinAddress().getOffset()
                    block_info["succs"].append(_hex(succ_start))

            functions.append(
                {
                    "name": name,
                    "start": _hex(entry.getOffset()),
                    "end": _hex(body.getMaxAddress().getOffset() + 1),
                    "blocks": blocks,
                }
            )

        input_path = program.getExecutablePath() or program.getName()
        image_base = program.getImageBase().getOffset()

    data = {
        "input_path": input_path,
        "image_base": _hex(image_base),
        "functions": functions,
    }

    if output_path is None:
        output_path = os.path.splitext(binary_path)[0] + "_ghidra_metadata.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[BeaconFlow] Exported {len(functions)} functions to {output_path}")
    return output_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_path> [output.json]")
        sys.exit(1)

    binary = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None
    export_metadata(binary, output)
