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
import tempfile


def _hex(value):
    return "0x{:x}".format(value)


def _is_interesting_constant(val):
    if val == 0:
        return False
    if val > 0xFFFFFFFF:
        return False
    if 0 < val < 4:
        return False
    return True


def _extract_block_context(program, block_start, block_end, succs_list, all_block_starts):
    from ghidra.program.model.symbol import RefType
    listing = program.getListing()

    instructions = []
    calls = []
    strings = []
    constants = []
    data_refs = []
    code_refs = []

    addr_factory = program.getAddressFactory()
    start_addr = addr_factory.getDefaultAddressSpace().getAddress(block_start)
    end_addr = addr_factory.getDefaultAddressSpace().getAddress(block_end)

    code_unit_iter = listing.getCodeUnits(start_addr, True)
    while code_unit_iter.hasNext():
        cu = code_unit_iter.next()
        if cu.getAddress().getOffset() >= block_end:
            break
        from ghidra.program.model.listing import Instruction
        if not isinstance(cu, Instruction):
            continue

        # 生成干净的汇编文本
        mnemonic = cu.getMnemonicString()
        # 构建操作数字符串
        op_parts = []
        for i in range(cu.getNumOperands()):
            op_str = cu.getDefaultOperandRepresentation(i)
            op_parts.append(op_str)
        if op_parts:
            instructions.append("{} {}".format(mnemonic, ", ".join(op_parts)))
        else:
            instructions.append(mnemonic)

        # 分析引用
        for ref in cu.getReferencesFrom():
            ref_type = ref.getReferenceType()
            target_addr = ref.getToAddress()
            target_offset = target_addr.getOffset()

            if ref_type.isCall():
                func = program.getFunctionManager().getFunctionContaining(target_addr)
                if func:
                    calls.append(func.getName())
                else:
                    # 尝试获取符号名
                    sym = program.getSymbolTable().getPrimarySymbol(target_addr)
                    if sym:
                        calls.append(sym.getName())
                    else:
                        calls.append(_hex(target_offset))
            elif ref_type.isData():
                data_at = listing.getDataAt(target_addr)
                if data_at and data_at.hasStringValue():
                    val = data_at.getValue()
                    strings.append(str(val)[:200])
                else:
                    data_refs.append(_hex(target_offset))
            elif ref_type.isFlow():
                if target_offset not in all_block_starts:
                    code_refs.append(_hex(target_offset))

        # 提取操作数中的标量常量
        for i in range(cu.getNumOperands()):
            op_objs = cu.getOpObjects(i)
            for obj in op_objs:
                # Ghidra 的标量常量类
                class_name = obj.getClass().getSimpleName()
                if class_name == "Scalar":
                    val = obj.getValue()
                    if isinstance(val, int) and _is_interesting_constant(val) and val not in constants:
                        constants.append(val)

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

    return context


def export_metadata(binary_path, output_path=None, project_location=None, project_name=None, with_context=True):
    import pyghidra

    ghidra_dir = os.environ.get(
        "GHIDRA_INSTALL_DIR", r"D:\TOOL\ghidra_12.0.4_PUBLIC"
    )
    pyghidra.start(install_dir=ghidra_dir)

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    if project_location is None:
        project_location = tempfile.mkdtemp(prefix="beaconflow_pyghidra_")
    if project_name is None:
        project_name = "beaconflow_export"

    with pyghidra.open_program(binary_path, project_location=project_location, project_name=project_name, nested_project_location=False) as api:
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
            block_start_set = set()
            code_blocks = block_model.getCodeBlocksContaining(body, monitor)
            while code_blocks.hasNext():
                cb = code_blocks.next()
                start = cb.getMinAddress().getOffset()
                end = cb.getMaxAddress().getOffset() + 1
                addr_to_block[start] = cb
                block_start_set.add(start)
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

            if with_context:
                # 构建前驱映射
                pred_map = {}
                for block_info in blocks:
                    for succ_hex in block_info["succs"]:
                        succ_offset = int(succ_hex, 16)
                        pred_map.setdefault(succ_offset, []).append(block_info["start"])

                for block_info in blocks:
                    start_offset = int(block_info["start"], 16)
                    end_offset = int(block_info["end"], 16)
                    ctx = _extract_block_context(
                        program, start_offset, end_offset,
                        block_info["succs"], block_start_set,
                    )
                    preds = pred_map.get(start_offset, [])
                    if preds:
                        ctx["predecessors"] = list(dict.fromkeys(preds))
                    if block_info["succs"]:
                        ctx["successors"] = block_info["succs"]
                    if ctx:
                        block_info["context"] = ctx

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
