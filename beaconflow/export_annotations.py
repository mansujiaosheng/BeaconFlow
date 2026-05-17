"""
导出标注脚本 - 将 BeaconFlow 分析结果回写到 IDA / Ghidra。

支持将以下信息标注回反汇编工具：
- 覆盖的基本块（covered blocks）
- 分支排名（branch_rank）
- 调度器候选（dispatcher candidates）
- 决策点（decision_points）
- 角色检测（roles）
- 比较事件（compare events）
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _parse_addr(addr: str | int) -> int:
    if isinstance(addr, int):
        return addr
    return int(addr, 16) if addr.lower().startswith("0x") else int(addr)


def _safe_comment(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")


def _collect_annotations(
    coverage_result: dict[str, Any] | None = None,
    branch_rank_result: dict[str, Any] | None = None,
    deflatten_result: dict[str, Any] | None = None,
    decision_points_result: dict[str, Any] | None = None,
    roles_result: dict[str, Any] | None = None,
    trace_compare_result: dict[str, Any] | None = None,
) -> dict[int, list[dict[str, str]]]:
    annotations: dict[int, list[dict[str, str]]] = {}

    def _add(addr: int, prefix: str, comment: str, color: str | None = None):
        entry = {"prefix": prefix, "comment": comment}
        if color:
            entry["color"] = color
        annotations.setdefault(addr, []).append(entry)

    if coverage_result:
        for func in coverage_result.get("covered_functions", []):
            for bs in func.get("covered_block_starts", []):
                addr = _parse_addr(bs)
                _add(addr, "BF_COVERED", f"{func.get('name', '?')} covered", "0x7CFC00")
        for func in coverage_result.get("uncovered_functions", []):
            for blk in func.get("blocks", []):
                if isinstance(blk, dict):
                    start = blk.get("start")
                else:
                    continue
                if start:
                    _add(_parse_addr(start), "BF_UNCOVERED", f"{func.get('name', '?')} uncovered", "0xFF4444")

    if branch_rank_result:
        for br in branch_rank_result.get("ranked_branches", []):
            addr = _parse_addr(br["block"])
            score = br.get("score", 0)
            why = ", ".join(br.get("why", []))
            _add(addr, "BF_BRANCH", f"score={score:.2f} {why}", "0xFFD700")

    if deflatten_result:
        for db in deflatten_result.get("dispatcher_blocks", []):
            addr = _parse_addr(db)
            _add(addr, "BF_DISPATCHER", "CFF dispatcher", "0xFF69B4")
        for bp in deflatten_result.get("real_branch_points", []):
            if isinstance(bp, dict):
                addr = _parse_addr(bp.get("address", bp.get("block", "0")))
                _add(addr, "BF_REAL_BRANCH", "deflattened branch", "0x00CED1")

    if decision_points_result:
        for dp in decision_points_result.get("decision_points", []):
            addr = _parse_addr(dp["address"])
            dp_type = dp.get("type", "?")
            priority = dp.get("ai_priority", "?")
            reason = dp.get("reason", "")
            _add(addr, "BF_DECISION", f"[{priority}] {dp_type}: {reason}", "0xFF8C00")

    if roles_result:
        for cand in roles_result.get("candidates", []):
            addr = _parse_addr(cand["address"])
            role = cand.get("role", "?")
            conf = cand.get("confidence", "?")
            _add(addr, "BF_ROLE", f"{role} ({conf})", "0x9370DB")

    if trace_compare_result:
        for cmp in trace_compare_result.get("compares", []):
            addr = _parse_addr(cmp.get("addr", cmp.get("address", "0")))
            cmp_type = cmp.get("type", "?")
            left = cmp.get("left", cmp.get("left_operand", "?"))
            right = cmp.get("right", cmp.get("right_operand", "?"))
            result_str = cmp.get("result", "?")
            _add(addr, "BF_COMPARE", f"{cmp_type}: {left} vs {right} -> {result_str}", "0x00BFFF")

    return annotations


def generate_ida_script(
    annotations: dict[int, list[dict[str, str]]],
) -> str:
    lines = [
        "# BeaconFlow IDA 标注脚本 - 自动生成",
        "# 在 IDA Python 控制台中运行此脚本",
        "import idaapi",
        "import idc",
        "",
    ]

    color_map = {
        "0x7CFC00": 0x7CFC00,
        "0xFF4444": 0xFF4444,
        "0xFFD700": 0xFFD700,
        "0xFF69B4": 0xFF69B4,
        "0x00CED1": 0x00CED1,
        "0xFF8C00": 0xFF8C00,
        "0x9370DB": 0x9370DB,
        "0x00BFFF": 0x00BFFF,
    }

    for addr in sorted(annotations.keys()):
        entries = annotations[addr]
        comment_parts = [f"[{e['prefix']}] {e['comment']}" for e in entries]
        full_comment = " | ".join(comment_parts)
        lines.append(f'idc.set_cmt(0x{addr:x}, "{_safe_comment(full_comment)}", 0)')

        for entry in entries:
            color_hex = entry.get("color")
            if color_hex and color_hex in color_map:
                lines.append(f"idaapi.set_item_color(0x{addr:x}, {color_map[color_hex]})")
                break

    lines.append("")
    lines.append(f'print("[BeaconFlow] Annotated {len(annotations)} addresses")')

    return "\n".join(lines)


def generate_ghidra_script(
    annotations: dict[int, list[dict[str, str]]],
) -> str:
    lines = [
        "// BeaconFlow Ghidra 标注脚本 - 自动生成",
        "// 在 Ghidra Script Manager 中运行此脚本",
        "// @category BeaconFlow",
        "import ghidra.app.script.GhidraScript;",
        "import ghidra.program.model.address.Address;",
        "import ghidra.program.model.listing.CodeUnit;",
        "import ghidra.app.util.HighlightProvider;",
        "",
        "currentProgram = getState().getCurrentProgram();",
        "listing = currentProgram.getListing();",
        "addrFactory = currentProgram.getAddressFactory();",
        "bookmarkMgr = currentProgram.getBookmarkManager();",
        "",
    ]

    color_map = {
        "0x7CFC00": "GREEN",
        "0xFF4444": "RED",
        "0xFFD700": "YELLOW",
        "0xFF69B4": "PINK",
        "0x00CED1": "CYAN",
        "0xFF8C00": "ORANGE",
        "0x9370DB": "MAGENTA",
        "0x00BFFF": "BLUE",
    }

    for addr in sorted(annotations.keys()):
        entries = annotations[addr]
        comment_parts = [f"[{e['prefix']}] {e['comment']}" for e in entries]
        full_comment = " | ".join(comment_parts)

        lines.append(f"addr_{addr:x} = addrFactory.getDefaultAddressSpace().getAddress(0x{addr:x});")
        lines.append(f'listing.setComment(addr_{addr:x}, CodeUnit.PLATE_COMMENT, "{_safe_comment(full_comment)}");')

        for entry in entries:
            color_hex = entry.get("color")
            if color_hex and color_hex in color_map:
                lines.append(f'bookmarkMgr.setBookmark(addr_{addr:x}, "BeaconFlow", "{entry["prefix"]}", "{_safe_comment(entry["comment"])}");')
                break

    lines.append("")
    lines.append(f'println("[BeaconFlow] Annotated {len(annotations)} addresses");')

    return "\n".join(lines)


def export_annotations(
    output_dir: str | Path,
    coverage_result: dict[str, Any] | None = None,
    branch_rank_result: dict[str, Any] | None = None,
    deflatten_result: dict[str, Any] | None = None,
    decision_points_result: dict[str, Any] | None = None,
    roles_result: dict[str, Any] | None = None,
    trace_compare_result: dict[str, Any] | None = None,
    format: str = "both",
) -> dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    annotations = _collect_annotations(
        coverage_result=coverage_result,
        branch_rank_result=branch_rank_result,
        deflatten_result=deflatten_result,
        decision_points_result=decision_points_result,
        roles_result=roles_result,
        trace_compare_result=trace_compare_result,
    )

    produced: list[str] = []

    if format in ("ida", "both"):
        ida_script = generate_ida_script(annotations)
        ida_path = out / "beaconflow_ida_annotations.py"
        ida_path.write_text(ida_script, encoding="utf-8")
        produced.append(str(ida_path))

    if format in ("ghidra", "both"):
        ghidra_script = generate_ghidra_script(annotations)
        ghidra_path = out / "beaconflow_ghidra_annotations.java"
        ghidra_path.write_text(ghidra_script, encoding="utf-8")
        produced.append(str(ghidra_path))

    annotations_json = out / "beaconflow_annotations.json"
    serializable = {hex(k): v for k, v in annotations.items()}
    annotations_json.write_text(json.dumps(serializable, indent=2, ensure_ascii=False), encoding="utf-8")
    produced.append(str(annotations_json))

    return {
        "status": "ok",
        "annotation_count": len(annotations),
        "produced_files": produced,
        "format": format,
    }
