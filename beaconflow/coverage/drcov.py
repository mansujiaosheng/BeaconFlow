from __future__ import annotations

import re
import struct
from pathlib import Path

from beaconflow.models import CoverageBlock, CoverageData, DrcovModule

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_LONG_DIGIT_RE = re.compile(r"^[0-9a-fA-F]{8,}$")


def _parse_num(value: str) -> int:
    value = value.strip()
    if _HEX_RE.match(value):
        return int(value, 16)
    # drcov v5 的 offset/preferred_base 等列使用 16 位宽十六进制（无 0x 前缀）
    if len(value) == 16 and all(c in "0123456789abcdefABCDEF" for c in value):
        return int(value, 16)
    if _LONG_DIGIT_RE.match(value) and any(c in "abcdefABCDEF" for c in value):
        return int(value, 16)
    return int(value)


def _parse_columns(line: str) -> list[str] | None:
    """解析 drcov Module Table 的 Columns 行，返回列名列表。"""
    text = line.strip()
    if text.startswith("Columns:"):
        text = text[len("Columns:"):].strip()
    return [c.strip().lower() for c in text.split(",")]


def _parse_module_line(line: str, columns: list[str] | None = None) -> DrcovModule | None:
    parts = [x.strip() for x in line.split(",")]
    if len(parts) < 4 or not parts[0].isdigit():
        return None

    module_id = int(parts[0])
    path = parts[-1].strip()

    # 解析所有数值列
    numeric_parts = []
    for p in parts[1:-1]:
        p = p.strip()
        if p and (_HEX_RE.match(p) or p.isdigit()):
            numeric_parts.append(_parse_num(p))

    # drcov v5: id, containing_id, start, end, entry, offset, preferred_base
    # drcov v4: id, start, end/size
    if columns:
        col_values: dict[str, int] = {}
        val_idx = 0
        for col in columns[1:]:
            if col == "path":
                break
            if val_idx < len(numeric_parts):
                col_values[col] = numeric_parts[val_idx]
                val_idx += 1
        start = col_values.get("start", 0)
        end = col_values.get("end", 0)
        seg_offset = col_values.get("offset", 0)
        preferred_base = col_values.get("preferred_base", 0)
    elif len(numeric_parts) >= 5:
        # v5 无 Columns 行回退: containing_id, start, end, entry, offset, preferred_base
        start = numeric_parts[1]
        end = numeric_parts[2]
        seg_offset = numeric_parts[4] if len(numeric_parts) > 4 else 0
        preferred_base = numeric_parts[5] if len(numeric_parts) > 5 else 0
    elif len(numeric_parts) >= 2:
        # v4 格式: start, end/size
        start = numeric_parts[0]
        end = numeric_parts[1]
        seg_offset = 0
        preferred_base = start
    else:
        return None

    return DrcovModule(
        module_id=module_id,
        start=start,
        end=end,
        path=path,
        base=0,
        seg_offset=seg_offset,
        preferred_base=preferred_base,
    )


def load_drcov(path: str | Path) -> CoverageData:
    """Load a DynamoRIO drcov file.

    Supports drcov v4 and v5 module table formats with a binary basic-block
    table. The returned block offsets are module-relative; absolute addresses
    are computed as base + offset when the module table includes a base column
    (v5), otherwise start + offset.
    """

    raw = Path(path).read_bytes()
    bb_marker = b"BB Table:"
    bb_pos = raw.find(bb_marker)
    if bb_pos < 0:
        raise ValueError("not a drcov file or missing BB Table: {}".format(path))

    header = raw[:bb_pos].decode("utf-8", errors="replace")
    modules: dict[int, DrcovModule] = {}
    in_modules = False
    columns: list[str] | None = None

    for line in header.splitlines():
        if line.startswith("Module Table:"):
            in_modules = True
            columns = None
            continue
        if in_modules and line.startswith("Columns:"):
            columns = _parse_columns(line)
            continue
        if in_modules and line.startswith("BB Table:"):
            break
        if in_modules:
            module = _parse_module_line(line, columns)
            if module:
                modules[module.module_id] = module

    bb_line_end = raw.find(b"\n", bb_pos)
    if bb_line_end < 0:
        raise ValueError("missing BB table payload: {}".format(path))

    blocks = []
    payload = raw[bb_line_end + 1:]
    entry_size = struct.calcsize("<IHH")
    for index in range(0, len(payload) - entry_size + 1, entry_size):
        offset, size, module_id = struct.unpack_from("<IHH", payload, index)
        if module_id == 0xFFFF:
            continue
        module = modules.get(module_id)
        if module:
            # drcov v5: offset 是段内偏移，absolute = start + offset（运行时地址）
            # drcov v4: offset 是模块内偏移，absolute = start + offset
            absolute = module.start + offset
        else:
            absolute = None
        blocks.append(CoverageBlock(module_id=module_id, offset=offset, size=size, absolute_start=absolute))

    return CoverageData(modules=modules, blocks=blocks)
