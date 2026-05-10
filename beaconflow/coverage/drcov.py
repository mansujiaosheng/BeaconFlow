from __future__ import annotations

import re
import struct
from pathlib import Path

from beaconflow.models import CoverageBlock, CoverageData, DrcovModule

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def _parse_num(value: str) -> int:
    value = value.strip()
    return int(value, 16) if _HEX_RE.match(value) else int(value)


def _parse_module_line(line: str) -> DrcovModule | None:
    parts = [x.strip() for x in line.split(",")]
    if len(parts) < 4 or not parts[0].isdigit():
        return None

    module_id = int(parts[0])
    numeric = [_parse_num(x) for x in parts[1:] if x and (_HEX_RE.match(x) or x.isdigit())]
    if len(numeric) < 2:
        return None

    start, end = numeric[0], numeric[1]
    path = parts[-1]
    return DrcovModule(module_id=module_id, start=start, end=end, path=path)


def load_drcov(path: str | Path) -> CoverageData:
    """Load a DynamoRIO drcov file.

    Supports common drcov text headers with a binary basic-block table. The
    returned block offsets are module-relative; absolute addresses are filled in
    when the module table includes the module base.
    """

    raw = Path(path).read_bytes()
    bb_marker = b"BB Table:"
    bb_pos = raw.find(bb_marker)
    if bb_pos < 0:
        raise ValueError(f"not a drcov file or missing BB Table: {path}")

    header = raw[:bb_pos].decode("utf-8", errors="replace")
    modules: dict[int, DrcovModule] = {}
    in_modules = False

    for line in header.splitlines():
        if line.startswith("Module Table:"):
            in_modules = True
            continue
        if in_modules and line.startswith("Columns:"):
            continue
        if in_modules and line.startswith("BB Table:"):
            break
        if in_modules:
            module = _parse_module_line(line)
            if module:
                modules[module.module_id] = module

    bb_line_end = raw.find(b"\n", bb_pos)
    if bb_line_end < 0:
        raise ValueError(f"missing BB table payload: {path}")

    blocks = []
    payload = raw[bb_line_end + 1 :]
    entry_size = struct.calcsize("<IHH")
    for index in range(0, len(payload) - entry_size + 1, entry_size):
        offset, size, module_id = struct.unpack_from("<IHH", payload, index)
        if module_id == 0xFFFF:
            continue
        module = modules.get(module_id)
        absolute = module.start + offset if module else None
        blocks.append(CoverageBlock(module_id=module_id, offset=offset, size=size, absolute_start=absolute))

    return CoverageData(modules=modules, blocks=blocks)

