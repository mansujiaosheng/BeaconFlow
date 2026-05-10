from __future__ import annotations

import re
from pathlib import Path

from beaconflow.models import CoverageBlock, CoverageData

_HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")
_QEMU_EXEC_RE = re.compile(r"\[[0-9a-fA-F]+/([0-9a-fA-F]+)/[0-9a-fA-F]+/[0-9a-fA-F]+\]")


def load_address_log(
    path: str | Path,
    block_size: int = 4,
    min_address: int | None = None,
    max_address: int | None = None,
) -> CoverageData:
    """Load an ordered text address log.

    Accepts simple files with one address per line and QEMU trace snippets such
    as ``0x00094290: instruction``. Addresses are treated as already-static
    program addresses and are kept in file order.
    """

    blocks: list[CoverageBlock] = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        address = _extract_address(line)
        if address is None:
            continue
        if min_address is not None and address < min_address:
            continue
        if max_address is not None and address >= max_address:
            continue
        blocks.append(CoverageBlock(module_id=0, offset=address, size=block_size, absolute_start=address))
    return CoverageData(modules={}, blocks=blocks)


def _extract_address(line: str) -> int | None:
    qemu_exec = _QEMU_EXEC_RE.search(line)
    if qemu_exec:
        return int(qemu_exec.group(1), 16)

    match = _HEX_RE.search(line)
    if not match:
        return None
    return int(match.group(1), 16)
