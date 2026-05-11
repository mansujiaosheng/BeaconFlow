from __future__ import annotations

import re
from pathlib import Path

from beaconflow.models import CoverageBlock, CoverageData

_HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")
_QEMU_EXEC_RE = re.compile(r"\[[0-9a-fA-F]+/([0-9a-fA-F]+)/[0-9a-fA-F]+/[0-9a-fA-F]+\]")
# exec,nochain 格式: "Trace 0: 0x00094290 [000/0094290/0x94290/0]"
_QEMU_EXEC_NOCHAIN_RE = re.compile(r"Trace\s+\d+:\s+0x([0-9a-fA-F]+)\s")


def load_address_log(
    path: str | Path,
    block_size: int = 4,
    min_address: int | None = None,
    max_address: int | None = None,
) -> CoverageData:
    """Load an ordered text address log.

    支持三种 QEMU 日志格式：
    - in_asm 格式: "0x00094290: instruction" 或 "[xxx/0094290/xxx/xxx]"
    - exec,nochain 格式: "Trace 0: 0x00094290 [000/0094290/0x94290/0]"
    - 简单地址格式: 每行一个 0x 地址

    exec,nochain 精确模式记录每条指令的每次执行，粒度比 in_asm 更细：
    - in_asm: 只记录基本块首次翻译，不记录重复执行
    - exec,nochain: 记录每条指令的每次执行，禁止翻译块链接

    对于反平坦化分析，exec,nochain 模式能提供更精确的执行流，
    因为它记录了 dispatcher 块的每次执行（而不仅仅是首次翻译），
    这对于识别 dispatcher 和重建真实控制流至关重要。
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
    # 优先匹配 exec,nochain 格式
    nochain = _QEMU_EXEC_NOCHAIN_RE.search(line)
    if nochain:
        return int(nochain.group(1), 16)

    # 匹配 in_asm 的 [xxx/addr/xxx/xxx] 格式
    qemu_exec = _QEMU_EXEC_RE.search(line)
    if qemu_exec:
        return int(qemu_exec.group(1), 16)

    # 匹配 "0xADDR: ..." 格式（in_asm 的指令行）
    match = _HEX_RE.search(line)
    if not match:
        return None
    return int(match.group(1), 16)
