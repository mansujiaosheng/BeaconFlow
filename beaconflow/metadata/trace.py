from __future__ import annotations

from collections import defaultdict

from beaconflow.models import BasicBlock, CoverageData, Function, ProgramMetadata


def build_trace_metadata(
    coverage: CoverageData,
    input_path: str = "",
    image_base: int = 0,
    gap: int = 0x100,
    name_prefix: str = "trace_region",
) -> ProgramMetadata:
    """Build minimal metadata from an ordered address trace.

    This is a fallback for architectures or environments where IDA metadata is
    not available. It groups executed addresses into nearby regions and creates
    basic blocks only for addresses that were actually observed.
    """

    addresses = [block.absolute_start for block in coverage.blocks if block.absolute_start is not None]
    size_by_address = {
        block.absolute_start: block.size
        for block in coverage.blocks
        if block.absolute_start is not None
    }
    unique_addresses = sorted(set(addresses))
    if not unique_addresses:
        return ProgramMetadata(input_path=input_path, image_base=image_base, functions=())

    ranges: list[tuple[int, int]] = []
    start = previous = unique_addresses[0]
    for address in unique_addresses[1:]:
        if address - previous > gap:
            ranges.append((start, previous))
            start = address
        previous = address
    ranges.append((start, previous))

    function_by_address: dict[int, int] = {}
    addresses_by_region: list[list[int]] = [[] for _ in ranges]
    region_index = 0
    for address in unique_addresses:
        while region_index + 1 < len(ranges) and address > ranges[region_index][1]:
            region_index += 1
        if ranges[region_index][0] <= address <= ranges[region_index][1]:
            function_by_address[address] = region_index
            addresses_by_region[region_index].append(address)

    succs: dict[int, set[int]] = defaultdict(set)
    previous_address: int | None = None
    previous_region: int | None = None
    for address in addresses:
        region = function_by_address.get(address)
        if previous_address is not None and previous_region == region and previous_address != address:
            succs[previous_address].add(address)
        previous_address = address
        previous_region = region

    functions: list[Function] = []
    for index, (range_start, range_end) in enumerate(ranges):
        region_addresses = addresses_by_region[index]
        blocks = tuple(
            BasicBlock(
                start=address,
                end=address + size_by_address.get(address, 4),
                succs=tuple(sorted(succs.get(address, ()))),
            )
            for address in region_addresses
        )
        functions.append(
            Function(
                name=f"{name_prefix}_{index:03d}_{range_start:x}",
                start=range_start,
                end=max(block.end for block in blocks),
                blocks=blocks,
            )
        )

    return ProgramMetadata(input_path=input_path, image_base=image_base, functions=tuple(functions))
