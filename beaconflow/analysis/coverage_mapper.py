from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from beaconflow.analysis.ai_digest import attach_ai_digest
from beaconflow.models import CoverageData, Function, ProgramMetadata, hex_addr, normalize_path_name


@dataclass(frozen=True)
class FunctionCoverage:
    function: Function
    covered_blocks: tuple[int, ...]

    @property
    def total_blocks(self) -> int:
        return len(self.function.blocks)

    @property
    def covered_count(self) -> int:
        return len(self.covered_blocks)

    @property
    def percent(self) -> float:
        if not self.total_blocks:
            return 0.0
        return round((self.covered_count / self.total_blocks) * 100.0, 2)

    @property
    def is_covered(self) -> bool:
        return self.covered_count > 0

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.function.name,
            "start": hex_addr(self.function.start),
            "end": hex_addr(self.function.end),
            "covered_blocks": self.covered_count,
            "total_blocks": self.total_blocks,
            "coverage_percent": self.percent,
            "covered_block_starts": [hex_addr(x) for x in self.covered_blocks],
        }


def _candidate_absolute_addresses(metadata: ProgramMetadata, coverage: CoverageData) -> set[int]:
    target_name = normalize_path_name(metadata.input_path)
    addresses: set[int] = set()

    for block in coverage.blocks:
        module = coverage.modules.get(block.module_id)
        if module and target_name and module.name == target_name:
            addresses.add(metadata.image_base + block.offset)
            continue
        if module and target_name:
            continue
        if block.absolute_start is not None:
            addresses.add(block.absolute_start)
            continue
        addresses.add(metadata.image_base + block.offset)

    return addresses


def _range_intersects(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def analyze_coverage(metadata: ProgramMetadata, coverage: CoverageData) -> dict[str, Any]:
    covered_addresses = _candidate_absolute_addresses(metadata, coverage)
    function_results: list[FunctionCoverage] = []

    for function in metadata.functions:
        covered_blocks: list[int] = []
        for block in function.blocks:
            if any(_range_intersects(addr, addr + 1, block.start, block.end) for addr in covered_addresses):
                covered_blocks.append(block.start)
        function_results.append(FunctionCoverage(function=function, covered_blocks=tuple(covered_blocks)))

    covered_functions = [x for x in function_results if x.is_covered]
    uncovered_functions = [x for x in function_results if not x.is_covered]

    return attach_ai_digest("coverage", {
        "summary": {
            "covered_functions": len(covered_functions),
            "total_functions": len(function_results),
            "covered_basic_blocks": sum(x.covered_count for x in function_results),
            "total_basic_blocks": sum(x.total_blocks for x in function_results),
        },
        "covered_functions": [x.to_json() for x in sorted(covered_functions, key=lambda x: (-x.percent, x.function.start))],
        "uncovered_functions": [x.to_json() for x in sorted(uncovered_functions, key=lambda x: x.function.start)],
    })


def diff_coverage(metadata: ProgramMetadata, left: CoverageData, right: CoverageData) -> dict[str, Any]:
    left_result = analyze_coverage(metadata, left)
    right_result = analyze_coverage(metadata, right)
    left_funcs = {x["start"]: x for x in left_result["covered_functions"]}
    right_funcs = {x["start"]: x for x in right_result["covered_functions"]}

    only_left = sorted(set(left_funcs) - set(right_funcs))
    only_right = sorted(set(right_funcs) - set(left_funcs))
    both = sorted(set(left_funcs) & set(right_funcs))

    return attach_ai_digest("coverage_diff", {
        "left_summary": left_result["summary"],
        "right_summary": right_result["summary"],
        "only_left_functions": [left_funcs[x] for x in only_left],
        "only_right_functions": [right_funcs[x] for x in only_right],
        "both_functions": [left_funcs[x] for x in both],
    })
