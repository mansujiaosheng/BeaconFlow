from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from beaconflow.models import BasicBlock, CoverageBlock, CoverageData, Function, ProgramMetadata, hex_addr, normalize_path_name


@dataclass(frozen=True)
class MappedBlock:
    event_index: int
    address: int
    size: int
    function: Function | None
    block: BasicBlock | None

    @property
    def key(self) -> tuple[str, int]:
        return (self.function.name if self.function else "<unknown>", self.block.start if self.block else self.address)

    def to_json(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "address": hex_addr(self.address),
            "size": self.size,
            "function": self.function.name if self.function else None,
            "function_start": hex_addr(self.function.start) if self.function else None,
            "block_start": hex_addr(self.block.start) if self.block else None,
            "block_end": hex_addr(self.block.end) if self.block else None,
        }


def _static_address(metadata: ProgramMetadata, coverage: CoverageData, block: CoverageBlock) -> int | None:
    module = coverage.modules.get(block.module_id)
    target_name = normalize_path_name(metadata.input_path)
    if module and target_name and module.name != target_name:
        return None
    if module and target_name and module.name == target_name:
        return metadata.image_base + block.offset
    if block.absolute_start is not None:
        return block.absolute_start
    return metadata.image_base + block.offset


def _find_function(metadata: ProgramMetadata, address: int) -> Function | None:
    for function in metadata.functions:
        if function.start <= address < function.end:
            return function
    return None


def _find_basic_block(function: Function | None, address: int) -> BasicBlock | None:
    if not function:
        return None
    for block in function.blocks:
        if block.start <= address < block.end:
            return block
    return None


def _compress_consecutive(events: list[MappedBlock]) -> list[MappedBlock]:
    compressed: list[MappedBlock] = []
    previous_key: tuple[str, int] | None = None
    for event in events:
        if event.key == previous_key:
            continue
        compressed.append(event)
        previous_key = event.key
    return compressed


def _transition_key(left: MappedBlock, right: MappedBlock) -> tuple[tuple[str, int], tuple[str, int]]:
    return left.key, right.key


def _format_key(key: tuple[str, int]) -> str:
    return f"{key[0]}:{hex_addr(key[1])}"


def _formatted_function_name(value: str) -> str:
    return value.rsplit(":", 1)[0]


def _is_runtime_function(name: str) -> bool:
    if name in {"_main", "main", "WinMain", "_WinMain@16"}:
        return False
    runtime_prefixes = (
        "__",
        "??",
        "?",
        "_mem",
        "_str",
        "_malloc",
        "_free",
        "_calloc",
        "_realloc",
        "_atoi",
        "_atol",
        "_set",
        "_get",
        "_lock",
        "_unlock",
        "_printf",
        "_sprintf",
        "_scanf",
        "_f",
        "std::",
    )
    return name.startswith(runtime_prefixes)


def _is_user_key(key: tuple[str, int]) -> bool:
    name = key[0]
    return name == "<unknown>" or not _is_runtime_function(name)


def _build_ai_report(
    compressed: list[MappedBlock],
    transitions: Counter[tuple[tuple[str, int], tuple[str, int]]],
    hot_blocks: Counter[tuple[str, int]],
    function_order: list[dict[str, Any]],
    flow_limit: int,
) -> dict[str, Any]:
    out_degree: dict[tuple[str, int], set[tuple[str, int]]] = {}
    in_degree: dict[tuple[str, int], set[tuple[str, int]]] = {}
    first_seen: dict[tuple[str, int], int] = {}

    for index, event in enumerate(compressed):
        first_seen.setdefault(event.key, index)

    for left, right in transitions:
        out_degree.setdefault(left, set()).add(right)
        in_degree.setdefault(right, set()).add(left)

    repeated_blocks = [
        {"block": _format_key(key), "hits": hits}
        for key, hits in hot_blocks.most_common(20)
        if hits > 1
    ]

    branch_points = [
        {
            "block": _format_key(key),
            "observed_successors": [_format_key(target) for target in sorted(targets)],
            "successor_count": len(targets),
            "hits": hot_blocks.get(key, 0),
        }
        for key, targets in sorted(out_degree.items(), key=lambda item: (-len(item[1]), item[0][1]))
        if len(targets) > 1
    ][:20]

    join_points = [
        {
            "block": _format_key(key),
            "observed_predecessors": [_format_key(source) for source in sorted(sources)],
            "predecessor_count": len(sources),
            "hits": hot_blocks.get(key, 0),
        }
        for key, sources in sorted(in_degree.items(), key=lambda item: (-len(item[1]), item[0][1]))
        if len(sources) > 1
    ][:20]

    loop_like_edges = [
        {
            "from": _format_key(left),
            "to": _format_key(right),
            "hits": hits,
        }
        for (left, right), hits in transitions.most_common()
        if first_seen.get(right, 0) <= first_seen.get(left, 0)
    ][:20]

    dispatcher_candidates = []
    for key, hits in hot_blocks.most_common(50):
        score = hits + len(out_degree.get(key, ())) * 2 + len(in_degree.get(key, ()))
        if hits > 1 or len(out_degree.get(key, ())) > 1 or len(in_degree.get(key, ())) > 1:
            dispatcher_candidates.append(
                {
                    "block": _format_key(key),
                    "score": score,
                    "hits": hits,
                    "observed_successors": len(out_degree.get(key, ())),
                    "observed_predecessors": len(in_degree.get(key, ())),
                }
            )
    dispatcher_candidates.sort(key=lambda item: (-item["score"], item["block"]))

    user_function_names: list[str] = []
    seen_user_functions: set[str] = set()
    for item in function_order:
        name = item["name"]
        if name in seen_user_functions or _is_runtime_function(name):
            continue
        seen_user_functions.add(name)
        user_function_names.append(name)

    user_dispatcher_candidates = [
        item for item in dispatcher_candidates if not _is_runtime_function(_formatted_function_name(item["block"]))
    ][:20]
    user_branch_points = [item for item in branch_points if not _is_runtime_function(_formatted_function_name(item["block"]))][:20]
    user_join_points = [item for item in join_points if not _is_runtime_function(_formatted_function_name(item["block"]))][:20]
    user_loop_like_edges = [item for item in loop_like_edges if not _is_runtime_function(_formatted_function_name(item["from"]))][:20]

    spine_keys: list[tuple[str, int]] = []
    previous: tuple[str, int] | None = None
    for event in compressed:
        if event.key == previous:
            continue
        spine_keys.append(event.key)
        previous = event.key

    preview_count = min(80, len(spine_keys))
    execution_spine = [_format_key(key) for key in spine_keys[:preview_count]]

    interpretation = [
        "Use flow as the observed path, not as a full CFG.",
        "Prioritize blocks in execution_spine, branch_points, join_points, and dispatcher_candidates.",
        "Ignore static CFG regions not present in flow until another input reaches them.",
    ]
    if dispatcher_candidates:
        interpretation.append("Dispatcher candidates are heuristic; confirm them in IDA pseudocode or with more inputs.")
    if flow_limit < len(compressed):
        interpretation.append("The flow list was truncated; rerun with max_events=0 before final reasoning.")

    return {
        "purpose": "AI-focused execution-flow digest for binary analysis and control-flow-flattening triage.",
        "how_to_use": interpretation,
        "function_order_text": " -> ".join(item["name"] for item in function_order) if function_order else "<no mapped functions>",
        "user_function_order_text": " -> ".join(user_function_names) if user_function_names else "<no mapped user functions>",
        "execution_spine_preview": execution_spine,
        "execution_spine_preview_count": preview_count,
        "repeated_blocks": repeated_blocks,
        "branch_points": branch_points,
        "join_points": join_points,
        "loop_like_edges": loop_like_edges,
        "dispatcher_candidates": dispatcher_candidates[:20],
        "user_branch_points": user_branch_points,
        "user_join_points": user_join_points,
        "user_loop_like_edges": user_loop_like_edges,
        "user_dispatcher_candidates": user_dispatcher_candidates,
        "next_steps": [
            "Start with user_dispatcher_candidates and user_branch_points before CRT/runtime-heavy fields.",
            "Open the top dispatcher candidates and inspect state-variable updates.",
            "Compare record_flow outputs from multiple inputs to separate real branches from dead flattened CFG edges.",
            "If a candidate needs value recovery, collect a richer trace with register or memory state.",
        ],
    }


def analyze_flow(metadata: ProgramMetadata, coverage: CoverageData, max_events: int = 0) -> dict[str, Any]:
    """Map a drcov BB table to an ordered execution-flow report.

    DynamoRIO drcov logs basic block entries in the order they were observed.
    This function keeps that order, maps target-module blocks back to IDA
    functions/basic blocks, and emits both raw and consecutive-deduplicated flow.
    """

    mapped: list[MappedBlock] = []
    for index, block in enumerate(coverage.blocks):
        address = _static_address(metadata, coverage, block)
        if address is None:
            continue
        function = _find_function(metadata, address)
        basic_block = _find_basic_block(function, address)
        mapped.append(
            MappedBlock(
                event_index=index,
                address=address,
                size=block.size,
                function=function,
                block=basic_block,
            )
        )

    compressed = _compress_consecutive(mapped)
    transitions = Counter(_transition_key(left, right) for left, right in zip(compressed, compressed[1:]))

    function_order: list[dict[str, Any]] = []
    seen_functions: set[int] = set()
    for event in compressed:
        if not event.function or event.function.start in seen_functions:
            continue
        seen_functions.add(event.function.start)
        function_order.append({"name": event.function.name, "start": hex_addr(event.function.start)})

    unique_blocks = {
        event.key
        for event in mapped
    }

    hot_blocks = Counter(event.key for event in mapped)
    flow_limit = max_events if max_events and max_events > 0 else len(compressed)
    ai_report = _build_ai_report(compressed, transitions, hot_blocks, function_order, flow_limit)

    return {
        "summary": {
            "raw_target_events": len(mapped),
            "compressed_events": len(compressed),
            "unique_blocks": len(unique_blocks),
            "unique_transitions": len(transitions),
            "functions_seen": len(function_order),
            "truncated": flow_limit < len(compressed),
        },
        "ai_report": ai_report,
        "function_order": function_order,
        "flow": [event.to_json() for event in compressed[:flow_limit]],
        "hot_blocks": [
            {"function": key[0], "block_start": hex_addr(key[1]), "hits": hits}
            for key, hits in hot_blocks.most_common(50)
        ],
        "transitions": [
            {
                "from": {"function": left[0], "block_start": hex_addr(left[1])},
                "to": {"function": right[0], "block_start": hex_addr(right[1])},
                "hits": hits,
            }
            for (left, right), hits in transitions.most_common(100)
        ],
    }
