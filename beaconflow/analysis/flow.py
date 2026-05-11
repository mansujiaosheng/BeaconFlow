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
        # drcov v5: absolute_start = start(运行时) + offset(段内)
        # 静态地址 = preferred_base + seg_offset + offset
        # 或简化：运行时地址 - (start - preferred_base - seg_offset)
        if module.seg_offset or module.preferred_base:
            # v5 格式：将运行时地址转换为静态地址
            # runtime_base = module.start（段的运行时起始地址）
            # static_base = module.preferred_base + module.seg_offset（段的静态起始地址）
            # 但 preferred_base 在 PIE ELF 中可能是 0 或 image_base
            # 更可靠的方式：offset 是段内偏移，静态地址 = image_base + seg_offset + offset
            return metadata.image_base + module.seg_offset + block.offset
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


def _matches_focus(event: MappedBlock, focus_function: str | None) -> bool:
    if not focus_function:
        return True
    if not event.function:
        return False
    focus = focus_function.lower()
    return event.function.name.lower() == focus or hex_addr(event.function.start).lower() == focus


def _resolve_function_address(metadata: ProgramMetadata, name_or_addr: str) -> int | None:
    """将函数名或地址字符串解析为起始地址。"""
    low = name_or_addr.lower()
    for function in metadata.functions:
        if function.name.lower() == low or hex_addr(function.start).lower() == low:
            return function.start
    try:
        return int(name_or_addr, 16) if name_or_addr.lower().startswith("0x") else int(name_or_addr)
    except ValueError:
        return None


def _resolve_function_end(metadata: ProgramMetadata, name_or_addr: str) -> int | None:
    """将函数名或地址字符串解析为结束地址。"""
    low = name_or_addr.lower()
    for function in metadata.functions:
        if function.name.lower() == low or hex_addr(function.start).lower() == low:
            return function.end
    try:
        return int(name_or_addr, 16) if name_or_addr.lower().startswith("0x") else int(name_or_addr)
    except ValueError:
        return None


def _key_from_json(item: dict[str, Any]) -> tuple[str, int]:
    function = item.get("function") or "<unknown>"
    block_start = item.get("block_start") or item.get("address")
    return function, int(block_start, 16)


def _edge_keys(flow: list[dict[str, Any]]) -> list[tuple[tuple[str, int], tuple[str, int]]]:
    return [(_key_from_json(left), _key_from_json(right)) for left, right in zip(flow, flow[1:])]


def _block_json(key: tuple[str, int]) -> dict[str, Any]:
    return {"function": key[0], "block_start": hex_addr(key[1])}


def _edge_json(edge: tuple[tuple[str, int], tuple[str, int]]) -> dict[str, Any]:
    return {"from": _block_json(edge[0]), "to": _block_json(edge[1])}


def _block_ranges_json(keys: list[tuple[str, int]], max_gap: int = 4) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    if not keys:
        return ranges

    current_function, start = keys[0]
    previous = start
    count = 1
    for function, address in keys[1:]:
        if function == current_function and address - previous <= max_gap:
            previous = address
            count += 1
            continue
        ranges.append(
            {
                "function": current_function,
                "start": hex_addr(start),
                "end": hex_addr(previous + max_gap),
                "blocks": count,
            }
        )
        current_function = function
        start = previous = address
        count = 1

    ranges.append(
        {
            "function": current_function,
            "start": hex_addr(start),
            "end": hex_addr(previous + max_gap),
            "blocks": count,
        }
    )
    return ranges


def _hot_counts(result: dict[str, Any]) -> dict[tuple[str, int], int]:
    return {
        (item["function"], int(item["block_start"], 16)): int(item["hits"])
        for item in result.get("hot_blocks", [])
    }


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


def _map_coverage(
    metadata: ProgramMetadata,
    coverage: CoverageData,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
) -> tuple[list[MappedBlock], list[MappedBlock], int, int, int]:
    """将覆盖率块映射到 metadata 的函数/基本块，返回 (mapped, compressed, skipped, unmapped_fn, unmapped_bb)。"""
    mapped: list[MappedBlock] = []
    skipped_module_events = 0
    unmapped_function_events = 0
    unmapped_block_events = 0
    for index, block in enumerate(coverage.blocks):
        address = _static_address(metadata, coverage, block)
        if address is None:
            skipped_module_events += 1
            continue
        if address_start is not None and address < address_start:
            continue
        if address_end is not None and address >= address_end:
            continue
        function = _find_function(metadata, address)
        basic_block = _find_basic_block(function, address)
        if function is None:
            unmapped_function_events += 1
        elif basic_block is None:
            unmapped_block_events += 1
        mapped.append(
            MappedBlock(
                event_index=index,
                address=address,
                size=block.size,
                function=function,
                block=basic_block,
            )
        )

    if focus_function:
        mapped = [event for event in mapped if _matches_focus(event, focus_function)]

    compressed = _compress_consecutive(mapped)
    return mapped, compressed, skipped_module_events, unmapped_function_events, unmapped_block_events


def analyze_flow(
    metadata: ProgramMetadata,
    coverage: CoverageData,
    max_events: int = 0,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
) -> dict[str, Any]:
    """Map a drcov BB table to an ordered execution-flow report.

    DynamoRIO drcov logs basic block entries in the order they were observed.
    This function keeps that order, maps target-module blocks back to IDA
    functions/basic blocks, and emits both raw and consecutive-deduplicated flow.

    address_start/address_end: 只保留此地址范围内的覆盖率事件，
    用于聚焦分析某个函数或地址区间。
    """

    mapped, compressed, skipped_module_events, unmapped_function_events, unmapped_block_events = _map_coverage(
        metadata, coverage, focus_function=focus_function, address_start=address_start, address_end=address_end,
    )

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
            "focus_function": focus_function,
        },
        "diagnostics": {
            "skipped_non_target_module_events": skipped_module_events,
            "unmapped_function_events": unmapped_function_events,
            "unmapped_basic_block_events": unmapped_block_events,
            "mapped_target_events": len(mapped),
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


def diff_flow(
    metadata: ProgramMetadata,
    left: CoverageData,
    right: CoverageData,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
) -> dict[str, Any]:
    left_result = analyze_flow(metadata, left, focus_function=focus_function, address_start=address_start, address_end=address_end)
    right_result = analyze_flow(metadata, right, focus_function=focus_function, address_start=address_start, address_end=address_end)
    left_blocks = {_key_from_json(item) for item in left_result["flow"]}
    right_blocks = {_key_from_json(item) for item in right_result["flow"]}
    left_edges = set(_edge_keys(left_result["flow"]))
    right_edges = set(_edge_keys(right_result["flow"]))
    left_hits = _hot_counts(left_result)
    right_hits = _hot_counts(right_result)

    only_left_blocks = sorted(left_blocks - right_blocks, key=lambda item: (item[0], item[1]))
    only_right_blocks = sorted(right_blocks - left_blocks, key=lambda item: (item[0], item[1]))
    only_left_edges = sorted(left_edges - right_edges, key=str)
    only_right_edges = sorted(right_edges - left_edges, key=str)

    user_only_left_blocks = [key for key in only_left_blocks if _is_user_key(key)]
    user_only_right_blocks = [key for key in only_right_blocks if _is_user_key(key)]
    user_only_left_edges = [edge for edge in only_left_edges if _is_user_key(edge[0]) or _is_user_key(edge[1])]
    user_only_right_edges = [edge for edge in only_right_edges if _is_user_key(edge[0]) or _is_user_key(edge[1])]
    hit_deltas = []
    for key in sorted(set(left_hits) | set(right_hits), key=lambda item: (item[0], item[1])):
        left_count = left_hits.get(key, 0)
        right_count = right_hits.get(key, 0)
        if left_count == right_count:
            continue
        hit_deltas.append(
            {
                "function": key[0],
                "block_start": hex_addr(key[1]),
                "left_hits": left_count,
                "right_hits": right_count,
                "delta": right_count - left_count,
            }
        )
    user_hit_deltas = [item for item in hit_deltas if not _is_runtime_function(item["function"])]

    return {
        "summary": {
            "focus_function": focus_function,
            "left_unique_blocks": len(left_blocks),
            "right_unique_blocks": len(right_blocks),
            "only_left_blocks": len(only_left_blocks),
            "only_right_blocks": len(only_right_blocks),
            "only_left_edges": len(only_left_edges),
            "only_right_edges": len(only_right_edges),
            "hit_count_deltas": len(hit_deltas),
        },
        "ai_report": {
            "purpose": "AI-focused differential execution-flow report.",
            "how_to_use": [
                "Start with user_only_right_blocks/edges to see what the right run uniquely reached.",
                "Use user_only_left_blocks/edges to identify failure or alternate-path logic.",
                "If focus_function is null and CRT noise dominates, rerun with --focus-function _main or a checker function.",
            ],
            "user_only_left_blocks": [_block_json(key) for key in user_only_left_blocks[:100]],
            "user_only_right_blocks": [_block_json(key) for key in user_only_right_blocks[:100]],
            "user_only_left_block_ranges": _block_ranges_json(user_only_left_blocks)[:50],
            "user_only_right_block_ranges": _block_ranges_json(user_only_right_blocks)[:50],
            "user_only_left_edges": [_edge_json(edge) for edge in user_only_left_edges[:100]],
            "user_only_right_edges": [_edge_json(edge) for edge in user_only_right_edges[:100]],
            "user_hit_count_deltas": user_hit_deltas[:100],
        },
        "only_left_blocks": [_block_json(key) for key in only_left_blocks[:200]],
        "only_right_blocks": [_block_json(key) for key in only_right_blocks[:200]],
        "only_left_edges": [_edge_json(edge) for edge in only_left_edges[:200]],
        "only_right_edges": [_edge_json(edge) for edge in only_right_edges[:200]],
        "hit_count_deltas": hit_deltas[:200],
        "left_diagnostics": left_result["diagnostics"],
        "right_diagnostics": right_result["diagnostics"],
    }


def rank_input_branches(
    metadata: ProgramMetadata,
    coverages: list[CoverageData],
    labels: list[str] | None = None,
    roles: list[str] | None = None,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
) -> dict[str, Any]:
    """Rank branch points most likely to be input-dependent.

    This is intentionally trace-driven: it does not claim to recover the
    condition expression. It identifies blocks whose observed outgoing edges or
    hit counts change across inputs, then ranks the blocks that best separate
    baseline/better/good traces.
    """
    if not coverages:
        return {"summary": {"error": "no coverage data provided"}}

    if labels is None:
        labels = [f"trace{i}" for i in range(len(coverages))]
    if roles is None:
        roles = ["unknown"] * len(coverages)

    trace_results: list[dict[str, Any]] = []
    all_edges: dict[tuple[str, int], dict[tuple[str, int], set[str]]] = {}
    all_hits: dict[tuple[str, int], dict[str, int]] = {}
    baseline_edges: set[tuple[tuple[str, int], tuple[str, int]]] = set()

    for index, (coverage, label) in enumerate(zip(coverages, labels)):
        role = roles[index] if index < len(roles) else "unknown"
        mapped, compressed, _, _, _ = _map_coverage(
            metadata,
            coverage,
            focus_function=focus_function,
            address_start=address_start,
            address_end=address_end,
        )
        flow_edges = set(_transition_key(left, right) for left, right in zip(compressed, compressed[1:]))
        if index == 0:
            baseline_edges = set(flow_edges)
        hit_counts = Counter(event.key for event in mapped)
        for edge in flow_edges:
            all_edges.setdefault(edge[0], {}).setdefault(edge[1], set()).add(label)
        for key, count in hit_counts.items():
            all_hits.setdefault(key, {})[label] = count
        trace_results.append(
            {
                "label": label,
                "role": role,
                "unique_blocks": len(set(event.key for event in mapped)),
                "unique_transitions": len(flow_edges),
            }
        )

    good_labels = {label for label, role in zip(labels, roles) if role == "good"}
    better_labels = {label for label, role in zip(labels, roles) if role == "better"}
    baseline_label = labels[0]

    ranked: list[dict[str, Any]] = []
    for source, targets in all_edges.items():
        if not _is_user_key(source):
            continue

        outgoing = [
            {
                "to": _format_key(target),
                "covered_by": sorted(trace_labels),
                "coverage_ratio": f"{len(trace_labels)}/{len(labels)}",
                "baseline_edge": (source, target) in baseline_edges,
            }
            for target, trace_labels in sorted(targets.items(), key=lambda item: (item[0][0], item[0][1]))
        ]
        new_targets = [
            target for target in targets
            if (source, target) not in baseline_edges
        ]
        hit_by_label = all_hits.get(source, {})
        hit_values = list(hit_by_label.values())
        hit_spread = (max(hit_values) - min(hit_values)) if hit_values else 0
        good_only_edges = 0
        better_or_good_edges = 0
        for target, trace_labels in targets.items():
            if (source, target) in baseline_edges:
                continue
            if trace_labels and trace_labels <= good_labels:
                good_only_edges += 1
            if trace_labels & (better_labels | good_labels):
                better_or_good_edges += 1

        score = 0
        score += len(new_targets) * 20
        score += max(0, len(targets) - 1) * 12
        score += good_only_edges * 25
        score += better_or_good_edges * 8
        score += min(hit_spread, 20)
        if baseline_label not in hit_by_label:
            score += 5
        if score == 0:
            continue

        reason: list[str] = []
        if new_targets:
            reason.append("has outgoing edge(s) absent from baseline")
        if len(targets) > 1:
            reason.append("observed multiple successors across traces")
        if good_only_edges:
            reason.append("has edge(s) only seen in good traces")
        if hit_spread:
            reason.append("hit count changes across inputs")

        ranked.append(
            {
                "block": _format_key(source),
                "score": score,
                "successor_count": len(targets),
                "new_successors_vs_baseline": len(new_targets),
                "hit_spread": hit_spread,
                "hits_by_trace": {label: hit_by_label.get(label, 0) for label in labels},
                "outgoing_edges": outgoing,
                "why": reason,
                "next_action": "Open this block in IDA/Ghidra and inspect the compare/conditional move/table lookup that selects the listed successors.",
            }
        )

    ranked.sort(key=lambda item: (-item["score"], item["block"]))
    return {
        "summary": {
            "total_traces": len(coverages),
            "baseline": baseline_label,
            "ranked_branch_points": len(ranked),
            "focus_function": focus_function,
        },
        "traces": trace_results,
        "ranked_branches": ranked[:100],
        "ai_interpretation": {
            "purpose": "Rank branch points most likely controlled by input differences.",
            "how_to_use": [
                "Start at the highest score block; it best separates baseline from better/good traces.",
                "A new_successors_vs_baseline value means this input reached an edge the baseline never used.",
                "hit_spread is useful only with precise trace modes; for QEMU in_asm treat it as weak evidence.",
            ],
            "next_steps": [
                "Use flow-diff around the top block to inspect left-only/right-only ranges.",
                "If using QEMU in_asm and hit counts matter, recollect with --trace-mode exec,nochain.",
                "Pair this report with disassembly to recover the actual comparison operands.",
            ],
        },
    }


def _identify_dispatchers(
    compressed: list[MappedBlock],
    hot_blocks: Counter[tuple[str, int]],
    min_hits: int = 2,
    min_pred: int = 2,
    min_succ: int = 2,
) -> set[tuple[str, int]]:
    """识别平坦化中的 dispatcher 块。

    dispatcher 的特征：高频执行 + 多前驱（多个真实块跳回 dispatcher）+ 多后继（dispatcher 分发到多个真实块）。
    """
    out_degree: dict[tuple[str, int], set[tuple[str, int]]] = {}
    in_degree: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for left, right in zip(compressed, compressed[1:]):
        out_degree.setdefault(left.key, set()).add(right.key)
        in_degree.setdefault(right.key, set()).add(left.key)

    dispatchers: set[tuple[str, int]] = set()
    for key, hits in hot_blocks.items():
        pred_count = len(in_degree.get(key, ()))
        succ_count = len(out_degree.get(key, ()))
        score = hits + succ_count * 2 + pred_count
        # dispatcher 判定：高频 + 多前驱或多后继
        if hits >= min_hits and (pred_count >= min_pred or succ_count >= min_succ):
            dispatchers.add(key)
        # 或者 score 足够高（即使 pred/succ 不多，但频率极高也说明是 dispatcher）
        elif score >= 10 and hits >= 3:
            dispatchers.add(key)

    return dispatchers


def deflatten_flow(
    metadata: ProgramMetadata,
    coverage: CoverageData,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
    dispatcher_min_hits: int = 2,
    dispatcher_min_pred: int = 2,
    dispatcher_min_succ: int = 2,
) -> dict[str, Any]:
    """反平坦化分析：从执行流中过滤 dispatcher 块，重建真实控制流边。

    核心思路：
    1. 识别 dispatcher 块（高频 + 多前驱/多后继）
    2. 从执行流中删除 dispatcher 块
    3. 重建真实边：A -> dispatcher -> B 变成 A -> B
    4. 输出"干净的"执行流
    """
    mapped, compressed, skipped_module_events, unmapped_function_events, unmapped_block_events = _map_coverage(
        metadata, coverage, focus_function=focus_function, address_start=address_start, address_end=address_end,
    )

    if not compressed:
        return {
            "summary": {
                "error": "no mapped events in the target range",
                "original_blocks": 0,
                "dispatcher_blocks": 0,
                "real_blocks": 0,
                "real_edges": 0,
            },
        }

    hot_blocks = Counter(event.key for event in mapped)

    # 识别 dispatcher 块
    dispatcher_keys = _identify_dispatchers(
        compressed, hot_blocks,
        min_hits=dispatcher_min_hits,
        min_pred=dispatcher_min_pred,
        min_succ=dispatcher_min_succ,
    )

    # 从压缩流中过滤 dispatcher，重建真实边
    real_events = [e for e in compressed if e.key not in dispatcher_keys]

    # 重建真实边
    real_edges: list[tuple[MappedBlock, MappedBlock]] = []
    last_real: MappedBlock | None = None
    for event in compressed:
        if event.key in dispatcher_keys:
            continue
        if last_real is not None:
            real_edges.append((last_real, event))
        last_real = event

    # 统计真实边的转移
    real_transitions: Counter[tuple[tuple[str, int], tuple[str, int]]] = Counter()
    for left, right in real_edges:
        real_transitions[(left.key, right.key)] += 1

    # 真实块的热度
    real_hot_blocks = Counter(event.key for event in real_events)

    # 真实块的出度/入度
    real_out_degree: dict[tuple[str, int], set[tuple[str, int]]] = {}
    real_in_degree: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for (left_key, right_key), hits in real_transitions.items():
        real_out_degree.setdefault(left_key, set()).add(right_key)
        real_in_degree.setdefault(right_key, set()).add(left_key)

    # 真实分支点
    real_branch_points = [
        {
            "block": _format_key(key),
            "successors": sorted([_format_key(t) for t in targets]),
            "successor_count": len(targets),
        }
        for key, targets in sorted(real_out_degree.items(), key=lambda item: (-len(item[1]), item[0][1]))
        if len(targets) > 1
    ]

    # 真实执行脊柱
    real_spine_keys: list[tuple[str, int]] = []
    previous: tuple[str, int] | None = None
    for event in real_events:
        if event.key == previous:
            continue
        real_spine_keys.append(event.key)
        previous = event.key

    # 真实函数顺序
    real_function_order: list[str] = []
    seen_real_functions: set[str] = set()
    for event in real_events:
        name = event.function.name if event.function else "<unknown>"
        if name not in seen_real_functions:
            seen_real_functions.add(name)
            real_function_order.append(name)

    # dispatcher 块详情
    dispatcher_details = []
    for key in sorted(dispatcher_keys, key=lambda k: (-hot_blocks.get(k, 0), k[1])):
        pred_set: set[tuple[str, int]] = set()
        succ_set: set[tuple[str, int]] = set()
        for idx in range(len(compressed)):
            if compressed[idx].key == key:
                for j in range(idx - 1, -1, -1):
                    if compressed[j].key not in dispatcher_keys:
                        pred_set.add(compressed[j].key)
                        break
                for j in range(idx + 1, len(compressed)):
                    if compressed[j].key not in dispatcher_keys:
                        succ_set.add(compressed[j].key)
                        break
        dispatcher_details.append({
            "block": _format_key(key),
            "hits": hot_blocks.get(key, 0),
            "real_predecessors": len(pred_set),
            "real_successors": len(succ_set),
        })

    # 构建原始 flow_result（用于兼容）
    transitions = Counter(_transition_key(left, right) for left, right in zip(compressed, compressed[1:]))
    function_order: list[dict[str, Any]] = []
    seen_functions: set[int] = set()
    for event in compressed:
        if not event.function or event.function.start in seen_functions:
            continue
        seen_functions.add(event.function.start)
        function_order.append({"name": event.function.name, "start": hex_addr(event.function.start)})

    flow_limit = len(compressed)
    ai_report = _build_ai_report(compressed, transitions, hot_blocks, function_order, flow_limit)

    flow_result = {
        "summary": {
            "raw_target_events": len(mapped),
            "compressed_events": len(compressed),
            "unique_blocks": len(set(e.key for e in mapped)),
            "unique_transitions": len(transitions),
            "functions_seen": len(function_order),
            "truncated": False,
            "focus_function": focus_function,
        },
        "diagnostics": {
            "skipped_non_target_module_events": skipped_module_events,
            "unmapped_function_events": unmapped_function_events,
            "unmapped_basic_block_events": unmapped_block_events,
            "mapped_target_events": len(mapped),
        },
        "ai_report": ai_report,
        "function_order": function_order,
        "flow": [event.to_json() for event in compressed],
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

    return {
        "summary": {
            "original_blocks": len(set(e.key for e in compressed)),
            "dispatcher_blocks": len(dispatcher_keys),
            "real_blocks": len(set(e.key for e in real_events)),
            "real_edges": len(real_transitions),
            "real_branch_points": len(real_branch_points),
            "real_events_in_spine": len(real_spine_keys),
        },
        "dispatcher_blocks": [_format_key(k) for k in sorted(dispatcher_keys, key=lambda k: (-hot_blocks.get(k, 0), k[1]))],
        "real_function_order": " -> ".join(real_function_order),
        "real_execution_spine": [_format_key(k) for k in real_spine_keys[:80]],
        "real_branch_points": real_branch_points[:20],
        "real_edges": [
            {
                "from": _format_key(left),
                "to": _format_key(right),
                "hits": hits,
            }
            for (left, right), hits in real_transitions.most_common(100)
        ],
        "real_hot_blocks": [
            {"block": _format_key(key), "hits": hits}
            for key, hits in real_hot_blocks.most_common(50)
        ],
        "original_flow_result": flow_result,
    }


def deflatten_merge(
    metadata: ProgramMetadata,
    coverages: list[CoverageData],
    labels: list[str] | None = None,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
    dispatcher_min_hits: int = 2,
    dispatcher_min_pred: int = 2,
    dispatcher_min_succ: int = 2,
) -> dict[str, Any]:
    """合并多次 deflatten 结果，还原完整真实 CFG。

    对每个 coverage 分别做 deflatten，然后合并所有真实边和真实块，
    标注每条边被哪些 trace 覆盖，从而还原完整的控制流图。
    """
    if not coverages:
        return {"summary": {"error": "no coverage data provided"}}

    if labels is None:
        labels = [f"trace{i}" for i in range(len(coverages))]

    per_trace: list[dict[str, Any]] = []
    all_real_edges: Counter[tuple[tuple[str, int], tuple[str, int]]] = Counter()
    all_real_blocks: Counter[tuple[str, int]] = Counter()
    all_dispatcher_blocks: set[tuple[str, int]] = set()
    edge_sources: dict[tuple[tuple[str, int], tuple[str, int]], list[str]] = {}
    block_sources: dict[tuple[str, int], list[str]] = {}

    for idx, (coverage, label) in enumerate(zip(coverages, labels)):
        result = deflatten_flow(
            metadata, coverage,
            focus_function=focus_function,
            address_start=address_start,
            address_end=address_end,
            dispatcher_min_hits=dispatcher_min_hits,
            dispatcher_min_pred=dispatcher_min_pred,
            dispatcher_min_succ=dispatcher_min_succ,
        )
        summary = result.get("summary", {})
        per_trace.append({
            "label": label,
            "original_blocks": summary.get("original_blocks", 0),
            "dispatcher_blocks": summary.get("dispatcher_blocks", 0),
            "real_blocks": summary.get("real_blocks", 0),
            "real_edges": summary.get("real_edges", 0),
            "real_branch_points": summary.get("real_branch_points", 0),
        })

        # 合并 dispatcher 块
        for block_str in result.get("dispatcher_blocks", []):
            key = _parse_key(block_str)
            all_dispatcher_blocks.add(key)

        # 合并真实边
        for edge in result.get("real_edges", []):
            left = _parse_key(edge["from"])
            right = _parse_key(edge["to"])
            edge_key = (left, right)
            all_real_edges[edge_key] += edge.get("hits", 1)
            edge_sources.setdefault(edge_key, []).append(label)

        # 合并真实块
        for block in result.get("real_hot_blocks", []):
            key = _parse_key(block["block"])
            all_real_blocks[key] += block.get("hits", 1)
            block_sources.setdefault(key, []).append(label)

        # 也加入没有在 hot_blocks 中但出现在 spine 中的块
        for block_str in result.get("real_execution_spine", []):
            key = _parse_key(block_str)
            if key not in all_real_blocks:
                all_real_blocks[key] += 1
                block_sources.setdefault(key, []).append(label)

    # 构建完整的真实 CFG
    # 出度/入度
    real_out: dict[tuple[str, int], set[tuple[str, int]]] = {}
    real_in: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for (left, right) in all_real_edges:
        real_out.setdefault(left, set()).add(right)
        real_in.setdefault(right, set()).add(left)

    # 分支点（出度 > 1）
    branch_points = []
    for key in sorted(real_out, key=lambda k: (-len(real_out[k]), k[1])):
        targets = real_out[key]
        if len(targets) > 1:
            branch_points.append({
                "block": _format_key(key),
                "successors": sorted([_format_key(t) for t in targets]),
                "successor_count": len(targets),
                "covered_by_traces": len(set(s for t in targets for s in edge_sources.get((key, t), []))),
            })

    # 汇合点（入度 > 1）
    merge_points = []
    for key in sorted(real_in, key=lambda k: (-len(real_in[k]), k[1])):
        sources = real_in[key]
        if len(sources) > 1:
            merge_points.append({
                "block": _format_key(key),
                "predecessors": sorted([_format_key(s) for s in sources]),
                "predecessor_count": len(sources),
            })

    # 块覆盖度统计
    total_traces = len(coverages)
    block_coverage = []
    for key in sorted(all_real_blocks, key=lambda k: (-all_real_blocks[k], k[1])):
        sources = block_sources.get(key, [])
        unique_sources = list(dict.fromkeys(sources))
        block_coverage.append({
            "block": _format_key(key),
            "total_hits": all_real_blocks[key],
            "covered_by": unique_sources,
            "coverage_ratio": f"{len(unique_sources)}/{total_traces}",
        })

    # 边覆盖度统计
    edge_coverage = []
    for (left, right), hits in all_real_edges.most_common(200):
        sources = edge_sources.get((left, right), [])
        unique_sources = list(dict.fromkeys(sources))
        edge_coverage.append({
            "from": _format_key(left),
            "to": _format_key(right),
            "total_hits": hits,
            "covered_by": unique_sources,
            "coverage_ratio": f"{len(unique_sources)}/{total_traces}",
        })

    # 只被部分 trace 覆盖的边（输入相关的分支）
    input_dependent_edges = [
        e for e in edge_coverage
        if len(dict.fromkeys(edge_sources.get((_parse_key(e["from"]), _parse_key(e["to"])), []))) < total_traces
    ]

    # 所有 trace 都覆盖的边（公共路径）
    common_edges = [
        e for e in edge_coverage
        if len(dict.fromkeys(edge_sources.get((_parse_key(e["from"]), _parse_key(e["to"])), []))) == total_traces
    ]

    return {
        "summary": {
            "total_traces": total_traces,
            "total_real_blocks": len(all_real_blocks),
            "total_real_edges": len(all_real_edges),
            "total_dispatcher_blocks": len(all_dispatcher_blocks),
            "total_branch_points": len(branch_points),
            "total_merge_points": len(merge_points),
            "common_edges": len(common_edges),
            "input_dependent_edges": len(input_dependent_edges),
        },
        "per_trace_summary": per_trace,
        "dispatcher_blocks": sorted([_format_key(k) for k in all_dispatcher_blocks]),
        "real_cfg": {
            "blocks": block_coverage[:100],
            "edges": edge_coverage[:100],
            "branch_points": branch_points[:30],
            "merge_points": merge_points[:30],
        },
        "common_path": {
            "description": "Edges covered by ALL traces (input-independent)",
            "edges": common_edges[:50],
        },
        "input_dependent_path": {
            "description": "Edges NOT covered by all traces (input-dependent, key for understanding different behaviors)",
            "edges": input_dependent_edges[:50],
        },
    }


def _parse_key(formatted: str) -> tuple[str, int]:
    """将 _format_key 的输出解析回 (function_name, address) 元组。"""
    if ":" in formatted:
        parts = formatted.rsplit(":", 1)
        try:
            return (parts[0], int(parts[1], 16))
        except ValueError:
            return (formatted, 0)
    try:
        return ("", int(formatted, 16))
    except ValueError:
        return (formatted, 0)


def recover_state_transitions(
    metadata: ProgramMetadata,
    coverages: list[CoverageData],
    labels: list[str] | None = None,
    focus_function: str | None = None,
    address_start: int | None = None,
    address_end: int | None = None,
    dispatcher_min_hits: int = 2,
    dispatcher_min_pred: int = 2,
    dispatcher_min_succ: int = 2,
) -> dict[str, Any]:
    """从多次执行 trace 中恢复状态转移表。

    在平坦化控制流中，dispatcher 通过状态变量决定跳转目标。
    本函数通过观察"真实块 -> dispatcher -> 真实块"链路，推断：
    - 确定性转移：真实块 A 之后 dispatcher 总是跳到 B（A 设置状态变量为固定值）
    - 输入相关转移：真实块 A 之后 dispatcher 可能跳到 B 或 C（取决于输入）

    这比 deflatten_merge 更进一步：不仅知道有哪些边，还知道每条边的
    "来源真实块"和"目标真实块"之间的确定性关系。
    """
    if not coverages:
        return {"summary": {"error": "no coverage data provided"}}

    if labels is None:
        labels = [f"trace{i}" for i in range(len(coverages))]

    total_traces = len(coverages)

    # 对每个 trace 做 deflatten，收集状态转移信息
    # state_transitions: (real_block_key) -> { next_real_block_key: [trace_labels] }
    state_transitions: dict[tuple[str, int], dict[tuple[str, int], list[str]]] = {}
    all_dispatcher_keys: set[tuple[str, int]] = set()
    all_real_blocks: set[tuple[str, int]] = set()

    for idx, (coverage, label) in enumerate(zip(coverages, labels)):
        mapped, compressed, _, _, _ = _map_coverage(
            metadata, coverage,
            focus_function=focus_function,
            address_start=address_start,
            address_end=address_end,
        )

        if not compressed:
            continue

        hot_blocks = Counter(event.key for event in mapped)
        dispatcher_keys = _identify_dispatchers(
            compressed, hot_blocks,
            min_hits=dispatcher_min_hits,
            min_pred=dispatcher_min_pred,
            min_succ=dispatcher_min_succ,
        )
        all_dispatcher_keys.update(dispatcher_keys)

        # 构建"真实块 -> 下一个真实块"的转移
        # 在压缩流中，跳过 dispatcher 块，记录连续真实块之间的转移
        last_real: tuple[str, int] | None = None
        for event in compressed:
            if event.key in dispatcher_keys:
                continue
            all_real_blocks.add(event.key)
            if last_real is not None:
                transitions_from_last = state_transitions.setdefault(last_real, {})
                targets = transitions_from_last.setdefault(event.key, [])
                targets.append(label)
            last_real = event.key

    # 分析每个真实块的状态转移
    deterministic_transitions: list[dict[str, Any]] = []
    input_dependent_transitions: list[dict[str, Any]] = []
    unknown_transitions: list[dict[str, Any]] = []

    for block_key in sorted(state_transitions, key=lambda k: (k[0], k[1])):
        targets = state_transitions[block_key]
        target_list = sorted(targets.items(), key=lambda item: (-len(item[1]), item[0][1]))

        for target_key, trace_labels in target_list:
            unique_traces = list(dict.fromkeys(trace_labels))
            coverage_count = len(unique_traces)
            entry = {
                "from_block": _format_key(block_key),
                "to_block": _format_key(target_key),
                "observed_in_traces": unique_traces,
                "coverage_ratio": f"{coverage_count}/{total_traces}",
            }

            if len(target_list) == 1:
                # 只有一个目标 -> 确定性转移
                deterministic_transitions.append(entry)
            elif coverage_count == total_traces:
                # 多个目标，但这条边被所有 trace 覆盖 -> 确定性（所有输入都走这条路）
                deterministic_transitions.append(entry)
            else:
                # 输入相关转移
                input_dependent_transitions.append(entry)

    # 对于有多个后继的真实块，标注为分支块
    branch_blocks: list[dict[str, Any]] = []
    for block_key, targets in sorted(state_transitions.items(), key=lambda item: (-len(item[1]), item[0][1])):
        if len(targets) > 1:
            # 统计每个后继被哪些 trace 覆盖
            successors = []
            for target_key, trace_labels in sorted(targets.items(), key=lambda item: (-len(item[1]), item[0][1])):
                unique_traces = list(dict.fromkeys(trace_labels))
                successors.append({
                    "block": _format_key(target_key),
                    "covered_by": unique_traces,
                    "coverage_ratio": f"{len(unique_traces)}/{total_traces}",
                })
            branch_blocks.append({
                "block": _format_key(block_key),
                "successor_count": len(targets),
                "successors": successors,
                "type": "input-dependent" if any(
                    len(dict.fromkeys(targets[t])) < total_traces for t in targets
                ) else "deterministic",
            })

    # 构建状态转移表（矩阵形式，方便 AI 阅读）
    # 只包含有多个后继的分支块
    transition_table: list[dict[str, Any]] = []
    for bb in branch_blocks:
        row = {
            "block": bb["block"],
            "transitions": {},
        }
        for succ in bb["successors"]:
            row["transitions"][succ["block"]] = {
                "traces": succ["covered_by"],
                "ratio": succ["coverage_ratio"],
            }
        transition_table.append(row)

    return {
        "summary": {
            "total_traces": total_traces,
            "total_real_blocks": len(all_real_blocks),
            "total_dispatcher_blocks": len(all_dispatcher_keys),
            "total_state_transitions": sum(len(t) for t in state_transitions.values()),
            "deterministic_transitions": len(deterministic_transitions),
            "input_dependent_transitions": len(input_dependent_transitions),
            "branch_blocks": len(branch_blocks),
        },
        "state_transition_table": transition_table[:30],
        "deterministic_transitions": deterministic_transitions[:50],
        "input_dependent_transitions": input_dependent_transitions[:50],
        "branch_blocks": branch_blocks[:30],
        "dispatcher_blocks": sorted([_format_key(k) for k in all_dispatcher_keys])[:50],
        "ai_interpretation": {
            "purpose": "State variable recovery for control-flow-flattened binaries.",
            "how_to_read": [
                "deterministic_transitions: real block A always leads to real block B (state variable set to fixed value).",
                "input_dependent_transitions: real block A leads to different blocks depending on input (state variable depends on branch condition).",
                "branch_blocks: real blocks with multiple successors in the real CFG; these are where input-dependent decisions happen.",
                "state_transition_table: compact matrix showing which trace inputs lead to which successors at each branch block.",
            ],
            "next_steps": [
                "For deterministic transitions, the real block sets the state variable to a constant before jumping to the dispatcher.",
                "For input-dependent transitions, the real block contains a conditional branch that sets the state variable based on input.",
                "Open each branch_block in IDA/Ghidra to find the comparison instruction that determines the state variable value.",
                "The state variable is typically compared against constants in the dispatcher block; match those constants to the successor blocks.",
            ],
        },
    }
