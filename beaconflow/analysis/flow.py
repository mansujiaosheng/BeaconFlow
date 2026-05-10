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
    flow_result = analyze_flow(
        metadata, coverage,
        focus_function=focus_function,
        address_start=address_start,
        address_end=address_end,
    )

    compressed_events: list[dict[str, Any]] = flow_result["flow"]
    if not compressed_events:
        return {
            "summary": {
                "error": "no mapped events in the target range",
                "original_blocks": 0,
                "dispatcher_blocks": 0,
                "real_blocks": 0,
                "real_edges": 0,
            },
        }

    # 重建 MappedBlock 列表
    mapped: list[MappedBlock] = []
    for index, block in enumerate(coverage.blocks):
        address = _static_address(metadata, coverage, block)
        if address is None:
            continue
        if address_start is not None and address < address_start:
            continue
        if address_end is not None and address >= address_end:
            continue
        function = _find_function(metadata, address)
        basic_block = _find_basic_block(function, address)
        mapped.append(MappedBlock(event_index=index, address=address, size=block.size, function=function, block=basic_block))

    if focus_function:
        mapped = [e for e in mapped if _matches_focus(e, focus_function)]

    compressed = _compress_consecutive(mapped)
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

    # 重建真实边：如果原始流是 A -> D1 -> D2 -> B（D1, D2 是 dispatcher），
    # 则真实边是 A -> B
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
        # 计算真实前驱：压缩流中，dispatcher 前一个非 dispatcher 块
        pred_set: set[tuple[str, int]] = set()
        succ_set: set[tuple[str, int]] = set()
        for idx in range(len(compressed)):
            if compressed[idx].key == key:
                # 前驱：往前找最近的非 dispatcher 块
                for j in range(idx - 1, -1, -1):
                    if compressed[j].key not in dispatcher_keys:
                        pred_set.add(compressed[j].key)
                        break
                # 后继：往后找最近的非 dispatcher 块
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
