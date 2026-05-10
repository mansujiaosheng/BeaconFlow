from __future__ import annotations

from typing import Any


def coverage_to_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Coverage Summary",
        "",
        f"- Functions: {summary['covered_functions']} / {summary['total_functions']}",
        f"- Basic blocks: {summary['covered_basic_blocks']} / {summary['total_basic_blocks']}",
        "",
        "## Covered Functions",
        "",
        "| Function | Address | Blocks | Coverage |",
        "| --- | --- | ---: | ---: |",
    ]

    for item in result["covered_functions"][:100]:
        lines.append(
            f"| `{item['name']}` | `{item['start']}` | "
            f"{item['covered_blocks']} / {item['total_blocks']} | {item['coverage_percent']}% |"
        )

    lines.extend(["", "## Uncovered Functions", ""])
    for item in result["uncovered_functions"][:100]:
        lines.append(f"- `{item['name']}` at `{item['start']}`")

    return "\n".join(lines) + "\n"


def deflatten_to_markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    lines = [
        "# BeaconFlow Deflatten Report",
        "",
        "## Summary",
        "",
        f"- Original blocks (with dispatcher): {summary.get('original_blocks', 0)}",
        f"- Dispatcher blocks removed: {summary.get('dispatcher_blocks', 0)}",
        f"- Real blocks (after deflatten): {summary.get('real_blocks', 0)}",
        f"- Real edges: {summary.get('real_edges', 0)}",
        f"- Real branch points: {summary.get('real_branch_points', 0)}",
        f"- Real events in spine: {summary.get('real_events_in_spine', 0)}",
        "",
    ]

    dispatchers = result.get("dispatcher_blocks", [])
    if dispatchers:
        lines.extend(["## Dispatcher Blocks (Removed)", ""])
        for block in dispatchers:
            lines.append(f"- `{block}`")
        lines.append("")

    lines.extend(["## Real Function Order", "", result.get("real_function_order", "<none>"), ""])

    spine = result.get("real_execution_spine", [])
    if spine:
        lines.extend(["## Real Execution Spine (Dispatcher Removed)", ""])
        for index, block in enumerate(spine[:40], start=1):
            lines.append(f"{index}. `{block}`")
        if len(spine) > 40:
            lines.append(f"... {len(spine) - 40} more blocks")
        lines.append("")

    branch_points = result.get("real_branch_points", [])
    if branch_points:
        lines.extend(["## Real Branch Points", ""])
        for item in branch_points:
            succs = ", ".join(f"`{s}`" for s in item["successors"])
            lines.append(f"- `{item['block']}` -> {succs}")
        lines.append("")

    edges = result.get("real_edges", [])
    if edges:
        lines.extend(["## Real Edges (Top 30)", ""])
        for item in edges[:30]:
            lines.append(f"- `{item['from']}` -> `{item['to']}` hits={item['hits']}")
        lines.append("")

    hot_blocks = result.get("real_hot_blocks", [])
    if hot_blocks:
        lines.extend(["## Real Hot Blocks (Top 20)", ""])
        for item in hot_blocks[:20]:
            lines.append(f"- `{item['block']}` hits={item['hits']}")
        lines.append("")

    lines.extend(["## How to Use This Report", ""])
    lines.append("- The **Real Execution Spine** shows the actual control flow without dispatcher noise.")
    lines.append("- The **Real Branch Points** show where the program makes real decisions (if/else, loops).")
    lines.append("- The **Real Edges** show the reconstructed control flow graph (A -> B, not A -> dispatcher -> B).")
    lines.append("- Compare deflatten outputs from multiple inputs to see which branches are input-dependent.")
    lines.append("- For state variable recovery, you need a richer trace (register/memory values).")

    return "\n".join(lines) + "\n"


def flow_to_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    diagnostics = result.get("diagnostics", {})
    ai = result.get("ai_report", {})
    lines = [
        "# BeaconFlow Execution Report",
        "",
        "## Summary",
        "",
        f"- Raw target events: {summary['raw_target_events']}",
        f"- Compressed events: {summary['compressed_events']}",
        f"- Unique blocks: {summary['unique_blocks']}",
        f"- Unique transitions: {summary['unique_transitions']}",
        f"- Functions seen: {summary['functions_seen']}",
        f"- Truncated: {summary['truncated']}",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        "",
        "## Diagnostics",
        "",
        f"- Skipped non-target module events: {diagnostics.get('skipped_non_target_module_events', 0)}",
        f"- Unmapped function events: {diagnostics.get('unmapped_function_events', 0)}",
        f"- Unmapped basic-block events: {diagnostics.get('unmapped_basic_block_events', 0)}",
        "",
        "## AI Guidance",
        "",
    ]

    for item in ai.get("how_to_use", []):
        lines.append(f"- {item}")

    lines.extend(["", "## User Function Order", "", ai.get("user_function_order_text", "<none>"), ""])
    lines.extend(["", "## Full Function Order", "", ai.get("function_order_text", "<none>"), ""])

    lines.extend(["## Execution Spine Preview", ""])
    spine = ai.get("execution_spine_preview", [])
    for index, block in enumerate(spine[:30], start=1):
        lines.append(f"{index}. `{block}`")
    if len(spine) > 30:
        lines.append(f"... {len(spine) - 30} more preview blocks omitted from Markdown report")

    lines.extend(["", "## User Dispatcher Candidates", ""])
    for item in ai.get("user_dispatcher_candidates", []):
        lines.append(
            f"- `{item['block']}` score={item['score']} hits={item['hits']} "
            f"pred={item['observed_predecessors']} succ={item['observed_successors']}"
        )

    lines.extend(["", "## All Dispatcher Candidates", ""])
    for item in ai.get("dispatcher_candidates", []):
        lines.append(
            f"- `{item['block']}` score={item['score']} hits={item['hits']} "
            f"pred={item['observed_predecessors']} succ={item['observed_successors']}"
        )

    lines.extend(["", "## User Branch Points", ""])
    for item in ai.get("user_branch_points", []):
        lines.append(f"- `{item['block']}` -> {', '.join(f'`{x}`' for x in item['observed_successors'])}")

    lines.extend(["", "## User Join Points", ""])
    for item in ai.get("user_join_points", []):
        lines.append(f"- `{item['block']}` <- {', '.join(f'`{x}`' for x in item['observed_predecessors'])}")

    lines.extend(["", "## User Loop-Like Edges", ""])
    for item in ai.get("user_loop_like_edges", []):
        lines.append(f"- `{item['from']}` -> `{item['to']}` hits={item['hits']}")

    lines.extend(["", "## Next Steps", ""])
    for item in ai.get("next_steps", []):
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def flow_diff_to_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    ai = result["ai_report"]
    lines = [
        "# BeaconFlow Flow Diff",
        "",
        "## Summary",
        "",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        f"- Left unique blocks: {summary['left_unique_blocks']}",
        f"- Right unique blocks: {summary['right_unique_blocks']}",
        f"- Only-left blocks: {summary['only_left_blocks']}",
        f"- Only-right blocks: {summary['only_right_blocks']}",
        f"- Only-left edges: {summary['only_left_edges']}",
        f"- Only-right edges: {summary['only_right_edges']}",
        f"- Hit-count deltas: {summary.get('hit_count_deltas', 0)}",
        "",
        "## AI Guidance",
        "",
    ]
    for item in ai.get("how_to_use", []):
        lines.append(f"- {item}")

    lines.extend(["", "## User Only-Right Block Ranges", ""])
    for item in ai.get("user_only_right_block_ranges", []):
        lines.append(f"- `{item['function']}:{item['start']}-{item['end']}` blocks={item['blocks']}")

    lines.extend(["", "## User Only-Left Block Ranges", ""])
    for item in ai.get("user_only_left_block_ranges", []):
        lines.append(f"- `{item['function']}:{item['start']}-{item['end']}` blocks={item['blocks']}")

    lines.extend(["", "## User Only-Right Blocks", ""])
    for item in ai.get("user_only_right_blocks", []):
        lines.append(f"- `{item['function']}:{item['block_start']}`")

    lines.extend(["", "## User Only-Left Blocks", ""])
    for item in ai.get("user_only_left_blocks", []):
        lines.append(f"- `{item['function']}:{item['block_start']}`")

    lines.extend(["", "## User Only-Right Edges", ""])
    for item in ai.get("user_only_right_edges", []):
        lines.append(
            f"- `{item['from']['function']}:{item['from']['block_start']}` -> "
            f"`{item['to']['function']}:{item['to']['block_start']}`"
        )

    lines.extend(["", "## User Only-Left Edges", ""])
    for item in ai.get("user_only_left_edges", []):
        lines.append(
            f"- `{item['from']['function']}:{item['from']['block_start']}` -> "
            f"`{item['to']['function']}:{item['to']['block_start']}`"
        )

    lines.extend(["", "## User Hit-Count Deltas", ""])
    for item in ai.get("user_hit_count_deltas", []):
        lines.append(
            f"- `{item['function']}:{item['block_start']}` "
            f"left={item['left_hits']} right={item['right_hits']} delta={item['delta']}"
        )

    return "\n".join(lines) + "\n"
