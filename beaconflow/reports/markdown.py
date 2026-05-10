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


def flow_to_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
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
