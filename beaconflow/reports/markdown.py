from __future__ import annotations

from typing import Any


def _hit_label(result: dict[str, Any]) -> str:
    precision = result.get("summary", {}).get("hit_count_precision", "unknown")
    if precision == "translation-log":
        return "translations"
    return "hits"


def _append_block_context(lines: list[str], item: dict[str, Any], key: str = "block_context") -> None:
    ctx = item.get(key)
    if not isinstance(ctx, dict):
        return
    parts = []
    if ctx.get("instructions"):
        parts.append(f"insn: {', '.join(ctx['instructions'][:5])}")
    if ctx.get("calls"):
        parts.append(f"calls: {', '.join(ctx['calls'][:3])}")
    if ctx.get("strings"):
        parts.append(f"str: {', '.join(repr(s) for s in ctx['strings'][:3])}")
    if ctx.get("constants"):
        parts.append(f"const: {', '.join(str(c) for c in ctx['constants'][:5])}")
    if parts:
        lines.append(f"  - {' | '.join(parts)}")


def _ai_digest_lines(result: dict[str, Any]) -> list[str]:
    digest = result.get("ai_digest")
    if not digest:
        return []
    lines = [
        "## AI Digest",
        "",
        f"- Task: {digest.get('task', '<unknown>')}",
        f"- Confidence: {digest.get('confidence', '<unknown>')}",
    ]
    if digest.get("warnings"):
        lines.append(f"- Warnings: {len(digest.get('warnings', []))}")
    findings = digest.get("top_findings", [])
    if findings:
        lines.extend(["", "### Top Findings"])
        for item in findings[:5]:
            lines.append(f"- `{item.get('evidence_id')}` {item.get('claim')} confidence={item.get('confidence')}")
    actions = digest.get("recommended_actions", [])
    if actions:
        lines.extend(["", "### Recommended Actions"])
        for item in actions[:5]:
            address = f" at `{item.get('address')}`" if item.get("address") else ""
            lines.append(f"- P{item.get('priority')}: {item.get('kind')}{address} - {item.get('reason')}")
    lines.append("")
    return lines


def coverage_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result["summary"]
    lines = [
        "# Coverage Summary",
        "",
        f"- Functions: {summary['covered_functions']} / {summary['total_functions']}",
        f"- Basic blocks: {summary['covered_basic_blocks']} / {summary['total_basic_blocks']}",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    if brief:
        top_covered = sorted(result["covered_functions"], key=lambda x: x["coverage_percent"], reverse=True)[:5]
        lines.extend(["## Top 5 Covered Functions (Brief)", "", "| Function | Address | Coverage |", "| --- | --- | ---: |"])
        for item in top_covered:
            lines.append(f"| `{item['name']}` | `{item['start']}` | {item['coverage_percent']}% |")
        return "\n".join(lines) + "\n"

    lines.extend(["## Covered Functions", "", "| Function | Address | Blocks | Coverage |", "| --- | --- | ---: | ---: |"])

    for item in result["covered_functions"][:100]:
        lines.append(
            f"| `{item['name']}` | `{item['start']}` | "
            f"{item['covered_blocks']} / {item['total_blocks']} | {item['coverage_percent']}% |"
        )

    lines.extend(["", "## Uncovered Functions", ""])
    for item in result["uncovered_functions"][:100]:
        lines.append(f"- `{item['name']}` at `{item['start']}`")

    return "\n".join(lines) + "\n"


def deflatten_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result.get("summary", {})
    lines = [
        "# BeaconFlow Deflatten Report",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    lines.extend([
        "## Summary",
        "",
        f"- Original blocks (with dispatcher): {summary.get('original_blocks', 0)}",
        f"- Dispatcher blocks removed: {summary.get('dispatcher_blocks', 0)}",
        f"- Real blocks (after deflatten): {summary.get('real_blocks', 0)}",
        f"- Real edges: {summary.get('real_edges', 0)}",
        f"- Real branch points: {summary.get('real_branch_points', 0)}",
        f"- Real events in spine: {summary.get('real_events_in_spine', 0)}",
        f"- Dispatcher mode: {summary.get('dispatcher_mode', 'strict')}",
        f"- Trace mode: {summary.get('trace_mode') or '<unknown>'}",
        f"- Hit-count precision: {summary.get('hit_count_precision', '<unknown>')}",
        "",
    ])
    if summary.get("trace_mode") == "in_asm":
        lines.extend([
            "> **Tip**: Using `exec,nochain` trace mode (e.g. `--trace-mode exec,nochain`) provides exact hit counts and more accurate dispatcher identification.",
            "",
        ])
    if brief:
        spine = result.get("real_execution_spine", [])
        if spine:
            lines.extend(["## Execution Spine (Top 10)", ""])
            for index, block in enumerate(spine[:10], start=1):
                lines.append(f"{index}. `{block}`")
            if len(spine) > 10:
                lines.append(f"... {len(spine) - 10} more blocks")
        branch_points = result.get("real_branch_points", [])
        if branch_points:
            lines.extend(["", "## Branch Points", ""])
            for item in branch_points[:5]:
                succs = ", ".join(f"`{s}`" for s in item["successors"])
                lines.append(f"- `{item['block']}` -> {succs}")
                _append_block_context(lines, item)
        return "\n".join(lines) + "\n"

    warnings = result.get("warnings", [])
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    dispatchers = result.get("dispatcher_blocks", [])
    if dispatchers:
        lines.extend(["## Dispatcher Blocks (Removed)", ""])
        for block in dispatchers:
            lines.append(f"- `{block}`")
        lines.append("")

    candidates = result.get("dispatcher_candidates", [])
    if candidates:
        lines.extend(["## Dispatcher Candidates (Top 20)", ""])
        for item in candidates[:20]:
            selected = "selected" if item.get("selected") else "not-selected"
            warning_text = f" warnings={'; '.join(item.get('warnings', []))}" if item.get("warnings") else ""
            lines.append(
                f"- `{item['block']}` {selected} confidence={item.get('confidence')} "
                f"mode={item.get('mode')} score={item.get('score')} hits={item.get('hits')} "
                f"pred={item.get('observed_predecessors')} succ={item.get('observed_successors')}{warning_text}"
            )
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
        hl = _hit_label(result)
        lines.extend(["## Real Edges (Top 30)", ""])
        for item in edges[:30]:
            lines.append(f"- `{item['from']}` -> `{item['to']}` {hl}={item['hits']}")
        lines.append("")

    hot_blocks = result.get("real_hot_blocks", [])
    if hot_blocks:
        hl = _hit_label(result)
        lines.extend(["## Real Hot Blocks (Top 20)", ""])
        for item in hot_blocks[:20]:
            lines.append(f"- `{item['block']}` {hl}={item['hits']}")
        lines.append("")

    lines.extend(["## How to Use This Report", ""])
    lines.append("- The **Real Execution Spine** shows the actual control flow without dispatcher noise.")
    lines.append("- The **Real Branch Points** show where the program makes real decisions (if/else, loops).")
    lines.append("- The **Real Edges** show the reconstructed control flow graph (A -> B, not A -> dispatcher -> B).")
    lines.append("- Compare deflatten outputs from multiple inputs to see which branches are input-dependent.")
    lines.append("- For state variable recovery, you need a richer trace (register/memory values).")

    return "\n".join(lines) + "\n"


def flow_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result["summary"]
    diagnostics = result.get("diagnostics", {})
    ai = result.get("ai_report", {})
    lines = [
        "# BeaconFlow Execution Report",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    lines.extend([
        "## Summary",
        "",
        f"- Raw target events: {summary['raw_target_events']}",
        f"- Compressed events: {summary['compressed_events']}",
        f"- Unique blocks: {summary['unique_blocks']}",
        f"- Unique transitions: {summary['unique_transitions']}",
        f"- Functions seen: {summary['functions_seen']}",
        f"- Truncated: {summary['truncated']}",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        f"- Trace mode: {summary.get('trace_mode') or '<unknown>'}",
        f"- Hit-count precision: {summary.get('hit_count_precision', '<unknown>')}",
        "",
        "## Diagnostics",
        "",
        f"- Skipped non-target module events: {diagnostics.get('skipped_non_target_module_events', 0)}",
        f"- Unmapped function events: {diagnostics.get('unmapped_function_events', 0)}",
        f"- Unmapped basic-block events: {diagnostics.get('unmapped_basic_block_events', 0)}",
        "",
        "## AI Guidance",
        "",
    ])

    if diagnostics.get("hit_count_warning"):
        lines.extend(["## Warnings", "", f"- {diagnostics['hit_count_warning']}", ""])

    for item in ai.get("how_to_use", []):
        lines.append(f"- {item}")

    if brief:
        lines.extend(["", "## Function Order (Brief)", "", ai.get("user_function_order_text", "<none>"), ""])
        spine = ai.get("execution_spine_preview", [])
        if spine:
            lines.extend(["", "## Execution Spine Preview (Top 10)", ""])
            for index, block in enumerate(spine[:10], start=1):
                lines.append(f"{index}. `{block}`")
        branch_pts = ai.get("user_branch_points", [])
        if branch_pts:
            lines.extend(["", "## Branch Points (Top 5)", ""])
            for item in branch_pts[:5]:
                lines.append(f"- `{item['block']}` -> {', '.join(f'`{x}`' for x in item['observed_successors'])}")
                _append_block_context(lines, item)
        return "\n".join(lines) + "\n"

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
        _append_block_context(lines, item)

    lines.extend(["", "## User Branch Points", ""])
    for item in ai.get("user_branch_points", []):
        lines.append(f"- `{item['block']}` -> {', '.join(f'`{x}`' for x in item['observed_successors'])}")
        _append_block_context(lines, item)

    lines.extend(["", "## User Join Points", ""])
    for item in ai.get("user_join_points", []):
        lines.append(f"- `{item['block']}` <- {', '.join(f'`{x}`' for x in item['observed_predecessors'])}")
        _append_block_context(lines, item)

    lines.extend(["", "## User Loop-Like Edges", ""])
    hl = _hit_label(result)
    for item in ai.get("user_loop_like_edges", []):
        lines.append(f"- `{item['from']}` -> `{item['to']}` {hl}={item['hits']}")
        _append_block_context(lines, item, key="from")

    lines.extend(["", "## Next Steps", ""])
    for item in ai.get("next_steps", []):
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def deflatten_merge_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result.get("summary", {})
    lines = [
        "# BeaconFlow Deflatten Merge Report",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    lines.extend([
        "## Summary",
        "",
        f"- Total traces merged: {summary.get('total_traces', 0)}",
        f"- Total real blocks (union): {summary.get('total_real_blocks', 0)}",
        f"- Total real edges (union): {summary.get('total_real_edges', 0)}",
        f"- Total dispatcher blocks: {summary.get('total_dispatcher_blocks', 0)}",
        f"- Total branch points: {summary.get('total_branch_points', 0)}",
        f"- Total merge points: {summary.get('total_merge_points', 0)}",
        f"- Common edges (all traces): {summary.get('common_edges', 0)}",
        f"- Input-dependent edges: {summary.get('input_dependent_edges', 0)}",
        f"- Dispatcher mode: {summary.get('dispatcher_mode', 'strict')}",
        f"- Hit-count precision: {summary.get('hit_count_precision', '<unknown>')}",
        "",
    ])

    warnings = result.get("warnings", [])
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    if brief:
        per_trace = result.get("per_trace_summary", [])
        if per_trace:
            lines.extend(["## Per-Trace Summary", ""])
            lines.append("| Trace | Real Blocks | Real Edges |")
            lines.append("| --- | ---: | ---: |")
            for item in per_trace:
                lines.append(f"| `{item['label']}` | {item['real_blocks']} | {item['real_edges']} |")
            lines.append("")
        input_dep = result.get("input_dependent_path", {})
        input_edges = input_dep.get("edges", [])
        if input_edges:
            lines.extend(["## Input-Dependent Edges (Top 5)", ""])
            for item in input_edges[:5]:
                lines.append(f"- `{item['from']}` -> `{item['to']}` covered_by={item['coverage_ratio']}")
        else:
            lines.extend(["## Input-Dependent Edges", "", "*No input-dependent edges found in the specified address range. This means all traces followed the same path within this range. Try widening the range (--from/--to) or adding more diverse inputs.*", ""])
        return "\n".join(lines) + "\n"

    per_trace = result.get("per_trace_summary", [])
    if per_trace:
        lines.extend(["## Per-Trace Summary", ""])
        lines.append("| Trace | Original | Dispatcher | Real Blocks | Real Edges | Branch Points |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for item in per_trace:
            lines.append(
                f"| `{item['label']}` | {item['original_blocks']} | {item['dispatcher_blocks']} | "
                f"{item['real_blocks']} | {item['real_edges']} | {item['real_branch_points']} |"
            )
        lines.append("")

    dispatchers = result.get("dispatcher_blocks", [])
    if dispatchers:
        lines.extend(["## Dispatcher Blocks (Union)", ""])
        for block in dispatchers[:30]:
            lines.append(f"- `{block}`")
        if len(dispatchers) > 30:
            lines.append(f"... {len(dispatchers) - 30} more dispatcher blocks")
        lines.append("")

    real_cfg = result.get("real_cfg", {})

    branch_points = real_cfg.get("branch_points", [])
    if branch_points:
        lines.extend(["## Branch Points (Real CFG)", ""])
        for item in branch_points:
            succs = ", ".join(f"`{s}`" for s in item["successors"])
            lines.append(f"- `{item['block']}` -> [{succs}] ({item['successor_count']} successors)")
        lines.append("")

    merge_points = real_cfg.get("merge_points", [])
    if merge_points:
        lines.extend(["## Merge Points (Real CFG)", ""])
        for item in merge_points:
            preds = ", ".join(f"`{s}`" for s in item["predecessors"])
            lines.append(f"- `{item['block']}` <- [{preds}] ({item['predecessor_count']} predecessors)")
        lines.append("")

    common_path = result.get("common_path", {})
    common_edges = common_path.get("edges", [])
    hl = _hit_label(result)
    if common_edges:
        lines.extend(["## Common Path (All Traces)", "", f"*{common_path.get('description', '')}*", ""])
        for item in common_edges[:30]:
            lines.append(f"- `{item['from']}` -> `{item['to']}` {hl}={item['total_hits']} covered_by={item['coverage_ratio']}")
        if len(common_edges) > 30:
            lines.append(f"... {len(common_edges) - 30} more common edges")
        lines.append("")

    input_dep = result.get("input_dependent_path", {})
    input_edges = input_dep.get("edges", [])
    if input_edges:
        lines.extend(["## Input-Dependent Path (Key Branches)", "", f"*{input_dep.get('description', '')}*", ""])
        for item in input_edges[:30]:
            lines.append(f"- `{item['from']}` -> `{item['to']}` {hl}={item['total_hits']} covered_by={item['coverage_ratio']}")
        if len(input_edges) > 30:
            lines.append(f"... {len(input_edges) - 30} more input-dependent edges")
        lines.append("")

    edges = real_cfg.get("edges", [])
    if edges:
        lines.extend(["## All Real Edges (Top 30)", ""])
        for item in edges[:30]:
            lines.append(f"- `{item['from']}` -> `{item['to']}` {hl}={item['total_hits']} covered_by={item['coverage_ratio']}")
        lines.append("")

    blocks = real_cfg.get("blocks", [])
    if blocks:
        lines.extend(["## All Real Blocks (Top 30)", ""])
        for item in blocks[:30]:
            lines.append(f"- `{item['block']}` {hl}={item['total_hits']} covered_by={item['coverage_ratio']}")
        lines.append("")

    lines.extend(["## How to Use This Report", ""])
    lines.append("- **Common Path** edges are input-independent; they execute regardless of input.")
    lines.append("- **Input-Dependent Path** edges are the key: they differ between traces and reveal branching logic.")
    lines.append("- **Branch Points** show where the program makes decisions; cross-reference with input-dependent edges.")
    lines.append("- **Merge Points** show where different paths converge; useful for understanding loop/function exits.")
    lines.append("- Use `flow-diff` for detailed two-trace comparison; use `deflatten-merge` for multi-trace overview.")

    return "\n".join(lines) + "\n"


def state_transitions_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result.get("summary", {})
    ai = result.get("ai_interpretation", {})
    lines = [
        "# BeaconFlow State Transition Recovery",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    lines.extend([
        "## Summary",
        "",
        f"- Total traces: {summary.get('total_traces', 0)}",
        f"- Total real blocks: {summary.get('total_real_blocks', 0)}",
        f"- Total dispatcher blocks: {summary.get('total_dispatcher_blocks', 0)}",
        f"- Total state transitions: {summary.get('total_state_transitions', 0)}",
        f"- Deterministic transitions: {summary.get('deterministic_transitions', 0)}",
        f"- Input-dependent transitions: {summary.get('input_dependent_transitions', 0)}",
        f"- Branch blocks (multi-successor): {summary.get('branch_blocks', 0)}",
        f"- Dispatcher mode: {summary.get('dispatcher_mode', 'strict')}",
        f"- Hit-count precision: {summary.get('hit_count_precision', '<unknown>')}",
        "",
    ])

    warnings = result.get("warnings", [])
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    if brief:
        inp = result.get("input_dependent_transitions", [])
        if inp:
            lines.extend(["## Input-Dependent Transitions (Top 5)", ""])
            for item in inp[:5]:
                lines.append(f"- `{item['from_block']}` -> `{item['to_block']}` ratio={item['coverage_ratio']}")
        else:
            lines.extend(["## Input-Dependent Transitions", "", "*No input-dependent transitions found. All branches in the specified range are deterministic (same path regardless of input). Try widening the range (--from/--to) or using more diverse inputs.*", ""])
        return "\n".join(lines) + "\n"

    branch_blocks = result.get("branch_blocks", [])
    if branch_blocks:
        lines.extend(["## Branch Blocks (State Variable Decision Points)", ""])
        for bb in branch_blocks:
            lines.append(f"### `{bb['block']}` ({bb['successor_count']} successors, {bb['type']})")
            for succ in bb["successors"]:
                lines.append(f"- -> `{succ['block']}` covered_by={succ['coverage_ratio']} traces={succ['covered_by']}")
            lines.append("")

    det = result.get("deterministic_transitions", [])
    if det:
        lines.extend(["## Deterministic Transitions (State Variable = Constant)", ""])
        lines.append("*After these real blocks, the dispatcher always jumps to the same next block.*")
        lines.append("")
        for item in det[:30]:
            lines.append(f"- `{item['from_block']}` -> `{item['to_block']}` ratio={item['coverage_ratio']}")
        if len(det) > 30:
            lines.append(f"... {len(det) - 30} more deterministic transitions")
        lines.append("")

    inp = result.get("input_dependent_transitions", [])
    if inp:
        lines.extend(["## Input-Dependent Transitions (State Variable = Branch Condition)", ""])
        lines.append("*After these real blocks, the dispatcher jumps to different blocks depending on input. The state variable is set by a conditional branch.*")
        lines.append("")
        for item in inp[:30]:
            lines.append(f"- `{item['from_block']}` -> `{item['to_block']}` ratio={item['coverage_ratio']} traces={item['observed_in_traces']}")
        if len(inp) > 30:
            lines.append(f"... {len(inp) - 30} more input-dependent transitions")
        lines.append("")

    table = result.get("state_transition_table", [])
    if table:
        lines.extend(["## State Transition Table", ""])
        for row in table:
            lines.append(f"### `{row['block']}`")
            for target, info in row["transitions"].items():
                lines.append(f"  -> `{target}`: traces={info['traces']} ratio={info['ratio']}")
            lines.append("")

    lines.extend(["## AI Interpretation", ""])
    for item in ai.get("how_to_read", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.extend(["## Next Steps", ""])
    for item in ai.get("next_steps", []):
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def branch_rank_to_markdown(result: dict[str, Any], top: int = 10, brief: bool = False) -> str:
    summary = result.get("summary", {})
    ai = result.get("ai_interpretation", {})
    lines = [
        "# BeaconFlow Branch Rank",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    lines.extend([
        "## Summary",
        "",
        f"- Total traces: {summary.get('total_traces', 0)}",
        f"- Baseline: `{summary.get('baseline', '<none>')}`",
        f"- Ranked branch points: {summary.get('ranked_branch_points', 0)}",
        f"- Showing top: {top}",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        f"- Hit-count precision: {summary.get('hit_count_precision', '<unknown>')}",
        "",
        "## Traces",
        "",
        "| Trace | Role | Blocks | Transitions |",
        "| --- | --- | ---: | ---: |",
    ])

    warnings = result.get("warnings", [])
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    for trace in result.get("traces", []):
        lines.append(
            f"| `{trace['label']}` | `{trace['role']}` | "
            f"{trace['unique_blocks']} | {trace['unique_transitions']} |"
        )

    if brief:
        branches = result.get("ranked_branches", [])
        if branches:
            lines.extend(["", "## Top Ranked Branches", ""])
            for index, branch in enumerate(branches[:top], start=1):
                lines.append(
                    f"{index}. `{branch['block']}` score={branch['score']} "
                    f"succ={branch['successor_count']} new_vs_baseline={branch['new_successors_vs_baseline']}"
                )
        return "\n".join(lines) + "\n"

    branches = result.get("ranked_branches", [])
    if branches:
        lines.extend(["", "## Ranked Branches", ""])
        for index, branch in enumerate(branches[:top], start=1):
            why = "; ".join(branch.get("why", [])) or "path evidence changed"
            lines.append(
                f"{index}. `{branch['block']}` score={branch['score']} "
                f"succ={branch['successor_count']} new_vs_baseline={branch['new_successors_vs_baseline']} "
                f"hit_spread={branch['hit_spread']}"
            )
            lines.append(f"   - Why: {why}")
            hl = _hit_label(result)
            hits = ", ".join(f"{label}={hits}" for label, hits in branch.get("hits_by_trace", {}).items())
            if hits:
                lines.append(f"   - {hl.capitalize()}: {hits}")
            for edge in branch.get("outgoing_edges", [])[:6]:
                baseline = "baseline" if edge.get("baseline_edge") else "new"
                lines.append(f"   - -> `{edge['to']}` {baseline} covered_by={edge['coverage_ratio']} traces={edge['covered_by']}")
        if len(branches) > top:
            lines.append(f"... {len(branches) - top} more ranked branches (use --top to show more)")

    lines.extend(["", "## AI Interpretation", ""])
    for item in ai.get("how_to_use", []):
        lines.append(f"- {item}")
    lines.extend(["", "## Next Steps", ""])
    for item in ai.get("next_steps", []):
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def flow_diff_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result["summary"]
    ai = result["ai_report"]
    only_left = summary.get('only_left_blocks', 0)
    only_right = summary.get('only_right_blocks', 0)
    left_label = summary.get('left_label', 'left')
    right_label = summary.get('right_label', 'right')
    diff_summary = f"Diff: {right_label} has {only_right} unique blocks, {left_label} has {only_left} unique blocks."
    if only_right > 0:
        focus_fn = summary.get('focus_function') or ''
        diff_summary += f" Focus on {right_label}-only blocks to understand the different execution path."
        if focus_fn:
            diff_summary += f" (focus: {focus_fn})"
    lines = [
        "# BeaconFlow Flow Diff",
        "",
        f"> **{diff_summary}**",
        "",
    ]
    lines.extend(_ai_digest_lines(result))
    lines.extend([
        "## Summary",
        "",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        f"- Left unique blocks: {summary['left_unique_blocks']}",
        f"- Right unique blocks: {summary['right_unique_blocks']}",
        f"- Only-left blocks: {only_left}",
        f"- Only-right blocks: {only_right}",
        f"- Only-left edges: {summary['only_left_edges']}",
        f"- Only-right edges: {summary['only_right_edges']}",
        f"- Hit-count deltas: {summary.get('hit_count_deltas', 0)}",
        "",
        "## AI Guidance",
        "",
    ])
    for item in ai.get("how_to_use", []):
        lines.append(f"- {item}")

    if brief:
        only_right_ranges = ai.get("user_only_right_block_ranges", [])
        if only_right_ranges:
            lines.extend(["", "## Only-Right Block Ranges (Top 5)", ""])
            for item in only_right_ranges[:5]:
                lines.append(f"- `{item['function']}:{item['start']}-{item['end']}` blocks={item['blocks']}")
        only_left_ranges = ai.get("user_only_left_block_ranges", [])
        if only_left_ranges:
            lines.extend(["", "## Only-Left Block Ranges (Top 5)", ""])
            for item in only_left_ranges[:5]:
                lines.append(f"- `{item['function']}:{item['start']}-{item['end']}` blocks={item['blocks']}")
        return "\n".join(lines) + "\n"

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


def decision_points_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result.get("summary", {})
    decision_points = result.get("decision_points", [])
    lines = [
        "# BeaconFlow Decision Points",
        "",
        f"- Total decision points: {summary.get('total', 0)}",
        f"- Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | Medium: {summary.get('medium', 0)} | Low: {summary.get('low', 0)}",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        "",
    ]

    priority_order = ["critical", "high", "medium", "low"]
    for priority in priority_order:
        items = [dp for dp in decision_points if dp["ai_priority"] == priority]
        if not items:
            continue
        if brief and priority in ("medium", "low") and summary.get("critical", 0) + summary.get("high", 0) > 0:
            continue
        lines.append(f"## {priority.upper()} Priority ({len(items)})")
        lines.append("")
        for dp in items[:20 if not brief else 5]:
            lines.append(f"- `{dp['function']}:{dp['address']}` type=`{dp['type']}`")
            if dp.get("call_instruction"):
                lines.append(f"  - call: `{dp['call_instruction']}()`")
            if dp.get("compare_instruction"):
                lines.append(f"  - compare: `{dp['compare_instruction']}`")
            if dp.get("branch_instruction"):
                lines.append(f"  - branch: `{dp['branch_instruction']}`")
            lines.append(f"  - reason: {dp['reason']}")
            if dp.get("successors"):
                lines.append(f"  - successors: {', '.join(f'`{s}`' for s in dp['successors'])}")
            if dp.get("taken"):
                lines.append(f"  - taken: `{dp['taken']}`")
        if len(items) > (20 if not brief else 5):
            lines.append(f"... {len(items) - (20 if not brief else 5)} more {priority} priority points")
        lines.append("")

    return "\n".join(lines) + "\n"


def roles_to_markdown(result: dict[str, Any], brief: bool = False) -> str:
    summary = result.get("summary", {})
    candidates = result.get("candidates", [])
    lines = [
        "# BeaconFlow Candidate Role Detection",
        "",
        f"- Total candidates: {summary.get('total', 0)}",
        f"- High confidence: {summary.get('confidence', {}).get('high', 0)} | Medium: {summary.get('confidence', {}).get('medium', 0)} | Low: {summary.get('confidence', {}).get('low', 0)}",
        f"- Focus function: {summary.get('focus_function') or '<none>'}",
        "",
    ]

    roles_found = summary.get("roles", {})
    if roles_found:
        lines.append("## Roles Summary")
        lines.append("")
        for role, count in sorted(roles_found.items(), key=lambda x: -x[1]):
            lines.append(f"- `{role}`: {count} function(s)")
        lines.append("")

    confidence_order = ["high", "medium", "low"]
    for conf in confidence_order:
        items = [c for c in candidates if c["confidence"] == conf]
        if not items:
            continue
        if brief and conf == "low" and (summary.get("confidence", {}).get("high", 0) + summary.get("confidence", {}).get("medium", 0)) > 0:
            continue
        lines.append(f"## {conf.upper()} Confidence ({len(items)})")
        lines.append("")
        for c in items[:20 if not brief else 10]:
            lines.append(f"### `{c['function']}` → `{c['role']}` (score: {c['score']})")
            lines.append("")
            if c.get("evidence"):
                for ev in c["evidence"][:5]:
                    lines.append(f"- {ev}")
            if c.get("recommended_actions"):
                lines.append("")
                lines.append("**Recommended actions:**")
                for act in c["recommended_actions"][:3]:
                    lines.append(f"- {act}")
            lines.append("")

    return "\n".join(lines) + "\n"
