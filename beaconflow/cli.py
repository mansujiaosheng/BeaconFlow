from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from beaconflow.analysis import analyze_coverage, analyze_decision_points, analyze_flow, analyze_roles, analyze_value_trace, deflatten_flow, deflatten_merge, diff_coverage, diff_flow, find_decision_points, inspect_decision_point, inspect_role, rank_input_branches, recover_state_transitions
from beaconflow.analysis.ai_digest import attach_ai_digest, compact_report, infer_report_kind
from beaconflow.coverage import collect_qemu_trace, load_address_log, load_drcov, qemu_available
from beaconflow.coverage.runner import collect_drcov
from beaconflow.ghidra import export_ghidra_metadata, find_ghidra_headless
from beaconflow.ida import load_metadata, save_metadata
from beaconflow.metadata import build_trace_metadata
from beaconflow.models import hex_addr
from beaconflow.reports import branch_rank_to_markdown, coverage_to_markdown, decision_points_to_markdown, deflatten_merge_to_markdown, deflatten_to_markdown, flow_diff_to_markdown, flow_to_markdown, roles_to_markdown, state_transitions_to_markdown, value_trace_to_markdown


def _fmt_markdown(fmt_choice: str, md_func, result, **kwargs) -> str:
    brief = fmt_choice == "markdown-brief"
    if fmt_choice in ("markdown", "markdown-brief"):
        return md_func(result, brief=brief, **kwargs)
    return json.dumps(result, indent=2)


def _cmd_analyze(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    coverage = load_drcov(args.coverage)
    result = analyze_coverage(metadata, coverage)
    text = _fmt_markdown(args.format, coverage_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    left = load_drcov(args.left)
    right = load_drcov(args.right)
    print(json.dumps(diff_coverage(metadata, left, right), indent=2))
    return 0


def _cmd_flow(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    coverage = _load_flow_input(args)
    address_start, address_end = _resolve_address_range(args, metadata)
    result = analyze_flow(
        metadata, coverage,
        max_events=args.max_events,
        focus_function=args.focus_function,
        address_start=address_start,
        address_end=address_end,
    )
    text = _fmt_markdown(args.format, flow_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_flow_diff(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    left = _load_address_log_arg(args.left_address_log, args) if args.left_address_log else load_drcov(args.left)
    right = _load_address_log_arg(args.right_address_log, args) if args.right_address_log else load_drcov(args.right)
    address_start, address_end = _resolve_address_range(args, metadata)
    result = diff_flow(
        metadata, left, right,
        focus_function=args.focus_function,
        address_start=address_start,
        address_end=address_end,
    )
    text = _fmt_markdown(args.format, flow_diff_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_deflatten(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    coverage = _load_flow_input(args)
    address_start, address_end = _resolve_address_range(args, metadata)
    result = deflatten_flow(
        metadata, coverage,
        focus_function=args.focus_function,
        address_start=address_start,
        address_end=address_end,
        dispatcher_min_hits=args.dispatcher_min_hits,
        dispatcher_min_pred=args.dispatcher_min_pred,
        dispatcher_min_succ=args.dispatcher_min_succ,
        dispatcher_mode=args.dispatcher_mode,
    )
    text = _fmt_markdown(args.format, deflatten_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_deflatten_merge(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    if args.address_log:
        coverages = [
            _load_address_log_arg(p, args) for p in args.address_log
        ]
    else:
        coverages = [load_drcov(p) for p in args.coverage]
    labels = args.label if args.label else None
    address_start, address_end = _resolve_address_range(args, metadata)
    result = deflatten_merge(
        metadata, coverages,
        labels=labels,
        focus_function=args.focus_function,
        address_start=address_start,
        address_end=address_end,
        dispatcher_min_hits=args.dispatcher_min_hits,
        dispatcher_min_pred=args.dispatcher_min_pred,
        dispatcher_min_succ=args.dispatcher_min_succ,
        dispatcher_mode=args.dispatcher_mode,
    )
    text = _fmt_markdown(args.format, deflatten_merge_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_recover_state(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    if args.address_log:
        coverages = [
            _load_address_log_arg(p, args) for p in args.address_log
        ]
    else:
        coverages = [load_drcov(p) for p in args.coverage]
    labels = args.label if args.label else None
    address_start, address_end = _resolve_address_range(args, metadata)
    result = recover_state_transitions(
        metadata, coverages,
        labels=labels,
        focus_function=args.focus_function,
        address_start=address_start,
        address_end=address_end,
        dispatcher_min_hits=args.dispatcher_min_hits,
        dispatcher_min_pred=args.dispatcher_min_pred,
        dispatcher_min_succ=args.dispatcher_min_succ,
        dispatcher_mode=args.dispatcher_mode,
    )
    text = _fmt_markdown(args.format, state_transitions_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_branch_rank(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    coverages = []
    labels = []
    roles = []

    if args.bad_address_log:
        coverages.append(_load_address_log_path(args.bad_address_log, args))
    else:
        coverages.append(load_drcov(args.bad))
    labels.append(args.bad_label or "bad")
    roles.append("bad")

    better_inputs = args.better_address_log or args.better or []
    for index, path in enumerate(better_inputs):
        if args.better_address_log:
            coverages.append(_load_address_log_path(path, args))
        else:
            coverages.append(load_drcov(path))
        labels.append((args.better_label or [])[index] if args.better_label and index < len(args.better_label) else f"better{index}")
        roles.append("better")

    good_inputs = args.good_address_log or args.good or []
    for index, path in enumerate(good_inputs):
        if args.good_address_log:
            coverages.append(_load_address_log_path(path, args))
        else:
            coverages.append(load_drcov(path))
        labels.append((args.good_label or [])[index] if args.good_label and index < len(args.good_label) else f"good{index}")
        roles.append("good")

    address_start, address_end = _resolve_address_range(args, metadata)
    result = rank_input_branches(
        metadata,
        coverages,
        labels=labels,
        roles=roles,
        focus_function=args.focus_function,
        address_start=address_start,
        address_end=address_end,
    )
    text = _fmt_markdown(args.format, branch_rank_to_markdown, result, top=args.top)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_inspect_block(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address)
    for func in metadata.functions:
        for block in func.blocks:
            if block.start == addr:
                result = {
                    "function": func.name,
                    "function_start": hex_addr(func.start),
                    "block_start": hex_addr(block.start),
                    "block_end": hex_addr(block.end),
                    "successors": [hex_addr(s) for s in block.succs],
                    "context": block.context.to_json(),
                }
                if args.format == "markdown":
                    text = _inspect_block_to_markdown(result)
                else:
                    text = json.dumps(result, indent=2)
                print(text)
                return 0
    print(f"Block at {hex_addr(addr)} not found in metadata.", file=sys.stderr)
    return 1


def _cmd_inspect_function(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    target_func = None
    if args.name:
        for func in metadata.functions:
            if func.name == args.name:
                target_func = func
                break
    elif args.address:
        addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address)
        for func in metadata.functions:
            if func.start == addr:
                target_func = func
                break
    else:
        print("Either --name or --address is required.", file=sys.stderr)
        return 1

    if target_func is None:
        print(f"Function not found in metadata.", file=sys.stderr)
        return 1

    blocks_data = []
    for block in target_func.blocks:
        blocks_data.append({
            "start": hex_addr(block.start),
            "end": hex_addr(block.end),
            "successors": [hex_addr(s) for s in block.succs],
            "context": block.context.to_json(),
        })

    result = {
        "name": target_func.name,
        "start": hex_addr(target_func.start),
        "end": hex_addr(target_func.end),
        "block_count": len(target_func.blocks),
        "blocks": blocks_data,
    }
    if args.format == "markdown":
        text = _inspect_function_to_markdown(result)
    else:
        text = json.dumps(result, indent=2)
    print(text)
    return 0


def _cmd_find_decision_points(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    result = analyze_decision_points(metadata, focus_function=args.focus_function)
    text = _fmt_markdown(args.format, decision_points_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_inspect_decision_point(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address)
    result = inspect_decision_point(metadata, addr)
    if result is None:
        print(f"No decision point found at {hex_addr(addr)}.", file=sys.stderr)
        return 1
    if args.format == "markdown":
        text = _inspect_decision_point_to_markdown(result)
    else:
        text = json.dumps(result, indent=2)
    print(text)
    return 0


def _inspect_decision_point_to_markdown(dp: dict[str, Any]) -> str:
    lines = [
        f"# Decision Point `{dp['address']}`",
        "",
        f"- Function: `{dp['function']}`",
        f"- Type: `{dp['type']}`",
        f"- AI Priority: `{dp['ai_priority']}`",
        f"- Reason: {dp['reason']}",
        "",
    ]
    if dp.get("call_instruction"):
        lines.append(f"- Call: `{dp['call_instruction']}()`")
    if dp.get("compare_instruction"):
        lines.append(f"- Compare: `{dp['compare_instruction']}`")
    if dp.get("branch_instruction"):
        lines.append(f"- Branch: `{dp['branch_instruction']}`")
    if dp.get("successors"):
        lines.append(f"- Successors: {', '.join(f'`{s}`' for s in dp['successors'])}")
    if dp.get("taken"):
        lines.append(f"- Taken: `{dp['taken']}`")
    if dp.get("fallthrough"):
        lines.append(f"- Fallthrough: `{dp['fallthrough']}`")
    if dp.get("target"):
        lines.append(f"- Target: `{dp['target']}`")
    lines.append("")
    ctx = dp.get("related_block_context")
    if ctx and isinstance(ctx, dict):
        lines.append("## Related Block Context")
        lines.append("")
        if ctx.get("instructions"):
            lines.append("### Instructions")
            lines.append("```")
            for insn in ctx["instructions"]:
                lines.append(insn)
            lines.append("```")
            lines.append("")
        if ctx.get("calls"):
            lines.append(f"### Calls: {', '.join(f'`{c}`' for c in ctx['calls'])}")
            lines.append("")
        if ctx.get("strings"):
            lines.append(f"### Strings: {', '.join(repr(s) for s in ctx['strings'])}")
            lines.append("")
        if ctx.get("constants"):
            lines.append(f"### Constants: {', '.join(f'`{c}`' for c in ctx['constants'])}")
            lines.append("")
    return "\n".join(lines) + "\n"


def _cmd_detect_roles(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    result = analyze_roles(
        metadata,
        rules_path=args.rules,
        focus_function=args.focus_function,
        min_score=args.min_score,
    )
    text = _fmt_markdown(args.format, roles_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_trace_values(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    executed_addrs = None
    if args.coverage:
        coverage = load_drcov(args.coverage)
        executed_addrs = set()
        for block in coverage.blocks:
            if block.absolute_start is not None:
                executed_addrs.add(block.absolute_start)
    elif args.address_log:
        addr_log = _load_address_log_path(args.address_log, args)
        executed_addrs = set()
        for block in addr_log.blocks:
            if block.absolute_start is not None:
                executed_addrs.add(block.absolute_start)
    result = analyze_value_trace(
        metadata,
        executed_addrs=executed_addrs,
        focus_function=args.focus_function,
    )
    text = _fmt_markdown(args.format, value_trace_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_inspect_role(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    addr = None
    if args.address:
        addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address)
    result = inspect_role(metadata, function_name=args.name, address=addr, rules_path=args.rules)
    if result is None:
        print("No role detected for the specified function.", file=sys.stderr)
        return 1
    if args.format == "markdown":
        text = _inspect_role_to_markdown(result)
    else:
        text = json.dumps(result, indent=2)
    print(text)
    return 0


def _inspect_role_to_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# Role: `{result['role']}` for `{result['function']}`",
        "",
        f"- Address: `{result['address']}`",
        f"- Confidence: `{result['confidence']}`",
        f"- Score: {result['score']}",
        "",
    ]
    if result.get("evidence"):
        lines.append("## Evidence")
        lines.append("")
        for ev in result["evidence"]:
            lines.append(f"- {ev}")
        lines.append("")
    if result.get("matched_rules"):
        lines.append(f"## Matched Rules: {', '.join(f'`{r}`' for r in result['matched_rules'])}")
        lines.append("")
    if result.get("recommended_actions"):
        lines.append("## Recommended Actions")
        lines.append("")
        for act in result["recommended_actions"]:
            lines.append(f"- {act}")
        lines.append("")
    if result.get("related_blocks"):
        lines.append(f"## Related Blocks: {', '.join(f'`{b}`' for b in result['related_blocks'])}")
        lines.append("")
    if result.get("related_decision_points"):
        lines.append(f"## Related Decision Points: {', '.join(f'`{d}`' for d in result['related_decision_points'])}")
        lines.append("")
    if result.get("related_io_sites"):
        lines.append(f"## Related I/O Sites: {', '.join(f'`{i}`' for i in result['related_io_sites'])}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _inspect_block_to_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# Block `{result['block_start']}`",
        "",
        f"- Function: `{result['function']}` (starts at `{result['function_start']}`)",
        f"- Range: `{result['block_start']}` - `{result['block_end']}`",
        f"- Successors: {', '.join(f'`{s}`' for s in result['successors']) or '<none>'}",
        "",
    ]
    ctx = result.get("context", {})
    if ctx:
        lines.append("## Context")
        lines.append("")
        if ctx.get("instructions"):
            lines.append("### Instructions")
            lines.append("```")
            for insn in ctx["instructions"]:
                lines.append(insn)
            lines.append("```")
            lines.append("")
        if ctx.get("calls"):
            lines.append(f"### Calls: {', '.join(f'`{c}`' for c in ctx['calls'])}")
            lines.append("")
        if ctx.get("strings"):
            lines.append(f"### Strings: {', '.join(repr(s) for s in ctx['strings'])}")
            lines.append("")
        if ctx.get("constants"):
            lines.append(f"### Constants: {', '.join(f'`{c}`' for c in ctx['constants'])}")
            lines.append("")
        if ctx.get("data_refs"):
            lines.append(f"### Data Refs: {', '.join(f'`{r}`' for r in ctx['data_refs'])}")
            lines.append("")
        if ctx.get("code_refs"):
            lines.append(f"### Code Refs: {', '.join(f'`{r}`' for r in ctx['code_refs'])}")
            lines.append("")
        if ctx.get("predecessors"):
            lines.append(f"### Predecessors: {', '.join(f'`{p}`' for p in ctx['predecessors'])}")
            lines.append("")
        if ctx.get("successors"):
            lines.append(f"### Successors: {', '.join(f'`{s}`' for s in ctx['successors'])}")
            lines.append("")
    else:
        lines.append("*No context available (re-export metadata with context enabled).*")
    return "\n".join(lines) + "\n"


def _inspect_function_to_markdown(result: dict[str, Any]) -> str:
    lines = [
        f"# Function `{result['name']}`",
        "",
        f"- Range: `{result['start']}` - `{result['end']}`",
        f"- Blocks: {result['block_count']}",
        "",
        "## Blocks",
        "",
    ]
    for block in result["blocks"]:
        lines.append(f"### `{block['start']}` - `{block['end']}`")
        lines.append(f"- Successors: {', '.join(f'`{s}`' for s in block['successors']) or '<none>'}")
        ctx = block.get("context", {})
        if ctx:
            parts = []
            if ctx.get("instructions"):
                parts.append(f"insn: {', '.join(ctx['instructions'][:5])}")
            if ctx.get("calls"):
                parts.append(f"calls: {', '.join(f'`{c}`' for c in ctx['calls'][:3])}")
            if ctx.get("strings"):
                parts.append(f"str: {', '.join(repr(s) for s in ctx['strings'][:3])}")
            if ctx.get("constants"):
                parts.append(f"const: {', '.join(f'`{c}`' for c in ctx['constants'][:5])}")
            if parts:
                lines.append(f"- Context: {' | '.join(parts)}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _cmd_ai_summary(args: argparse.Namespace) -> int:
    result = json.loads(Path(args.input).read_text(encoding="utf-8"))
    kind = args.kind or infer_report_kind(result)
    compact = compact_report(kind, result, max_findings=args.max_findings)
    text = _ai_summary_to_markdown(compact) if args.format == "markdown" else json.dumps(compact, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _ai_summary_to_markdown(result: dict) -> str:
    digest = result.get("ai_digest", {})
    quality = result.get("data_quality", {})
    lines = [
        "# BeaconFlow AI Summary",
        "",
        "## Digest",
        "",
        f"- Task: {digest.get('task', '<unknown>')}",
        f"- Confidence: {digest.get('confidence', '<unknown>')}",
        f"- Hit-count precision: {quality.get('hit_count_precision', '<unknown>')}",
        f"- Mapping ratio: {quality.get('mapping_ratio') if quality.get('mapping_ratio') is not None else '<unknown>'}",
        "",
    ]
    warnings = digest.get("warnings", [])
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    findings = digest.get("top_findings", [])
    if findings:
        lines.extend(["## Top Findings", ""])
        for item in findings:
            lines.append(f"- `{item.get('evidence_id')}` {item.get('claim')} confidence={item.get('confidence')}")
        lines.append("")
    actions = digest.get("recommended_actions", [])
    if actions:
        lines.extend(["## Recommended Actions", ""])
        for item in actions:
            address = f" at `{item.get('address')}`" if item.get("address") else ""
            lines.append(f"- P{item.get('priority')}: {item.get('kind')}{address} - {item.get('reason')}")
    return "\n".join(lines) + "\n"


def _load_flow_input(args: argparse.Namespace):
    if args.address_log:
        return _load_address_log_arg(args.address_log, args)
    return load_drcov(args.coverage)


def _load_address_log_arg(path: str, args: argparse.Namespace):
    return _load_address_log_path(path, args)


def _load_address_log_path(path: str, args: argparse.Namespace):
    return load_address_log(
        path,
        block_size=args.block_size,
        min_address=_parse_optional_int(args.address_min),
        max_address=_parse_optional_int(args.address_max),
    )


def _parse_optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _resolve_address_range(args: argparse.Namespace, metadata):
    """将 --from/--to 参数（函数名或地址）解析为 address_start/address_end 整数。"""
    from beaconflow.analysis.flow import _resolve_function_address, _resolve_function_end
    address_start = None
    address_end = None
    from_val = getattr(args, "from_", None)
    to_val = getattr(args, "to", None)
    if from_val:
        address_start = _resolve_function_address(metadata, from_val)
        if address_start is None:
            address_start = _parse_optional_int(from_val)
    if to_val:
        address_end = _resolve_function_end(metadata, to_val)
        if address_end is None:
            address_end = _parse_optional_int(to_val)
    return address_start, address_end


def _cmd_metadata_from_address_log(args: argparse.Namespace) -> int:
    coverage = _load_many_address_logs(args.address_log, args)
    metadata = build_trace_metadata(
        coverage,
        input_path=args.input_path or args.address_log[0],
        image_base=_parse_optional_int(args.image_base) or 0,
        gap=_parse_optional_int(args.gap) or 0x100,
        name_prefix=args.name_prefix,
    )
    save_metadata(metadata, args.output)
    print(
        json.dumps(
            {
                "output": args.output,
                "events": len(coverage.blocks),
                "functions": len(metadata.functions),
                "basic_blocks": sum(len(function.blocks) for function in metadata.functions),
            },
            indent=2,
        )
    )
    return 0


def _load_many_address_logs(paths: list[str], args: argparse.Namespace):
    merged = load_address_log(
        paths[0],
        block_size=args.block_size,
        min_address=_parse_optional_int(args.address_min),
        max_address=_parse_optional_int(args.address_max),
    )
    for path in paths[1:]:
        extra = load_address_log(
            path,
            block_size=args.block_size,
            min_address=_parse_optional_int(args.address_min),
            max_address=_parse_optional_int(args.address_max),
        )
        merged.blocks.extend(extra.blocks)
    return merged


def _cmd_collect(args: argparse.Namespace) -> int:
    stdin_text = _read_stdin_arg(args)
    result = collect_drcov(
        target=args.target,
        target_args=args.target_args,
        output_dir=args.output_dir,
        arch=args.arch,
        drrun_path=args.drrun,
        stdin_text=stdin_text,
        run_cwd=args.run_cwd,
        timeout=args.timeout,
        name=getattr(args, "name", None),
    )
    print(json.dumps(result.to_json(), indent=2))
    return 0


def _cmd_record_flow(args: argparse.Namespace) -> int:
    stdin_text = _read_stdin_arg(args)
    run_result = collect_drcov(
        target=args.target,
        target_args=args.target_args,
        output_dir=args.output_dir,
        arch=args.arch,
        drrun_path=args.drrun,
        stdin_text=stdin_text,
        run_cwd=args.run_cwd,
        timeout=getattr(args, "timeout", 120),
    )
    metadata = load_metadata(args.metadata)
    result = analyze_flow(
        metadata,
        load_drcov(run_result.log_path),
        max_events=args.max_events,
        focus_function=args.focus_function,
    )
    result["coverage_path"] = str(run_result.log_path)
    text = _fmt_markdown(args.format, flow_to_markdown, result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_collect_qemu(args: argparse.Namespace) -> int:
    result = collect_qemu_trace(
        target=args.target,
        output_dir=args.output_dir,
        qemu_arch=args.qemu_arch,
        target_args=args.target_args,
        stdin_text=_read_stdin_arg(args),
        run_cwd=args.run_cwd,
        trace_mode=args.trace_mode,
        qemu_path=args.qemu,
        timeout=args.timeout,
        name=args.name,
    )
    print(json.dumps(result.to_json(), indent=2))
    return 0


def _cmd_export_ghidra(args: argparse.Namespace) -> int:
    result = export_ghidra_metadata(
        target=args.target,
        output=args.output,
        ghidra_path=args.ghidra_path,
        project_dir=args.project_dir,
        script_path=args.script_path,
        timeout=args.timeout,
        backend=args.backend,
        with_context=not args.no_context,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_qemu_explore(args: argparse.Namespace) -> int:
    inputs = _explore_inputs(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    total = len(inputs)
    max_workers = min(total, getattr(args, "jobs", 0) or total)

    def _run_one(index: int, stdin_text: str | None) -> dict:
        name = f"case{index:03d}"
        print(f"[qemu-explore] Running {name} ({index + 1}/{total}): stdin={_preview(stdin_text, 40)}", flush=True)
        result = collect_qemu_trace(
            target=args.target,
            output_dir=output_dir,
            qemu_arch=args.qemu_arch,
            target_args=args.target_args,
            stdin_text=stdin_text,
            run_cwd=args.run_cwd,
            trace_mode=args.trace_mode,
            qemu_path=args.qemu,
            timeout=args.timeout,
            name=name,
        )
        verdict = _classify_run(result.stdout, result.stderr, result.returncode, args)
        print(f"[qemu-explore] {name} done: rc={result.returncode} verdict={verdict} stdout={_preview(result.stdout, 60)}", flush=True)
        return {"name": name, "stdin": stdin_text, "qemu": result, "index": index}

    runs: list[dict] = [None] * total  # type: ignore[list-item]
    if max_workers > 1:
        print(f"[qemu-explore] Running {total} inputs with {max_workers} parallel workers...", flush=True)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_run_one, i, stdin): i for i, stdin in enumerate(inputs)}
            for future in as_completed(futures):
                item = future.result()
                runs[item.pop("index")] = item
    else:
        for index, stdin_text in enumerate(inputs):
            item = _run_one(index, stdin_text)
            item.pop("index")
            runs[index] = item

    log_paths = [str(item["qemu"].log_path) for item in runs]

    print(f"[qemu-explore] Building metadata from {len(log_paths)} trace logs...", flush=True)
    metadata = build_trace_metadata(
        _load_address_logs_for_paths(log_paths, args),
        input_path=args.target,
        image_base=0,
        gap=_parse_optional_int(args.gap) or 0x100,
        name_prefix=args.name_prefix,
    )
    metadata_path = output_dir / "qemu_explore_metadata.json"
    save_metadata(metadata, metadata_path)
    print(f"[qemu-explore] Metadata saved: {metadata_path} ({len(metadata.functions)} functions, {sum(len(f.blocks) for f in metadata.functions)} blocks)", flush=True)

    baseline_keys: set[tuple[str, str]] | None = None
    seen_keys: set[tuple[str, str]] = set()
    report_runs = []
    for item in runs:
        coverage = load_address_log(
            item["qemu"].log_path,
            block_size=args.block_size,
            min_address=_parse_optional_int(args.address_min),
            max_address=_parse_optional_int(args.address_max),
        )
        flow = analyze_flow(metadata, coverage, focus_function=args.focus_function)
        keys = {(event.get("function") or "<unknown>", event.get("block_start") or event["address"]) for event in flow["flow"]}
        if baseline_keys is None:
            baseline_keys = set(keys)
        new_vs_baseline = keys - baseline_keys
        new_global = keys - seen_keys
        seen_keys.update(keys)
        report_runs.append(
            {
                "name": item["name"],
                "stdin_preview": _preview(item["stdin"]),
                "log_path": str(item["qemu"].log_path),
                "returncode": item["qemu"].returncode,
                "stdout": item["qemu"].stdout,
                "stderr": item["qemu"].stderr,
                "verdict": _classify_run(item["qemu"].stdout, item["qemu"].stderr, item["qemu"].returncode, args),
                "output_fingerprint": _output_fingerprint(item["qemu"].stdout, item["qemu"].stderr),
                "unique_blocks": flow["summary"]["unique_blocks"],
                "unique_transitions": flow["summary"]["unique_transitions"],
                "functions_seen": flow["summary"]["functions_seen"],
                "new_blocks_vs_baseline": len(new_vs_baseline),
                "new_blocks_global": len(new_global),
                "function_order": flow["ai_report"].get("user_function_order_text"),
            }
        )

    report = attach_ai_digest("qemu_explore", {
        "summary": {
            "target": args.target,
            "qemu_arch": args.qemu_arch,
            "trace_mode": args.trace_mode,
            "hit_count_precision": "exact" if args.trace_mode == "exec,nochain" else ("translation-log" if args.trace_mode == "in_asm" else "unknown"),
            "qemu_available": qemu_available(args.qemu_arch),
            "metadata_path": str(metadata_path),
            "runs": len(report_runs),
            "total_union_functions": len(metadata.functions),
            "total_union_blocks": sum(len(function.blocks) for function in metadata.functions),
        },
        "runs": report_runs,
        "recommended_runs": sorted(
            report_runs,
            key=lambda item: (
                item["verdict"] != "success",
                -item["new_blocks_vs_baseline"],
                -item["new_blocks_global"],
                item["name"],
            ),
        )[: max(1, args.keep_top)],
    })
    text = _fmt_markdown(args.format, _qemu_explore_to_markdown, report)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _load_address_logs_for_paths(paths: list[str], args: argparse.Namespace):
    merged = load_address_log(
        paths[0],
        block_size=args.block_size,
        min_address=_parse_optional_int(args.address_min),
        max_address=_parse_optional_int(args.address_max),
    )
    for path in paths[1:]:
        extra = load_address_log(
            path,
            block_size=args.block_size,
            min_address=_parse_optional_int(args.address_min),
            max_address=_parse_optional_int(args.address_max),
        )
        merged.blocks.extend(extra.blocks)
    return merged


def _explore_inputs(args: argparse.Namespace) -> list[str | None]:
    auto_nl = getattr(args, "auto_newline", False)
    values: list[str | None] = []
    for value in args.stdin or []:
        values.append(_ensure_newline(value, auto_nl))
    for path in args.stdin_file or []:
        values.append(_ensure_newline(Path(path).read_text(encoding="utf-8"), auto_nl))
    for value in _mutated_inputs(args):
        values.append(_ensure_newline(value, auto_nl))
    return values or [None]


def _mutated_inputs(args: argparse.Namespace) -> list[str]:
    patterns = getattr(args, "mutate_format", None)
    if not patterns:
        return []
    if isinstance(patterns, str):
        patterns = [patterns]
    all_cases: list[str] = []
    for pattern in patterns:
        for value in _mutated_inputs_for_pattern(args, pattern):
            if value not in all_cases:
                all_cases.append(value)
    return all_cases


def _mutated_inputs_for_pattern(args: argparse.Namespace, pattern: str) -> list[str]:
    strategy = getattr(args, "strategy", "byte-flip")
    limit = max(0, getattr(args, "mutate_limit", 128) or 128)
    seed, mutable_positions = _seed_and_mutable_positions(pattern)
    seed = getattr(args, "mutate_seed", None) or seed
    if getattr(args, "mutate_seed", None):
        mutable_positions = [index for index, ch in enumerate(seed) if ch not in "{}\r\n"]
    custom_positions = _parse_mutate_positions(getattr(args, "mutate_positions", None), len(seed))
    if custom_positions is not None:
        mutable_positions = custom_positions
    alphabet = getattr(args, "mutate_alphabet", None) or "0123456789abcdef"
    cases: list[str] = []

    def add(value: str) -> None:
        if value not in cases and len(cases) < limit:
            cases.append(value)

    add(seed)
    if strategy in {"byte-flip", "all"}:
        for index in mutable_positions:
            ch = seed[index]
            for replacement in alphabet:
                if replacement != ch:
                    add(seed[:index] + replacement + seed[index + 1:])
                if len(cases) >= limit:
                    return cases
    if strategy in {"length", "all"}:
        for delta in (-2, -1, 1, 2, 8):
            if delta < 0:
                add(seed[:delta])
            else:
                add(seed + (alphabet[0] * delta))
    return cases[:limit]


def _seed_from_mutate_format(pattern: str) -> str:
    return _seed_and_mutable_positions(pattern)[0]


def _seed_and_mutable_positions(pattern: str) -> tuple[str, list[int]]:
    import re

    output: list[str] = []
    mutable_positions: list[int] = []
    cursor = 0

    def repl(match) -> str:
        count = int(match.group(1))
        kind = match.group(2)
        fill = "0" if kind in {"x", "X", "d"} else "A"
        return fill * count

    for match in re.finditer(r"%(\d+)([xXds])", pattern):
        output.append(pattern[cursor:match.start()])
        start = sum(len(part) for part in output)
        replacement = repl(match)
        output.append(replacement)
        mutable_positions.extend(range(start, start + len(replacement)))
        cursor = match.end()
    output.append(pattern[cursor:])
    if not mutable_positions:
        mutable_positions = [index for index, ch in enumerate(pattern) if ch not in "{}\r\n"]
    return "".join(output), mutable_positions


def _parse_mutate_positions(value: str | None, seed_length: int) -> list[int] | None:
    if not value:
        return None
    positions: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item or ":" in item:
            separator = "-" if "-" in item else ":"
            left, right = item.split(separator, 1)
            start = int(left)
            end = int(right)
            if separator == ":":
                end -= 1
            positions.update(range(start, end + 1))
        else:
            positions.add(int(item))
    return sorted(index for index in positions if 0 <= index < seed_length)


def _classify_run(stdout: str, stderr: str, returncode: int, args: argparse.Namespace) -> str:
    text = (stdout or "") + "\n" + (stderr or "")
    if args.success_regex and __import__("re").search(args.success_regex, text):
        return "success"
    if args.failure_regex and __import__("re").search(args.failure_regex, text):
        return "failure"
    if returncode != 0:
        return "nonzero-exit"
    return "unknown"


def _output_fingerprint(stdout: str, stderr: str) -> str:
    import hashlib

    return hashlib.sha256(((stdout or "") + "\0" + (stderr or "")).encode("utf-8", errors="replace")).hexdigest()[:16]


def _preview(value: str | None, limit: int = 80) -> str:
    if value is None:
        return "<no stdin>"
    text = value.replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit] + "..."


def _qemu_explore_to_markdown(report: dict[str, object]) -> str:
    summary = report["summary"]
    lines = [
        "# BeaconFlow QEMU Explore",
        "",
    ]
    digest = compact_report("qemu_explore", report, max_findings=5).get("ai_digest", {})
    if digest:
        lines.extend(["## AI Digest", "", f"- Task: {digest.get('task')}", f"- Confidence: {digest.get('confidence')}", ""])
        if digest.get("top_findings"):
            lines.extend(["### Top Findings"])
            for item in digest["top_findings"][:5]:
                lines.append(f"- `{item.get('evidence_id')}` {item.get('claim')} confidence={item.get('confidence')}")
            lines.append("")
        if digest.get("recommended_actions"):
            lines.extend(["### Recommended Actions"])
            for item in digest["recommended_actions"][:5]:
                lines.append(f"- P{item.get('priority')}: {item.get('kind')} - {item.get('reason')}")
            lines.append("")
    lines.extend([
        "## Summary",
        "",
        f"- Target: `{summary['target']}`",
        f"- QEMU arch: `{summary['qemu_arch']}`",
        f"- Trace mode: `{summary['trace_mode']}`",
        f"- Metadata: `{summary['metadata_path']}`",
        f"- Runs: {summary['runs']}",
        f"- Union functions: {summary['total_union_functions']}",
        f"- Union blocks: {summary['total_union_blocks']}",
        "",
        "## Runs",
        "",
        "| Case | Verdict | Return | Unique Blocks | New vs Baseline | New Global | Output | Stdin |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
    ])
    for run in report["runs"]:
        lines.append(
            f"| `{run['name']}` | `{run['verdict']}` | {run['returncode']} | "
            f"{run['unique_blocks']} | {run['new_blocks_vs_baseline']} | {run['new_blocks_global']} | "
            f"`{run['output_fingerprint']}` | `{run['stdin_preview']}` |"
        )
    lines.extend(["", "## AI Notes", ""])
    lines.append("- Inputs with nonzero `New vs Baseline` reached code not seen by case000; inspect those first.")
    lines.append("- Different output fingerprints with no path novelty usually mean data-state differences, not control-flow differences.")
    lines.append("- Use the generated metadata path with `flow` or `flow-diff` for detailed block and edge analysis.")
    if summary["trace_mode"] == "in_asm":
        lines.append("- QEMU `in_asm` hit counts are translation-log evidence, not exact execution counts; use `exec,nochain` when timing, loop counts, dispatcher frequency, or branch-rank hit deltas matter.")
    recommended = report.get("recommended_runs", [])
    if recommended:
        lines.extend(["", "## Recommended Runs", ""])
        for run in recommended:
            lines.append(
                f"- `{run['name']}` verdict=`{run['verdict']}` new_vs_baseline={run['new_blocks_vs_baseline']} "
                f"new_global={run['new_blocks_global']} stdin=`{run['stdin_preview']}`"
            )
    return "\n".join(lines) + "\n"


def _ensure_newline(text: str | None, auto_newline: bool) -> str | None:
    if text is None or not auto_newline:
        return text
    if not text.endswith("\n"):
        return text + "\n"
    return text


def _read_stdin_arg(args: argparse.Namespace) -> str | None:
    if getattr(args, "stdin_file", None):
        text = Path(args.stdin_file).read_text(encoding="utf-8")
    elif getattr(args, "stdin", None) is not None:
        text = args.stdin
    else:
        return None
    return _ensure_newline(text, getattr(args, "auto_newline", False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="beaconflow")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze drcov coverage against exported IDA metadata.")
    analyze.add_argument("--metadata", required=True, help="IDA metadata JSON exported by ida_scripts/export_ida_metadata.py")
    analyze.add_argument("--coverage", required=True, help="DynamoRIO drcov coverage file")
    analyze.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    analyze.add_argument("--output")
    analyze.set_defaults(func=_cmd_analyze)

    diff = sub.add_parser("diff", help="Compare two drcov files against the same IDA metadata.")
    diff.add_argument("--metadata", required=True)
    diff.add_argument("--left", required=True)
    diff.add_argument("--right", required=True)
    diff.set_defaults(func=_cmd_diff)

    flow = sub.add_parser("flow", help="Recover ordered target-module basic-block flow from a drcov file.")
    flow.add_argument("--metadata", required=True)
    source = flow.add_mutually_exclusive_group(required=True)
    source.add_argument("--coverage", help="DynamoRIO drcov coverage file.")
    source.add_argument("--address-log", help="Text file containing ordered executed addresses.")
    flow.add_argument("--max-events", type=int, default=0, help="Maximum flow events to return; 0 means all.")
    flow.add_argument("--block-size", type=int, default=4, help="Instruction/block size for --address-log input.")
    flow.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    flow.add_argument("--address-max", help="Keep only address-log events below this address.")
    flow.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    flow.add_argument("--focus-function", help="Only keep events mapped to this function name or start address.")
    flow.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    flow.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    flow.add_argument("--output")
    flow.set_defaults(func=_cmd_flow)

    flow_diff = sub.add_parser("flow-diff", help="Compare two ordered execution flows at block and edge level.")
    flow_diff.add_argument("--metadata", required=True)
    left_source = flow_diff.add_mutually_exclusive_group(required=True)
    left_source.add_argument("--left", help="Left drcov file.")
    left_source.add_argument("--left-address-log", help="Left text address log.")
    right_source = flow_diff.add_mutually_exclusive_group(required=True)
    right_source.add_argument("--right", help="Right drcov file.")
    right_source.add_argument("--right-address-log", help="Right text address log.")
    flow_diff.add_argument("--focus-function", help="Only compare events mapped to this function name or start address.")
    flow_diff.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    flow_diff.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    flow_diff.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    flow_diff.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    flow_diff.add_argument("--address-max", help="Keep only address-log events below this address.")
    flow_diff.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    flow_diff.add_argument("--output")
    flow_diff.set_defaults(func=_cmd_flow_diff)

    deflatten = sub.add_parser("deflatten", help="Deflatten control flow: remove dispatcher blocks and reconstruct real edges.")
    deflatten.add_argument("--metadata", required=True)
    deflatten.add_argument("--coverage", help="Path to a drcov log file.")
    deflatten.add_argument("--address-log", help="Path to a QEMU address log file.")
    deflatten.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    deflatten.add_argument("--address-min")
    deflatten.add_argument("--address-max")
    deflatten.add_argument("--focus-function", help="Only analyze events in this function.")
    deflatten.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    deflatten.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    deflatten.add_argument("--dispatcher-min-hits", type=int, default=2, help="Min hits for a block to be considered dispatcher (default: 2).")
    deflatten.add_argument("--dispatcher-min-pred", type=int, default=2, help="Min predecessors for dispatcher (default: 2).")
    deflatten.add_argument("--dispatcher-min-succ", type=int, default=2, help="Min successors for dispatcher (default: 2).")
    deflatten.add_argument("--dispatcher-mode", choices=("strict", "balanced", "aggressive"), default="strict", help="Dispatcher selection mode. strict requires hot + multi-predecessor + multi-successor shape; aggressive is legacy heuristic-like.")
    deflatten.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    deflatten.add_argument("--output")
    deflatten.set_defaults(func=_cmd_deflatten)

    deflatten_merge_parser = sub.add_parser("deflatten-merge", help="Merge multiple deflatten results to restore complete real CFG.")
    deflatten_merge_parser.add_argument("--metadata", required=True)
    coverage_source = deflatten_merge_parser.add_mutually_exclusive_group(required=True)
    coverage_source.add_argument("--coverage", nargs="+", help="Two or more drcov log files from different inputs.")
    coverage_source.add_argument("--address-log", nargs="+", help="Two or more QEMU address log files from different inputs.")
    deflatten_merge_parser.add_argument("--label", nargs="+", action="extend", help="Label(s) for each coverage file (in order). Can be repeated or space-separated: --label A B C or --label A --label B --label C.")
    deflatten_merge_parser.add_argument("--focus-function", help="Only analyze events in this function.")
    deflatten_merge_parser.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    deflatten_merge_parser.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    deflatten_merge_parser.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    deflatten_merge_parser.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    deflatten_merge_parser.add_argument("--address-max", help="Keep only address-log events below this address.")
    deflatten_merge_parser.add_argument("--dispatcher-min-hits", type=int, default=2, help="Min hits for a block to be considered dispatcher (default: 2).")
    deflatten_merge_parser.add_argument("--dispatcher-min-pred", type=int, default=2, help="Min predecessors for dispatcher (default: 2).")
    deflatten_merge_parser.add_argument("--dispatcher-min-succ", type=int, default=2, help="Min successors for dispatcher (default: 2).")
    deflatten_merge_parser.add_argument("--dispatcher-mode", choices=("strict", "balanced", "aggressive"), default="strict", help="Dispatcher selection mode. strict avoids hot-loop/state-machine false positives; aggressive is legacy heuristic-like.")
    deflatten_merge_parser.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    deflatten_merge_parser.add_argument("--output")
    deflatten_merge_parser.set_defaults(func=_cmd_deflatten_merge)

    recover_state_parser = sub.add_parser("recover-state", help="Recover state transition table from multiple traces for CFF deflattening.")
    recover_state_parser.add_argument("--metadata", required=True)
    state_source = recover_state_parser.add_mutually_exclusive_group(required=True)
    state_source.add_argument("--coverage", nargs="+", help="Two or more drcov log files from different inputs.")
    state_source.add_argument("--address-log", nargs="+", help="Two or more QEMU address log files from different inputs.")
    recover_state_parser.add_argument("--label", nargs="+", action="extend", help="Label(s) for each coverage file (in order). Can be repeated or space-separated: --label A B C or --label A --label B --label C.")
    recover_state_parser.add_argument("--focus-function", help="Only analyze events in this function.")
    recover_state_parser.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    recover_state_parser.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    recover_state_parser.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    recover_state_parser.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    recover_state_parser.add_argument("--address-max", help="Keep only address-log events below this address.")
    recover_state_parser.add_argument("--dispatcher-min-hits", type=int, default=2, help="Min hits for a block to be considered dispatcher (default: 2).")
    recover_state_parser.add_argument("--dispatcher-min-pred", type=int, default=2, help="Min predecessors for dispatcher (default: 2).")
    recover_state_parser.add_argument("--dispatcher-min-succ", type=int, default=2, help="Min successors for dispatcher (default: 2).")
    recover_state_parser.add_argument("--dispatcher-mode", choices=("strict", "balanced", "aggressive"), default="strict", help="Dispatcher selection mode. strict avoids hot-loop/state-machine false positives; aggressive is legacy heuristic-like.")
    recover_state_parser.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    recover_state_parser.add_argument("--output")
    recover_state_parser.set_defaults(func=_cmd_recover_state)

    branch_rank = sub.add_parser("branch-rank", help="Rank input-dependent branch points across bad/better/good traces.")
    branch_rank.add_argument("--metadata", required=True)
    bad_source = branch_rank.add_mutually_exclusive_group(required=True)
    bad_source.add_argument("--bad", help="Baseline bad drcov log.")
    bad_source.add_argument("--bad-address-log", help="Baseline bad address log.")
    better_source = branch_rank.add_mutually_exclusive_group()
    better_source.add_argument("--better", action="append", help="Better drcov log. Can be repeated.")
    better_source.add_argument("--better-address-log", action="append", help="Better address log. Can be repeated.")
    good_source = branch_rank.add_mutually_exclusive_group()
    good_source.add_argument("--good", action="append", help="Known-good drcov log. Can be repeated.")
    good_source.add_argument("--good-address-log", action="append", help="Known-good address log. Can be repeated.")
    branch_rank.add_argument("--bad-label")
    branch_rank.add_argument("--better-label", action="append")
    branch_rank.add_argument("--good-label", action="append")
    branch_rank.add_argument("--focus-function", help="Only analyze events in this function.")
    branch_rank.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    branch_rank.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    branch_rank.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    branch_rank.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    branch_rank.add_argument("--address-max", help="Keep only address-log events below this address.")
    branch_rank.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    branch_rank.add_argument("--top", type=int, default=10, help="Only show top N ranked branches in markdown report (default: 10).")
    branch_rank.add_argument("--output")
    branch_rank.set_defaults(func=_cmd_branch_rank)

    inspect_block = sub.add_parser("inspect-block", help="Show detailed context for a single basic block.")
    inspect_block.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    inspect_block.add_argument("--address", required=True, help="Block start address (e.g. 0x1400014c7).")
    inspect_block.add_argument("--format", choices=("json", "markdown"), default="markdown")
    inspect_block.set_defaults(func=_cmd_inspect_block)

    inspect_func = sub.add_parser("inspect-function", help="Show detailed context for a function and its blocks.")
    inspect_func.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    inspect_func.add_argument("--name", help="Function name (e.g. check_flag).")
    inspect_func.add_argument("--address", help="Function start address (e.g. 0x140001460).")
    inspect_func.add_argument("--format", choices=("json", "markdown"), default="markdown")
    inspect_func.set_defaults(func=_cmd_inspect_function)

    find_dp = sub.add_parser("find-decision-points", help="Find and prioritize decision points (cmp+jcc, test+jcc, checker calls, cmovcc, setcc, jump tables).")
    find_dp.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    find_dp.add_argument("--focus-function", help="Only find decision points in this function (name or address).")
    find_dp.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    find_dp.add_argument("--output")
    find_dp.set_defaults(func=_cmd_find_decision_points)

    inspect_dp = sub.add_parser("inspect-decision-point", help="Inspect a single decision point by block address.")
    inspect_dp.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    inspect_dp.add_argument("--address", required=True, help="Block start address of the decision point (e.g. 0x1400014c7).")
    inspect_dp.add_argument("--format", choices=("json", "markdown"), default="markdown")
    inspect_dp.set_defaults(func=_cmd_inspect_decision_point)

    detect_roles = sub.add_parser("detect-roles", help="Detect candidate roles for functions (validator, crypto, dispatcher, etc.) using configurable rules.")
    detect_roles.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    detect_roles.add_argument("--rules", help="Path to custom role rules YAML file.")
    detect_roles.add_argument("--focus-function", help="Only detect roles for this function (name or address).")
    detect_roles.add_argument("--min-score", type=float, default=0.1, help="Minimum score threshold (default: 0.1).")
    detect_roles.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    detect_roles.add_argument("--output")
    detect_roles.set_defaults(func=_cmd_detect_roles)

    inspect_role_cmd = sub.add_parser("inspect-role", help="Inspect the detected role for a specific function.")
    inspect_role_cmd.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    inspect_role_cmd.add_argument("--name", help="Function name to inspect.")
    inspect_role_cmd.add_argument("--address", help="Function start address to inspect (e.g. 0x401000).")
    inspect_role_cmd.add_argument("--rules", help="Path to custom role rules YAML file.")
    inspect_role_cmd.add_argument("--format", choices=("json", "markdown"), default="markdown")
    inspect_role_cmd.set_defaults(func=_cmd_inspect_role)

    trace_values = sub.add_parser("trace-values", help="Trace register/memory/compare values at key decision points.")
    trace_values.add_argument("--metadata", required=True, help="Path to metadata JSON file.")
    trace_values_source = trace_values.add_mutually_exclusive_group()
    trace_values_source.add_argument("--coverage", help="DynamoRIO drcov coverage file (optional, for branch result inference).")
    trace_values_source.add_argument("--address-log", help="QEMU address log file (optional, for branch result inference).")
    trace_values.add_argument("--focus-function", help="Only trace values in this function (name or address).")
    trace_values.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    trace_values.add_argument("--address-min")
    trace_values.add_argument("--address-max")
    trace_values.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    trace_values.add_argument("--output")
    trace_values.set_defaults(func=_cmd_trace_values)

    ai_summary = sub.add_parser("ai-summary", help="Compact an existing BeaconFlow JSON report into an AI-first digest.")
    ai_summary.add_argument("--input", required=True, help="Input BeaconFlow JSON report.")
    ai_summary.add_argument("--kind", choices=("coverage", "flow", "flow_diff", "deflatten", "deflatten_merge", "recover_state", "branch_rank", "qemu_explore", "unknown"), help="Report kind. Auto-detected if omitted.")
    ai_summary.add_argument("--max-findings", type=int, default=5)
    ai_summary.add_argument("--format", choices=("json", "markdown"), default="json")
    ai_summary.add_argument("--output")
    ai_summary.set_defaults(func=_cmd_ai_summary)

    collect = sub.add_parser("collect", help="Run a target under bundled DynamoRIO drcov. Supports both PE (Windows) and ELF (via WSL on Windows).")
    collect.add_argument("--target", required=True, help="Executable to run (PE or ELF).")
    collect.add_argument("--output-dir", default=".", help="Directory for generated drcov logs.")
    collect.add_argument("--arch", choices=("x86", "x64"), default="x64")
    collect.add_argument("--drrun", help="Optional custom drrun path.")
    collect.add_argument("--stdin", help="Text to send to target stdin.")
    collect.add_argument("--stdin-file", help="File contents to send to target stdin.")
    collect.add_argument("--auto-newline", action="store_true", help="Append a newline to --stdin/--stdin-file if missing.")
    collect.add_argument("--run-cwd", help="Working directory for the target process.")
    collect.add_argument("--timeout", type=int, default=120, help="Timeout in seconds (default: 120).")
    collect.add_argument("--name", help="Custom name for the drcov log file.")
    collect.add_argument("target_args", nargs=argparse.REMAINDER, help="Arguments passed after -- to the target.")
    collect.set_defaults(func=_cmd_collect)

    collect_qemu = sub.add_parser("collect-qemu", help="Run a target under QEMU user-mode tracing.")
    collect_qemu.add_argument("--target", required=True)
    collect_qemu.add_argument("--output-dir", default=".")
    collect_qemu.add_argument("--qemu-arch", required=True, help="QEMU user arch, for example loongarch64, mips, arm, aarch64.")
    collect_qemu.add_argument("--qemu", help="Optional custom qemu user-mode executable.")
    collect_qemu.add_argument("--trace-mode", default="in_asm", help="QEMU -d trace mode, for example in_asm or exec,nochain.")
    collect_qemu.add_argument("--stdin", help="Text to send to target stdin.")
    collect_qemu.add_argument("--stdin-file", help="File contents to send to target stdin.")
    collect_qemu.add_argument("--auto-newline", action="store_true", help="Append a newline to --stdin/--stdin-file if missing.")
    collect_qemu.add_argument("--run-cwd", help="Working directory for the target process.")
    collect_qemu.add_argument("--timeout", type=int, default=120)
    collect_qemu.add_argument("--name")
    collect_qemu.add_argument("target_args", nargs=argparse.REMAINDER)
    collect_qemu.set_defaults(func=_cmd_collect_qemu)

    record = sub.add_parser("record-flow", help="Run a target once and emit the ordered executed flow.")
    record.add_argument("--metadata", required=True)
    record.add_argument("--target", required=True)
    record.add_argument("--output-dir", default=".")
    record.add_argument("--arch", choices=("x86", "x64"), default="x64")
    record.add_argument("--drrun")
    record.add_argument("--timeout", type=int, default=120, help="Timeout in seconds (default: 120).")
    record.add_argument("--max-events", type=int, default=0, help="Maximum flow events to return; 0 means all.")
    record.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    record.add_argument("--focus-function", help="Only keep events mapped to this function name or start address.")
    record.add_argument("--output")
    record.add_argument("--stdin", help="Text to send to target stdin.")
    record.add_argument("--stdin-file", help="File contents to send to target stdin.")
    record.add_argument("--auto-newline", action="store_true", help="Append a newline to --stdin/--stdin-file if missing.")
    record.add_argument("--run-cwd", help="Working directory for the target process.")
    record.add_argument("target_args", nargs=argparse.REMAINDER)
    record.set_defaults(func=_cmd_record_flow)

    trace_meta = sub.add_parser(
        "metadata-from-address-log",
        help="Build fallback metadata by clustering an ordered executed-address log.",
    )
    trace_meta.add_argument(
        "--address-log",
        required=True,
        nargs="+",
        help="One or more text files containing ordered executed addresses.",
    )
    trace_meta.add_argument("--output", required=True, help="Output metadata JSON.")
    trace_meta.add_argument("--input-path", default="", help="Original binary path to store in metadata.")
    trace_meta.add_argument("--image-base", default="0", help="Image base to store in metadata.")
    trace_meta.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log events.")
    trace_meta.add_argument("--address-min", help="Keep only events at or above this address.")
    trace_meta.add_argument("--address-max", help="Keep only events below this address.")
    trace_meta.add_argument("--gap", default="0x100", help="Start a new trace region when unique addresses gap exceeds this.")
    trace_meta.add_argument("--name-prefix", default="trace_region")
    trace_meta.set_defaults(func=_cmd_metadata_from_address_log)

    qemu_explore = sub.add_parser("qemu-explore", help="Run multiple QEMU traced inputs and rank path novelty.")
    qemu_explore.add_argument("--target", required=True)
    qemu_explore.add_argument("--output-dir", default="qemu_explore")
    qemu_explore.add_argument("--qemu-arch", required=True)
    qemu_explore.add_argument("--qemu", help="Optional custom qemu user-mode executable.")
    qemu_explore.add_argument("--trace-mode", default="in_asm")
    qemu_explore.add_argument("--stdin", action="append", help="One stdin test case. Can be repeated.")
    qemu_explore.add_argument("--stdin-file", action="append", help="One stdin file test case. Can be repeated.")
    qemu_explore.add_argument("--mutate-template", "--mutate-format", dest="mutate_format", action="append", help="Generate stdin cases from a custom template such as token=%%16x or user:%%8s. Can be repeated.")
    qemu_explore.add_argument("--mutate-seed", help="Seed input for mutation. Defaults to the zero-filled mutate format.")
    qemu_explore.add_argument("--mutate-alphabet", default="0123456789abcdef", help="Characters used by byte-flip mutation.")
    qemu_explore.add_argument("--mutate-positions", help="Comma-separated 0-based positions or ranges to mutate in the seed, for example 0,3,8-15 or 8:16.")
    qemu_explore.add_argument("--mutate-limit", type=int, default=128, help="Maximum generated mutation cases.")
    qemu_explore.add_argument("--strategy", choices=("byte-flip", "length", "all"), default="byte-flip", help="Input mutation strategy.")
    qemu_explore.add_argument("--keep-top", type=int, default=20, help="Number of recommended runs to keep in the report.")
    qemu_explore.add_argument("--auto-newline", action="store_true", help="Append a newline to each --stdin/--stdin-file if missing.")
    qemu_explore.add_argument("--jobs", type=int, default=0, help="Max parallel QEMU workers; 0 means all.")
    qemu_explore.add_argument("--run-cwd")
    qemu_explore.add_argument("--timeout", type=int, default=120)
    qemu_explore.add_argument("--block-size", type=int, default=4)
    qemu_explore.add_argument("--address-min")
    qemu_explore.add_argument("--address-max")
    qemu_explore.add_argument("--gap", default="0x100")
    qemu_explore.add_argument("--name-prefix", default="qemu_trace")
    qemu_explore.add_argument("--focus-function")
    qemu_explore.add_argument("--success-regex", help="Classify runs as success when stdout/stderr matches.")
    qemu_explore.add_argument("--failure-regex", help="Classify runs as failure when stdout/stderr matches.")
    qemu_explore.add_argument("--format", choices=("json", "markdown", "markdown-brief"), default="json")
    qemu_explore.add_argument("--output")
    qemu_explore.add_argument("target_args", nargs=argparse.REMAINDER)
    qemu_explore.set_defaults(func=_cmd_qemu_explore)

    export_ghidra = sub.add_parser("export-ghidra-metadata", help="Export metadata from a binary using Ghidra headless mode.")
    export_ghidra.add_argument("--target", required=True, help="Binary file to analyze with Ghidra.")
    export_ghidra.add_argument("--output", required=True, help="Output metadata JSON path.")
    export_ghidra.add_argument("--ghidra-path", help="Path to analyzeHeadless script. Auto-detected if omitted.")
    export_ghidra.add_argument("--project-dir", help="Temporary Ghidra project directory. Default: next to output file.")
    export_ghidra.add_argument("--script-path", help="Path to ExportBeaconFlowMetadata.py. Default: ghidra_scripts/ in repo.")
    export_ghidra.add_argument("--backend", choices=("pyghidra", "headless"), default="pyghidra", help="Ghidra export backend. Default uses pyghidra; headless keeps the legacy analyzeHeadless script path.")
    export_ghidra.add_argument("--timeout", type=int, default=600, help="Ghidra headless timeout in seconds.")
    export_ghidra.add_argument("--no-context", action="store_true", help="Skip block context extraction (instructions, calls, strings, etc.) for faster export.")
    export_ghidra.set_defaults(func=_cmd_export_ghidra)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
