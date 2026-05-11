from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from beaconflow.analysis import analyze_coverage, analyze_flow, deflatten_flow, deflatten_merge, diff_coverage, diff_flow, recover_state_transitions
from beaconflow.coverage import collect_qemu_trace, load_address_log, load_drcov, qemu_available
from beaconflow.coverage.runner import collect_drcov
from beaconflow.ghidra import export_ghidra_metadata, find_ghidra_headless
from beaconflow.ida import load_metadata, save_metadata
from beaconflow.metadata import build_trace_metadata
from beaconflow.reports import coverage_to_markdown, deflatten_merge_to_markdown, deflatten_to_markdown, flow_diff_to_markdown, flow_to_markdown, state_transitions_to_markdown


def _cmd_analyze(args: argparse.Namespace) -> int:
    metadata = load_metadata(args.metadata)
    coverage = load_drcov(args.coverage)
    result = analyze_coverage(metadata, coverage)
    text = coverage_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
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
    text = flow_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
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
    text = flow_diff_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
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
    )
    text = deflatten_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
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
    )
    text = deflatten_merge_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
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
    )
    text = state_transitions_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _load_flow_input(args: argparse.Namespace):
    if args.address_log:
        return _load_address_log_arg(args.address_log, args)
    return load_drcov(args.coverage)


def _load_address_log_arg(path: str, args: argparse.Namespace):
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
    text = flow_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
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

    report = {
        "summary": {
            "target": args.target,
            "qemu_arch": args.qemu_arch,
            "trace_mode": args.trace_mode,
            "qemu_available": qemu_available(args.qemu_arch),
            "metadata_path": str(metadata_path),
            "runs": len(report_runs),
            "total_union_functions": len(metadata.functions),
            "total_union_blocks": sum(len(function.blocks) for function in metadata.functions),
        },
        "runs": report_runs,
    }
    text = _qemu_explore_to_markdown(report) if args.format == "markdown" else json.dumps(report, indent=2)
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
    return values or [None]


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
    ]
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
    analyze.add_argument("--format", choices=("json", "markdown"), default="json")
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
    flow.add_argument("--format", choices=("json", "markdown"), default="json")
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
    flow_diff.add_argument("--format", choices=("json", "markdown"), default="json")
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
    deflatten.add_argument("--format", choices=("json", "markdown"), default="json")
    deflatten.add_argument("--output")
    deflatten.set_defaults(func=_cmd_deflatten)

    deflatten_merge_parser = sub.add_parser("deflatten-merge", help="Merge multiple deflatten results to restore complete real CFG.")
    deflatten_merge_parser.add_argument("--metadata", required=True)
    coverage_source = deflatten_merge_parser.add_mutually_exclusive_group(required=True)
    coverage_source.add_argument("--coverage", nargs="+", help="Two or more drcov log files from different inputs.")
    coverage_source.add_argument("--address-log", nargs="+", help="Two or more QEMU address log files from different inputs.")
    deflatten_merge_parser.add_argument("--label", action="append", help="Label for each coverage file (in order). Can be repeated.")
    deflatten_merge_parser.add_argument("--focus-function", help="Only analyze events in this function.")
    deflatten_merge_parser.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    deflatten_merge_parser.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    deflatten_merge_parser.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    deflatten_merge_parser.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    deflatten_merge_parser.add_argument("--address-max", help="Keep only address-log events below this address.")
    deflatten_merge_parser.add_argument("--dispatcher-min-hits", type=int, default=2, help="Min hits for a block to be considered dispatcher (default: 2).")
    deflatten_merge_parser.add_argument("--dispatcher-min-pred", type=int, default=2, help="Min predecessors for dispatcher (default: 2).")
    deflatten_merge_parser.add_argument("--dispatcher-min-succ", type=int, default=2, help="Min successors for dispatcher (default: 2).")
    deflatten_merge_parser.add_argument("--format", choices=("json", "markdown"), default="json")
    deflatten_merge_parser.add_argument("--output")
    deflatten_merge_parser.set_defaults(func=_cmd_deflatten_merge)

    recover_state_parser = sub.add_parser("recover-state", help="Recover state transition table from multiple traces for CFF deflattening.")
    recover_state_parser.add_argument("--metadata", required=True)
    state_source = recover_state_parser.add_mutually_exclusive_group(required=True)
    state_source.add_argument("--coverage", nargs="+", help="Two or more drcov log files from different inputs.")
    state_source.add_argument("--address-log", nargs="+", help="Two or more QEMU address log files from different inputs.")
    recover_state_parser.add_argument("--label", action="append", help="Label for each coverage file (in order). Can be repeated.")
    recover_state_parser.add_argument("--focus-function", help="Only analyze events in this function.")
    recover_state_parser.add_argument("--from", dest="from_", help="Start address or function name for range filtering (inclusive).")
    recover_state_parser.add_argument("--to", dest="to", help="End address or function name for range filtering (exclusive).")
    recover_state_parser.add_argument("--block-size", type=int, default=4, help="Instruction/block size for address-log inputs.")
    recover_state_parser.add_argument("--address-min", help="Keep only address-log events at or above this address.")
    recover_state_parser.add_argument("--address-max", help="Keep only address-log events below this address.")
    recover_state_parser.add_argument("--dispatcher-min-hits", type=int, default=2, help="Min hits for a block to be considered dispatcher (default: 2).")
    recover_state_parser.add_argument("--dispatcher-min-pred", type=int, default=2, help="Min predecessors for dispatcher (default: 2).")
    recover_state_parser.add_argument("--dispatcher-min-succ", type=int, default=2, help="Min successors for dispatcher (default: 2).")
    recover_state_parser.add_argument("--format", choices=("json", "markdown"), default="json")
    recover_state_parser.add_argument("--output")
    recover_state_parser.set_defaults(func=_cmd_recover_state)

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
    record.add_argument("--format", choices=("json", "markdown"), default="json")
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
    qemu_explore.add_argument("--format", choices=("json", "markdown"), default="json")
    qemu_explore.add_argument("--output")
    qemu_explore.add_argument("target_args", nargs=argparse.REMAINDER)
    qemu_explore.set_defaults(func=_cmd_qemu_explore)

    export_ghidra = sub.add_parser("export-ghidra-metadata", help="Export metadata from a binary using Ghidra headless mode.")
    export_ghidra.add_argument("--target", required=True, help="Binary file to analyze with Ghidra.")
    export_ghidra.add_argument("--output", required=True, help="Output metadata JSON path.")
    export_ghidra.add_argument("--ghidra-path", help="Path to analyzeHeadless script. Auto-detected if omitted.")
    export_ghidra.add_argument("--project-dir", help="Temporary Ghidra project directory. Default: next to output file.")
    export_ghidra.add_argument("--script-path", help="Path to ExportBeaconFlowMetadata.py. Default: ghidra_scripts/ in repo.")
    export_ghidra.add_argument("--timeout", type=int, default=600, help="Ghidra headless timeout in seconds.")
    export_ghidra.set_defaults(func=_cmd_export_ghidra)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
