from __future__ import annotations

import argparse
import json
from pathlib import Path

from beaconflow.analysis import analyze_coverage, analyze_flow, diff_coverage
from beaconflow.coverage import load_drcov
from beaconflow.coverage.runner import collect_drcov
from beaconflow.ida import load_metadata
from beaconflow.reports import coverage_to_markdown, flow_to_markdown


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
    coverage = load_drcov(args.coverage)
    result = analyze_flow(metadata, coverage, max_events=args.max_events)
    text = flow_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_collect(args: argparse.Namespace) -> int:
    stdin_text = _read_stdin_arg(args)
    log_path = collect_drcov(
        target=args.target,
        target_args=args.target_args,
        output_dir=args.output_dir,
        arch=args.arch,
        drrun_path=args.drrun,
        stdin_text=stdin_text,
    )
    print(log_path)
    return 0


def _cmd_record_flow(args: argparse.Namespace) -> int:
    stdin_text = _read_stdin_arg(args)
    log_path = collect_drcov(
        target=args.target,
        target_args=args.target_args,
        output_dir=args.output_dir,
        arch=args.arch,
        drrun_path=args.drrun,
        stdin_text=stdin_text,
    )
    metadata = load_metadata(args.metadata)
    result = analyze_flow(metadata, load_drcov(log_path), max_events=args.max_events)
    result["coverage_path"] = str(log_path)
    text = flow_to_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def _read_stdin_arg(args: argparse.Namespace) -> str | None:
    if getattr(args, "stdin_file", None):
        return Path(args.stdin_file).read_text(encoding="utf-8")
    if getattr(args, "stdin", None) is not None:
        return args.stdin
    return None


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
    flow.add_argument("--coverage", required=True)
    flow.add_argument("--max-events", type=int, default=0, help="Maximum flow events to return; 0 means all.")
    flow.add_argument("--format", choices=("json", "markdown"), default="json")
    flow.add_argument("--output")
    flow.set_defaults(func=_cmd_flow)

    collect = sub.add_parser("collect", help="Run a target under bundled DynamoRIO drcov.")
    collect.add_argument("--target", required=True, help="Executable to run.")
    collect.add_argument("--output-dir", default=".", help="Directory for generated drcov logs.")
    collect.add_argument("--arch", choices=("x86", "x64"), default="x64")
    collect.add_argument("--drrun", help="Optional custom drrun.exe path.")
    collect.add_argument("--stdin", help="Text to send to target stdin.")
    collect.add_argument("--stdin-file", help="File contents to send to target stdin.")
    collect.add_argument("target_args", nargs=argparse.REMAINDER, help="Arguments passed after -- to the target.")
    collect.set_defaults(func=_cmd_collect)

    record = sub.add_parser("record-flow", help="Run a target once and emit the ordered executed flow.")
    record.add_argument("--metadata", required=True)
    record.add_argument("--target", required=True)
    record.add_argument("--output-dir", default=".")
    record.add_argument("--arch", choices=("x86", "x64"), default="x64")
    record.add_argument("--drrun")
    record.add_argument("--max-events", type=int, default=0, help="Maximum flow events to return; 0 means all.")
    record.add_argument("--format", choices=("json", "markdown"), default="json")
    record.add_argument("--output")
    record.add_argument("--stdin", help="Text to send to target stdin.")
    record.add_argument("--stdin-file", help="File contents to send to target stdin.")
    record.add_argument("target_args", nargs=argparse.REMAINDER)
    record.set_defaults(func=_cmd_record_flow)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
