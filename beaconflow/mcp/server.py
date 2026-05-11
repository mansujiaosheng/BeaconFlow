from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from beaconflow.analysis import analyze_coverage, analyze_flow, deflatten_flow, deflatten_merge, diff_coverage, diff_flow, recover_state_transitions
from beaconflow.coverage import collect_qemu_trace, load_address_log, load_drcov, qemu_available
from beaconflow.coverage.runner import collect_drcov
from beaconflow.ghidra import export_ghidra_metadata, find_ghidra_headless
from beaconflow.ida import load_metadata, save_metadata
from beaconflow.metadata import build_trace_metadata
from beaconflow.reports import coverage_to_markdown, deflatten_merge_to_markdown, deflatten_to_markdown, flow_diff_to_markdown, flow_to_markdown, state_transitions_to_markdown


TOOLS: dict[str, dict[str, Any]] = {
    "analyze_coverage": {
        "description": "Analyze a drcov coverage file against IDA-exported metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "coverage_path": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path", "coverage_path"],
        },
    },
    "diff_coverage": {
        "description": "Compare two drcov coverage files against the same IDA-exported metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "left_coverage_path": {"type": "string"},
                "right_coverage_path": {"type": "string"},
            },
            "required": ["metadata_path", "left_coverage_path", "right_coverage_path"],
        },
    },
    "analyze_flow": {
        "description": "Recover ordered target-module basic-block flow from a drcov file or text address log.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "coverage_path": {"type": "string"},
                "address_log_path": {"type": "string"},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "max_events": {"type": "integer", "default": 0},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
                "focus_function": {"type": "string"},
            },
            "required": ["metadata_path"],
        },
    },
    "diff_flow": {
        "description": "Compare two drcov runs or text address logs at ordered-flow block and edge level.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "left_coverage_path": {"type": "string"},
                "right_coverage_path": {"type": "string"},
                "left_address_log_path": {"type": "string"},
                "right_address_log_path": {"type": "string"},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "focus_function": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "metadata_from_address_log": {
        "description": "Build fallback metadata by clustering one or more ordered executed-address logs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address_log_paths": {"type": "array", "items": {"type": "string"}},
                "output_path": {"type": "string"},
                "input_path": {"type": "string"},
                "image_base": {"type": "string", "default": "0"},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "gap": {"type": "string", "default": "0x100"},
                "name_prefix": {"type": "string", "default": "trace_region"},
            },
            "required": ["address_log_paths", "output_path"],
        },
    },
    "record_flow": {
        "description": "Run a Windows target under bundled DynamoRIO drcov and return ordered executed flow.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "target_path": {"type": "string"},
                "target_args": {"type": "array", "items": {"type": "string"}, "default": []},
                "output_dir": {"type": "string", "default": "."},
                "arch": {"type": "string", "enum": ["x86", "x64"], "default": "x64"},
                "max_events": {"type": "integer", "default": 0},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
                "drrun_path": {"type": "string"},
                "stdin": {"type": "string"},
                "focus_function": {"type": "string"},
                "run_cwd": {"type": "string"},
            },
            "required": ["metadata_path", "target_path"],
        },
    },
    "collect_drcov": {
        "description": "Run a Windows target under bundled DynamoRIO drcov and return the generated log path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "target_args": {"type": "array", "items": {"type": "string"}, "default": []},
                "output_dir": {"type": "string", "default": "."},
                "arch": {"type": "string", "enum": ["x86", "x64"], "default": "x64"},
                "drrun_path": {"type": "string"},
                "stdin": {"type": "string"},
                "auto_newline": {"type": "boolean", "default": False},
                "run_cwd": {"type": "string"},
            },
            "required": ["target_path"],
        },
    },
    "collect_qemu": {
        "description": "Run a target under QEMU user-mode tracing and return the trace log path and output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "qemu_arch": {"type": "string", "description": "QEMU user arch, e.g. loongarch64, mips, arm, aarch64."},
                "qemu_path": {"type": "string"},
                "trace_mode": {"type": "string", "default": "in_asm", "description": "QEMU -d trace mode, e.g. in_asm or exec,nochain."},
                "target_args": {"type": "array", "items": {"type": "string"}, "default": []},
                "output_dir": {"type": "string", "default": "."},
                "stdin": {"type": "string"},
                "auto_newline": {"type": "boolean", "default": True, "description": "Append newline to stdin if missing."},
                "run_cwd": {"type": "string"},
                "timeout": {"type": "integer", "default": 120},
                "name": {"type": "string"},
            },
            "required": ["target_path", "qemu_arch"],
        },
    },
    "qemu_explore": {
        "description": "Run multiple QEMU traced inputs, classify verdicts, and rank path novelty. For exploring unknown binaries where you don't know the correct input.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "qemu_arch": {"type": "string"},
                "qemu_path": {"type": "string"},
                "trace_mode": {"type": "string", "default": "in_asm"},
                "stdin_cases": {"type": "array", "items": {"type": "string"}, "description": "List of stdin test cases."},
                "auto_newline": {"type": "boolean", "default": True, "description": "Append newline to each stdin case if missing."},
                "output_dir": {"type": "string", "default": "qemu_explore"},
                "run_cwd": {"type": "string"},
                "timeout": {"type": "integer", "default": 120},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "gap": {"type": "string", "default": "0x100"},
                "name_prefix": {"type": "string", "default": "qemu_trace"},
                "success_regex": {"type": "string", "description": "Classify runs as success when stdout/stderr matches."},
                "failure_regex": {"type": "string", "description": "Classify runs as failure when stdout/stderr matches."},
                "focus_function": {"type": "string"},
                "jobs": {"type": "integer", "default": 0, "description": "Max parallel QEMU workers; 0 means all."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["target_path", "qemu_arch", "stdin_cases"],
        },
    },
    "export_ghidra_metadata": {
        "description": "Export function/basic-block/CFG metadata from a binary using Ghidra headless mode. Supports architectures that IDA cannot open, such as LoongArch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Binary file to analyze with Ghidra."},
                "output_path": {"type": "string", "description": "Output metadata JSON path."},
                "ghidra_path": {"type": "string", "description": "Path to analyzeHeadless script. Auto-detected if omitted."},
                "project_dir": {"type": "string", "description": "Temporary Ghidra project directory."},
                "script_path": {"type": "string", "description": "Path to ExportBeaconFlowMetadata.py. Default: ghidra_scripts/ in repo."},
                "timeout": {"type": "integer", "default": 600, "description": "Ghidra headless timeout in seconds."},
            },
            "required": ["target_path", "output_path"],
        },
    },
    "deflatten_flow": {
        "description": "Remove dispatcher blocks from execution flow and reconstruct real control flow edges. Key tool for control-flow-flattening (CFF) deflattening.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "coverage_path": {"type": "string", "description": "Path to a drcov log file."},
                "address_log_path": {"type": "string", "description": "Path to a QEMU address log file."},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "focus_function": {"type": "string"},
                "dispatcher_min_hits": {"type": "integer", "default": 2, "description": "Min hits for a block to be considered dispatcher."},
                "dispatcher_min_pred": {"type": "integer", "default": 2, "description": "Min predecessors for dispatcher."},
                "dispatcher_min_succ": {"type": "integer", "default": 2, "description": "Min successors for dispatcher."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "deflatten_merge": {
        "description": "Merge multiple deflatten results from different inputs to restore the complete real CFG. Identifies common paths and input-dependent branches.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "coverage_paths": {"type": "array", "items": {"type": "string"}, "description": "Two or more drcov log files from different inputs."},
                "address_log_paths": {"type": "array", "items": {"type": "string"}, "description": "Two or more QEMU address log files from different inputs."},
                "labels": {"type": "array", "items": {"type": "string"}, "description": "Label for each coverage file (in order)."},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "focus_function": {"type": "string"},
                "dispatcher_min_hits": {"type": "integer", "default": 2},
                "dispatcher_min_pred": {"type": "integer", "default": 2},
                "dispatcher_min_succ": {"type": "integer", "default": 2},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "recover_state_transitions": {
        "description": "Recover state transition table from multiple traces for CFF deflattening. Identifies deterministic vs input-dependent state variable transitions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "coverage_paths": {"type": "array", "items": {"type": "string"}, "description": "Two or more drcov log files from different inputs."},
                "address_log_paths": {"type": "array", "items": {"type": "string"}, "description": "Two or more QEMU address log files from different inputs."},
                "labels": {"type": "array", "items": {"type": "string"}, "description": "Label for each coverage file (in order)."},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "focus_function": {"type": "string"},
                "dispatcher_min_hits": {"type": "integer", "default": 2},
                "dispatcher_min_pred": {"type": "integer", "default": 2},
                "dispatcher_min_succ": {"type": "integer", "default": 2},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
}


def _tool_result(value: str | dict[str, Any]) -> dict[str, Any]:
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    return {"content": [{"type": "text", "text": text}]}


def _parse_optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _ensure_newline(text: str | None, auto_newline: bool) -> str | None:
    if text is None or not auto_newline:
        return text
    if not text.endswith("\n"):
        return text + "\n"
    return text


def _classify_run(stdout: str, stderr: str, returncode: int, arguments: dict[str, Any]) -> str:
    import re as _re
    text = (stdout or "") + "\n" + (stderr or "")
    if arguments.get("success_regex") and _re.search(arguments["success_regex"], text):
        return "success"
    if arguments.get("failure_regex") and _re.search(arguments["failure_regex"], text):
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


def _mcp_qemu_explore(arguments: dict[str, Any]) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    target = arguments["target_path"]
    qemu_arch = arguments["qemu_arch"]
    stdin_cases = arguments.get("stdin_cases") or []
    auto_nl = arguments.get("auto_newline", True)
    output_dir = Path(arguments.get("output_dir") or "qemu_explore")
    output_dir.mkdir(parents=True, exist_ok=True)
    total = len(stdin_cases)
    max_workers = min(total, arguments.get("jobs") or total)

    def _run_one(index: int, stdin_text: str | None) -> dict:
        name = f"case{index:03d}"
        result = collect_qemu_trace(
            target=target,
            output_dir=output_dir,
            qemu_arch=qemu_arch,
            target_args=arguments.get("target_args") or [],
            stdin_text=stdin_text,
            run_cwd=arguments.get("run_cwd"),
            trace_mode=arguments.get("trace_mode") or "in_asm",
            qemu_path=arguments.get("qemu_path"),
            timeout=arguments.get("timeout") or 120,
            name=name,
        )
        return {"name": name, "stdin": stdin_text, "qemu": result, "index": index}

    runs: list[dict] = [None] * total  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, i, _ensure_newline(s, auto_nl)): i for i, s in enumerate(stdin_cases)}
        for future in as_completed(futures):
            item = future.result()
            runs[item.pop("index")] = item

    log_paths = [str(item["qemu"].log_path) for item in runs]

    merged = load_address_log(
        log_paths[0],
        block_size=arguments.get("block_size") or 4,
        min_address=_parse_optional_int(arguments.get("address_min")),
        max_address=_parse_optional_int(arguments.get("address_max")),
    )
    for path in log_paths[1:]:
        extra = load_address_log(
            path,
            block_size=arguments.get("block_size") or 4,
            min_address=_parse_optional_int(arguments.get("address_min")),
            max_address=_parse_optional_int(arguments.get("address_max")),
        )
        merged.blocks.extend(extra.blocks)

    metadata = build_trace_metadata(
        merged,
        input_path=target,
        image_base=0,
        gap=_parse_optional_int(arguments.get("gap")) or 0x100,
        name_prefix=arguments.get("name_prefix") or "qemu_trace",
    )
    metadata_path = output_dir / "qemu_explore_metadata.json"
    save_metadata(metadata, metadata_path)

    baseline_keys: set[tuple[str, str]] | None = None
    seen_keys: set[tuple[str, str]] = set()
    report_runs = []
    for item in runs:
        coverage = load_address_log(
            item["qemu"].log_path,
            block_size=arguments.get("block_size") or 4,
            min_address=_parse_optional_int(arguments.get("address_min")),
            max_address=_parse_optional_int(arguments.get("address_max")),
        )
        flow = analyze_flow(metadata, coverage, focus_function=arguments.get("focus_function"))
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
                "verdict": _classify_run(item["qemu"].stdout, item["qemu"].stderr, item["qemu"].returncode, arguments),
                "output_fingerprint": _output_fingerprint(item["qemu"].stdout, item["qemu"].stderr),
                "unique_blocks": flow["summary"]["unique_blocks"],
                "unique_transitions": flow["summary"]["unique_transitions"],
                "functions_seen": flow["summary"]["functions_seen"],
                "new_blocks_vs_baseline": len(new_vs_baseline),
                "new_blocks_global": len(new_global),
                "function_order": flow["ai_report"].get("user_function_order_text"),
            }
        )

    return {
        "summary": {
            "target": target,
            "qemu_arch": qemu_arch,
            "trace_mode": arguments.get("trace_mode") or "in_asm",
            "qemu_available": qemu_available(qemu_arch),
            "metadata_path": str(metadata_path),
            "runs": len(report_runs),
            "total_union_functions": len(metadata.functions),
            "total_union_blocks": sum(len(f.blocks) for f in metadata.functions),
        },
        "runs": report_runs,
    }


def _load_flow_source(arguments: dict[str, Any], coverage_key: str, address_log_key: str):
    if arguments.get(address_log_key):
        return load_address_log(
            arguments[address_log_key],
            block_size=arguments.get("block_size") or 4,
            min_address=_parse_optional_int(arguments.get("address_min")),
            max_address=_parse_optional_int(arguments.get("address_max")),
        )
    if arguments.get(coverage_key):
        return load_drcov(arguments[coverage_key])
    raise ValueError(f"missing {coverage_key} or {address_log_key}")


def _load_many_address_logs(arguments: dict[str, Any]):
    paths = arguments.get("address_log_paths") or []
    if not paths:
        raise ValueError("address_log_paths is required")
    merged = load_address_log(
        paths[0],
        block_size=arguments.get("block_size") or 4,
        min_address=_parse_optional_int(arguments.get("address_min")),
        max_address=_parse_optional_int(arguments.get("address_max")),
    )
    for path in paths[1:]:
        extra = load_address_log(
            path,
            block_size=arguments.get("block_size") or 4,
            min_address=_parse_optional_int(arguments.get("address_min")),
            max_address=_parse_optional_int(arguments.get("address_max")),
        )
        merged.blocks.extend(extra.blocks)
    return merged


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "analyze_coverage":
        metadata = load_metadata(arguments["metadata_path"])
        coverage = load_drcov(arguments["coverage_path"])
        result = analyze_coverage(metadata, coverage)
        if arguments.get("format") == "markdown":
            return _tool_result(coverage_to_markdown(result))
        return _tool_result(result)

    if name == "diff_coverage":
        metadata = load_metadata(arguments["metadata_path"])
        left = load_drcov(arguments["left_coverage_path"])
        right = load_drcov(arguments["right_coverage_path"])
        return _tool_result(diff_coverage(metadata, left, right))

    if name == "analyze_flow":
        metadata = load_metadata(arguments["metadata_path"])
        coverage = _load_flow_source(arguments, "coverage_path", "address_log_path")
        result = analyze_flow(
            metadata,
            coverage,
            max_events=arguments.get("max_events") or 0,
            focus_function=arguments.get("focus_function"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(flow_to_markdown(result))
        return _tool_result(result)

    if name == "diff_flow":
        metadata = load_metadata(arguments["metadata_path"])
        left = _load_flow_source(arguments, "left_coverage_path", "left_address_log_path")
        right = _load_flow_source(arguments, "right_coverage_path", "right_address_log_path")
        result = diff_flow(metadata, left, right, focus_function=arguments.get("focus_function"))
        if arguments.get("format") == "markdown":
            return _tool_result(flow_diff_to_markdown(result))
        return _tool_result(result)

    if name == "metadata_from_address_log":
        coverage = _load_many_address_logs(arguments)
        metadata = build_trace_metadata(
            coverage,
            input_path=arguments.get("input_path") or arguments["address_log_paths"][0],
            image_base=_parse_optional_int(arguments.get("image_base")) or 0,
            gap=_parse_optional_int(arguments.get("gap")) or 0x100,
            name_prefix=arguments.get("name_prefix") or "trace_region",
        )
        save_metadata(metadata, arguments["output_path"])
        return _tool_result(
            {
                "output_path": arguments["output_path"],
                "events": len(coverage.blocks),
                "functions": len(metadata.functions),
                "basic_blocks": sum(len(function.blocks) for function in metadata.functions),
            }
        )

    if name == "record_flow":
        run_result = collect_drcov(
            target=arguments["target_path"],
            target_args=arguments.get("target_args") or [],
            output_dir=arguments.get("output_dir") or ".",
            arch=arguments.get("arch") or "x64",
            drrun_path=arguments.get("drrun_path"),
            stdin_text=arguments.get("stdin"),
            run_cwd=arguments.get("run_cwd"),
            timeout=arguments.get("timeout") or 120,
        )
        metadata = load_metadata(arguments["metadata_path"])
        result = analyze_flow(
            metadata,
            load_drcov(run_result.log_path),
            max_events=arguments.get("max_events") or 0,
            focus_function=arguments.get("focus_function"),
        )
        result["coverage_path"] = str(run_result.log_path)
        if arguments.get("format") == "markdown":
            return _tool_result(flow_to_markdown(result))
        return _tool_result(result)

    if name == "collect_drcov":
        run_result = collect_drcov(
            target=arguments["target_path"],
            target_args=arguments.get("target_args") or [],
            output_dir=arguments.get("output_dir") or ".",
            arch=arguments.get("arch") or "x64",
            drrun_path=arguments.get("drrun_path"),
            stdin_text=_ensure_newline(arguments.get("stdin"), arguments.get("auto_newline", False)),
            run_cwd=arguments.get("run_cwd"),
            timeout=arguments.get("timeout") or 120,
        )
        return _tool_result(run_result.to_json())

    if name == "collect_qemu":
        result = collect_qemu_trace(
            target=arguments["target_path"],
            output_dir=arguments.get("output_dir") or ".",
            qemu_arch=arguments["qemu_arch"],
            target_args=arguments.get("target_args") or [],
            stdin_text=_ensure_newline(arguments.get("stdin"), arguments.get("auto_newline", True)),
            run_cwd=arguments.get("run_cwd"),
            trace_mode=arguments.get("trace_mode") or "in_asm",
            qemu_path=arguments.get("qemu_path"),
            timeout=arguments.get("timeout") or 120,
            name=arguments.get("name"),
        )
        return _tool_result(result.to_json())

    if name == "qemu_explore":
        return _tool_result(_mcp_qemu_explore(arguments))

    if name == "export_ghidra_metadata":
        result = export_ghidra_metadata(
            target=arguments["target_path"],
            output=arguments["output_path"],
            ghidra_path=arguments.get("ghidra_path"),
            project_dir=arguments.get("project_dir"),
            script_path=arguments.get("script_path"),
            timeout=arguments.get("timeout") or 600,
        )
        return _tool_result(result)

    if name == "deflatten_flow":
        metadata = load_metadata(arguments["metadata_path"])
        coverage = _load_flow_source(arguments, "coverage_path", "address_log_path")
        result = deflatten_flow(
            metadata, coverage,
            focus_function=arguments.get("focus_function"),
            dispatcher_min_hits=arguments.get("dispatcher_min_hits", 2),
            dispatcher_min_pred=arguments.get("dispatcher_min_pred", 2),
            dispatcher_min_succ=arguments.get("dispatcher_min_succ", 2),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(deflatten_to_markdown(result))
        return _tool_result(result)

    if name == "deflatten_merge":
        metadata = load_metadata(arguments["metadata_path"])
        if arguments.get("address_log_paths"):
            coverages = [
                load_address_log(
                    p,
                    block_size=arguments.get("block_size", 4),
                    min_address=_parse_optional_int(arguments.get("address_min")),
                    max_address=_parse_optional_int(arguments.get("address_max")),
                )
                for p in arguments["address_log_paths"]
            ]
        elif arguments.get("coverage_paths"):
            coverages = [load_drcov(p) for p in arguments["coverage_paths"]]
        else:
            raise ValueError("coverage_paths or address_log_paths is required")
        result = deflatten_merge(
            metadata, coverages,
            labels=arguments.get("labels"),
            focus_function=arguments.get("focus_function"),
            dispatcher_min_hits=arguments.get("dispatcher_min_hits", 2),
            dispatcher_min_pred=arguments.get("dispatcher_min_pred", 2),
            dispatcher_min_succ=arguments.get("dispatcher_min_succ", 2),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(deflatten_merge_to_markdown(result))
        return _tool_result(result)

    if name == "recover_state_transitions":
        metadata = load_metadata(arguments["metadata_path"])
        if arguments.get("address_log_paths"):
            coverages = [
                load_address_log(
                    p,
                    block_size=arguments.get("block_size", 4),
                    min_address=_parse_optional_int(arguments.get("address_min")),
                    max_address=_parse_optional_int(arguments.get("address_max")),
                )
                for p in arguments["address_log_paths"]
            ]
        elif arguments.get("coverage_paths"):
            coverages = [load_drcov(p) for p in arguments["coverage_paths"]]
        else:
            raise ValueError("coverage_paths or address_log_paths is required")
        result = recover_state_transitions(
            metadata, coverages,
            labels=arguments.get("labels"),
            focus_function=arguments.get("focus_function"),
            dispatcher_min_hits=arguments.get("dispatcher_min_hits", 2),
            dispatcher_min_pred=arguments.get("dispatcher_min_pred", 2),
            dispatcher_min_succ=arguments.get("dispatcher_min_succ", 2),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(state_transitions_to_markdown(result))
        return _tool_result(result)

    raise ValueError(f"unknown tool: {name}")


async def _stdio_loop() -> None:
    while True:
        line = await asyncio.to_thread(sys.stdin.readline)
        if not line:
            return
        request = json.loads(line)
        response: dict[str, Any] = {"jsonrpc": "2.0", "id": request.get("id")}
        try:
            method = request.get("method")
            params = request.get("params") or {}
            if method == "initialize":
                response["result"] = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "beaconflow", "version": "0.1.0"},
                }
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                response["result"] = {
                    "tools": [
                        {"name": name, **definition}
                        for name, definition in TOOLS.items()
                    ]
                }
            elif method == "tools/call":
                response["result"] = _call_tool(params["name"], params.get("arguments") or {})
            else:
                response["error"] = {"code": -32601, "message": f"method not found: {method}"}
        except Exception as exc:
            response["error"] = {"code": -32000, "message": str(exc)}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def main() -> int:
    asyncio.run(_stdio_loop())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
