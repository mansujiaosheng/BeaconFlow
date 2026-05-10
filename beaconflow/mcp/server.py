from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from beaconflow.analysis import analyze_coverage, analyze_flow, diff_coverage
from beaconflow.coverage import load_drcov
from beaconflow.coverage.runner import collect_drcov
from beaconflow.ida import load_metadata
from beaconflow.reports import coverage_to_markdown, flow_to_markdown


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
        "description": "Recover ordered target-module basic-block flow from a drcov file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "coverage_path": {"type": "string"},
                "max_events": {"type": "integer", "default": 0},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path", "coverage_path"],
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
            },
            "required": ["target_path"],
        },
    },
}


def _tool_result(value: str | dict[str, Any]) -> dict[str, Any]:
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    return {"content": [{"type": "text", "text": text}]}


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
        coverage = load_drcov(arguments["coverage_path"])
        result = analyze_flow(metadata, coverage, max_events=arguments.get("max_events") or 0)
        if arguments.get("format") == "markdown":
            return _tool_result(flow_to_markdown(result))
        return _tool_result(result)

    if name == "record_flow":
        log_path = collect_drcov(
            target=arguments["target_path"],
            target_args=arguments.get("target_args") or [],
            output_dir=arguments.get("output_dir") or ".",
            arch=arguments.get("arch") or "x64",
            drrun_path=arguments.get("drrun_path"),
            stdin_text=arguments.get("stdin"),
        )
        metadata = load_metadata(arguments["metadata_path"])
        result = analyze_flow(metadata, load_drcov(log_path), max_events=arguments.get("max_events") or 0)
        result["coverage_path"] = str(log_path)
        if arguments.get("format") == "markdown":
            return _tool_result(flow_to_markdown(result))
        return _tool_result(result)

    if name == "collect_drcov":
        log_path = collect_drcov(
            target=arguments["target_path"],
            target_args=arguments.get("target_args") or [],
            output_dir=arguments.get("output_dir") or ".",
            arch=arguments.get("arch") or "x64",
            drrun_path=arguments.get("drrun_path"),
            stdin_text=arguments.get("stdin"),
        )
        return _tool_result({"coverage_path": str(log_path)})

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
