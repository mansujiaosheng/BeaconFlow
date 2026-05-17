from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from beaconflow.analysis import analyze_coverage, analyze_decision_points, analyze_flow, analyze_input_taint, analyze_roles, analyze_trace_compare, analyze_value_trace, decompile_function, decompile_to_markdown, deflatten_flow, deflatten_merge, diff_coverage, diff_flow, feedback_auto_explore, find_decision_points, inspect_decision_point, inspect_role, ir_to_markdown, match_signatures, normalize_to_ir, rank_input_branches, recover_state_transitions, sig_match_to_markdown
from beaconflow.analysis.ai_digest import attach_ai_digest, compact_report, infer_report_kind
from beaconflow.coverage import collect_qemu_trace, load_address_log, load_drcov, qemu_available
from beaconflow.coverage.runner import collect_drcov
from beaconflow.doctor import doctor_to_markdown, run_doctor
from beaconflow.ghidra import export_ghidra_metadata, find_ghidra_headless
from beaconflow.ida import load_metadata, save_metadata
from beaconflow.metadata import build_trace_metadata
from beaconflow.reports import branch_rank_to_markdown, coverage_to_markdown, decision_points_to_markdown, deflatten_merge_to_markdown, deflatten_to_markdown, feedback_explore_to_markdown, flow_diff_to_markdown, flow_to_markdown, input_taint_to_markdown, roles_to_markdown, state_transitions_to_markdown, trace_compare_to_markdown, value_trace_to_markdown
from beaconflow.workspace import add_metadata as ws_add_metadata, add_note as ws_add_note, add_report as ws_add_report, add_run as ws_add_run, case_to_markdown, destroy_case, init_case, list_notes, list_reports, list_runs, load_manifest, summarize_case
from beaconflow.wasm_parser import analyze_wasm, wasm_to_metadata
from beaconflow.runtime.trace_calls import trace_calls, trace_calls_to_markdown
from beaconflow.runtime.trace_compare import trace_compare, trace_compare_to_markdown
from beaconflow.analysis.auto_explore import auto_explore_loop, auto_explore_to_markdown
from beaconflow.analysis.input_impact import input_impact, input_impact_to_markdown
from beaconflow.analysis.decision_points import find_decision_points
from beaconflow.analysis.role_detector import analyze_roles
from beaconflow.update_checker import check_for_update, update_check_to_markdown


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
                "allow_unbounded_address_logs": {"type": "boolean", "default": False, "description": "Allow post-processing large QEMU logs without address_min/address_max. By default BeaconFlow returns a warning instead of spending minutes clustering runtime/library addresses."},
                "max_unbounded_log_bytes": {"type": "integer", "default": 8000000, "description": "Soft limit for total QEMU log bytes when no address range is supplied."},
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
                "backend": {"type": "string", "enum": ["pyghidra", "headless"], "default": "pyghidra", "description": "Default uses pyghidra; headless keeps the legacy analyzeHeadless script path."},
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
                "dispatcher_mode": {"type": "string", "enum": ["strict", "balanced", "aggressive"], "default": "strict", "description": "strict requires hot + multi-predecessor + multi-successor shape; aggressive is legacy heuristic-like."},
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
                "dispatcher_mode": {"type": "string", "enum": ["strict", "balanced", "aggressive"], "default": "strict"},
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
                "dispatcher_mode": {"type": "string", "enum": ["strict", "balanced", "aggressive"], "default": "strict"},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "branch_rank": {
        "description": "Rank input-dependent branch points across bad/better/good drcov or address-log traces.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string"},
                "bad_coverage_path": {"type": "string"},
                "bad_address_log_path": {"type": "string"},
                "better_coverage_paths": {"type": "array", "items": {"type": "string"}},
                "better_address_log_paths": {"type": "array", "items": {"type": "string"}},
                "good_coverage_paths": {"type": "array", "items": {"type": "string"}},
                "good_address_log_paths": {"type": "array", "items": {"type": "string"}},
                "labels": {"type": "array", "items": {"type": "string"}},
                "address_min": {"type": "string"},
                "address_max": {"type": "string"},
                "block_size": {"type": "integer", "default": 4},
                "focus_function": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "ai_summary": {
        "description": "Compact an existing BeaconFlow JSON report into an AI-first digest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_path": {"type": "string"},
                "kind": {"type": "string", "enum": ["coverage", "flow", "flow_diff", "deflatten", "deflatten_merge", "recover_state", "branch_rank", "qemu_explore", "unknown"]},
                "max_findings": {"type": "integer", "default": 5},
            },
            "required": ["report_path"],
        },
    },
    "inspect_block": {
        "description": "Show detailed context for a single basic block: instructions, calls, strings, constants, data/code refs, predecessors, successors.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "address": {"type": "string", "description": "Block start address (e.g. 0x1400014c7)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path", "address"],
        },
    },
    "inspect_function": {
        "description": "Show detailed context for a function and all its basic blocks: instructions, calls, strings, constants per block.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "name": {"type": "string", "description": "Function name (e.g. check_flag)."},
                "address": {"type": "string", "description": "Function start address (e.g. 0x140001460)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path"],
        },
    },
    "find_decision_points": {
        "description": "Find and prioritize decision points in a binary: cmp+jcc, test+jcc, checker calls (strcmp/memcmp/strlen), cmovcc, setcc, jump tables. Returns AI-prioritized list with reasons.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "focus_function": {"type": "string", "description": "Only find decision points in this function (name or address)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "inspect_decision_point": {
        "description": "Inspect a single decision point by block address. Shows type, priority, compare/branch instructions, successors, and related block context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "address": {"type": "string", "description": "Block start address of the decision point (e.g. 0x1400014c7)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path", "address"],
        },
    },
    "detect_roles": {
        "description": "Detect candidate roles for functions (validator, crypto_like, dispatcher, input_handler, success/failure_handler, anti_debug, etc.) using configurable rules based on name patterns, decision points, call patterns, and block features.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "rules_path": {"type": "string", "description": "Path to custom role rules YAML file."},
                "focus_function": {"type": "string", "description": "Only detect roles for this function (name or address)."},
                "min_score": {"type": "number", "description": "Minimum score threshold (default: 0.1)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "inspect_role": {
        "description": "Inspect the detected role for a specific function. Shows role, confidence, score, evidence, matched rules, and recommended actions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "function_name": {"type": "string", "description": "Function name to inspect."},
                "address": {"type": "string", "description": "Function start address to inspect (e.g. 0x401000)."},
                "rules_path": {"type": "string", "description": "Path to custom role rules YAML file."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path"],
        },
    },
    "trace_values": {
        "description": "Trace register/memory/compare values at key decision points. Extracts compare events, input sites, and dispatcher states from metadata. Optionally uses coverage data to infer branch results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "coverage_path": {"type": "string", "description": "Optional drcov coverage file for branch result inference."},
                "address_log_path": {"type": "string", "description": "Optional QEMU address log for branch result inference."},
                "focus_function": {"type": "string", "description": "Only trace values in this function (name or address)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "analyze_compare": {
        "description": "Extract compare semantics at input check points from metadata (static analysis). Identifies cmp reg/imm, cmp reg/reg, test, strcmp/strncmp/memcmp, strlen, and switch/jump table patterns. Outputs structured comparison information with inferred results. Requires metadata_path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "coverage_path": {"type": "string", "description": "Optional drcov coverage file for result inference."},
                "address_log_path": {"type": "string", "description": "Optional QEMU address log for result inference."},
                "focus_function": {"type": "string", "description": "Only extract compares in this function (name or address)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "doctor": {
        "description": "Check BeaconFlow environment and dependencies. Verifies Python version, beaconflow import, IDA/Ghidra availability, DynamoRIO drrun, QEMU user-mode, WSL, MCP, and PyYAML.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "qemu_arch": {"type": "string", "description": "Check specific QEMU arch (e.g. loongarch64, mips, arm)."},
                "target_path": {"type": "string", "description": "Check if a target binary file exists."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
        },
    },
    "input_taint": {
        "description": "Lightweight taint analysis: trace input bytes to branch decisions. Identifies input sources (read/recv/scanf), compare sinks (CMP/TEST), and the register propagation paths connecting them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "focus_function": {"type": "string", "description": "Only analyze taint in this function (name or address)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "feedback_explore": {
        "description": "Generate input modification plan based on failed compare results. Uses trace_compare to identify failed comparisons, then suggests byte-level patches to fix the input. Supports multi-round exploration strategy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "focus_function": {"type": "string", "description": "Only explore compares in this function."},
                "input_file_path": {"type": "string", "description": "Current input file to patch (optional)."},
                "input_offset_base": {"type": "integer", "description": "Base offset for input patches.", "default": 0},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "json"},
            },
            "required": ["metadata_path"],
        },
    },
    "decompile_function": {
        "description": "Generate pseudo-code summary for a function from metadata. Produces block-level pseudo-code with branch conditions, calls, and loop detection. Useful for understanding function logic without full decompilation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "function_name": {"type": "string", "description": "Function name to decompile."},
                "function_address": {"type": "string", "description": "Function start address (e.g. 0x401000)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path"],
        },
    },
    "normalize_ir": {
        "description": "Convert function instructions to normalized IR (architecture-independent). Supports x86/x64, ARM/AArch64, MIPS, LoongArch, and RISC-V. Outputs ASSIGN/LOAD/STORE/COMPARE/BRANCH/CALL/RETURN/BINARY operations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "function_name": {"type": "string", "description": "Function name to convert."},
                "function_address": {"type": "string", "description": "Function start address (e.g. 0x401000)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path"],
        },
    },
    "sig_match": {
        "description": "Match crypto/VM/packer/anti-debug signatures in metadata. Identifies AES, DES, RC4, TEA, ChaCha20, SM4, MD5/SHA, Base64, CRC, VM interpreters, UPX, VMProtect, and anti-debug techniques.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "metadata_path": {"type": "string", "description": "Path to metadata JSON file."},
                "sig_library_path": {"type": "string", "description": "Path to custom signature library YAML file."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["metadata_path"],
        },
    },
    "init_case": {
        "description": "Initialize a case workspace for a target binary. Creates .case/ directory with manifest.json, metadata/, runs/, reports/, notes/ subdirectories. AI Agent can work on the same case across multiple analysis rounds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Target binary file path."},
                "arch": {"type": "string", "default": "x64", "description": "Target architecture (e.g. x64, loongarch64, mips, arm)."},
                "backend": {"type": "string", "enum": ["qemu", "dynamorio"], "default": "qemu", "description": "Execution backend."},
                "root": {"type": "string", "description": "Workspace root directory (default: current directory)."},
                "overwrite": {"type": "boolean", "default": False, "description": "Overwrite existing workspace."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["target_path"],
        },
    },
    "summarize_case": {
        "description": "Summarize the current case workspace status. Shows target info, metadata count, runs count with verdict summary, reports count, and notes count. Helps AI Agent quickly understand current analysis progress.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Workspace root directory."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
        },
    },
    "add_metadata_to_case": {
        "description": "Add a metadata file to the case workspace. Copies the metadata JSON into .case/metadata/ and records it in manifest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Metadata name (e.g. 'ghidra', 'ida')."},
                "path": {"type": "string", "description": "Path to metadata JSON file."},
                "description": {"type": "string", "description": "Description of this metadata."},
                "root": {"type": "string", "description": "Workspace root directory."},
            },
            "required": ["name", "path"],
        },
    },
    "add_run_to_case": {
        "description": "Add a run/trace result to the case workspace. Records stdin, verdict, return code, and copies the trace file into .case/runs/.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Run name (e.g. 'case001')."},
                "path": {"type": "string", "description": "Path to run output file (drcov/trace log)."},
                "stdin_preview": {"type": "string", "description": "Preview of stdin input used."},
                "verdict": {"type": "string", "description": "Run verdict (success, failure, nonzero-exit, unknown)."},
                "returncode": {"type": "integer", "description": "Process return code."},
                "notes": {"type": "string", "description": "Additional notes about this run."},
                "root": {"type": "string", "description": "Workspace root directory."},
            },
            "required": ["name"],
        },
    },
    "add_report_to_case": {
        "description": "Add an analysis report to the case workspace. Copies the report file into .case/reports/ and records it in manifest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Report name."},
                "path": {"type": "string", "description": "Path to report file."},
                "report_type": {"type": "string", "description": "Report type (e.g. 'flow', 'coverage', 'sig-match')."},
                "description": {"type": "string", "description": "Description of this report."},
                "root": {"type": "string", "description": "Workspace root directory."},
            },
            "required": ["name", "path"],
        },
    },
    "add_note_to_case": {
        "description": "Add a note to the case workspace. Useful for AI Agent to record analysis findings, hypotheses, or next steps across multiple rounds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Note content."},
                "title": {"type": "string", "description": "Note title."},
                "root": {"type": "string", "description": "Workspace root directory."},
            },
            "required": ["content"],
        },
    },
    "list_case_runs": {
        "description": "List all runs in the case workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Workspace root directory."},
            },
        },
    },
    "list_case_reports": {
        "description": "List all reports in the case workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Workspace root directory."},
            },
        },
    },
    "list_case_notes": {
        "description": "List all notes in the case workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Workspace root directory."},
            },
        },
    },
    "export_wasm_metadata": {
        "description": "Export metadata from a WebAssembly (.wasm) binary using pure Python parser. Extracts functions, basic blocks, instructions, exports, and imports. No external dependencies required.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "wasm_path": {"type": "string", "description": "Path to WASM binary file."},
                "output_path": {"type": "string", "description": "Output metadata JSON path."},
            },
            "required": ["wasm_path", "output_path"],
        },
    },
    "wasm_analyze": {
        "description": "Analyze a WebAssembly module for RE triage: imports, exports, strings, data segments, and function summaries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "wasm_path": {"type": "string", "description": "Path to WASM binary file."},
                "output_path": {"type": "string", "description": "Optional output report path."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
                "min_string": {"type": "integer", "default": 4, "description": "Minimum ASCII string length to report."},
                "max_functions": {"type": "integer", "default": 0, "description": "Limit function summaries; 0 means all."},
            },
            "required": ["wasm_path"],
        },
    },
    "trace_calls": {
        "description": "Trace library function calls (strcmp/memcmp/strncmp/strlen/etc.) at runtime using Frida. Captures actual parameter values, return values, and call sites. Most useful for seeing what values are being compared in CTF challenges. Default filter_user_only=true filters out CRT/runtime library internal calls to reduce noise.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target binary to run."},
                "stdin_data": {"type": "string", "description": "Stdin data to send to the target."},
                "auto_newline": {"type": "boolean", "default": True, "description": "Auto-append newline to stdin."},
                "run_cwd": {"type": "string", "description": "Working directory for the target process."},
                "timeout": {"type": "integer", "default": 30, "description": "Timeout in seconds."},
                "hook": {"type": "string", "description": "Comma-separated list of functions to hook."},
                "max_read": {"type": "integer", "default": 128, "description": "Max bytes to read from pointer args."},
                "max_events": {"type": "integer", "default": 1000, "description": "Max events to capture."},
                "filter_user_only": {"type": "boolean", "default": True, "description": "Only keep calls from user code (main module), filtering out CRT/runtime library internal noise."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["target"],
        },
    },
    "trace_compare": {
        "description": "Trace compare instructions at runtime using Frida. Extracts register values at cmp/test/jcc decision points. Helps AI understand what values are being compared at branch points. Currently supports x86/x64 only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target binary to run."},
                "metadata_path": {"type": "string", "description": "Path to metadata JSON (to find decision points automatically)."},
                "stdin_data": {"type": "string", "description": "Stdin data to send to the target."},
                "auto_newline": {"type": "boolean", "default": True, "description": "Auto-append newline to stdin."},
                "focus_function": {"type": "string", "description": "Only hook decision points in this function."},
                "addresses": {"type": "string", "description": "Comma-separated list of addresses to hook (hex)."},
                "address_min": {"type": "string", "description": "Minimum address to hook (hex)."},
                "address_max": {"type": "string", "description": "Maximum address to hook (hex)."},
                "timeout": {"type": "integer", "default": 30, "description": "Timeout in seconds."},
                "max_events": {"type": "integer", "default": 1000, "description": "Max events to capture."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["target"],
        },
    },
    "auto_explore_loop": {
        "description": "Multi-round feedback-driven input exploration. Keeps better inputs and continues mutating across rounds. Not a full fuzzer - focuses on AI-readable, explainable results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target binary."},
                "metadata_path": {"type": "string", "description": "Path to metadata JSON."},
                "seed": {"type": "string", "description": "Initial seed input."},
                "mutate_template": {"type": "string", "description": "Mutation template (e.g. 'ISCC{%32x}')."},
                "rounds": {"type": "integer", "default": 20, "description": "Number of exploration rounds."},
                "batch_size": {"type": "integer", "default": 64, "description": "Mutations per round."},
                "keep_top": {"type": "integer", "default": 8, "description": "Top candidates to keep per round."},
                "success_regex": {"type": "string", "description": "Regex matching success output."},
                "failure_regex": {"type": "string", "description": "Regex matching failure output."},
                "positions": {"type": "string", "description": "Mutation position range (e.g. '5:37')."},
                "alphabet": {"type": "string", "description": "Mutation character set."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["target", "metadata_path"],
        },
    },
    "input_impact": {
        "description": "Black-box differential input impact analysis. Perturbs each input position and observes output changes. Infers which input bytes affect which branches. Not a full taint analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target binary."},
                "seed": {"type": "string", "description": "Seed input string."},
                "positions": {"type": "string", "description": "Position range to test (e.g. '5:37')."},
                "alphabet": {"type": "string", "description": "Characters to try (default: 0-9a-f)."},
                "max_mutations": {"type": "integer", "default": 8, "description": "Max mutations per position."},
                "timeout": {"type": "integer", "default": 10, "description": "Timeout per run (seconds)."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
            "required": ["target", "seed"],
        },
    },
    "check_update": {
        "description": "Check if a newer version of BeaconFlow is available on GitHub. Non-mandatory - just shows update info and the command to update. Results are cached for 1 hour.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "force": {"type": "boolean", "default": False, "description": "Force check, ignoring cache."},
                "format": {"type": "string", "enum": ["json", "markdown"], "default": "markdown"},
            },
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
    has_address_range = bool(arguments.get("address_min") or arguments.get("address_max"))
    total_log_bytes = sum(Path(path).stat().st_size for path in log_paths if Path(path).exists())
    max_unbounded = int(arguments.get("max_unbounded_log_bytes") or 8_000_000)
    if not has_address_range and not arguments.get("allow_unbounded_address_logs", False) and total_log_bytes > max_unbounded:
        report_runs = [
            {
                "name": item["name"],
                "stdin_preview": _preview(item["stdin"]),
                "log_path": str(item["qemu"].log_path),
                "returncode": item["qemu"].returncode,
                "stdout": item["qemu"].stdout,
                "stderr": item["qemu"].stderr,
                "verdict": _classify_run(item["qemu"].stdout, item["qemu"].stderr, item["qemu"].returncode, arguments),
                "output_fingerprint": _output_fingerprint(item["qemu"].stdout, item["qemu"].stderr),
            }
            for item in runs
        ]
        return {
            "status": "needs_address_range",
            "summary": {
                "target": target,
                "qemu_arch": qemu_arch,
                "trace_mode": arguments.get("trace_mode") or "in_asm",
                "runs": len(report_runs),
                "total_log_bytes": total_log_bytes,
                "max_unbounded_log_bytes": max_unbounded,
            },
            "runs": report_runs,
            "warnings": [
                "QEMU logs were collected, but BeaconFlow skipped unbounded post-processing because no address_min/address_max was supplied and the logs exceed the soft limit.",
                "Re-run qemu_explore with address_min/address_max for the target code range, or set allow_unbounded_address_logs=true if full-log clustering is intentional.",
            ],
            "recommended_arguments": {
                "address_min": "0x<target_text_start>",
                "address_max": "0x<target_text_end>",
            },
        }

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

    return attach_ai_digest("qemu_explore", {
        "summary": {
            "target": target,
            "qemu_arch": qemu_arch,
            "trace_mode": arguments.get("trace_mode") or "in_asm",
            "hit_count_precision": "exact" if (arguments.get("trace_mode") or "in_asm") == "exec,nochain" else ("translation-log" if (arguments.get("trace_mode") or "in_asm") == "in_asm" else "unknown"),
            "qemu_available": qemu_available(qemu_arch),
            "metadata_path": str(metadata_path),
            "runs": len(report_runs),
            "total_log_bytes": total_log_bytes,
            "total_union_functions": len(metadata.functions),
            "total_union_blocks": sum(len(f.blocks) for f in metadata.functions),
        },
        "runs": report_runs,
    })


def _qemu_explore_to_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# BeaconFlow QEMU Explore",
        "",
        f"- Status: `{report.get('status', 'ok')}`",
        f"- Target: `{summary.get('target', '')}`",
        f"- QEMU arch: `{summary.get('qemu_arch', '')}`",
        f"- Trace mode: `{summary.get('trace_mode', '')}`",
        f"- Runs: {summary.get('runs', 0)}",
    ]
    if summary.get("total_log_bytes") is not None:
        lines.append(f"- Total log bytes: {summary.get('total_log_bytes')}")
    if summary.get("metadata_path"):
        lines.append(f"- Metadata: `{summary.get('metadata_path')}`")
    lines.append("")

    warnings = report.get("warnings") or []
    if warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")

    digest = report.get("ai_digest") or {}
    if digest.get("top_findings"):
        lines.extend(["## AI Digest", ""])
        for finding in digest.get("top_findings", [])[:5]:
            lines.append(f"- {finding.get('evidence_id')}: {finding.get('claim')}")
        lines.append("")

    runs = report.get("runs") or []
    if runs:
        lines.extend(["## Runs", ""])
        lines.append("| Name | Verdict | New vs baseline | Unique blocks | Output | Log |")
        lines.append("| --- | --- | ---: | ---: | --- | --- |")
        for run in runs:
            lines.append(
                f"| `{run.get('name', '')}` | `{run.get('verdict', '')}` | "
                f"{run.get('new_blocks_vs_baseline', '')} | {run.get('unique_blocks', '')} | "
                f"`{run.get('output_fingerprint', '')}` | `{run.get('log_path', '')}` |"
            )
        lines.append("")

    rec = report.get("recommended_arguments") or {}
    if rec:
        lines.extend(["## Recommended Arguments", ""])
        for key, value in rec.items():
            lines.append(f"- `{key}`: `{value}`")
        lines.append("")
    return "\n".join(lines)


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
        result = _mcp_qemu_explore(arguments)
        if arguments.get("format") == "markdown":
            return _tool_result(_qemu_explore_to_markdown(result))
        return _tool_result(result)

    if name == "export_ghidra_metadata":
        result = export_ghidra_metadata(
            target=arguments["target_path"],
            output=arguments["output_path"],
            ghidra_path=arguments.get("ghidra_path"),
            project_dir=arguments.get("project_dir"),
            script_path=arguments.get("script_path"),
            timeout=arguments.get("timeout") or 600,
            backend=arguments.get("backend") or "pyghidra",
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
            dispatcher_mode=arguments.get("dispatcher_mode") or "strict",
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
            dispatcher_mode=arguments.get("dispatcher_mode") or "strict",
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
            dispatcher_mode=arguments.get("dispatcher_mode") or "strict",
        )
        if arguments.get("format") == "markdown":
            return _tool_result(state_transitions_to_markdown(result))
        return _tool_result(result)

    if name == "branch_rank":
        metadata = load_metadata(arguments["metadata_path"])
        coverages = []
        labels = []
        roles = []
        block_size = arguments.get("block_size", 4)
        address_min = _parse_optional_int(arguments.get("address_min"))
        address_max = _parse_optional_int(arguments.get("address_max"))

        def add_trace(path: str, role: str, is_address_log: bool) -> None:
            if is_address_log:
                coverages.append(load_address_log(path, block_size=block_size, min_address=address_min, max_address=address_max))
            else:
                coverages.append(load_drcov(path))
            roles.append(role)

        if arguments.get("bad_address_log_path"):
            add_trace(arguments["bad_address_log_path"], "bad", True)
        elif arguments.get("bad_coverage_path"):
            add_trace(arguments["bad_coverage_path"], "bad", False)
        else:
            raise ValueError("bad_coverage_path or bad_address_log_path is required")

        for path in arguments.get("better_address_log_paths") or []:
            add_trace(path, "better", True)
        for path in arguments.get("better_coverage_paths") or []:
            add_trace(path, "better", False)
        for path in arguments.get("good_address_log_paths") or []:
            add_trace(path, "good", True)
        for path in arguments.get("good_coverage_paths") or []:
            add_trace(path, "good", False)

        labels = arguments.get("labels") or [f"{role}{index}" for index, role in enumerate(roles)]
        result = rank_input_branches(
            metadata,
            coverages,
            labels=labels,
            roles=roles,
            focus_function=arguments.get("focus_function"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(branch_rank_to_markdown(result))
        return _tool_result(result)

    if name == "ai_summary":
        result = json.loads(Path(arguments["report_path"]).read_text(encoding="utf-8"))
        kind = arguments.get("kind") or infer_report_kind(result)
        return _tool_result(compact_report(kind, result, max_findings=arguments.get("max_findings") or 5))

    if name == "inspect_block":
        from beaconflow.models import hex_addr as _hex_addr
        metadata = load_metadata(arguments["metadata_path"])
        addr = _parse_optional_int(arguments["address"])
        if addr is None:
            raise ValueError("Invalid address")
        for func in metadata.functions:
            for block in func.blocks:
                if block.start == addr:
                    result = {
                        "function": func.name,
                        "function_start": _hex_addr(func.start),
                        "block_start": _hex_addr(block.start),
                        "block_end": _hex_addr(block.end),
                        "successors": [_hex_addr(s) for s in block.succs],
                        "context": block.context.to_json(),
                    }
                    return _tool_result(result)
        raise ValueError(f"Block at {_hex_addr(addr)} not found in metadata")

    if name == "inspect_function":
        from beaconflow.models import hex_addr as _hex_addr
        metadata = load_metadata(arguments["metadata_path"])
        target_func = None
        if arguments.get("name"):
            for func in metadata.functions:
                if func.name == arguments["name"]:
                    target_func = func
                    break
        elif arguments.get("address"):
            addr = _parse_optional_int(arguments["address"])
            if addr is not None:
                for func in metadata.functions:
                    if func.start == addr:
                        target_func = func
                        break
        if target_func is None:
            raise ValueError("Function not found in metadata")
        blocks_data = []
        for block in target_func.blocks:
            blocks_data.append({
                "start": _hex_addr(block.start),
                "end": _hex_addr(block.end),
                "successors": [_hex_addr(s) for s in block.succs],
                "context": block.context.to_json(),
            })
        result = {
            "name": target_func.name,
            "start": _hex_addr(target_func.start),
            "end": _hex_addr(target_func.end),
            "block_count": len(target_func.blocks),
            "blocks": blocks_data,
        }
        return _tool_result(result)

    if name == "find_decision_points":
        metadata = load_metadata(arguments["metadata_path"])
        result = analyze_decision_points(metadata, focus_function=arguments.get("focus_function"))
        if arguments.get("format") == "markdown":
            return _tool_result(decision_points_to_markdown(result))
        return _tool_result(result)

    if name == "inspect_decision_point":
        from beaconflow.models import hex_addr as _hex_addr
        metadata = load_metadata(arguments["metadata_path"])
        addr = _parse_optional_int(arguments["address"])
        if addr is None:
            raise ValueError("Invalid address")
        result = inspect_decision_point(metadata, addr)
        if result is None:
            raise ValueError(f"No decision point found at {_hex_addr(addr)}")
        return _tool_result(result)

    if name == "detect_roles":
        metadata = load_metadata(arguments["metadata_path"])
        result = analyze_roles(
            metadata,
            rules_path=arguments.get("rules_path"),
            focus_function=arguments.get("focus_function"),
            min_score=arguments.get("min_score", 0.1),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(roles_to_markdown(result))
        return _tool_result(result)

    if name == "inspect_role":
        metadata = load_metadata(arguments["metadata_path"])
        addr = _parse_optional_int(arguments.get("address"))
        result = inspect_role(
            metadata,
            function_name=arguments.get("function_name"),
            address=addr,
            rules_path=arguments.get("rules_path"),
        )
        if result is None:
            raise ValueError("No role detected for the specified function")
        return _tool_result(result)

    if name == "trace_values":
        metadata = load_metadata(arguments["metadata_path"])
        executed_addrs = None
        if arguments.get("coverage_path"):
            coverage = load_drcov(arguments["coverage_path"])
            executed_addrs = set()
            for block in coverage.blocks:
                if block.absolute_start is not None:
                    executed_addrs.add(block.absolute_start)
        elif arguments.get("address_log_path"):
            addr_log = load_address_log(
                arguments["address_log_path"],
                block_size=arguments.get("block_size", 4),
            )
            executed_addrs = set()
            for block in addr_log.blocks:
                if block.absolute_start is not None:
                    executed_addrs.add(block.absolute_start)
        result = analyze_value_trace(
            metadata,
            executed_addrs=executed_addrs,
            focus_function=arguments.get("focus_function"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(value_trace_to_markdown(result))
        return _tool_result(result)

    if name == "analyze_compare":
        metadata = load_metadata(arguments["metadata_path"])
        executed_addrs = None
        if arguments.get("coverage_path"):
            coverage = load_drcov(arguments["coverage_path"])
            executed_addrs = set()
            for block in coverage.blocks:
                if block.absolute_start is not None:
                    executed_addrs.add(block.absolute_start)
        elif arguments.get("address_log_path"):
            addr_log = load_address_log(
                arguments["address_log_path"],
                block_size=arguments.get("block_size", 4),
            )
            executed_addrs = set()
            for block in addr_log.blocks:
                if block.absolute_start is not None:
                    executed_addrs.add(block.absolute_start)
        result = analyze_trace_compare(
            metadata,
            executed_addrs=executed_addrs,
            focus_function=arguments.get("focus_function"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(trace_compare_to_markdown(result))
        return _tool_result(result)

    if name == "doctor":
        result = run_doctor(
            qemu_arch=arguments.get("qemu_arch"),
            target=arguments.get("target_path"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(doctor_to_markdown(result))
        return _tool_result(result)

    if name == "input_taint":
        metadata = load_metadata(arguments["metadata_path"])
        result = analyze_input_taint(
            metadata,
            focus_function=arguments.get("focus_function"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(input_taint_to_markdown(result))
        return _tool_result(result)

    if name == "feedback_explore":
        metadata = load_metadata(arguments["metadata_path"])
        trace_compare_result = analyze_trace_compare(
            metadata,
            focus_function=arguments.get("focus_function"),
        )
        current_input = None
        if arguments.get("input_file_path"):
            current_input = Path(arguments["input_file_path"]).read_bytes()
        result = feedback_auto_explore(
            metadata,
            trace_compare_result,
            current_input=current_input,
            input_offset_base=arguments.get("input_offset_base", 0),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(feedback_explore_to_markdown(result))
        return _tool_result(result)

    if name == "decompile_function":
        metadata = load_metadata(arguments["metadata_path"])
        func_address = None
        if arguments.get("function_address"):
            addr_str = arguments["function_address"]
            try:
                func_address = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            except ValueError:
                pass
        result = decompile_function(
            metadata,
            function_name=arguments.get("function_name"),
            function_address=func_address,
        )
        if arguments.get("format") == "markdown":
            return _tool_result(decompile_to_markdown(result))
        return _tool_result(result)

    if name == "normalize_ir":
        metadata = load_metadata(arguments["metadata_path"])
        func_address = None
        if arguments.get("function_address"):
            addr_str = arguments["function_address"]
            try:
                func_address = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            except ValueError:
                pass
        result = normalize_to_ir(
            metadata,
            function_name=arguments.get("function_name"),
            function_address=func_address,
        )
        if arguments.get("format") == "markdown":
            return _tool_result(ir_to_markdown(result))
        return _tool_result(result)

    if name == "sig_match":
        metadata = load_metadata(arguments["metadata_path"])
        result = match_signatures(
            metadata,
            sig_library_path=arguments.get("sig_library_path"),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(sig_match_to_markdown(result))
        return _tool_result(result)

    if name == "init_case":
        result = init_case(
            target=arguments["target_path"],
            arch=arguments.get("arch", "x64"),
            backend=arguments.get("backend", "qemu"),
            root=arguments.get("root"),
            overwrite=arguments.get("overwrite", False),
        )
        if arguments.get("format") == "markdown":
            if result.get("status") == "already_exists":
                return _tool_result(f"# Case Already Exists\n\nWorkspace at `{result.get('case_dir', '')}`.\nUse `overwrite` to reinitialize.\n")
            if result.get("status") == "error":
                return _tool_result(f"# Error\n\n{result.get('message', '')}\n")
            summary = summarize_case(root=arguments.get("root"))
            return _tool_result(case_to_markdown(summary))
        return _tool_result(result)

    if name == "summarize_case":
        summary = summarize_case(root=arguments.get("root"))
        if arguments.get("format") == "markdown":
            return _tool_result(case_to_markdown(summary))
        return _tool_result(summary)

    if name == "add_metadata_to_case":
        result = ws_add_metadata(
            name=arguments["name"],
            path=arguments["path"],
            description=arguments.get("description", ""),
            root=arguments.get("root"),
        )
        return _tool_result(result)

    if name == "add_run_to_case":
        result = ws_add_run(
            name=arguments["name"],
            path=arguments.get("path"),
            stdin_preview=arguments.get("stdin_preview"),
            verdict=arguments.get("verdict"),
            returncode=arguments.get("returncode"),
            notes=arguments.get("notes", ""),
            root=arguments.get("root"),
        )
        return _tool_result(result)

    if name == "add_report_to_case":
        result = ws_add_report(
            name=arguments["name"],
            path=arguments["path"],
            report_type=arguments.get("report_type", ""),
            description=arguments.get("description", ""),
            root=arguments.get("root"),
        )
        return _tool_result(result)

    if name == "add_note_to_case":
        result = ws_add_note(
            content=arguments["content"],
            title=arguments.get("title", ""),
            root=arguments.get("root"),
        )
        return _tool_result(result)

    if name == "list_case_runs":
        return _tool_result(list_runs(root=arguments.get("root")))

    if name == "list_case_reports":
        return _tool_result(list_reports(root=arguments.get("root")))

    if name == "list_case_notes":
        return _tool_result(list_notes(root=arguments.get("root")))

    if name == "export_wasm_metadata":
        result = wasm_to_metadata(
            wasm_path=arguments["wasm_path"],
            output_path=arguments["output_path"],
        )
        return _tool_result(result)

    if name == "wasm_analyze":
        result = analyze_wasm(
            wasm_path=arguments["wasm_path"],
            output_path=arguments.get("output_path"),
            fmt=arguments.get("format") or "markdown",
            min_string=arguments.get("min_string") or 4,
            max_functions=arguments.get("max_functions") or 0,
        )
        return _tool_result(result)

    if name == "trace_calls":
        result = trace_calls(
            target=arguments["target"],
            stdin_data=arguments.get("stdin_data"),
            auto_newline=arguments.get("auto_newline", True),
            run_cwd=arguments.get("run_cwd"),
            timeout=arguments.get("timeout", 30),
            hook=arguments.get("hook"),
            max_read=arguments.get("max_read", 128),
            max_events=arguments.get("max_events", 1000),
            filter_user_only=arguments.get("filter_user_only", True),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(trace_calls_to_markdown(result))
        return _tool_result(result)

    if name == "trace_compare":
        metadata = None
        if arguments.get("metadata_path"):
            try:
                metadata = json.loads(Path(arguments["metadata_path"]).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        addr_list = None
        if arguments.get("addresses"):
            addr_list = [a.strip() for a in arguments["addresses"].split(",") if a.strip()]
        result = trace_compare(
            target=arguments["target"],
            metadata=metadata,
            metadata_path=arguments.get("metadata_path"),
            stdin_data=arguments.get("stdin_data"),
            auto_newline=arguments.get("auto_newline", True),
            run_cwd=arguments.get("run_cwd"),
            focus_function=arguments.get("focus_function"),
            addresses=addr_list,
            address_min=arguments.get("address_min"),
            address_max=arguments.get("address_max"),
            max_events=arguments.get("max_events", 1000),
            timeout=arguments.get("timeout", 30),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(trace_compare_to_markdown(result))
        return _tool_result(result)

    if name == "auto_explore_loop":
        metadata = load_metadata(arguments["metadata_path"])
        result = auto_explore_loop(
            target=arguments["target"],
            metadata=metadata,
            seed=arguments.get("seed", ""),
            mutate_template=arguments.get("mutate_template", ""),
            rounds=arguments.get("rounds", 20),
            batch_size=arguments.get("batch_size", 64),
            keep_top=arguments.get("keep_top", 8),
            success_regex=arguments.get("success_regex", ""),
            failure_regex=arguments.get("failure_regex", ""),
            positions=arguments.get("positions", ""),
            alphabet=arguments.get("alphabet", ""),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(auto_explore_to_markdown(result))
        return _tool_result(result)

    if name == "input_impact":
        result = input_impact(
            target=arguments["target"],
            seed=arguments["seed"],
            positions=arguments.get("positions", ""),
            alphabet=arguments.get("alphabet", "0123456789abcdef"),
            max_mutations_per_pos=arguments.get("max_mutations", 8),
            timeout=arguments.get("timeout", 10),
        )
        if arguments.get("format") == "markdown":
            return _tool_result(input_impact_to_markdown(result))
        return _tool_result(result)

    if name == "check_update":
        result = check_for_update(force=arguments.get("force", False))
        if arguments.get("format") == "markdown":
            return _tool_result(update_check_to_markdown(result))
        return _tool_result(result)

    raise ValueError(f"unknown tool: {name}")


RESOURCES: list[dict[str, Any]] = [
    {
        "uri": "beaconflow://cases/current/manifest",
        "name": "Current Case Manifest",
        "description": "The manifest.json of the current case workspace, containing target info, runs, reports, and notes.",
        "mimeType": "application/json",
    },
    {
        "uri": "beaconflow://cases/current/summary",
        "name": "Current Case Summary",
        "description": "Markdown summary of the current case workspace status.",
        "mimeType": "text/markdown",
    },
    {
        "uri": "beaconflow://runs/latest",
        "name": "Latest Run",
        "description": "The most recent run record from the case workspace.",
        "mimeType": "application/json",
    },
    {
        "uri": "beaconflow://reports/latest",
        "name": "Latest Report",
        "description": "The most recent analysis report from the case workspace.",
        "mimeType": "application/json",
    },
    {
        "uri": "beaconflow://metadata/functions",
        "name": "Metadata Functions Index",
        "description": "List of all functions in the current metadata, with names and addresses.",
        "mimeType": "application/json",
    },
    {
        "uri": "beaconflow://metadata/decision-points",
        "name": "Decision Points",
        "description": "All decision points (cmp/test/jcc) found in the current metadata.",
        "mimeType": "application/json",
    },
    {
        "uri": "beaconflow://metadata/roles",
        "name": "Function Roles",
        "description": "Detected roles (validator, crypto, dispatcher, etc.) for all functions in the current metadata.",
        "mimeType": "application/json",
    },
]


def _read_resource(uri: str) -> str:
    """读取指定 URI 的资源内容。"""
    if uri == "beaconflow://cases/current/manifest":
        manifest = load_manifest()
        if manifest is None:
            return json.dumps({"error": "No case workspace found. Run init-case first."}, indent=2)
        return json.dumps(manifest, indent=2, ensure_ascii=False)

    if uri == "beaconflow://cases/current/summary":
        summary = summarize_case()
        return case_to_markdown(summary)

    if uri == "beaconflow://runs/latest":
        runs_result = list_runs()
        runs = runs_result.get("runs", [])
        if not runs:
            return json.dumps({"message": "No runs recorded yet."}, indent=2)
        return json.dumps(runs[-1], indent=2, ensure_ascii=False)

    if uri == "beaconflow://reports/latest":
        reports_result = list_reports()
        reports = reports_result.get("reports", [])
        if not reports:
            return json.dumps({"message": "No reports generated yet."}, indent=2)
        return json.dumps(reports[-1], indent=2, ensure_ascii=False)

    if uri == "beaconflow://metadata/functions":
        manifest = load_manifest()
        if manifest is None:
            return json.dumps({"error": "No case workspace found."}, indent=2)
        meta_info = manifest.get("metadata", {})
        if not meta_info:
            return json.dumps({"error": "No metadata registered in case workspace."}, indent=2)
        first_meta = list(meta_info.values())[0] if meta_info else None
        if not first_meta:
            return json.dumps({"error": "No metadata entries."}, indent=2)
        rel_path = first_meta.get("path", "")
        case_dir = Path.cwd() / ".case"
        meta_path = case_dir / rel_path
        if not meta_path.exists():
            return json.dumps({"error": f"Metadata file not found: {rel_path}"}, indent=2)
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            functions = [
                {"name": f.get("name", ""), "start": f.get("start", ""), "end": f.get("end", "")}
                for f in metadata.get("functions", [])
            ]
            return json.dumps({"total": len(functions), "functions": functions}, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, OSError) as e:
            return json.dumps({"error": str(e)}, indent=2)

    if uri == "beaconflow://metadata/decision-points":
        manifest = load_manifest()
        if manifest is None:
            return json.dumps({"error": "No case workspace found."}, indent=2)
        meta_info = manifest.get("metadata", {})
        if not meta_info:
            return json.dumps({"error": "No metadata registered."}, indent=2)
        first_meta = list(meta_info.values())[0]
        rel_path = first_meta.get("path", "")
        case_dir = Path.cwd() / ".case"
        meta_path = case_dir / rel_path
        if not meta_path.exists():
            return json.dumps({"error": f"Metadata file not found: {rel_path}"}, indent=2)
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            result = find_decision_points(metadata)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)

    if uri == "beaconflow://metadata/roles":
        manifest = load_manifest()
        if manifest is None:
            return json.dumps({"error": "No case workspace found."}, indent=2)
        meta_info = manifest.get("metadata", {})
        if not meta_info:
            return json.dumps({"error": "No metadata registered."}, indent=2)
        first_meta = list(meta_info.values())[0]
        rel_path = first_meta.get("path", "")
        case_dir = Path.cwd() / ".case"
        meta_path = case_dir / rel_path
        if not meta_path.exists():
            return json.dumps({"error": f"Metadata file not found: {rel_path}"}, indent=2)
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            result = analyze_roles(metadata)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)

    return json.dumps({"error": f"Unknown resource URI: {uri}"}, indent=2)


async def _stdio_loop() -> None:
    while True:
        line = await asyncio.to_thread(sys.stdin.readline)
        if not line:
            return
        if not line.strip():
            continue
        request = json.loads(line)
        response: dict[str, Any] = {"jsonrpc": "2.0", "id": request.get("id")}
        try:
            method = request.get("method")
            params = request.get("params") or {}
            if method == "initialize":
                response["result"] = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "resources": {}},
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
            elif method == "resources/list":
                response["result"] = {
                    "resources": RESOURCES,
                }
            elif method == "resources/read":
                uri = params.get("uri", "")
                content = _read_resource(uri)
                mime = "application/json"
                for r in RESOURCES:
                    if r["uri"] == uri:
                        mime = r.get("mimeType", "application/json")
                        break
                response["result"] = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": mime,
                            "text": content,
                        }
                    ]
                }
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
