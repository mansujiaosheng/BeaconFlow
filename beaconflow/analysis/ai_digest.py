from __future__ import annotations

from typing import Any


def attach_ai_digest(kind: str, result: dict[str, Any], *, max_findings: int = 5) -> dict[str, Any]:
    result["data_quality"] = _data_quality(result)
    result["ai_digest"] = build_ai_digest(kind, result, max_findings=max_findings)
    return result


def build_ai_digest(kind: str, result: dict[str, Any], *, max_findings: int = 5) -> dict[str, Any]:
    warnings = _warnings(result)
    findings = _top_findings(kind, result, max_findings=max_findings)
    actions = _next_actions(kind, result, warnings=warnings, max_actions=max_findings)
    confidence = _confidence(result, warnings)
    return {
        "task": kind,
        "confidence": confidence,
        "warnings": warnings,
        "top_findings": findings,
        "recommended_actions": actions,
        "evidence_refs": [item["evidence_id"] for item in findings if item.get("evidence_id")],
    }


def compact_report(kind: str, result: dict[str, Any], *, max_findings: int = 5) -> dict[str, Any]:
    digest = build_ai_digest(kind, result, max_findings=max_findings)
    return {
        "summary": result.get("summary") or {
            "left_summary": result.get("left_summary"),
            "right_summary": result.get("right_summary"),
        },
        "data_quality": result.get("data_quality") or _data_quality(result),
        "ai_digest": digest,
    }


def infer_report_kind(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    if "ranked_branches" in result:
        return "branch_rank"
    if "real_cfg" in result and "input_dependent_path" in result:
        return "deflatten_merge"
    if "state_transition_table" in result:
        return "recover_state"
    if "dispatcher_candidates" in result:
        return "deflatten"
    if "only_right_blocks" in result and "only_left_blocks" in result:
        return "flow_diff"
    if "flow" in result and "ai_report" in result:
        return "flow"
    if "covered_functions" in result and "uncovered_functions" in result:
        return "coverage"
    if "runs" in result and "recommended_runs" in result:
        return "qemu_explore"
    if "covered_functions" in summary:
        return "coverage"
    return "unknown"


def _warnings(result: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for value in result.get("warnings") or []:
        if value:
            out.append(str(value))
    diagnostics = result.get("diagnostics") or {}
    if diagnostics.get("hit_count_warning"):
        out.append(str(diagnostics["hit_count_warning"]))
    for side in ("left_diagnostics", "right_diagnostics"):
        diag = result.get(side) or {}
        if diag.get("hit_count_warning"):
            out.append(str(diag["hit_count_warning"]))
    return list(dict.fromkeys(out))


def _data_quality(result: dict[str, Any]) -> dict[str, Any]:
    summary = result.get("summary") or {}
    diagnostics = result.get("diagnostics") or {}
    raw = int(summary.get("raw_target_events") or diagnostics.get("mapped_target_events") or 0)
    unmapped = int(diagnostics.get("unmapped_function_events") or 0) + int(diagnostics.get("unmapped_basic_block_events") or 0)
    mapped = int(diagnostics.get("mapped_target_events") or max(raw - unmapped, 0))
    mapping_ratio = round(mapped / raw, 4) if raw else None
    precision = summary.get("hit_count_precision")
    if not precision and result.get("traces"):
        precision = ",".join(sorted(set(str(t.get("hit_count_precision", "unknown")) for t in result["traces"])))
    recommended = None
    if precision and "translation-log" in str(precision):
        recommended = "Recollect with QEMU --trace-mode exec,nochain before trusting hit counts, loop counts, or timing/path-oracle deltas."
    return {
        "trace_mode": summary.get("trace_mode"),
        "hit_count_precision": precision or "unknown",
        "mapping_ratio": mapping_ratio,
        "unmapped_events": unmapped if raw else None,
        "recommended_recollection": recommended,
    }


def _confidence(result: dict[str, Any], warnings: list[str]) -> str:
    quality = result.get("data_quality") or _data_quality(result)
    precision = str(quality.get("hit_count_precision") or "")
    mapping_ratio = quality.get("mapping_ratio")
    if warnings or "translation-log" in precision:
        return "medium"
    if isinstance(mapping_ratio, float) and mapping_ratio < 0.4:
        return "low"
    if isinstance(mapping_ratio, float) and mapping_ratio < 0.75:
        return "medium"
    return "high"


def _top_findings(kind: str, result: dict[str, Any], *, max_findings: int) -> list[dict[str, Any]]:
    if kind == "branch_rank":
        return [_branch_finding(i, item) for i, item in enumerate(result.get("ranked_branches", [])[:max_findings])]
    if kind == "flow_diff":
        return _flow_diff_findings(result, max_findings)
    if kind == "deflatten":
        return _deflatten_findings(result, max_findings)
    if kind == "deflatten_merge":
        return _merge_findings(result, max_findings)
    if kind == "recover_state":
        return _state_findings(result, max_findings)
    if kind == "flow":
        return _flow_findings(result, max_findings)
    if kind == "coverage":
        return _coverage_findings(result, max_findings)
    if kind == "coverage_diff":
        return _coverage_diff_findings(result, max_findings)
    if kind == "qemu_explore":
        return _qemu_explore_findings(result, max_findings)
    return []


def _branch_finding(index: int, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": f"branch_rank:{index}",
        "claim": f"{item.get('block')} is a high-priority input-dependent branch candidate.",
        "confidence": "high" if item.get("new_successors_vs_baseline", 0) else "medium",
        "primary_address": _address_from_block(item.get("block")),
        "reason": item.get("why", []),
        "evidence": {
            "score": item.get("score"),
            "new_successors_vs_baseline": item.get("new_successors_vs_baseline"),
            "successor_count": item.get("successor_count"),
            "outgoing_edges": item.get("outgoing_edges", [])[:6],
        },
    }


def _flow_diff_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    ai = result.get("ai_report", {})
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(ai.get("user_only_right_block_ranges", [])[:max_findings]):
        findings.append(
            {
                "evidence_id": f"flow_diff:right_range:{index}",
                "claim": f"Right trace uniquely reached {item.get('function')}:{item.get('start')}-{item.get('end')}.",
                "confidence": "high",
                "primary_address": item.get("start"),
                "reason": ["right-only block range"],
                "evidence": item,
            }
        )
    remaining = max_findings - len(findings)
    for index, item in enumerate(ai.get("user_only_left_block_ranges", [])[:remaining]):
        findings.append(
            {
                "evidence_id": f"flow_diff:left_range:{index}",
                "claim": f"Left trace uniquely reached {item.get('function')}:{item.get('start')}-{item.get('end')}.",
                "confidence": "high",
                "primary_address": item.get("start"),
                "reason": ["left-only block range"],
                "evidence": item,
            }
        )
    return findings


def _deflatten_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(result.get("real_branch_points", [])[:max_findings]):
        findings.append(
            {
                "evidence_id": f"deflatten:branch:{index}",
                "claim": f"{item.get('block')} is a real branch point after dispatcher removal.",
                "confidence": "high",
                "primary_address": _address_from_block(item.get("block")),
                "reason": ["multiple real successors after deflattening"],
                "evidence": item,
            }
        )
    if not findings:
        for index, item in enumerate(result.get("dispatcher_candidates", [])[:max_findings]):
            findings.append(
                {
                    "evidence_id": f"deflatten:dispatcher_candidate:{index}",
                    "claim": f"{item.get('block')} is a dispatcher candidate.",
                    "confidence": item.get("confidence", "medium"),
                    "primary_address": _address_from_block(item.get("block")),
                    "reason": item.get("warnings") or ["dispatcher candidate"],
                    "evidence": item,
                }
            )
    return findings


def _merge_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    edges = (result.get("input_dependent_path") or {}).get("edges", [])
    return [
        {
            "evidence_id": f"deflatten_merge:input_edge:{index}",
            "claim": f"Input-dependent real edge {item.get('from')} -> {item.get('to')}.",
            "confidence": "high",
            "primary_address": _address_from_block(item.get("from")),
            "reason": ["edge not covered by all traces"],
            "evidence": item,
        }
        for index, item in enumerate(edges[:max_findings])
    ]


def _state_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": f"recover_state:branch:{index}",
            "claim": f"{item.get('block')} appears to set an input-dependent state transition.",
            "confidence": "medium" if item.get("type") == "input-dependent" else "low",
            "primary_address": _address_from_block(item.get("block")),
            "reason": [f"{item.get('successor_count')} observed successors", str(item.get("type"))],
            "evidence": item,
        }
        for index, item in enumerate(result.get("branch_blocks", [])[:max_findings])
    ]


def _flow_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    ai = result.get("ai_report", {})
    out: list[dict[str, Any]] = []
    for index, item in enumerate(ai.get("user_branch_points", [])[:max_findings]):
        out.append(
            {
                "evidence_id": f"flow:branch:{index}",
                "claim": f"{item.get('block')} has multiple observed successors.",
                "confidence": "medium",
                "primary_address": _address_from_block(item.get("block")),
                "reason": ["observed branch point"],
                "evidence": item,
            }
        )
    return out


def _coverage_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": f"coverage:function:{index}",
            "claim": f"{item.get('name')} was covered at {item.get('coverage_percent')}%.",
            "confidence": "high",
            "primary_address": item.get("start"),
            "reason": ["covered function"],
            "evidence": item,
        }
        for index, item in enumerate(result.get("covered_functions", [])[:max_findings])
    ]


def _coverage_diff_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(result.get("only_right_functions", [])[:max_findings]):
        findings.append(
            {
                "evidence_id": f"coverage_diff:right_function:{index}",
                "claim": f"{item.get('name')} is covered only in the right run.",
                "confidence": "high",
                "primary_address": item.get("start"),
                "reason": ["right-only covered function"],
                "evidence": item,
            }
        )
    remaining = max_findings - len(findings)
    for index, item in enumerate(result.get("only_left_functions", [])[:remaining]):
        findings.append(
            {
                "evidence_id": f"coverage_diff:left_function:{index}",
                "claim": f"{item.get('name')} is covered only in the left run.",
                "confidence": "high",
                "primary_address": item.get("start"),
                "reason": ["left-only covered function"],
                "evidence": item,
            }
        )
    return findings


def _qemu_explore_findings(result: dict[str, Any], max_findings: int) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": f"qemu_explore:run:{index}",
            "claim": f"{item.get('name')} is a high-value input to inspect.",
            "confidence": "high" if item.get("new_blocks_vs_baseline", 0) else "medium",
            "primary_address": None,
            "reason": ["path novelty", f"verdict={item.get('verdict')}"],
            "evidence": {
                "stdin_preview": item.get("stdin_preview"),
                "new_blocks_vs_baseline": item.get("new_blocks_vs_baseline"),
                "new_blocks_global": item.get("new_blocks_global"),
                "output_fingerprint": item.get("output_fingerprint"),
            },
        }
        for index, item in enumerate(result.get("recommended_runs", result.get("runs", []))[:max_findings])
    ]


def _next_actions(kind: str, result: dict[str, Any], *, warnings: list[str], max_actions: int) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if any("exec,nochain" in item for item in warnings):
        actions.append(
            {
                "priority": 1,
                "kind": "recollect_trace",
                "trace_mode": "exec,nochain",
                "reason": "Current trace hit counts are not exact.",
            }
        )
    findings = _top_findings(kind, result, max_findings=max_actions)
    for index, finding in enumerate(findings[: max(0, max_actions - len(actions))], start=len(actions) + 1):
        address = finding.get("primary_address")
        action_kind = "open_disassembly" if address else "inspect_report_item"
        actions.append(
            {
                "priority": index,
                "kind": action_kind,
                "address": address,
                "evidence_id": finding.get("evidence_id"),
                "reason": finding.get("claim"),
                "expected_pattern": _expected_pattern(kind),
            }
        )
    return actions


def _expected_pattern(kind: str) -> list[str]:
    if kind in {"branch_rank", "flow_diff", "recover_state"}:
        return ["cmp", "conditional branch", "cmov", "xor", "table lookup", "input load"]
    if kind in {"deflatten", "deflatten_merge"}:
        return ["dispatcher jump", "state variable update", "switch/table lookup", "real branch"]
    return ["function call", "branch", "data-dependent operation"]


def _address_from_block(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if ":" not in value:
        return value if value.startswith("0x") else None
    address = value.rsplit(":", 1)[-1]
    return address if address.startswith("0x") else None
