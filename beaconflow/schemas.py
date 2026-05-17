from __future__ import annotations

from copy import deepcopy
from typing import Any


_AI_DIGEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/ai-digest.json",
    "title": "BeaconFlow ai_digest",
    "type": "object",
    "required": ["task", "confidence"],
    "properties": {
        "task": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "top_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["evidence_id", "claim", "confidence"],
                "properties": {
                    "evidence_id": {"type": "string"},
                    "claim": {"type": "string"},
                    "confidence": {"type": "string"},
                    "primary_address": {"type": ["string", "null"]},
                    "reason": {"type": "array", "items": {"type": "string"}},
                    "evidence": {"type": "object"},
                },
                "additionalProperties": True,
            },
        },
        "recommended_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["priority", "kind", "reason"],
                "properties": {
                    "priority": {"type": "integer"},
                    "kind": {"type": "string"},
                    "address": {"type": ["string", "null"]},
                    "evidence_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "expected_pattern": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": True,
            },
        },
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}


REPORT_CONFIDENCE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/report-confidence.json",
    "title": "BeaconFlow report_confidence",
    "type": "object",
    "required": ["level", "score", "basis", "limitations", "recommendation"],
    "properties": {
        "level": {"type": "string", "enum": ["high", "medium", "low"]},
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "basis": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "recommendation": {"type": "string"},
    },
    "additionalProperties": True,
}


_DATA_QUALITY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/data-quality.json",
    "title": "BeaconFlow data_quality",
    "type": "object",
    "properties": {
        "trace_mode": {"type": ["string", "null"]},
        "hit_count_precision": {"type": "string"},
        "mapping_ratio": {"type": ["number", "null"]},
        "unmapped_events": {"type": ["integer", "null"]},
        "recommended_recollection": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}


_COMMON_REPORT_FIELDS: dict[str, Any] = {
    "data_quality": _DATA_QUALITY_SCHEMA,
    "report_confidence": REPORT_CONFIDENCE_SCHEMA,
    "ai_digest": _AI_DIGEST_SCHEMA,
}


_COVERAGE_FUNCTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name", "start", "end"],
    "properties": {
        "name": {"type": "string"},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "covered_blocks": {"type": "integer"},
        "total_blocks": {"type": "integer"},
        "coverage_percent": {"type": "number"},
        "covered_block_starts": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}


COVERAGE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/coverage.json",
    "title": "BeaconFlow coverage report",
    "type": "object",
    "required": ["summary", "covered_functions", "uncovered_functions"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["covered_functions", "total_functions", "covered_basic_blocks", "total_basic_blocks"],
            "properties": {
                "covered_functions": {"type": "integer"},
                "total_functions": {"type": "integer"},
                "covered_basic_blocks": {"type": "integer"},
                "total_basic_blocks": {"type": "integer"},
            },
            "additionalProperties": True,
        },
        "covered_functions": {"type": "array", "items": _COVERAGE_FUNCTION_SCHEMA},
        "uncovered_functions": {"type": "array", "items": _COVERAGE_FUNCTION_SCHEMA},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


COVERAGE_DIFF_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/coverage-diff.json",
    "title": "BeaconFlow coverage_diff report",
    "type": "object",
    "required": ["left_summary", "right_summary"],
    "properties": {
        "left_summary": {"type": "object", "additionalProperties": True},
        "right_summary": {"type": "object", "additionalProperties": True},
        "only_left_functions": {"type": "array", "items": _COVERAGE_FUNCTION_SCHEMA},
        "only_right_functions": {"type": "array", "items": _COVERAGE_FUNCTION_SCHEMA},
        "both_functions": {"type": "array", "items": _COVERAGE_FUNCTION_SCHEMA},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


_FLOW_EVENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["event_index", "address", "function", "block_start", "block_end"],
    "properties": {
        "event_index": {"type": "integer"},
        "address": {"type": "string"},
        "size": {"type": "integer"},
        "function": {"type": "string"},
        "function_start": {"type": "string"},
        "block_start": {"type": "string"},
        "block_end": {"type": "string"},
        "block_context": {"type": "object", "additionalProperties": True},
    },
    "additionalProperties": True,
}


FLOW_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/flow.json",
    "title": "BeaconFlow flow report",
    "type": "object",
    "required": ["summary", "flow"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["raw_target_events", "unique_blocks", "unique_transitions"],
            "properties": {
                "raw_target_events": {"type": "integer"},
                "compressed_events": {"type": "integer"},
                "unique_blocks": {"type": "integer"},
                "unique_transitions": {"type": "integer"},
                "functions_seen": {"type": "integer"},
                "truncated": {"type": "boolean"},
                "focus_function": {"type": ["string", "null"]},
                "source_kind": {"type": "string"},
                "trace_mode": {"type": ["string", "null"]},
                "hit_count_precision": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "diagnostics": {"type": "object", "additionalProperties": True},
        "ai_report": {"type": "object", "additionalProperties": True},
        "function_order": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "flow": {"type": "array", "items": _FLOW_EVENT_SCHEMA},
        "hot_blocks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "transitions": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


FLOW_DIFF_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/flow-diff.json",
    "title": "BeaconFlow flow_diff report",
    "type": "object",
    "required": ["summary"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "focus_function": {"type": ["string", "null"]},
                "left_unique_blocks": {"type": "integer"},
                "right_unique_blocks": {"type": "integer"},
                "only_left_blocks": {"type": "integer"},
                "only_right_blocks": {"type": "integer"},
                "only_left_edges": {"type": "integer"},
                "only_right_edges": {"type": "integer"},
            },
            "additionalProperties": True,
        },
        "ai_report": {"type": "object", "additionalProperties": True},
        "only_left_blocks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "only_right_blocks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "only_left_edges": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "only_right_edges": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "hit_count_deltas": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "left_diagnostics": {"type": "object", "additionalProperties": True},
        "right_diagnostics": {"type": "object", "additionalProperties": True},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


_DISPATCHER_CANDIDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["block", "selected", "confidence"],
    "properties": {
        "block": {"type": "string"},
        "selected": {"type": "boolean"},
        "confidence": {"type": "string"},
        "mode": {"type": "string"},
        "score": {"type": "number"},
        "hits": {"type": "integer"},
        "observed_predecessors": {"type": "integer"},
        "observed_successors": {"type": "integer"},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}


DEFLATTEN_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/deflatten.json",
    "title": "BeaconFlow deflatten report",
    "type": "object",
    "required": ["summary"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["original_blocks", "dispatcher_blocks", "real_blocks", "real_edges"],
            "properties": {
                "original_blocks": {"type": "integer"},
                "dispatcher_blocks": {"type": "integer"},
                "real_blocks": {"type": "integer"},
                "real_edges": {"type": "integer"},
                "real_branch_points": {"type": "integer"},
                "real_events_in_spine": {"type": "integer"},
                "dispatcher_mode": {"type": "string"},
                "source_kind": {"type": "string"},
                "trace_mode": {"type": ["string", "null"]},
                "hit_count_precision": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
        "dispatcher_blocks": {"type": "array", "items": {"type": "string"}},
        "dispatcher_candidates": {"type": "array", "items": _DISPATCHER_CANDIDATE_SCHEMA},
        "real_function_order": {"type": "string"},
        "real_execution_spine": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "real_branch_points": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "real_edges": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "real_hot_blocks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


DEFLATTEN_MERGE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/deflatten-merge.json",
    "title": "BeaconFlow deflatten_merge report",
    "type": "object",
    "required": ["summary", "real_cfg"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["total_traces", "total_real_blocks", "total_real_edges"],
            "properties": {
                "total_traces": {"type": "integer"},
                "total_real_blocks": {"type": "integer"},
                "total_real_edges": {"type": "integer"},
                "total_dispatcher_blocks": {"type": "integer"},
                "total_branch_points": {"type": "integer"},
                "total_merge_points": {"type": "integer"},
                "common_edges": {"type": "integer"},
                "input_dependent_edges": {"type": "integer"},
                "dispatcher_mode": {"type": "string"},
                "hit_count_precision": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "per_trace_summary": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "dispatcher_blocks": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "real_cfg": {"type": "object", "additionalProperties": True},
        "common_path": {"type": "object", "additionalProperties": True},
        "input_dependent_path": {"type": "object", "additionalProperties": True},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


RECOVER_STATE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/recover-state.json",
    "title": "BeaconFlow recover_state report",
    "type": "object",
    "required": ["summary"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["total_traces", "total_real_blocks"],
            "properties": {
                "total_traces": {"type": "integer"},
                "total_real_blocks": {"type": "integer"},
                "total_dispatcher_blocks": {"type": "integer"},
                "total_state_transitions": {"type": "integer"},
                "deterministic_transitions": {"type": "integer"},
                "input_dependent_transitions": {"type": "integer"},
                "branch_blocks": {"type": "integer"},
                "dispatcher_mode": {"type": "string"},
                "hit_count_precision": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
        "state_transition_table": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "deterministic_transitions": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "input_dependent_transitions": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "branch_blocks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "dispatcher_blocks": {"type": "array", "items": {"type": "string"}},
        "ai_interpretation": {"type": "object", "additionalProperties": True},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


BRANCH_RANK_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/branch-rank.json",
    "title": "BeaconFlow branch_rank report",
    "type": "object",
    "required": ["summary", "ranked_branches"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["total_traces", "ranked_branch_points"],
            "properties": {
                "total_traces": {"type": "integer"},
                "baseline": {"type": "string"},
                "ranked_branch_points": {"type": "integer"},
                "focus_function": {"type": ["string", "null"]},
                "hit_count_precision": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
        "traces": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "ranked_branches": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["block", "score"],
                "properties": {
                    "block": {"type": "string"},
                    "score": {"type": "number"},
                    "successor_count": {"type": "integer"},
                    "new_successors_vs_baseline": {"type": "integer"},
                    "hit_spread": {"type": "number"},
                    "hits_by_trace": {"type": "object", "additionalProperties": True},
                    "outgoing_edges": {"type": "array", "items": {"type": "string"}},
                    "why": {"type": "array", "items": {"type": "string"}},
                    "next_action": {"type": "string"},
                },
                "additionalProperties": True,
            },
        },
        "ai_interpretation": {"type": "object", "additionalProperties": True},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


BLOCK_CONTEXT_REPORT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/block-context-report.json",
    "title": "BeaconFlow inspect_block report",
    "type": "object",
    "required": ["function", "function_start", "block_start", "block_end", "successors", "context"],
    "properties": {
        "function": {"type": "string"},
        "function_start": {"type": "string"},
        "block_start": {"type": "string"},
        "block_end": {"type": "string"},
        "predecessors": {"type": "array", "items": {"type": "string"}},
        "successors": {"type": "array", "items": {"type": "string"}},
        "context": {
            "type": "object",
            "properties": {
                "instructions": {"type": "array", "items": {"type": "string"}},
                "calls": {"type": "array", "items": {"type": "string"}},
                "strings": {"type": "array", "items": {"type": "string"}},
                "constants": {"type": "array", "items": {"type": ["string", "integer"]}},
                "data_refs": {"type": "array", "items": {"type": "string"}},
                "code_refs": {"type": "array", "items": {"type": "string"}},
                "predecessors": {"type": "array", "items": {"type": "string"}},
                "successors": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
        "nearby_comparisons": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["index", "kind", "instruction", "reason"],
                "properties": {
                    "index": {"type": "integer"},
                    "kind": {"type": "string"},
                    "instruction": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "additionalProperties": True,
            },
        },
        "recommendation": {
            "type": "object",
            "required": ["priority", "reasons"],
            "properties": {
                "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


DECISION_POINTS_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/decision-points.json",
    "title": "BeaconFlow decision_points report",
    "type": "object",
    "required": ["summary", "decision_points"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["total"],
            "properties": {
                "total": {"type": "integer"},
                "critical": {"type": "integer"},
                "high": {"type": "integer"},
                "medium": {"type": "integer"},
                "low": {"type": "integer"},
                "focus_function": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        "decision_points": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["function", "address", "type", "ai_priority", "reason"],
                "properties": {
                    "function": {"type": "string"},
                    "address": {"type": "string"},
                    "type": {"type": "string"},
                    "compare_instruction": {"type": ["string", "null"]},
                    "branch_instruction": {"type": ["string", "null"]},
                    "call_instruction": {"type": ["string", "null"]},
                    "successors": {"type": "array", "items": {"type": "string"}},
                    "observed_successor": {"type": ["string", "null"]},
                    "taken": {"type": ["string", "null"]},
                    "fallthrough": {"type": ["string", "null"]},
                    "target": {"type": ["string", "null"]},
                    "ai_priority": {"type": "string"},
                    "reason": {"type": "string"},
                    "related_block_context": {"type": ["object", "null"]},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


ROLES_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/roles.json",
    "title": "BeaconFlow roles report",
    "type": "object",
    "required": ["summary", "candidates"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["total"],
            "properties": {
                "total": {"type": "integer"},
                "roles": {"type": "object", "additionalProperties": {"type": "integer"}},
                "confidence": {"type": "object", "additionalProperties": {"type": "integer"}},
                "focus_function": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["role", "function", "address", "confidence", "score"],
                "properties": {
                    "role": {"type": "string"},
                    "function": {"type": "string"},
                    "address": {"type": "string"},
                    "confidence": {"type": "string"},
                    "score": {"type": "number"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "matched_rules": {"type": "array", "items": {"type": "string"}},
                    "related_blocks": {"type": "array", "items": {"type": "string"}},
                    "related_decision_points": {"type": "array", "items": {"type": "string"}},
                    "related_io_sites": {"type": "array", "items": {"type": "string"}},
                    "related_path_diffs": {"type": "array", "items": {"type": "string"}},
                    "recommended_actions": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


VALUE_TRACE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/value-trace.json",
    "title": "BeaconFlow value_trace report",
    "type": "object",
    "required": ["summary"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "total_compare_events": {"type": "integer"},
                "immediate_compares": {"type": "integer"},
                "input_sites": {"type": "integer"},
                "dispatcher_states": {"type": "integer"},
                "focus_function": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        "compare_events": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["address", "function", "compare_type", "instruction", "left_operand", "right_operand"],
                "properties": {
                    "address": {"type": "string"},
                    "function": {"type": "string"},
                    "compare_type": {"type": "string"},
                    "instruction": {"type": "string"},
                    "left_operand": {"type": "string"},
                    "right_operand": {"type": "string"},
                    "branch_result": {"type": ["string", "null"]},
                    "taken_address": {"type": ["string", "null"]},
                    "fallthrough_address": {"type": ["string", "null"]},
                    "input_offset": {"type": ["integer", "null"]},
                    "context": {"type": "object", "additionalProperties": True},
                },
                "additionalProperties": True,
            },
        },
        "immediate_compares": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "input_sites": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["address", "function", "call_name", "input_type"],
                "properties": {
                    "address": {"type": "string"},
                    "function": {"type": "string"},
                    "call_name": {"type": "string"},
                    "input_type": {"type": "string"},
                    "context": {"type": "object", "additionalProperties": True},
                },
                "additionalProperties": True,
            },
        },
        "dispatcher_states": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["address", "function"],
                "properties": {
                    "address": {"type": "string"},
                    "function": {"type": "string"},
                    "state_variable_hint": {"type": ["string", "null"]},
                    "observed_targets": {"type": "array", "items": {"type": "string"}},
                    "context": {"type": "object", "additionalProperties": True},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


TRACE_COMPARE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/trace-compare.json",
    "title": "BeaconFlow trace_compare report",
    "type": "object",
    "required": ["summary"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "by_type": {"type": "object", "additionalProperties": {"type": "integer"}},
                "failed_compares": {"type": "integer"},
                "passed_compares": {"type": "integer"},
                "focus_function": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        "compares": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["addr", "type", "instruction", "left", "right", "function"],
                "properties": {
                    "addr": {"type": "string"},
                    "type": {"type": "string"},
                    "instruction": {"type": "string"},
                    "left": {"type": "string"},
                    "right": {"type": "string"},
                    "function": {"type": "string"},
                    "length": {"type": ["integer", "null"]},
                    "result": {"type": ["string", "null"]},
                    "branch_taken": {"type": ["boolean", "null"]},
                    "jump_targets": {"type": "array", "items": {"type": "string"}},
                    "context": {"type": "object", "additionalProperties": True},
                },
                "additionalProperties": True,
            },
        },
        "failed_compares": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "passed_compares": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
    },
    "additionalProperties": True,
}


INPUT_TAINT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/input-taint.json",
    "title": "BeaconFlow input_taint report",
    "type": "object",
    "required": ["summary"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "sources": {"type": "integer"},
                "sinks": {"type": "integer"},
                "edges": {"type": "integer"},
                "mappings": {"type": "integer"},
                "focus_function": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        "sources": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["address", "function", "call_name", "input_type"],
                "properties": {
                    "address": {"type": "string"},
                    "function": {"type": "string"},
                    "call_name": {"type": "string"},
                    "input_type": {"type": "string"},
                    "output_register": {"type": ["string", "null"]},
                    "context": {"type": "object", "additionalProperties": True},
                },
                "additionalProperties": True,
            },
        },
        "sinks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["address", "function", "compare_type", "instruction"],
                "properties": {
                    "address": {"type": "string"},
                    "function": {"type": "string"},
                    "compare_type": {"type": "string"},
                    "instruction": {"type": "string"},
                    "left_operand": {"type": "string"},
                    "right_operand": {"type": "string"},
                    "branch_result": {"type": ["string", "null"]},
                    "context": {"type": "object", "additionalProperties": True},
                },
                "additionalProperties": True,
            },
        },
        "edges": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["source_address", "sink_address", "function", "confidence"],
                "properties": {
                    "source_address": {"type": "string"},
                    "sink_address": {"type": "string"},
                    "function": {"type": "string"},
                    "taint_register": {"type": "string"},
                    "propagation_path": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "string"},
                },
                "additionalProperties": True,
            },
        },
        "mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "sink": {"type": "string"},
                    "edge": {"type": "string"},
                    "input_offset": {"type": ["integer", "null"]},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


FEEDBACK_EXPLORE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/feedback-explore.json",
    "title": "BeaconFlow feedback_explore report",
    "type": "object",
    "required": ["summary", "plan"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "total_failed_compares": {"type": "integer"},
                "total_patches": {"type": "integer"},
                "high_confidence_patches": {"type": "integer"},
                "medium_confidence_patches": {"type": "integer"},
                "low_confidence_patches": {"type": "integer"},
                "total_rounds": {"type": "integer"},
            },
            "additionalProperties": True,
        },
        "plan": {
            "type": "object",
            "required": ["target", "total_rounds", "rounds"],
            "properties": {
                "target": {"type": "string"},
                "total_rounds": {"type": "integer"},
                "rounds": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["round", "strategy", "patches"],
                        "properties": {
                            "round": {"type": "integer"},
                            "strategy": {"type": "string"},
                            "description": {"type": "string"},
                            "patches": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["offset", "suggested_value", "size", "reason", "confidence"],
                                    "properties": {
                                        "offset": {"type": "integer"},
                                        "suggested_value": {"type": "string"},
                                        "size": {"type": "integer"},
                                        "reason": {"type": "string"},
                                        "compare_address": {"type": "string"},
                                        "compare_instruction": {"type": "string"},
                                        "confidence": {"type": "string"},
                                        "original_value": {"type": ["string", "null"]},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                        },
                        "additionalProperties": True,
                    },
                },
                "notes": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


SIG_MATCH_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/sig-match.json",
    "title": "BeaconFlow sig_match report",
    "type": "object",
    "required": ["summary", "matches"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "total_matches": {"type": "integer"},
                "by_category": {"type": "object", "additionalProperties": {"type": "integer"}},
            },
            "additionalProperties": True,
        },
        "matches": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["category", "name", "confidence"],
                "properties": {
                    "category": {"type": "string"},
                    "name": {"type": "string"},
                    "confidence": {"type": "string"},
                    "evidence": {"type": ["string", "array"]},
                    "address": {"type": ["string", "null"]},
                    "function": {"type": ["string", "null"]},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


DECOMPILE_FUNCTION_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/decompile-function.json",
    "title": "BeaconFlow decompile_function report",
    "type": "object",
    "required": ["name", "address", "block_count", "blocks"],
    "properties": {
        "name": {"type": "string"},
        "address": {"type": "string"},
        "size": {"type": "integer"},
        "block_count": {"type": "integer"},
        "blocks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["label", "address"],
                "properties": {
                    "label": {"type": "string"},
                    "address": {"type": "string"},
                    "operations": {"type": "array", "items": {"type": "string"}},
                    "branch_condition": {"type": ["string", "null"]},
                    "branch_targets": {"type": "array", "items": {"type": "string"}},
                    "calls": {"type": "array", "items": {"type": "string"}},
                    "is_entry": {"type": "boolean"},
                    "is_exit": {"type": "boolean"},
                },
                "additionalProperties": True,
            },
        },
        "signature_hint": {"type": ["string", "null"]},
        "loops": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
        "pseudo_code": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}


NORMALIZE_IR_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/normalize-ir.json",
    "title": "BeaconFlow normalize_ir report",
    "type": "object",
    "required": ["summary", "ir"],
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "function": {"type": "string"},
                "address": {"type": "string"},
                "blocks": {"type": "integer"},
                "op_counts": {"type": "object", "additionalProperties": {"type": "integer"}},
            },
            "additionalProperties": True,
        },
        "ir": {
            "type": "object",
            "required": ["name", "address", "blocks"],
            "properties": {
                "name": {"type": "string"},
                "address": {"type": "string"},
                "blocks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["label", "address", "instructions"],
                        "properties": {
                            "label": {"type": "string"},
                            "address": {"type": "string"},
                            "instructions": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["op", "operands", "original", "address"],
                                    "properties": {
                                        "op": {"type": "string"},
                                        "operands": {"type": "array", "items": {"type": "string"}},
                                        "original": {"type": "string"},
                                        "address": {"type": "string"},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                            "successors": {"type": "array", "items": {"type": "string"}},
                        },
                        "additionalProperties": True,
                    },
                },
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


INPUT_IMPACT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/input-impact.json",
    "title": "BeaconFlow input_impact report",
    "type": "object",
    "required": ["status", "target", "seed", "affected_positions"],
    "properties": {
        "status": {"type": "string"},
        "target": {"type": "string"},
        "seed": {"type": "string"},
        "seed_length": {"type": "integer"},
        "positions_scanned": {"type": "string"},
        "total_positions": {"type": "integer"},
        "affected_positions": {"type": "integer"},
        "baseline": {
            "type": "object",
            "properties": {
                "returncode": {"type": "integer"},
                "stdout_preview": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "position_reports": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["position", "original_char", "mutations_tested", "changes_detected"],
                "properties": {
                    "position": {"type": "integer"},
                    "original_char": {"type": "string"},
                    "mutations_tested": {"type": "integer"},
                    "changes_detected": {"type": "integer"},
                    "chars_causing_change": {"type": "array", "items": {"type": "string"}},
                    "change_details": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


AUTO_EXPLORE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/auto-explore.json",
    "title": "BeaconFlow auto_explore report",
    "type": "object",
    "required": ["status", "target", "rounds_completed"],
    "properties": {
        "status": {"type": "string"},
        "target": {"type": "string"},
        "rounds_completed": {"type": "integer"},
        "best_candidate": {"type": ["string", "null"]},
        "best_score": {"type": "number"},
        "success_found": {"type": "boolean"},
        "success_input": {"type": ["string", "null"]},
        "rounds": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["round", "candidates_tested", "best_score"],
                "properties": {
                    "round": {"type": "integer"},
                    "candidates_tested": {"type": "integer"},
                    "best_score": {"type": "number"},
                    "best_input": {"type": ["string", "null"]},
                    "seeds_for_next_round": {"type": "array", "items": {"type": "string"}},
                    "elapsed_seconds": {"type": "number"},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


QEMU_EXPLORE_REPORT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://beaconflow.local/schema/qemu-explore-report.json",
    "title": "BeaconFlow qemu_explore report",
    "type": "object",
    "required": ["summary", "runs"],
    "properties": {
        "summary": {
            "type": "object",
            "required": ["target", "qemu_arch", "trace_mode", "runs"],
            "properties": {
                "target": {"type": "string"},
                "qemu_arch": {"type": "string"},
                "trace_mode": {"type": "string"},
                "hit_count_precision": {"type": "string"},
                "metadata_path": {"type": "string"},
                "runs": {"type": "integer"},
                "total_union_functions": {"type": "integer"},
                "total_union_blocks": {"type": "integer"},
                "address_min": {"type": ["string", "null"]},
                "address_max": {"type": ["string", "null"]},
                "auto_address_range": {"type": ["object", "null"]},
            },
            "additionalProperties": True,
        },
        "runs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "verdict", "returncode"],
                "properties": {
                    "name": {"type": "string"},
                    "stdin_preview": {"type": ["string", "null"]},
                    "log_path": {"type": "string"},
                    "returncode": {"type": "integer"},
                    "stdout": {"type": "string"},
                    "stderr": {"type": "string"},
                    "verdict": {"type": "string"},
                    "output_fingerprint": {"type": "string"},
                    "unique_blocks": {"type": "integer"},
                    "unique_transitions": {"type": "integer"},
                    "functions_seen": {"type": "integer"},
                    "new_blocks_vs_baseline": {"type": "integer"},
                    "new_blocks_global": {"type": "integer"},
                    "function_order": {"type": ["string", "null"]},
                },
                "additionalProperties": True,
            },
        },
        "recommended_runs": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        **_COMMON_REPORT_FIELDS,
    },
    "additionalProperties": True,
}


SCHEMAS: dict[str, dict[str, Any]] = {
    "ai_digest": _AI_DIGEST_SCHEMA,
    "auto_explore": AUTO_EXPLORE_SCHEMA,
    "block_context": BLOCK_CONTEXT_REPORT_SCHEMA,
    "branch_rank": BRANCH_RANK_SCHEMA,
    "coverage": COVERAGE_SCHEMA,
    "coverage_diff": COVERAGE_DIFF_SCHEMA,
    "data_quality": _DATA_QUALITY_SCHEMA,
    "decision_points": DECISION_POINTS_SCHEMA,
    "decompile_function": DECOMPILE_FUNCTION_SCHEMA,
    "deflatten": DEFLATTEN_SCHEMA,
    "deflatten_merge": DEFLATTEN_MERGE_SCHEMA,
    "feedback_explore": FEEDBACK_EXPLORE_SCHEMA,
    "flow": FLOW_SCHEMA,
    "flow_diff": FLOW_DIFF_SCHEMA,
    "input_impact": INPUT_IMPACT_SCHEMA,
    "input_taint": INPUT_TAINT_SCHEMA,
    "inspect_block": BLOCK_CONTEXT_REPORT_SCHEMA,
    "normalize_ir": NORMALIZE_IR_SCHEMA,
    "qemu_explore": QEMU_EXPLORE_REPORT_SCHEMA,
    "recover_state": RECOVER_STATE_SCHEMA,
    "report_confidence": REPORT_CONFIDENCE_SCHEMA,
    "roles": ROLES_SCHEMA,
    "sig_match": SIG_MATCH_SCHEMA,
    "trace_compare": TRACE_COMPARE_SCHEMA,
    "value_trace": VALUE_TRACE_SCHEMA,
}


def list_schemas() -> list[str]:
    return sorted(SCHEMAS)


def get_schema(name: str) -> dict[str, Any]:
    if name not in SCHEMAS:
        raise KeyError(f"unknown schema: {name}")
    return deepcopy(SCHEMAS[name])


def _validate_type(value: Any, type_spec: Any) -> bool:
    if isinstance(type_spec, str):
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
            "null": type(None),
        }
        expected = type_map.get(type_spec)
        if expected is None:
            return True
        if type_spec == "integer" and isinstance(value, bool):
            return False
        if type_spec == "number" and isinstance(value, bool):
            return False
        return isinstance(value, expected)
    if isinstance(type_spec, list):
        if len(type_spec) == 1 and type_spec[0] == "null":
            return value is None
        return any(_validate_type(value, t) for t in type_spec)
    return True


def _validate_field(
    value: Any,
    field_name: str,
    prop_schema: dict[str, Any],
    path: str,
) -> list[str]:
    errors: list[str] = []
    full_path = f"{path}.{field_name}" if path else field_name

    if "type" in prop_schema:
        type_spec = prop_schema["type"]
        if not _validate_type(value, type_spec):
            errors.append(f"{full_path}: expected type {type_spec}, got {type(value).__name__}")

    if "enum" in prop_schema and value not in prop_schema["enum"]:
        errors.append(f"{full_path}: value {value!r} not in enum {prop_schema['enum']}")

    if "minimum" in prop_schema and isinstance(value, (int, float)):
        if value < prop_schema["minimum"]:
            errors.append(f"{full_path}: value {value} below minimum {prop_schema['minimum']}")

    if "maximum" in prop_schema and isinstance(value, (int, float)):
        if value > prop_schema["maximum"]:
            errors.append(f"{full_path}: value {value} above maximum {prop_schema['maximum']}")

    if isinstance(value, dict) and "properties" in prop_schema:
        errors.extend(_validate_object(value, prop_schema, full_path))

    if isinstance(value, list) and "items" in prop_schema:
        item_schema = prop_schema["items"]
        for i, item in enumerate(value):
            idx_path = f"{full_path}[{i}]"
            if isinstance(item_schema, dict):
                if "type" in item_schema and not _validate_type(item, item_schema["type"]):
                    errors.append(f"{idx_path}: expected type {item_schema['type']}, got {type(item).__name__}")
                if isinstance(item, dict) and "properties" in item_schema:
                    errors.extend(_validate_object(item, item_schema, idx_path))
                if "required" in item_schema:
                    for req in item_schema["required"]:
                        if req not in item:
                            errors.append(f"{idx_path}: missing required field '{req}'")

    return errors


def _validate_object(
    obj: dict[str, Any],
    schema: dict[str, Any],
    path: str,
) -> list[str]:
    errors: list[str] = []

    required = schema.get("required", [])
    for field in required:
        if field not in obj:
            errors.append(f"{path}: missing required field '{field}'")

    properties = schema.get("properties", {})
    for field_name, field_schema in properties.items():
        if field_name not in obj:
            continue
        value = obj[field_name]
        errors.extend(_validate_field(value, field_name, field_schema, path))

    return errors


SCHEMA_VERSION = "1.0.0"


def validate_report(report: dict[str, Any], schema_name: str) -> list[str]:
    errors: list[str] = []
    schema = SCHEMAS.get(schema_name)
    if schema is None:
        return [f"unknown schema: {schema_name}"]

    errors.extend(_validate_object(report, schema, schema_name))

    return errors


def validate_report_strict(report: dict[str, Any], schema_name: str) -> dict[str, Any]:
    errors = validate_report(report, schema_name)
    is_valid = len(errors) == 0
    return {
        "schema_name": schema_name,
        "schema_version": SCHEMA_VERSION,
        "valid": is_valid,
        "error_count": len(errors),
        "errors": errors,
    }


_SCHEMA_NAME_HINTS: dict[str, list[str]] = {
    "coverage": ["coverage", "cov"],
    "coverage_diff": ["coverage_diff", "cov_diff"],
    "flow": ["flow"],
    "flow_diff": ["flow_diff"],
    "deflatten": ["deflatten", "deflat"],
    "deflatten_merge": ["deflatten_merge", "deflat_merge"],
    "recover_state": ["recover_state", "state_trans"],
    "branch_rank": ["branch_rank"],
    "decision_points": ["decision_points", "dp_"],
    "roles": ["roles"],
    "value_trace": ["value_trace"],
    "trace_compare": ["trace_compare"],
    "input_taint": ["input_taint"],
    "feedback_explore": ["feedback_explore"],
    "sig_match": ["sig_match"],
    "decompile_function": ["decompile"],
    "normalize_ir": ["normalize_ir", "ir_"],
    "qemu_explore": ["qemu_explore"],
    "block_context": ["block_context", "inspect_block"],
}


def _guess_schema_name(filename: str) -> str | None:
    """根据文件名猜测最可能的 schema 名称。"""
    lower = filename.lower()
    best: str | None = None
    best_len = 0
    for schema_name, hints in _SCHEMA_NAME_HINTS.items():
        for hint in hints:
            if hint in lower and len(hint) > best_len:
                best = schema_name
                best_len = len(hint)
    return best


def validate_all_reports(
    directory: str | Path,
    recursive: bool = True,
) -> dict[str, Any]:
    """批量验证目录下所有 JSON 报告文件是否符合 schema。

    参数:
        directory: 要扫描的目录路径
        recursive: 是否递归扫描子目录

    返回:
        包含每个文件验证结果的汇总字典
    """
    import json as _json
    from pathlib import Path as _Path

    dir_path = _Path(directory).resolve()
    if not dir_path.exists():
        return {
            "status": "error",
            "message": f"目录不存在: {dir_path}",
            "results": [],
        }

    pattern = "**/*.json" if recursive else "*.json"
    json_files = sorted(dir_path.glob(pattern))

    results: list[dict[str, Any]] = []
    for jf in json_files:
        # 跳过 manifest.json 等非报告文件
        if jf.name in ("manifest.json", "package.json", "tsconfig.json"):
            continue

        try:
            data = _json.loads(jf.read_text(encoding="utf-8"))
        except (_json.JSONDecodeError, OSError) as e:
            results.append({
                "path": str(jf),
                "filename": jf.name,
                "schema_name": None,
                "valid": False,
                "error_count": 1,
                "errors": [f"无法解析 JSON: {e}"],
            })
            continue

        if not isinstance(data, dict):
            continue

        # 猜测 schema 名称
        guessed = _guess_schema_name(jf.name)
        if guessed is None:
            # 尝试根据报告内容推断
            if "flow" in data and "summary" in data:
                guessed = "flow"
            elif "covered_functions" in data and "uncovered_functions" in data:
                guessed = "coverage"
            elif "decision_points" in data:
                guessed = "decision_points"
            elif "candidates" in data and "summary" in data:
                guessed = "roles"
            elif "matches" in data and "summary" in data:
                guessed = "sig_match"
            elif "ranked_branches" in data:
                guessed = "branch_rank"
            elif "dispatcher_blocks" in data and "real_edges" in data:
                guessed = "deflatten"
            elif "compare_events" in data:
                guessed = "value_trace"
            elif "compares" in data and "summary" in data:
                guessed = "trace_compare"

        if guessed is None:
            results.append({
                "path": str(jf),
                "filename": jf.name,
                "schema_name": None,
                "valid": None,
                "error_count": 0,
                "errors": [],
                "note": "无法自动匹配 schema，跳过验证",
            })
            continue

        if guessed not in SCHEMAS:
            results.append({
                "path": str(jf),
                "filename": jf.name,
                "schema_name": guessed,
                "valid": None,
                "error_count": 0,
                "errors": [],
                "note": f"猜测的 schema '{guessed}' 不存在，跳过",
            })
            continue

        validation = validate_report_strict(data, guessed)
        results.append({
            "path": str(jf),
            "filename": jf.name,
            "schema_name": guessed,
            "valid": validation["valid"],
            "error_count": validation["error_count"],
            "errors": validation["errors"],
        })

    total = len(results)
    valid_count = sum(1 for r in results if r["valid"] is True)
    invalid_count = sum(1 for r in results if r["valid"] is False)
    skipped_count = sum(1 for r in results if r["valid"] is None)

    return {
        "status": "ok",
        "directory": str(dir_path),
        "total_files": total,
        "valid": valid_count,
        "invalid": invalid_count,
        "skipped": skipped_count,
        "results": results,
    }
