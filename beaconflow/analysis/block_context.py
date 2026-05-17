from __future__ import annotations

from typing import Any

from beaconflow.models import BasicBlock, Function, hex_addr


COMPARE_HINTS = (
    ("cmp", "compare"),
    ("test", "compare"),
    ("cmov", "conditional_move"),
    ("set", "conditional_set"),
    ("j", "conditional_branch"),
)


def build_block_context_report(function: Function, block: BasicBlock) -> dict[str, Any]:
    context = block.context.to_json()
    predecessors = _predecessors(function, block, context)
    successors = [hex_addr(s) for s in block.succs] or list(context.get("successors", ()))
    nearby_comparisons = _nearby_comparisons(context.get("instructions", ()))
    why = _recommendation_reasons(context, predecessors, successors, nearby_comparisons)

    return {
        "function": function.name,
        "function_start": hex_addr(function.start),
        "block_start": hex_addr(block.start),
        "block_end": hex_addr(block.end),
        "successors": successors,
        "predecessors": predecessors,
        "context": context,
        "nearby_comparisons": nearby_comparisons,
        "recommendation": {
            "priority": _priority(why),
            "reasons": why,
        },
    }


def _predecessors(function: Function, target: BasicBlock, context: dict[str, Any]) -> list[str]:
    if context.get("predecessors"):
        return list(context["predecessors"])
    preds = []
    for block in function.blocks:
        if target.start in block.succs:
            preds.append(hex_addr(block.start))
    return preds


def _nearby_comparisons(instructions: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    result = []
    for index, instruction in enumerate(instructions):
        mnemonic = instruction.strip().split(None, 1)[0].lower() if instruction.strip() else ""
        kind = _comparison_kind(mnemonic)
        if kind is None:
            continue
        result.append(
            {
                "index": index,
                "kind": kind,
                "instruction": instruction,
                "reason": _comparison_reason(kind),
            }
        )
    return result


def _comparison_kind(mnemonic: str) -> str | None:
    if not mnemonic:
        return None
    for prefix, kind in COMPARE_HINTS:
        if mnemonic.startswith(prefix):
            if prefix == "j" and mnemonic in {"jmp", "jr", "jirl"}:
                return None
            return kind
    return None


def _comparison_reason(kind: str) -> str:
    if kind == "compare":
        return "The block contains a direct compare/test instruction."
    if kind == "conditional_branch":
        return "The block contains a conditional branch that may encode a path decision."
    if kind in {"conditional_move", "conditional_set"}:
        return "The block contains conditional data flow that can hide a branch predicate."
    return "The instruction may affect path selection."


def _recommendation_reasons(
    context: dict[str, Any],
    predecessors: list[str],
    successors: list[str],
    nearby_comparisons: list[dict[str, Any]],
) -> list[str]:
    reasons = []
    if len(successors) > 1:
        reasons.append("multiple successors: likely branch or dispatcher decision point")
    if len(predecessors) > 1:
        reasons.append("multiple predecessors: block may merge control-flow state")
    if nearby_comparisons:
        reasons.append("nearby compare/conditional instructions found")
    if context.get("calls"):
        reasons.append("calls helper/API functions that may validate input or transform state")
    if context.get("strings"):
        reasons.append("references strings useful for semantic labeling")
    if context.get("constants"):
        reasons.append("contains constants that may be thresholds, magic values, or state ids")
    if context.get("data_refs") or context.get("code_refs"):
        reasons.append("has data/code references worth opening in the disassembler")
    return reasons or ["no strong heuristic signal; inspect only if reached by an interesting trace"]


def _priority(reasons: list[str]) -> str:
    joined = " ".join(reasons)
    if "multiple successors" in joined and "compare" in joined:
        return "high"
    if "calls" in joined or "constants" in joined or "multiple predecessors" in joined:
        return "medium"
    return "low"
