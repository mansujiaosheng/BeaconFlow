from __future__ import annotations

import re
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr

_JCC_MNEMONICS = frozenset({
    "JE", "JZ", "JNE", "JNZ", "JL", "JNGE", "JGE", "JNL", "JLE", "JNG",
    "JG", "JNLE", "JB", "JNAE", "JAE", "JNB", "JBE", "JNA", "JA", "JNBE",
    "JS", "JNS", "JO", "JNO", "JP", "JPE", "JNP", "JPO", "JCXZ", "JECXZ", "JRCXZ",
})

_COMPARE_MNEMONICS = frozenset({"CMP", "TEST", "COMISS", "COMISD", "UCOMISS", "UCOMISD"})

_CMOV_MNEMONICS = frozenset({
    "CMOVA", "CMOVAE", "CMOVB", "CMOVBE", "CMOVC", "CMOVE", "CMOVG",
    "CMOVGE", "CMOVL", "CMOVLE", "CMOVNA", "CMOVNAE", "CMOVNB", "CMOVNBE",
    "CMOVNC", "CMOVNE", "CMOVNG", "CMOVNGE", "CMOVNL", "CMOVNLE", "CMOVNO",
    "CMOVNP", "CMOVNS", "CMOVO", "CMOVP", "CMOVPE", "CMOVPO", "CMOVS", "CMOVZ", "CMOVNZ",
})

_SETCC_MNEMONICS = frozenset({
    "SETA", "SETAE", "SETB", "SETBE", "SETC", "SETE", "SETG", "SETGE",
    "SETL", "SETLE", "SETNA", "SETNAE", "SETNB", "SETNBE", "SETNC", "SETNE",
    "SETNG", "SETNGE", "SETNL", "SETNLE", "SETNO", "SETNP", "SETNS", "SETO",
    "SETP", "SETPE", "SETPO", "SETS", "SETZ", "SETNZ",
})

_CHECKER_CALLS = frozenset({"strcmp", "strncmp", "memcmp", "strlen", "wcscmp", "wcsncmp"})

_JUMP_TABLE_PATTERNS = [
    re.compile(r"\b(JMP|BR)\s+\[", re.IGNORECASE),
    re.compile(r"\b(JMP|BR)\s+.*\+.*\*", re.IGNORECASE),
    re.compile(r"\bSHL\b.*\bADD\b", re.IGNORECASE),
]


def _parse_mnemonic(insn: str) -> str:
    parts = insn.strip().split(None, 1)
    return parts[0].upper() if parts else ""


def _is_jcc(mnemonic: str) -> bool:
    return mnemonic in _JCC_MNEMONICS


def _is_compare(mnemonic: str) -> bool:
    return mnemonic in _COMPARE_MNEMONICS


def _is_cmov(mnemonic: str) -> bool:
    return mnemonic in _CMOV_MNEMONICS


def _is_setcc(mnemonic: str) -> bool:
    return mnemonic in _SETCC_MNEMONICS


def _is_checker_call(call_name: str) -> bool:
    return call_name.lower().rstrip("_") in _CHECKER_CALLS


def _is_jump_table_insn(insn: str) -> bool:
    for pat in _JUMP_TABLE_PATTERNS:
        if pat.search(insn):
            return True
    return False


def _extract_jcc_target(insn: str) -> str | None:
    parts = insn.strip().split(None, 1)
    if len(parts) < 2:
        return None
    operand = parts[1].strip().rstrip(",")
    if operand.startswith("0x") or operand.startswith("0X"):
        return operand
    for token in operand.split(","):
        token = token.strip()
        if token.startswith("0x") or token.startswith("0X"):
            return token
    return None


def _compute_priority(dp_type: str, call_name: str | None, has_checker: bool) -> str:
    if dp_type == "checker_call":
        return "critical"
    if dp_type == "jump_table":
        return "high"
    if has_checker:
        return "high"
    if dp_type in ("cmp_jcc", "test_jcc"):
        return "medium"
    if dp_type in ("cmovcc", "setcc"):
        return "low"
    return "low"


def _compute_reason(dp_type: str, compare_insn: str | None, branch_insn: str | None, call_name: str | None) -> str:
    if dp_type == "checker_call" and call_name:
        return f"String/memory comparison via {call_name}() followed by conditional branch"
    if dp_type == "jump_table":
        return "Switch/jump table dispatch"
    if dp_type == "cmp_jcc" and compare_insn:
        return f"Comparison ({compare_insn.split()[0]}) followed by conditional branch"
    if dp_type == "test_jcc" and compare_insn:
        return f"Bit test ({compare_insn.split()[0]}) followed by conditional branch"
    if dp_type == "cmovcc":
        return "Conditional move (data-dependent selection)"
    if dp_type == "setcc":
        return "Conditional set (flag to boolean)"
    return "Conditional branch"


def find_decision_points(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            addr_match = focus_function.startswith("0x") and func.start == int(focus_function, 16)
            if not addr_match:
                continue

        for block in func.blocks:
            ctx = block.context
            if not ctx.instructions:
                continue

            dp = _scan_block_for_decision(func, block)
            if dp:
                results.extend(dp)

    results.sort(key=lambda x: (
        0 if x["ai_priority"] == "critical" else (1 if x["ai_priority"] == "high" else (2 if x["ai_priority"] == "medium" else 3)),
        x.get("address", 0),
    ))
    return results


def analyze_decision_points(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
) -> dict[str, Any]:
    # 查找所有 decision points
    decision_points = find_decision_points(metadata, focus_function=focus_function)

    # 统计各优先级数量
    priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for dp in decision_points:
        p = dp.get("ai_priority", "low")
        if p in priority_counts:
            priority_counts[p] += 1

    return {
        "summary": {
            "total": len(decision_points),
            "critical": priority_counts["critical"],
            "high": priority_counts["high"],
            "medium": priority_counts["medium"],
            "low": priority_counts["low"],
            "focus_function": focus_function,
        },
        "decision_points": decision_points,
    }


def inspect_decision_point(
    metadata: ProgramMetadata,
    address: int,
) -> dict[str, Any] | None:
    # 在所有 decision points 中查找指定地址
    for func in metadata.functions:
        for block in func.blocks:
            if block.start == address:
                dp_list = _scan_block_for_decision(func, block)
                if dp_list:
                    return dp_list[0]
    return None


def _scan_block_for_decision(func: Any, block: Any) -> list[dict[str, Any]]:
    instructions = list(block.context.instructions)
    results: list[dict[str, Any]] = []
    checker_call_name: str | None = None

    for i, insn in enumerate(instructions):
        mnemonic = _parse_mnemonic(insn)

        # 检测 checker call (strcmp, memcmp, strlen 等)
        if mnemonic == "CALL" and block.context.calls:
            for call_name in block.context.calls:
                if _is_checker_call(call_name):
                    checker_call_name = call_name
                    break

        # cmp + jcc 模式
        if _is_compare(mnemonic) and i + 1 < len(instructions):
            next_mnemonic = _parse_mnemonic(instructions[i + 1])
            if _is_jcc(next_mnemonic):
                dp_type = "cmp_jcc" if mnemonic == "CMP" else "test_jcc"
                target = _extract_jcc_target(instructions[i + 1])
                has_checker = checker_call_name is not None
                dp = _build_decision_point(
                    func=func, block=block, dp_type=dp_type,
                    compare_insn=insn, branch_insn=instructions[i + 1],
                    call_name=checker_call_name, target=target,
                    has_checker=has_checker,
                )
                if dp:
                    results.append(dp)
                continue

        # jcc 紧跟在 checker call 块后面（跨块模式，通过 call 字段检测）
        if _is_jcc(mnemonic) and checker_call_name and i > 0:
            prev_mnemonic = _parse_mnemonic(instructions[i - 1])
            if prev_mnemonic not in _COMPARE_MNEMONICS:
                target = _extract_jcc_target(insn)
                dp = _build_decision_point(
                    func=func, block=block, dp_type="checker_call",
                    compare_insn=None, branch_insn=insn,
                    call_name=checker_call_name, target=target,
                    has_checker=True,
                )
                if dp:
                    results.append(dp)
                continue

        # cmovcc 模式
        if _is_cmov(mnemonic):
            dp = _build_decision_point(
                func=func, block=block, dp_type="cmovcc",
                compare_insn=None, branch_insn=insn,
                call_name=None, target=None, has_checker=False,
            )
            if dp:
                results.append(dp)
            continue

        # setcc 模式
        if _is_setcc(mnemonic):
            dp = _build_decision_point(
                func=func, block=block, dp_type="setcc",
                compare_insn=None, branch_insn=insn,
                call_name=None, target=None, has_checker=False,
            )
            if dp:
                results.append(dp)
            continue

        # jump table 模式
        if _is_jump_table_insn(insn):
            dp = _build_decision_point(
                func=func, block=block, dp_type="jump_table",
                compare_insn=None, branch_insn=insn,
                call_name=None, target=None, has_checker=False,
            )
            if dp:
                results.append(dp)
            continue

    return results


def _build_decision_point(
    func: Any,
    block: Any,
    dp_type: str,
    compare_insn: str | None,
    branch_insn: str | None,
    call_name: str | None,
    target: str | None,
    has_checker: bool,
) -> dict[str, Any] | None:
    successors = [hex_addr(s) for s in block.succs]
    fallthrough = hex_addr(block.end) if block.succs else None

    dp = {
        "function": func.name,
        "address": hex_addr(block.start),
        "type": dp_type,
        "compare_instruction": compare_insn,
        "branch_instruction": branch_insn,
        "call_instruction": call_name,
        "successors": successors,
        "observed_successor": None,
        "taken": target,
        "fallthrough": fallthrough,
        "target": target,
        "ai_priority": _compute_priority(dp_type, call_name, has_checker),
        "reason": _compute_reason(dp_type, compare_insn, branch_insn, call_name),
        "related_block_context": block.context.to_json(),
    }
    return dp
