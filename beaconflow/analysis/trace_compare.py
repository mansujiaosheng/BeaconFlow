"""
Trace Compare - 比较语义提取。

专门提取程序中的"输入校验点"，输出结构化的比较语义信息。
让 AI 可以从"路径失败"进一步知道"失败原因"。

例如：
    {
        "addr": "0x401300",
        "type": "memcmp",
        "arg1": "input+8",
        "arg2": "table+0x20",
        "length": 16,
        "result": "not_equal"
    }

重点识别：
- cmp reg, imm
- cmp reg, reg
- test reg, reg
- strcmp / strncmp / memcmp
- strlen
- switch / jump table
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr


@dataclass
class CompareSemantics:
    address: int
    function: str
    compare_type: str
    instruction: str
    left: str
    right: str
    length: int | None = None
    result: str | None = None
    branch_taken: str | None = None
    jump_targets: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "addr": hex_addr(self.address),
            "type": self.compare_type,
            "instruction": self.instruction,
            "left": self.left,
            "right": self.right,
        }
        if self.function:
            result["function"] = self.function
        if self.length is not None:
            result["length"] = self.length
        if self.result is not None:
            result["result"] = self.result
        if self.branch_taken is not None:
            result["branch_taken"] = self.branch_taken
        if self.jump_targets:
            result["jump_targets"] = self.jump_targets
        if self.context:
            result["context"] = self.context
        return result


_CMP_IMM_PATTERN = re.compile(r"\bCMP\s+(\S+)\s*,\s*(0[xX][0-9a-fA-F]+|\d+)", re.IGNORECASE)
_CMP_REG_PATTERN = re.compile(r"\bCMP\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_TEST_PATTERN = re.compile(r"\bTEST\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_SUB_PATTERN = re.compile(r"\bSUB\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)

_STRING_COMPARE_CALLS = {
    "strcmp": {"type": "strcmp", "length": None},
    "strncmp": {"type": "strncmp", "length": "arg3"},
    "memcmp": {"type": "memcmp", "length": "arg3"},
    "wmemcmp": {"type": "wmemcmp", "length": "arg3"},
    "bcmp": {"type": "bcmp", "length": "arg3"},
    "strlen": {"type": "strlen", "length": None},
    "wcslen": {"type": "wcslen", "length": None},
    "wcscmp": {"type": "wcscmp", "length": None},
    "wcsncmp": {"type": "wcsncmp", "length": "arg3"},
}

_JCC_MNEMONICS = frozenset({
    "JE", "JZ", "JNE", "JNZ", "JL", "JNGE", "JGE", "JNL", "JLE", "JNG",
    "JG", "JNLE", "JB", "JNAE", "JAE", "JNB", "JBE", "JNA", "JA", "JNBE",
    "JS", "JNS", "JO", "JNO", "JP", "JPE", "JNP", "JPO",
})

_JUMP_TABLE_PATTERNS = [
    re.compile(r"\bJMP\s+\[", re.IGNORECASE),
    re.compile(r"\bJMP\s+.*\+.*\*", re.IGNORECASE),
    re.compile(r"\bBR\s+\[", re.IGNORECASE),
]


def _parse_mnemonic(insn: str) -> str:
    parts = insn.strip().split(None, 1)
    return parts[0].upper() if parts else ""


def _is_immediate(operand: str) -> bool:
    cleaned = operand.strip().rstrip(",").rstrip("hH")
    return bool(re.match(r"^(0[xX][0-9a-fA-F]+|\d+)$", cleaned))


def _try_parse_int(value: str) -> int | None:
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        return None


def _infer_string_compare_result(
    call_name: str,
    executed_addrs: set[int] | None,
    block_start: int,
    block_end: int,
    succs: tuple[int, ...],
) -> str | None:
    if executed_addrs is None or not succs:
        return None
    for succ in succs:
        if succ in executed_addrs:
            if succ == block_end:
                return "equal"
            return "not_equal"
    return None


def _infer_cmp_result(
    executed_addrs: set[int] | None,
    block_start: int,
    block_end: int,
    succs: tuple[int, ...],
    jcc_target: int | None,
) -> str | None:
    if executed_addrs is None or not succs:
        return None
    for succ in succs:
        if succ in executed_addrs:
            if jcc_target is not None and succ == jcc_target:
                return "not_equal" if jcc_target != block_end else "equal"
            if succ == block_end:
                return "equal"
            return "not_equal"
    return None


def _detect_jump_table(insn: str) -> bool:
    for pat in _JUMP_TABLE_PATTERNS:
        if pat.search(insn):
            return True
    return False


def extract_compare_semantics(
    metadata: ProgramMetadata,
    executed_addrs: set[int] | None = None,
    focus_function: str | None = None,
) -> list[CompareSemantics]:
    results: list[CompareSemantics] = []

    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            addr_match = focus_function.startswith("0x") and func.start == int(focus_function, 16)
            if not addr_match:
                continue

        for block in func.blocks:
            ctx = block.context
            if not ctx.instructions:
                continue

            string_call_info: dict[str, Any] | None = None
            for call in ctx.calls:
                call_lower = call.lower().rstrip("_")
                if call_lower in _STRING_COMPARE_CALLS:
                    string_call_info = {"name": call, **_STRING_COMPARE_CALLS[call_lower]}
                    break

            instructions = list(ctx.instructions)
            for i, insn in enumerate(instructions):
                mnemonic = _parse_mnemonic(insn)

                # cmp reg, imm 模式
                m = _CMP_IMM_PATTERN.search(insn)
                if m:
                    left = m.group(1).rstrip(",")
                    right = m.group(2)
                    right_val = _try_parse_int(right)
                    jcc_target = None
                    branch_taken = None
                    if i + 1 < len(instructions):
                        next_mnemonic = _parse_mnemonic(instructions[i + 1])
                        if next_mnemonic in _JCC_MNEMONICS:
                            parts = instructions[i + 1].strip().split(None, 1)
                            if len(parts) >= 2:
                                target_str = parts[1].strip().rstrip(",")
                                jcc_target = _try_parse_int(target_str)
                            cmp_result = _infer_cmp_result(
                                executed_addrs, block.start, block.end,
                                block.succs, jcc_target,
                            )
                            if cmp_result:
                                branch_taken = cmp_result

                    results.append(CompareSemantics(
                        address=block.start,
                        function=func.name,
                        compare_type="cmp_imm",
                        instruction=insn.strip(),
                        left=left,
                        right=right,
                        length=right_val,
                        result=branch_taken,
                        branch_taken=branch_taken,
                        context=ctx.to_json(),
                    ))
                    continue

                # cmp reg, reg 模式
                m = _CMP_REG_PATTERN.search(insn)
                if m and mnemonic == "CMP":
                    left = m.group(1).rstrip(",")
                    right = m.group(2).rstrip(",")
                    if not _is_immediate(right):
                        jcc_target = None
                        branch_taken = None
                        if i + 1 < len(instructions):
                            next_mnemonic = _parse_mnemonic(instructions[i + 1])
                            if next_mnemonic in _JCC_MNEMONICS:
                                parts = instructions[i + 1].strip().split(None, 1)
                                if len(parts) >= 2:
                                    target_str = parts[1].strip().rstrip(",")
                                    jcc_target = _try_parse_int(target_str)
                                cmp_result = _infer_cmp_result(
                                    executed_addrs, block.start, block.end,
                                    block.succs, jcc_target,
                                )
                                if cmp_result:
                                    branch_taken = cmp_result

                        results.append(CompareSemantics(
                            address=block.start,
                            function=func.name,
                            compare_type="cmp_reg",
                            instruction=insn.strip(),
                            left=left,
                            right=right,
                            result=branch_taken,
                            branch_taken=branch_taken,
                            context=ctx.to_json(),
                        ))
                        continue

                # test reg, reg 模式
                m = _TEST_PATTERN.search(insn)
                if m:
                    left = m.group(1).rstrip(",")
                    right = m.group(2).rstrip(",")
                    jcc_target = None
                    branch_taken = None
                    if i + 1 < len(instructions):
                        next_mnemonic = _parse_mnemonic(instructions[i + 1])
                        if next_mnemonic in _JCC_MNEMONICS:
                            parts = instructions[i + 1].strip().split(None, 1)
                            if len(parts) >= 2:
                                target_str = parts[1].strip().rstrip(",")
                                jcc_target = _try_parse_int(target_str)
                            cmp_result = _infer_cmp_result(
                                executed_addrs, block.start, block.end,
                                block.succs, jcc_target,
                            )
                            if cmp_result:
                                branch_taken = cmp_result

                    results.append(CompareSemantics(
                        address=block.start,
                        function=func.name,
                        compare_type="test",
                        instruction=insn.strip(),
                        left=left,
                        right=right,
                        result=branch_taken,
                        branch_taken=branch_taken,
                        context=ctx.to_json(),
                    ))
                    continue

                # sub 模式（常用于长度检查）
                m = _SUB_PATTERN.search(insn)
                if m and i + 1 < len(instructions):
                    next_mnemonic = _parse_mnemonic(instructions[i + 1])
                    if next_mnemonic in _JCC_MNEMONICS:
                        left = m.group(1).rstrip(",")
                        right = m.group(2).rstrip(",")
                        results.append(CompareSemantics(
                            address=block.start,
                            function=func.name,
                            compare_type="sub_cmp",
                            instruction=insn.strip(),
                            left=left,
                            right=right,
                            context=ctx.to_json(),
                        ))
                        continue

                # 字符串/内存比较调用
                if mnemonic == "CALL" and string_call_info:
                    result_str = _infer_string_compare_result(
                        string_call_info["name"],
                        executed_addrs, block.start, block.end, block.succs,
                    )
                    results.append(CompareSemantics(
                        address=block.start,
                        function=func.name,
                        compare_type=string_call_info["type"],
                        instruction=insn.strip(),
                        left="arg1",
                        right="arg2",
                        length=None,
                        result=result_str,
                        branch_taken=result_str,
                        context=ctx.to_json(),
                    ))
                    continue

                # jump table / switch 模式
                if _detect_jump_table(insn):
                    targets = [hex_addr(s) for s in block.succs]
                    results.append(CompareSemantics(
                        address=block.start,
                        function=func.name,
                        compare_type="switch",
                        instruction=insn.strip(),
                        left="index",
                        right="table",
                        jump_targets=targets,
                        context=ctx.to_json(),
                    ))
                    continue

    return results


def analyze_trace_compare(
    metadata: ProgramMetadata,
    executed_addrs: set[int] | None = None,
    focus_function: str | None = None,
) -> dict[str, Any]:
    semantics = extract_compare_semantics(metadata, executed_addrs, focus_function)

    type_counts: dict[str, int] = {}
    for s in semantics:
        type_counts[s.compare_type] = type_counts.get(s.compare_type, 0) + 1

    failed_compares = [s for s in semantics if s.result == "not_equal"]
    passed_compares = [s for s in semantics if s.result == "equal"]

    return {
        "summary": {
            "total": len(semantics),
            "by_type": type_counts,
            "failed_compares": len(failed_compares),
            "passed_compares": len(passed_compares),
            "focus_function": focus_function,
        },
        "compares": [s.to_dict() for s in semantics],
        "failed_compares": [s.to_dict() for s in failed_compares],
        "passed_compares": [s.to_dict() for s in passed_compares],
    }
