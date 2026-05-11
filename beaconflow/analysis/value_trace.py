"""
Value Trace - 关键比较点寄存器/内存/比较值追踪。

让 AI 不只知道"哪个块被执行"，还知道关键比较点发生了什么。
例如：
    0x40123a cmp eax, 0x41
    eax = 0x42
    branch = fail
    input_offset = 3

支持从 DynamoRIO drcov 日志和 QEMU 地址日志中提取执行流，
结合 metadata 中的 decision point 信息，推断比较语义。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr


@dataclass
class CompareEvent:
    address: int
    function: str
    compare_type: str
    instruction: str
    left_operand: str
    right_operand: str
    branch_result: str | None = None
    taken_address: int | None = None
    fallthrough_address: int | None = None
    input_offset: int | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "address": hex_addr(self.address),
            "function": self.function,
            "compare_type": self.compare_type,
            "instruction": self.instruction,
            "left_operand": self.left_operand,
            "right_operand": self.right_operand,
        }
        if self.branch_result is not None:
            result["branch_result"] = self.branch_result
        if self.taken_address is not None:
            result["taken_address"] = hex_addr(self.taken_address)
        if self.fallthrough_address is not None:
            result["fallthrough_address"] = hex_addr(self.fallthrough_address)
        if self.input_offset is not None:
            result["input_offset"] = self.input_offset
        if self.context:
            result["context"] = self.context
        return result


@dataclass
class InputSite:
    address: int
    function: str
    call_name: str
    input_type: str
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "address": hex_addr(self.address),
            "function": self.function,
            "call_name": self.call_name,
            "input_type": self.input_type,
        }
        if self.context:
            result["context"] = self.context
        return result


@dataclass
class DispatcherState:
    address: int
    function: str
    state_variable_hint: str | None = None
    observed_targets: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "address": hex_addr(self.address),
            "function": self.function,
        }
        if self.state_variable_hint:
            result["state_variable_hint"] = self.state_variable_hint
        if self.observed_targets:
            result["observed_targets"] = self.observed_targets
        if self.context:
            result["context"] = self.context
        return result


_COMPARE_PATTERNS = [
    re.compile(r"\bCMP\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
    re.compile(r"\bTEST\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
    re.compile(r"\bSUB\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
    re.compile(r"\bADD\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
    re.compile(r"\bAND\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
    re.compile(r"\bXOR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
    re.compile(r"\bOR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE),
]

_JCC_MNEMONICS = frozenset({
    "JE", "JZ", "JNE", "JNZ", "JL", "JNGE", "JGE", "JNL", "JLE", "JNG",
    "JG", "JNLE", "JB", "JNAE", "JAE", "JNB", "JBE", "JNA", "JA", "JNBE",
    "JS", "JNS", "JO", "JNO", "JP", "JPE", "JNP", "JPO", "JCXZ", "JECXZ", "JRCXZ",
})

_CHECKER_CALLS = frozenset({
    "strcmp", "strncmp", "memcmp", "strlen", "wcscmp", "wcsncmp",
    "wmemcmp", "bcmp",
})

_INPUT_CALLS = frozenset({
    "read", "recv", "recvfrom", "scanf", "sscanf", "fscanf",
    "fgets", "gets", "getchar", "fgetc", "fread",
    "readline", "input",
})

_IMMEDIATE_PATTERN = re.compile(r"^0[xX][0-9a-fA-F]+$|^[0-9]+$")


def _parse_mnemonic(insn: str) -> str:
    parts = insn.strip().split(None, 1)
    return parts[0].upper() if parts else ""


def _is_immediate(operand: str) -> bool:
    return bool(_IMMEDIATE_PATTERN.match(operand.strip().rstrip(",").rstrip("hH")))


def _extract_compare_operands(insn: str) -> tuple[str, str] | None:
    for pat in _COMPARE_PATTERNS:
        m = pat.search(insn)
        if m:
            return m.group(1).rstrip(","), m.group(2).rstrip(",")
    return None


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


def _classify_compare_type(mnemonic: str, call_name: str | None) -> str:
    if call_name and call_name.lower().rstrip("_") in _CHECKER_CALLS:
        return "string_compare"
    if mnemonic == "CMP":
        return "cmp"
    if mnemonic == "TEST":
        return "test"
    if mnemonic in ("SUB", "ADD", "AND", "XOR", "OR"):
        return "arithmetic"
    return "unknown"


def _infer_branch_result(
    block_addr: int,
    block_end: int,
    succs: tuple[int, ...],
    jcc_target_str: str | None,
    executed_addrs: set[int] | None,
) -> str | None:
    if executed_addrs is None:
        return None
    if not succs:
        return None
    taken_addr = None
    fallthrough_addr = block_end
    if jcc_target_str:
        try:
            taken_addr = int(jcc_target_str, 16)
        except ValueError:
            pass
    for succ in succs:
        if succ in executed_addrs:
            if taken_addr is not None and succ == taken_addr:
                return "taken"
            if succ == fallthrough_addr:
                return "fallthrough"
    for succ in succs:
        if succ in executed_addrs:
            return "taken" if succ != fallthrough_addr else "fallthrough"
    return "not_executed"


def _find_input_offset_for_block(
    block_addr: int,
    input_sites: list[InputSite],
    max_distance: int = 0x200,
) -> int | None:
    closest = None
    closest_dist = max_distance
    for site in input_sites:
        dist = block_addr - site.address
        if 0 < dist < closest_dist:
            closest_dist = dist
            closest = site
    return closest_dist if closest else None


def extract_compare_events(
    metadata: ProgramMetadata,
    executed_addrs: set[int] | None = None,
    focus_function: str | None = None,
) -> list[CompareEvent]:
    events: list[CompareEvent] = []

    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            addr_match = focus_function.startswith("0x") and func.start == int(focus_function, 16)
            if not addr_match:
                continue

        for block in func.blocks:
            ctx = block.context
            if not ctx.instructions:
                continue

            checker_call: str | None = None
            for call in ctx.calls:
                if call.lower().rstrip("_") in _CHECKER_CALLS:
                    checker_call = call
                    break

            instructions = list(ctx.instructions)
            for i, insn in enumerate(instructions):
                mnemonic = _parse_mnemonic(insn)
                operands = _extract_compare_operands(insn)

                if operands is None and mnemonic not in _JCC_MNEMONICS:
                    continue

                if operands:
                    left, right = operands
                    compare_type = _classify_compare_type(mnemonic, checker_call)

                    jcc_target_str = None
                    if i + 1 < len(instructions):
                        next_mnemonic = _parse_mnemonic(instructions[i + 1])
                        if next_mnemonic in _JCC_MNEMONICS:
                            jcc_target_str = _extract_jcc_target(instructions[i + 1])

                    branch_result = _infer_branch_result(
                        block.start, block.end, block.succs,
                        jcc_target_str, executed_addrs,
                    )

                    taken_addr = None
                    fallthrough_addr = block.end
                    if jcc_target_str:
                        try:
                            taken_addr = int(jcc_target_str, 16)
                        except ValueError:
                            pass

                    event = CompareEvent(
                        address=block.start,
                        function=func.name,
                        compare_type=compare_type,
                        instruction=insn.strip(),
                        left_operand=left,
                        right_operand=right,
                        branch_result=branch_result,
                        taken_address=taken_addr,
                        fallthrough_address=fallthrough_addr,
                        context=ctx.to_json(),
                    )
                    events.append(event)

                elif mnemonic in _JCC_MNEMONICS and checker_call and i > 0:
                    prev_mnemonic = _parse_mnemonic(instructions[i - 1])
                    if prev_mnemonic not in ("CMP", "TEST"):
                        jcc_target_str = _extract_jcc_target(insn)
                        branch_result = _infer_branch_result(
                            block.start, block.end, block.succs,
                            jcc_target_str, executed_addrs,
                        )
                        taken_addr = None
                        if jcc_target_str:
                            try:
                                taken_addr = int(jcc_target_str, 16)
                            except ValueError:
                                pass

                        event = CompareEvent(
                            address=block.start,
                            function=func.name,
                            compare_type="string_compare",
                            instruction=insn.strip(),
                            left_operand=f"{checker_call}()",
                            right_operand="<expected>",
                            branch_result=branch_result,
                            taken_address=taken_addr,
                            fallthrough_address=block.end,
                            context=ctx.to_json(),
                        )
                        events.append(event)

    return events


def extract_input_sites(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
) -> list[InputSite]:
    sites: list[InputSite] = []

    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            addr_match = focus_function.startswith("0x") and func.start == int(focus_function, 16)
            if not addr_match:
                continue

        for block in func.blocks:
            for call in block.context.calls:
                call_lower = call.lower().rstrip("_")
                if call_lower in _INPUT_CALLS:
                    input_type = "network" if call_lower in ("recv", "recvfrom") else "file" if call_lower in ("fread", "fgets", "fgetc") else "stdio"
                    sites.append(InputSite(
                        address=block.start,
                        function=func.name,
                        call_name=call,
                        input_type=input_type,
                        context=block.context.to_json(),
                    ))

    return sites


def extract_dispatcher_states(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
    min_succs: int = 4,
) -> list[DispatcherState]:
    dispatchers: list[DispatcherState] = []

    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            addr_match = focus_function.startswith("0x") and func.start == int(focus_function, 16)
            if not addr_match:
                continue

        for block in func.blocks:
            if len(block.succs) < min_succs:
                continue

            state_hint = None
            for insn in block.context.instructions:
                insn_upper = insn.upper()
                if "CMP" in insn_upper or "SUB" in insn_upper:
                    m = re.search(r"(?:CMP|SUB)\s+\w+\s*,\s*(\S+)", insn, re.IGNORECASE)
                    if m:
                        state_hint = m.group(1).rstrip(",")
                        break

            dispatchers.append(DispatcherState(
                address=block.start,
                function=func.name,
                state_variable_hint=state_hint,
                observed_targets=[hex_addr(s) for s in block.succs],
                context=block.context.to_json(),
            ))

    return dispatchers


def analyze_value_trace(
    metadata: ProgramMetadata,
    executed_addrs: set[int] | None = None,
    focus_function: str | None = None,
) -> dict[str, Any]:
    compare_events = extract_compare_events(metadata, executed_addrs, focus_function)
    input_sites = extract_input_sites(metadata, focus_function)
    dispatcher_states = extract_dispatcher_states(metadata, focus_function)

    for event in compare_events:
        offset = _find_input_offset_for_block(event.address, input_sites)
        if offset is not None:
            event.input_offset = offset

    immediate_compares = [
        e for e in compare_events
        if _is_immediate(e.right_operand) and e.compare_type in ("cmp", "string_compare")
    ]

    return {
        "summary": {
            "total_compare_events": len(compare_events),
            "immediate_compares": len(immediate_compares),
            "input_sites": len(input_sites),
            "dispatcher_states": len(dispatcher_states),
            "focus_function": focus_function,
        },
        "compare_events": [e.to_dict() for e in compare_events],
        "immediate_compares": [e.to_dict() for e in immediate_compares],
        "input_sites": [s.to_dict() for s in input_sites],
        "dispatcher_states": [d.to_dict() for d in dispatcher_states],
    }
