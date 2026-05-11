"""
Input Taint - 输入到分支的轻量污点分析。

从输入点（read/recv/scanf）出发，通过寄存器传递链追踪到比较/分支点，
输出"输入偏移 → 分支"的映射。

让 AI 知道"第 N 个字节影响了哪个分支"。

实现策略：
1. 识别输入点（InputSite）和比较点（ComparePoint）
2. 通过函数内基本块的寄存器传递链（MOV/LEA/XOR/ADD/SUB）追踪
3. 输出 InputOffset → Branch 映射

注意：这是轻量级静态分析，不做完整的数据流分析。
仅追踪函数内可见的寄存器传递链。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr


@dataclass
class TaintSource:
    address: int
    function: str
    call_name: str
    input_type: str
    output_register: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "address": hex_addr(self.address),
            "function": self.function,
            "call_name": self.call_name,
            "input_type": self.input_type,
        }
        if self.output_register:
            result["output_register"] = self.output_register
        if self.context:
            result["context"] = self.context
        return result


@dataclass
class TaintSink:
    address: int
    function: str
    compare_type: str
    instruction: str
    left_operand: str
    right_operand: str
    branch_result: str | None = None
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
        if self.context:
            result["context"] = self.context
        return result


@dataclass
class TaintEdge:
    source_address: int
    sink_address: int
    function: str
    taint_register: str
    propagation_path: list[str] = field(default_factory=list)
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_address": hex_addr(self.source_address),
            "sink_address": hex_addr(self.sink_address),
            "function": self.function,
            "taint_register": self.taint_register,
            "confidence": self.confidence,
        }
        if self.propagation_path:
            result["propagation_path"] = self.propagation_path
        return result


@dataclass
class InputBranchMapping:
    input_offset: int | None
    source: TaintSource
    sink: TaintSink
    edge: TaintEdge

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "edge": self.edge.to_dict(),
        }
        if self.input_offset is not None:
            result["input_offset"] = self.input_offset
        return result


_INPUT_CALLS = frozenset({
    "read", "recv", "recvfrom", "scanf", "sscanf", "fscanf",
    "fgets", "gets", "getchar", "fgetc", "fread",
    "readline", "input",
})

_INPUT_OUTPUT_REGS = {
    "read": "RAX",
    "recv": "RAX",
    "recvfrom": "RAX",
    "scanf": "RAX",
    "sscanf": "RAX",
    "fscanf": "RAX",
    "fgets": "RAX",
    "gets": "RAX",
    "getchar": "EAX",
    "fgetc": "EAX",
    "fread": "RAX",
    "readline": "RAX",
    "input": "RAX",
}

_COMPARE_MNEMONICS = frozenset({"CMP", "TEST"})
_JCC_MNEMONICS = frozenset({
    "JE", "JZ", "JNE", "JNZ", "JL", "JNGE", "JGE", "JNL", "JLE", "JNG",
    "JG", "JNLE", "JB", "JNAE", "JAE", "JNB", "JBE", "JNA", "JA", "JNBE",
    "JS", "JNS", "JO", "JNO", "JP", "JPE", "JNP", "JPO",
})

_MOV_PATTERN = re.compile(r"\bMOV\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_LEA_PATTERN = re.compile(r"\bLEA\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_CMP_PATTERN = re.compile(r"\bCMP\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_TEST_PATTERN = re.compile(r"\bTEST\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_XOR_PATTERN = re.compile(r"\bXOR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_ADD_PATTERN = re.compile(r"\bADD\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_SUB_PATTERN = re.compile(r"\bSUB\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)


def _parse_mnemonic(insn: str) -> str:
    parts = insn.strip().split(None, 1)
    return parts[0].upper() if parts else ""


def _clean_operand(op: str) -> str:
    return op.strip().rstrip(",").upper()


def _extract_taint_sources(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
) -> list[TaintSource]:
    sources: list[TaintSource] = []
    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            continue
        for block in func.blocks:
            for call in block.context.calls:
                call_lower = call.lower().rstrip("_")
                if call_lower in _INPUT_CALLS:
                    output_reg = _INPUT_OUTPUT_REGS.get(call_lower)
                    input_type = "network" if call_lower in ("recv", "recvfrom") else "file" if call_lower in ("fread", "fgets", "fgetc") else "stdio"
                    sources.append(TaintSource(
                        address=block.start,
                        function=func.name,
                        call_name=call,
                        input_type=input_type,
                        output_register=output_reg,
                        context=block.context.to_json(),
                    ))
    return sources


def _extract_taint_sinks(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
) -> list[TaintSink]:
    sinks: list[TaintSink] = []
    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            continue
        for block in func.blocks:
            for insn in block.context.instructions:
                mnemonic = _parse_mnemonic(insn)
                if mnemonic in _COMPARE_MNEMONICS:
                    m = _CMP_PATTERN.search(insn) if mnemonic == "CMP" else _TEST_PATTERN.search(insn)
                    if m:
                        left = _clean_operand(m.group(1))
                        right = _clean_operand(m.group(2))
                        sinks.append(TaintSink(
                            address=block.start,
                            function=func.name,
                            compare_type=mnemonic.lower(),
                            instruction=insn.strip(),
                            left_operand=left,
                            right_operand=right,
                            context=block.context.to_json(),
                        ))
    return sinks


def _trace_register_propagation(
    func_blocks: list[Any],
    start_reg: str,
    source_addr: int,
) -> dict[str, list[str]]:
    reg_state: dict[str, str] = {start_reg: "input"}
    propagation: dict[str, list[str]] = {start_reg: [f"input@{hex_addr(source_addr)}"]}

    # 初始化子寄存器污点
    _SUB_REG_MAP = {
        "RAX": ("EAX", "AX", "AL"),
        "RBX": ("EBX", "BX", "BL"),
        "RCX": ("ECX", "CX", "CL"),
        "RDX": ("EDX", "DX", "DL"),
        "RSI": ("ESI", "SI", "SIL"),
        "RDI": ("EDI", "DI", "DIL"),
        "RBP": ("EBP", "BP", "BPL"),
        "RSP": ("ESP", "SP", "SPL"),
        "R8": ("R8D", "R8W", "R8B"),
        "R9": ("R9D", "R9W", "R9B"),
    }
    if start_reg in _SUB_REG_MAP:
        for sub in _SUB_REG_MAP[start_reg]:
            reg_state[sub] = "input"
            propagation[sub] = [f"input@{hex_addr(source_addr)}"]

    sorted_blocks = sorted(func_blocks, key=lambda b: b.start)

    for block in sorted_blocks:
        for insn in block.context.instructions:
            mnemonic = _parse_mnemonic(insn)

            if mnemonic == "MOV":
                m = _MOV_PATTERN.search(insn)
                if m:
                    dst = _clean_operand(m.group(1))
                    src = _clean_operand(m.group(2))
                    if src in reg_state and dst not in ("EFLAGS",):
                        reg_state[dst] = reg_state[src]
                        propagation[dst] = propagation.get(src, []) + [f"MOV->{dst}@{hex_addr(block.start)}"]
                        # 处理子寄存器传播
                        if dst in ("RAX",) and "EAX" not in reg_state:
                            reg_state["EAX"] = reg_state[dst]
                            propagation["EAX"] = propagation.get(dst, [])
                        if dst in ("EAX",) and "AL" not in reg_state:
                            reg_state["AL"] = reg_state[dst]
                            propagation["AL"] = propagation.get(dst, [])

            elif mnemonic == "LEA":
                m = _LEA_PATTERN.search(insn)
                if m:
                    dst = _clean_operand(m.group(1))
                    src = _clean_operand(m.group(2))
                    if any(r in src for r in reg_state):
                        reg_state[dst] = "input"
                        propagation[dst] = [f"LEA->{dst}@{hex_addr(block.start)}"]

            elif mnemonic == "XOR":
                m = _XOR_PATTERN.search(insn)
                if m:
                    dst = _clean_operand(m.group(1))
                    src = _clean_operand(m.group(2))
                    if dst == src:
                        reg_state.pop(dst, None)
                        propagation.pop(dst, None)
                    elif src in reg_state:
                        reg_state[dst] = reg_state[src]
                        propagation[dst] = propagation.get(src, []) + [f"XOR->{dst}@{hex_addr(block.start)}"]

            elif mnemonic in ("ADD", "SUB"):
                pat = _ADD_PATTERN if mnemonic == "ADD" else _SUB_PATTERN
                m = pat.search(insn)
                if m:
                    dst = _clean_operand(m.group(1))
                    src = _clean_operand(m.group(2))
                    if dst in reg_state or src in reg_state:
                        reg_state[dst] = "input"
                        propagation[dst] = propagation.get(dst, propagation.get(src, [])) + [f"{mnemonic}->{dst}@{hex_addr(block.start)}"]

    return propagation


def analyze_input_taint(
    metadata: ProgramMetadata,
    focus_function: str | None = None,
) -> dict[str, Any]:
    sources = _extract_taint_sources(metadata, focus_function)
    sinks = _extract_taint_sinks(metadata, focus_function)

    if not sources or not sinks:
        return {
            "summary": {
                "sources": len(sources),
                "sinks": len(sinks),
                "edges": 0,
                "mappings": 0,
                "focus_function": focus_function,
            },
            "sources": [s.to_dict() for s in sources],
            "sinks": [sk.to_dict() for sk in sinks],
            "edges": [],
            "mappings": [],
        }

    func_blocks_map: dict[str, list[Any]] = {}
    for func in metadata.functions:
        func_blocks_map[func.name] = list(func.blocks)

    edges: list[TaintEdge] = []
    mappings: list[InputBranchMapping] = []

    for source in sources:
        if not source.output_register:
            continue

        func_name = source.function
        blocks = func_blocks_map.get(func_name, [])
        if not blocks:
            continue

        propagation = _trace_register_propagation(blocks, source.output_register, source.address)

        for sink in sinks:
            if sink.function != func_name:
                continue

            tainted_in_sink = False
            taint_reg = None

            for reg in (sink.left_operand, sink.right_operand):
                if reg in propagation:
                    tainted_in_sink = True
                    taint_reg = reg
                    break

            # 检查子寄存器匹配
            if not tainted_in_sink:
                sub_reg_map = {
                    "RAX": ("EAX", "AX", "AL"),
                    "EAX": ("AX", "AL"),
                    "RBX": ("EBX", "BX", "BL"),
                    "RCX": ("ECX", "CX", "CL"),
                    "RDX": ("EDX", "DX", "DL"),
                }
                for reg in (sink.left_operand, sink.right_operand):
                    for parent, children in sub_reg_map.items():
                        if reg in children and parent in propagation:
                            tainted_in_sink = True
                            taint_reg = parent
                            break
                    if tainted_in_sink:
                        break

            if tainted_in_sink and taint_reg:
                prop_path = propagation.get(taint_reg, [])
                confidence = "high" if len(prop_path) <= 3 else "medium" if len(prop_path) <= 6 else "low"

                edge = TaintEdge(
                    source_address=source.address,
                    sink_address=sink.address,
                    function=func_name,
                    taint_register=taint_reg,
                    propagation_path=prop_path,
                    confidence=confidence,
                )
                edges.append(edge)

                input_offset = None
                if source.address < sink.address:
                    input_offset = sink.address - source.address

                mappings.append(InputBranchMapping(
                    input_offset=input_offset,
                    source=source,
                    sink=sink,
                    edge=edge,
                ))

    return {
        "summary": {
            "sources": len(sources),
            "sinks": len(sinks),
            "edges": len(edges),
            "mappings": len(mappings),
            "focus_function": focus_function,
        },
        "sources": [s.to_dict() for s in sources],
        "sinks": [sk.to_dict() for sk in sinks],
        "edges": [e.to_dict() for e in edges],
        "mappings": [m.to_dict() for m in mappings],
    }
