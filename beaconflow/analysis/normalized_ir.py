"""
Normalized IR - 统一中间表示。

将不同架构的指令统一为一种 IR，使后续分析不依赖具体架构。

IR 指令集：
- ASSIGN dst, src        : 赋值
- LOAD dst, addr         : 内存读取
- STORE addr, src        : 内存写入
- COMPARE left, right    : 比较
- BRANCH cond, target    : 条件分支
- JUMP target            : 无条件跳转
- CALL func, args        : 函数调用
- RETURN value           : 返回
- BINARY op, dst, src    : 二元运算 (ADD/SUB/AND/OR/XOR)
- NOP                    : 空操作

架构支持：
- x86/x64
- ARM/AArch64
- MIPS
- LoongArch
- RISC-V
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr


@dataclass
class IRInstruction:
    op: str
    operands: list[str] = field(default_factory=list)
    original: str = ""
    address: int = 0

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"op": self.op}
        if self.operands:
            result["operands"] = self.operands
        if self.original:
            result["original"] = self.original
        if self.address:
            result["address"] = hex_addr(self.address)
        return result


@dataclass
class IRBlock:
    label: str
    address: int
    instructions: list[IRInstruction] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "address": hex_addr(self.address),
            "instructions": [i.to_dict() for i in self.instructions],
            "successors": self.successors,
        }


@dataclass
class IRFunction:
    name: str
    address: int
    blocks: list[IRBlock] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": hex_addr(self.address),
            "blocks": [b.to_dict() for b in self.blocks],
        }


_X86_PATTERNS = [
    (re.compile(r"\bMOV\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "ASSIGN"),
    (re.compile(r"\bLEA\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "ASSIGN"),
    (re.compile(r"\bCMP\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "COMPARE"),
    (re.compile(r"\bTEST\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "COMPARE"),
    (re.compile(r"\bADD\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_ADD"),
    (re.compile(r"\bSUB\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_SUB"),
    (re.compile(r"\bAND\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_AND"),
    (re.compile(r"\bOR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_OR"),
    (re.compile(r"\bXOR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_XOR"),
    (re.compile(r"\bSHL\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_SHL"),
    (re.compile(r"\bSHR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_SHR"),
    (re.compile(r"\bCALL\s+(\S+)", re.IGNORECASE), "CALL"),
    (re.compile(r"\bRET", re.IGNORECASE), "RETURN"),
    (re.compile(r"\bNOP", re.IGNORECASE), "NOP"),
    (re.compile(r"\bPUSH\s+(\S+)", re.IGNORECASE), "PUSH"),
    (re.compile(r"\bPOP\s+(\S+)", re.IGNORECASE), "POP"),
]

_X86_JCC = re.compile(r"\b(J\w+)\s+(\S+)", re.IGNORECASE)
_X86_JMP = re.compile(r"\bJMP\s+(\S+)", re.IGNORECASE)

_JCC_TO_COND = {
    "JE": "equal", "JZ": "equal", "JNE": "not_equal", "JNZ": "not_equal",
    "JL": "less", "JNGE": "less", "JGE": "greater_equal", "JNL": "greater_equal",
    "JLE": "less_equal", "JNG": "less_equal", "JG": "greater", "JNLE": "greater",
    "JB": "below", "JNAE": "below", "JAE": "above_equal", "JNB": "above_equal",
    "JBE": "below_equal", "JNA": "below_equal", "JA": "above", "JNBE": "above",
    "JS": "sign", "JNS": "not_sign",
}

_ARM_PATTERNS = [
    (re.compile(r"\bMOV\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "ASSIGN"),
    (re.compile(r"\bLDR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "LOAD"),
    (re.compile(r"\bSTR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "STORE"),
    (re.compile(r"\bCMP\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "COMPARE"),
    (re.compile(r"\bTST\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "COMPARE"),
    (re.compile(r"\bADD\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_ADD"),
    (re.compile(r"\bSUB\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_SUB"),
    (re.compile(r"\bAND\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_AND"),
    (re.compile(r"\bORR\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_OR"),
    (re.compile(r"\bEOR\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_XOR"),
    (re.compile(r"\bBL\s+(\S+)", re.IGNORECASE), "CALL"),
    (re.compile(r"\bBX\s+LR", re.IGNORECASE), "RETURN"),
    (re.compile(r"\bNOP", re.IGNORECASE), "NOP"),
    (re.compile(r"\bPUSH\s+\{", re.IGNORECASE), "PUSH"),
    (re.compile(r"\bPOP\s+\{", re.IGNORECASE), "POP"),
]

_ARM_BRANCH = re.compile(r"\bB\.\w+\s+(\S+)", re.IGNORECASE)
_ARM_COND_MAP = {
    "EQ": "equal", "NE": "not_equal", "LT": "less", "GT": "greater",
    "LE": "less_equal", "GE": "greater_equal", "CS": "above_equal",
    "CC": "below", "LS": "below_equal", "HI": "above",
    "MI": "sign", "PL": "not_sign",
}

_MIPS_PATTERNS = [
    (re.compile(r"\b(lw|lb|lh|lbu)\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "LOAD"),
    (re.compile(r"\b(sw|sb|sh)\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "STORE"),
    (re.compile(r"\baddi?u?\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_ADD"),
    (re.compile(r"\bsubi?u?\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_SUB"),
    (re.compile(r"\band\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_AND"),
    (re.compile(r"\bor\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_OR"),
    (re.compile(r"\bxor\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_XOR"),
    (re.compile(r"\bjal\s+(\S+)", re.IGNORECASE), "CALL"),
    (re.compile(r"\bjr\s+\$ra", re.IGNORECASE), "RETURN"),
    (re.compile(r"\bnop", re.IGNORECASE), "NOP"),
    (re.compile(r"\bmove\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "ASSIGN"),
]

_MIPS_BRANCH = re.compile(r"\bb(eq|ne|gtz|lez|ltz|gez)\s+(\S+)", re.IGNORECASE)
_MIPS_COND_MAP = {
    "eq": "equal", "ne": "not_equal", "gtz": "greater", "lez": "less_equal",
    "ltz": "less", "gez": "greater_equal",
}

_LOONGARCH_PATTERNS = [
    (re.compile(r"\bli\.w\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "ASSIGN"),
    (re.compile(r"\bmove\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "ASSIGN"),
    (re.compile(r"\bld\.w\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "LOAD"),
    (re.compile(r"\bst\.w\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE), "STORE"),
    (re.compile(r"\badd\.w\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_ADD"),
    (re.compile(r"\bsub\.w\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_SUB"),
    (re.compile(r"\band\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_AND"),
    (re.compile(r"\bor\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_OR"),
    (re.compile(r"\bxor\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "BINARY_XOR"),
    (re.compile(r"\bbl\s+(\S+)", re.IGNORECASE), "CALL"),
    (re.compile(r"\bjirl\s+\$r0\s*,\s*\$ra\s*,\s*0", re.IGNORECASE), "RETURN"),
    (re.compile(r"\bnop", re.IGNORECASE), "NOP"),
    (re.compile(r"\bslt[u]?\s+(\S+)\s*,\s*(\S+)\s*,\s*(\S+)", re.IGNORECASE), "COMPARE"),
]

_LOONGARCH_BRANCH = re.compile(r"\bb(eq|ne|lt|gt|le|ge|ltu|gtu)\s+(\S+)", re.IGNORECASE)
_LOONGARCH_COND_MAP = {
    "eq": "equal", "ne": "not_equal", "lt": "less", "gt": "greater",
    "le": "less_equal", "ge": "greater_equal",
    "ltu": "below", "gtu": "above",
}

_WASM_PATTERNS = [
    (re.compile(r"\blocal\.get\s+(\S+)"), "LOAD"),
    (re.compile(r"\blocal\.set\s+(\S+)"), "STORE"),
    (re.compile(r"\blocal\.tee\s+(\S+)"), "STORE"),
    (re.compile(r"\bglobal\.get\s+(\S+)"), "LOAD"),
    (re.compile(r"\bglobal\.set\s+(\S+)"), "STORE"),
    (re.compile(r"\bi32\.const\s+(\S+)"), "ASSIGN"),
    (re.compile(r"\bi64\.const\s+(\S+)"), "ASSIGN"),
    (re.compile(r"\bi32\.load\S*\s+(\S+)"), "LOAD"),
    (re.compile(r"\bi64\.load\S*\s+(\S+)"), "LOAD"),
    (re.compile(r"\bf32\.load\s+(\S+)"), "LOAD"),
    (re.compile(r"\bf64\.load\s+(\S+)"), "LOAD"),
    (re.compile(r"\bi32\.store\S*\s+(\S+)"), "STORE"),
    (re.compile(r"\bi64\.store\S*\s+(\S+)"), "STORE"),
    (re.compile(r"\bf32\.store\s+(\S+)"), "STORE"),
    (re.compile(r"\bf64\.store\s+(\S+)"), "STORE"),
    (re.compile(r"\bi32\.add\b"), "BINARY_ADD"),
    (re.compile(r"\bi64\.add\b"), "BINARY_ADD"),
    (re.compile(r"\bi32\.sub\b"), "BINARY_SUB"),
    (re.compile(r"\bi64\.sub\b"), "BINARY_SUB"),
    (re.compile(r"\bi32\.mul\b"), "BINARY_MUL"),
    (re.compile(r"\bi64\.mul\b"), "BINARY_MUL"),
    (re.compile(r"\bi32\.and\b"), "BINARY_AND"),
    (re.compile(r"\bi64\.and\b"), "BINARY_AND"),
    (re.compile(r"\bi32\.or\b"), "BINARY_OR"),
    (re.compile(r"\bi64\.or\b"), "BINARY_OR"),
    (re.compile(r"\bi32\.xor\b"), "BINARY_XOR"),
    (re.compile(r"\bi64\.xor\b"), "BINARY_XOR"),
    (re.compile(r"\bi32\.shl\b"), "BINARY_SHL"),
    (re.compile(r"\bi64\.shl\b"), "BINARY_SHL"),
    (re.compile(r"\bi32\.shr_[su]\b"), "BINARY_SHR"),
    (re.compile(r"\bi64\.shr_[su]\b"), "BINARY_SHR"),
    (re.compile(r"\bi32\.rotl\b"), "BINARY_ROL"),
    (re.compile(r"\bi64\.rotl\b"), "BINARY_ROL"),
    (re.compile(r"\bi32\.rotr\b"), "BINARY_ROR"),
    (re.compile(r"\bi64\.rotr\b"), "BINARY_ROR"),
    (re.compile(r"\bi32\.eqz\b"), "COMPARE"),
    (re.compile(r"\bi64\.eqz\b"), "COMPARE"),
    (re.compile(r"\bi32\.eq\b"), "COMPARE"),
    (re.compile(r"\bi64\.eq\b"), "COMPARE"),
    (re.compile(r"\bi32\.ne\b"), "COMPARE"),
    (re.compile(r"\bi64\.ne\b"), "COMPARE"),
    (re.compile(r"\bi32\.lt_[su]\b"), "COMPARE"),
    (re.compile(r"\bi64\.lt_[su]\b"), "COMPARE"),
    (re.compile(r"\bi32\.gt_[su]\b"), "COMPARE"),
    (re.compile(r"\bi64\.gt_[su]\b"), "COMPARE"),
    (re.compile(r"\bi32\.le_[su]\b"), "COMPARE"),
    (re.compile(r"\bi64\.le_[su]\b"), "COMPARE"),
    (re.compile(r"\bi32\.ge_[su]\b"), "COMPARE"),
    (re.compile(r"\bi64\.ge_[su]\b"), "COMPARE"),
    (re.compile(r"\bcall\s+(\S+)"), "CALL"),
    (re.compile(r"\bcall_indirect\s+(\S+)"), "CALL"),
    (re.compile(r"\breturn\b"), "RETURN"),
    (re.compile(r"\bbr_if\s+(\S+)"), "BRANCH"),
    (re.compile(r"\bbr\s+(\S+)"), "JUMP"),
    (re.compile(r"\bbr_table\s+(\S+)"), "BRANCH"),
    (re.compile(r"\bnop\b"), "NOP"),
    (re.compile(r"\bdrop\b"), "POP"),
    (re.compile(r"\bselect\b"), "SELECT"),
    (re.compile(r"\bunreachable\b"), "UNREACHABLE"),
    (re.compile(r"\bmemory\.size\b"), "LOAD"),
    (re.compile(r"\bmemory\.grow\b"), "STORE"),
]

_WASM_BRANCH = re.compile(r"\bbr_if\s+(\S+)")
_WASM_COND_MAP = {
    "0": "loop_back",
    "1": "block_exit",
    "2": "outer_exit",
}


def _clean_operand(op: str) -> str:
    return op.strip().rstrip(",")


def _translate_insn(insn: str, block_addr: int) -> IRInstruction | None:
    insn_stripped = insn.strip()

    # x86/x64 条件分支
    m = _X86_JCC.search(insn_stripped)
    if m:
        jcc = m.group(1).upper()
        target = _clean_operand(m.group(2))
        cond = _JCC_TO_COND.get(jcc, jcc.lower())
        return IRInstruction("BRANCH", [cond, target], insn_stripped, block_addr)

    # x86/x64 无条件跳转
    m = _X86_JMP.search(insn_stripped)
    if m:
        target = _clean_operand(m.group(1))
        return IRInstruction("JUMP", [target], insn_stripped, block_addr)

    # ARM 条件分支
    m = _ARM_BRANCH.search(insn_stripped)
    if m:
        cond_suffix = insn_stripped.split(".")[1].split()[0].upper() if "." in insn_stripped else ""
        target = _clean_operand(m.group(1))
        cond = _ARM_COND_MAP.get(cond_suffix, cond_suffix.lower() if cond_suffix else "always")
        return IRInstruction("BRANCH", [cond, target], insn_stripped, block_addr)

    # MIPS 条件分支
    m = _MIPS_BRANCH.search(insn_stripped)
    if m:
        cond_suffix = m.group(1).lower()
        target = _clean_operand(m.group(2))
        cond = _MIPS_COND_MAP.get(cond_suffix, cond_suffix)
        return IRInstruction("BRANCH", [cond, target], insn_stripped, block_addr)

    # LoongArch 条件分支
    m = _LOONGARCH_BRANCH.search(insn_stripped)
    if m:
        cond_suffix = m.group(1).lower()
        target = _clean_operand(m.group(2))
        cond = _LOONGARCH_COND_MAP.get(cond_suffix, cond_suffix)
        return IRInstruction("BRANCH", [cond, target], insn_stripped, block_addr)

    # WASM 条件分支
    m = _WASM_BRANCH.search(insn_stripped)
    if m:
        label = _clean_operand(m.group(1))
        cond = _WASM_COND_MAP.get(label, f"wasm_br_{label}")
        return IRInstruction("BRANCH", [cond, label], insn_stripped, block_addr)

    # 通用指令匹配（按优先级尝试所有架构模式）
    all_patterns = _X86_PATTERNS + _ARM_PATTERNS + _MIPS_PATTERNS + _LOONGARCH_PATTERNS + _WASM_PATTERNS
    for pat, ir_op in all_patterns:
        m = pat.search(insn_stripped)
        if m:
            operands = [_clean_operand(g) for g in m.groups() if g]
            # 特殊处理 XOR reg, reg → ASSIGN reg, 0
            if ir_op == "BINARY_XOR" and len(operands) == 2 and operands[0] == operands[1]:
                return IRInstruction("ASSIGN", [operands[0], "0"], insn_stripped, block_addr)
            return IRInstruction(ir_op, operands, insn_stripped, block_addr)

    return None


def _translate_block(block: Any, func_start: int) -> IRBlock:
    label = f"bb_{block.start - func_start:x}"
    ir_instructions: list[IRInstruction] = []
    successors: list[str] = []

    for insn in block.context.instructions:
        ir_insn = _translate_insn(insn, block.start)
        if ir_insn is not None:
            ir_instructions.append(ir_insn)
        else:
            ir_instructions.append(IRInstruction("UNKNOWN", [], insn.strip(), block.start))

    for succ in block.succs:
        successors.append(f"bb_{succ - func_start:x}")

    return IRBlock(
        label=label,
        address=block.start,
        instructions=ir_instructions,
        successors=successors,
    )


def normalize_to_ir(
    metadata: ProgramMetadata,
    function_name: str | None = None,
    function_address: int | None = None,
) -> dict[str, Any]:
    target_func = None
    for func in metadata.functions:
        if function_name and func.name == function_name:
            target_func = func
            break
        if function_address and func.start == function_address:
            target_func = func
            break

    if target_func is None:
        return {
            "error": f"Function not found: {function_name or hex_addr(function_address or 0)}",
            "available_functions": [f.name for f in metadata.functions[:50]],
        }

    ir_blocks: list[IRBlock] = []
    for block in target_func.blocks:
        ir_blocks.append(_translate_block(block, target_func.start))

    ir_func = IRFunction(
        name=target_func.name,
        address=target_func.start,
        blocks=ir_blocks,
    )

    op_counts: dict[str, int] = {}
    for b in ir_blocks:
        for i in b.instructions:
            op_counts[i.op] = op_counts.get(i.op, 0) + 1

    return {
        "summary": {
            "function": target_func.name,
            "address": hex_addr(target_func.start),
            "blocks": len(ir_blocks),
            "op_counts": op_counts,
        },
        "ir": ir_func.to_dict(),
    }


def ir_to_markdown(result: dict[str, Any]) -> str:
    if "error" in result:
        lines = ["# Normalized IR - Error", ""]
        lines.append(f"**Error**: {result['error']}")
        if result.get("available_functions"):
            lines.append("")
            lines.append("Available functions:")
            for name in result["available_functions"][:20]:
                lines.append(f"- `{name}`")
        return "\n".join(lines) + "\n"

    summary = result["summary"]
    ir = result["ir"]
    lines = [
        f"# Normalized IR: {summary['function']}",
        "",
        f"- Address: `{summary['address']}`",
        f"- Blocks: {summary['blocks']}",
        f"- Operations: {summary['op_counts']}",
        "",
    ]

    for block in ir["blocks"]:
        lines.extend([f"## {block['label']} (`{block['address']}`)", ""])
        if block.get("successors"):
            lines.append(f"Successors: {', '.join(f'`{s}`' for s in block['successors'])}")
            lines.append("")

        lines.append("```")
        for insn in block["instructions"]:
            ops = " ".join(insn.get("operands", []))
            original = insn.get("original", "")
            if original:
                lines.append(f"  {insn['op']:12s} {ops:20s}  // {original}")
            else:
                lines.append(f"  {insn['op']:12s} {ops}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines) + "\n"
