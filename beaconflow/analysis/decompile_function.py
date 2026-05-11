"""
Decompile Function - 伪代码摘要导出。

从 metadata 的 block context 中生成函数级别的伪代码摘要。
让 AI 不需要完整反编译也能理解函数逻辑。

输出格式：
- 函数签名（从调用约定推断）
- 基本块级别的伪代码摘要
- 分支/循环结构
- 关键操作（比较、调用、内存访问）
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr


@dataclass
class BlockSummary:
    address: int
    end_address: int
    label: str
    operations: list[str] = field(default_factory=list)
    branch_condition: str | None = None
    branch_targets: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "label": self.label,
            "address": hex_addr(self.address),
            "operations": self.operations,
        }
        if self.branch_condition:
            result["branch_condition"] = self.branch_condition
        if self.branch_targets:
            result["branch_targets"] = self.branch_targets
        if self.calls:
            result["calls"] = self.calls
        if self.is_entry:
            result["is_entry"] = True
        if self.is_exit:
            result["is_exit"] = True
        return result


@dataclass
class FunctionSummary:
    name: str
    address: int
    size: int
    block_count: int
    blocks: list[BlockSummary] = field(default_factory=list)
    signature_hint: str = ""
    loops: list[list[str]] = field(default_factory=list)
    pseudo_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "address": hex_addr(self.address),
            "size": self.size,
            "block_count": self.block_count,
            "blocks": [b.to_dict() for b in self.blocks],
        }
        if self.signature_hint:
            result["signature_hint"] = self.signature_hint
        if self.loops:
            result["loops"] = self.loops
        if self.pseudo_code:
            result["pseudo_code"] = self.pseudo_code
        return result


_CALL_PATTERN = re.compile(r"\bCALL\s+(\S+)", re.IGNORECASE)
_CMP_PATTERN = re.compile(r"\bCMP\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_TEST_PATTERN = re.compile(r"\bTEST\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_JCC_PATTERN = re.compile(r"\b(J\w+)\s+(\S+)", re.IGNORECASE)
_JMP_PATTERN = re.compile(r"\bJMP\s+(\S+)", re.IGNORECASE)
_MOV_PATTERN = re.compile(r"\bMOV\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_LEA_PATTERN = re.compile(r"\bLEA\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_RET_PATTERN = re.compile(r"\bRET", re.IGNORECASE)
_PUSH_PATTERN = re.compile(r"\bPUSH\s+(\S+)", re.IGNORECASE)
_ADD_PATTERN = re.compile(r"\bADD\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_SUB_PATTERN = re.compile(r"\bSUB\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_XOR_PATTERN = re.compile(r"\bXOR\s+(\S+)\s*,\s*(\S+)", re.IGNORECASE)
_NOP_PATTERN = re.compile(r"\bNOP", re.IGNORECASE)

_JCC_CONDITIONS = {
    "JE": "equal", "JZ": "zero", "JNE": "not_equal", "JNZ": "not_zero",
    "JL": "less", "JNGE": "less", "JGE": "greater_equal", "JNL": "greater_equal",
    "JLE": "less_equal", "JNG": "less_equal", "JG": "greater", "JNLE": "greater",
    "JB": "below", "JNAE": "below", "JAE": "above_equal", "JNB": "above_equal",
    "JBE": "below_equal", "JNA": "below_equal", "JA": "above", "JNBE": "above",
    "JS": "sign", "JNS": "not_sign",
}


def _clean_operand(op: str) -> str:
    return op.strip().rstrip(",")


def _summarize_block(block: Any, func_start: int, is_first: bool) -> BlockSummary:
    ctx = block.context
    label = f"bb_{block.start - func_start:x}"
    operations: list[str] = []
    branch_condition = None
    branch_targets: list[str] = []
    calls: list[str] = []
    is_exit = False

    instructions = list(ctx.instructions)

    for insn in instructions:
        insn_stripped = insn.strip()
        upper = insn_stripped.upper()

        if _NOP_PATTERN.search(upper):
            continue

        if _RET_PATTERN.search(upper):
            is_exit = True
            operations.append("return")
            continue

        m = _CALL_PATTERN.search(insn_stripped)
        if m:
            call_name = _clean_operand(m.group(1))
            calls.append(call_name)
            operations.append(f"call {call_name}")
            continue

        m = _JCC_PATTERN.search(insn_stripped)
        if m:
            jcc_mnemonic = m.group(1).upper()
            target = _clean_operand(m.group(2))
            condition = _JCC_CONDITIONS.get(jcc_mnemonic, jcc_mnemonic.lower())
            branch_condition = condition
            branch_targets.append(target)
            continue

        m = _JMP_PATTERN.search(insn_stripped)
        if m:
            target = _clean_operand(m.group(1))
            branch_targets.append(target)
            operations.append(f"goto {target}")
            continue

        m = _CMP_PATTERN.search(insn_stripped)
        if m:
            left = _clean_operand(m.group(1))
            right = _clean_operand(m.group(2))
            operations.append(f"compare({left}, {right})")
            continue

        m = _TEST_PATTERN.search(insn_stripped)
        if m:
            left = _clean_operand(m.group(1))
            right = _clean_operand(m.group(2))
            operations.append(f"test({left}, {right})")
            continue

        m = _MOV_PATTERN.search(insn_stripped)
        if m:
            dst = _clean_operand(m.group(1))
            src = _clean_operand(m.group(2))
            operations.append(f"{dst} = {src}")
            continue

        m = _LEA_PATTERN.search(insn_stripped)
        if m:
            dst = _clean_operand(m.group(1))
            src = _clean_operand(m.group(2))
            operations.append(f"{dst} = &{src}")
            continue

        m = _ADD_PATTERN.search(insn_stripped)
        if m:
            dst = _clean_operand(m.group(1))
            src = _clean_operand(m.group(2))
            operations.append(f"{dst} += {src}")
            continue

        m = _SUB_PATTERN.search(insn_stripped)
        if m:
            dst = _clean_operand(m.group(1))
            src = _clean_operand(m.group(2))
            operations.append(f"{dst} -= {src}")
            continue

        m = _XOR_PATTERN.search(insn_stripped)
        if m:
            dst = _clean_operand(m.group(1))
            src = _clean_operand(m.group(2))
            if dst == src:
                operations.append(f"{dst} = 0")
            else:
                operations.append(f"{dst} ^= {src}")
            continue

        m = _PUSH_PATTERN.search(insn_stripped)
        if m:
            val = _clean_operand(m.group(1))
            operations.append(f"push({val})")
            continue

        operations.append(insn_stripped)

    return BlockSummary(
        address=block.start,
        end_address=block.end,
        label=label,
        operations=operations,
        branch_condition=branch_condition,
        branch_targets=branch_targets,
        calls=calls,
        is_entry=is_first,
        is_exit=is_exit,
    )


def _infer_signature(func: Any, blocks: list[BlockSummary]) -> str:
    all_calls: list[str] = []
    for b in blocks:
        all_calls.extend(b.calls)

    args_count = 0
    first_block = blocks[0] if blocks else None
    if first_block:
        push_count = sum(1 for op in first_block.operations if op.startswith("push("))
        args_count = min(push_count, 6)

    ret_type = "void"
    for b in blocks:
        if b.is_exit:
            for op in b.operations:
                if op == "return" or op.startswith("return "):
                    ret_type = "int"
                    break

    params = ", ".join(f"arg{i}" for i in range(args_count))
    return f"{ret_type} {func.name}({params})"


def _detect_loops(blocks: list[BlockSummary]) -> list[list[str]]:
    label_to_block = {b.label: b for b in blocks}
    addr_to_label: dict[int, str] = {}
    for b in blocks:
        addr_to_label[b.address] = b.label

    loops: list[list[str]] = []
    for b in blocks:
        for target in b.branch_targets:
            target_label = None
            try:
                target_addr = int(target, 16)
                target_label = addr_to_label.get(target_addr)
            except ValueError:
                target_label = target

            if target_label and target_label in label_to_block:
                target_block = label_to_block[target_label]
                if target_block.address <= b.address:
                    loop_blocks = []
                    for lb in blocks:
                        if target_block.address <= lb.address <= b.address:
                            loop_blocks.append(lb.label)
                    if len(loop_blocks) >= 2:
                        loops.append(loop_blocks)

    return loops


def _generate_pseudo_code(blocks: list[BlockSummary], func_name: str, signature: str) -> str:
    lines = [f"{signature} {{"]
    indent = "  "

    for b in blocks:
        if b.is_entry:
            lines.append(f"{indent}// entry block")
        else:
            lines.append(f"{indent}// {b.label}:")

        for op in b.operations:
            if op.startswith("call "):
                lines.append(f"{indent}{op};")
            elif op.startswith("compare("):
                lines.append(f"{indent}{op};")
            elif op.startswith("test("):
                lines.append(f"{indent}{op};")
            elif op == "return":
                lines.append(f"{indent}return;")
            elif op.startswith("return "):
                lines.append(f"{indent}{op};")
            elif op.startswith("push("):
                continue
            elif op.startswith("goto "):
                lines.append(f"{indent}{op};")
            else:
                lines.append(f"{indent}{op};")

        if b.branch_condition:
            taken = b.branch_targets[0] if b.branch_targets else "?"
            lines.append(f"{indent}if ({b.branch_condition}) goto {taken};")

        lines.append("")

    lines.append("}")
    return "\n".join(lines)


def decompile_function(
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

    blocks: list[BlockSummary] = []
    for i, block in enumerate(target_func.blocks):
        blocks.append(_summarize_block(block, target_func.start, i == 0))

    signature = _infer_signature(target_func, blocks)
    loops = _detect_loops(blocks)
    pseudo_code = _generate_pseudo_code(blocks, target_func.name, signature)

    summary = FunctionSummary(
        name=target_func.name,
        address=target_func.start,
        size=target_func.end - target_func.start,
        block_count=len(blocks),
        blocks=blocks,
        signature_hint=signature,
        loops=loops,
        pseudo_code=pseudo_code,
    )

    return summary.to_dict()


def decompile_to_markdown(result: dict[str, Any]) -> str:
    if "error" in result:
        lines = ["# Decompile Function - Error", ""]
        lines.append(f"**Error**: {result['error']}")
        if result.get("available_functions"):
            lines.append("")
            lines.append("Available functions:")
            for name in result["available_functions"][:20]:
                lines.append(f"- `{name}`")
        return "\n".join(lines) + "\n"

    lines = [
        f"# Function: {result['name']}",
        "",
        f"- Address: `{result['address']}`",
        f"- Size: {result['size']} bytes",
        f"- Blocks: {result['block_count']}",
        f"- Signature: `{result.get('signature_hint', 'unknown')}`",
        "",
    ]

    if result.get("loops"):
        lines.extend(["## Loops", ""])
        for i, loop in enumerate(result["loops"]):
            lines.append(f"- Loop {i + 1}: {' → '.join(loop)}")
        lines.append("")

    if result.get("pseudo_code"):
        lines.extend(["## Pseudo Code", "", "```c", result["pseudo_code"], "```", ""])

    lines.extend(["## Block Details", ""])
    for b in result.get("blocks", []):
        tags = []
        if b.get("is_entry"):
            tags.append("ENTRY")
        if b.get("is_exit"):
            tags.append("EXIT")
        tag_str = f" [{','.join(tags)}]" if tags else ""

        lines.append(f"### {b['label']}{tag_str}")
        lines.append(f"- Address: `{b['address']}`")
        if b.get("calls"):
            lines.append(f"- Calls: {', '.join(f'`{c}`' for c in b['calls'])}")
        if b.get("branch_condition"):
            lines.append(f"- Branch: `{b['branch_condition']}` → {', '.join(f'`{t}`' for t in b['branch_targets'])}")
        lines.append("")
        for op in b.get("operations", []):
            lines.append(f"  - `{op}`")
        lines.append("")

    return "\n".join(lines) + "\n"
