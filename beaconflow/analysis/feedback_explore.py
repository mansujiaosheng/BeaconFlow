"""
Feedback Auto-Explore - 反馈式输入探索。

根据 trace_compare 的失败比较结果，自动建议输入修改方案。
支持多轮迭代探索。

核心流程：
1. 获取当前 trace_compare 结果
2. 识别 failed_compares
3. 为每个 failed_compare 生成输入修改建议
4. 输出结构化的探索方案

让 AI 可以从"知道失败原因"到"知道怎么修改输入"。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr


@dataclass
class InputPatch:
    offset: int
    original_value: int | None
    suggested_value: int
    size: int
    reason: str
    compare_address: int
    compare_instruction: str
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "offset": self.offset,
            "suggested_value": f"0x{self.suggested_value:x}" if self.suggested_value > 0xff else str(self.suggested_value),
            "size": self.size,
            "reason": self.reason,
            "compare_address": hex_addr(self.compare_address),
            "compare_instruction": self.compare_instruction,
            "confidence": self.confidence,
        }
        if self.original_value is not None:
            result["original_value"] = f"0x{self.original_value:x}" if self.original_value > 0xff else str(self.original_value)
        return result


@dataclass
class ExploreRound:
    round_number: int
    patches: list[InputPatch] = field(default_factory=list)
    strategy: str = "immediate_fix"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round_number,
            "strategy": self.strategy,
            "description": self.description,
            "patches": [p.to_dict() for p in self.patches],
        }


@dataclass
class ExplorePlan:
    target: str
    total_rounds: int
    rounds: list[ExploreRound] = field(default_factory=list)
    current_input: bytes | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "target": self.target,
            "total_rounds": self.total_rounds,
            "rounds": [r.to_dict() for r in self.rounds],
        }
        if self.notes:
            result["notes"] = self.notes
        return result


def _try_parse_int(value: str) -> int | None:
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        return None


def _infer_byte_size(value: int) -> int:
    if value <= 0xFF:
        return 1
    if value <= 0xFFFF:
        return 2
    if value <= 0xFFFFFFFF:
        return 4
    return 8


def _generate_patches_from_failed_compares(
    failed_compares: list[dict[str, Any]],
    input_offset_base: int = 0,
) -> list[InputPatch]:
    patches: list[InputPatch] = []

    for fc in failed_compares:
        compare_type = fc.get("type", "")
        left = fc.get("left", "")
        right = fc.get("right", "")
        addr_str = fc.get("addr", "0x0")
        instruction = fc.get("instruction", "")

        try:
            addr = int(addr_str, 16) if isinstance(addr_str, str) else addr_str
        except (ValueError, TypeError):
            addr = 0

        if compare_type == "cmp_imm":
            right_val = _try_parse_int(right)
            if right_val is not None:
                byte_size = _infer_byte_size(right_val)
                offset = input_offset_base + (addr & 0xF)
                patches.append(InputPatch(
                    offset=offset,
                    original_value=None,
                    suggested_value=right_val,
                    size=byte_size,
                    reason=f"cmp_imm: make {left} == {right}",
                    compare_address=addr,
                    compare_instruction=instruction,
                    confidence="high",
                ))

        elif compare_type in ("strcmp", "strncmp", "memcmp", "wcscmp", "wcsncmp", "wmemcmp"):
            patches.append(InputPatch(
                offset=input_offset_base,
                original_value=None,
                suggested_value=0,
                size=0,
                reason=f"{compare_type}: input does not match expected string/buffer at {addr_str}",
                compare_address=addr,
                compare_instruction=instruction,
                confidence="medium",
            ))

        elif compare_type == "test":
            if right == left:
                patches.append(InputPatch(
                    offset=input_offset_base,
                    original_value=None,
                    suggested_value=0,
                    size=4,
                    reason=f"test {left},{left}: ensure {left} is zero",
                    compare_address=addr,
                    compare_instruction=instruction,
                    confidence="medium",
                ))

        elif compare_type == "cmp_reg":
            patches.append(InputPatch(
                offset=input_offset_base,
                original_value=None,
                suggested_value=0,
                size=4,
                reason=f"cmp_reg: {left} != {right}, need to trace values",
                compare_address=addr,
                compare_instruction=instruction,
                confidence="low",
            ))

        elif compare_type == "switch":
            patches.append(InputPatch(
                offset=input_offset_base,
                original_value=None,
                suggested_value=0,
                size=4,
                reason=f"switch: need to determine correct dispatch index",
                compare_address=addr,
                compare_instruction=instruction,
                confidence="low",
            ))

    return patches


def _apply_patches_to_input(input_data: bytes, patches: list[InputPatch]) -> bytes:
    result = bytearray(input_data)
    for patch in patches:
        if patch.size == 0 or patch.offset < 0 or patch.offset >= len(result):
            continue
        end = min(patch.offset + patch.size, len(result))
        size = end - patch.offset
        if size <= 0:
            continue
        value_bytes = patch.suggested_value.to_bytes(size, byteorder="little")
        result[patch.offset:end] = value_bytes[:size]
    return bytes(result)


def generate_explore_plan(
    metadata: ProgramMetadata,
    failed_compares: list[dict[str, Any]],
    current_input: bytes | None = None,
    input_offset_base: int = 0,
    max_rounds: int = 3,
) -> dict[str, Any]:
    if not failed_compares:
        return {
            "summary": {
                "status": "no_failed_compares",
                "message": "No failed compares found. Input may already be correct.",
            },
            "plan": ExplorePlan(
                target=metadata.input_path,
                total_rounds=0,
            ).to_dict(),
        }

    patches = _generate_patches_from_failed_compares(failed_compares, input_offset_base)

    high_conf = [p for p in patches if p.confidence == "high"]
    medium_conf = [p for p in patches if p.confidence == "medium"]
    low_conf = [p for p in patches if p.confidence == "low"]

    rounds: list[ExploreRound] = []

    # 第一轮：修复高置信度的立即数比较
    if high_conf:
        rounds.append(ExploreRound(
            round_number=1,
            patches=high_conf,
            strategy="immediate_fix",
            description="Fix immediate value compares (cmp_imm) where the expected value is known.",
        ))

    # 第二轮：修复中等置信度的字符串/内存比较
    if medium_conf:
        rounds.append(ExploreRound(
            round_number=len(rounds) + 1,
            patches=medium_conf,
            strategy="string_compare",
            description="Fix string/memory compares. Need to determine expected buffer content.",
        ))

    # 第三轮：探索低置信度的寄存器比较和 switch
    if low_conf:
        rounds.append(ExploreRound(
            round_number=len(rounds) + 1,
            patches=low_conf,
            strategy="exploration",
            description="Explore register compares and switch dispatches. Need dynamic analysis to determine correct values.",
        ))

    plan = ExplorePlan(
        target=metadata.input_path,
        total_rounds=len(rounds),
        rounds=rounds,
        current_input=current_input,
        notes=[],
    )

    if current_input and high_conf:
        modified = _apply_patches_to_input(current_input, high_conf)
        plan.notes.append(f"Round 1 would modify {len(high_conf)} byte(s) in the input.")
        plan.notes.append(f"Modified input (hex): {modified.hex()}")

    return {
        "summary": {
            "status": "plan_generated",
            "total_failed_compares": len(failed_compares),
            "total_patches": len(patches),
            "high_confidence_patches": len(high_conf),
            "medium_confidence_patches": len(medium_conf),
            "low_confidence_patches": len(low_conf),
            "total_rounds": len(rounds),
        },
        "plan": plan.to_dict(),
    }


def feedback_auto_explore(
    metadata: ProgramMetadata,
    trace_compare_result: dict[str, Any],
    current_input: bytes | None = None,
    input_offset_base: int = 0,
) -> dict[str, Any]:
    failed_compares = trace_compare_result.get("failed_compares", [])
    return generate_explore_plan(
        metadata,
        failed_compares,
        current_input=current_input,
        input_offset_base=input_offset_base,
    )
