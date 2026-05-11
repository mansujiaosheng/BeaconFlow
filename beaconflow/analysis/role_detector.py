"""
Candidate Role Detector - 通过可配置规则、调用关系、路径差异和块内特征推断函数角色。

支持的角色: input_handler, input_normalizer, validator, transformer, crypto_like,
             dispatcher, state_update, success_handler, failure_handler,
             anti_debug, runtime_init, unknown_interesting
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from beaconflow.models import BasicBlock, BlockContext, Function, ProgramMetadata


@dataclass
class RoleCandidate:
    role: str
    function: str
    address: int
    confidence: str  # high / medium / low
    score: float
    evidence: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    related_blocks: list[str] = field(default_factory=list)
    related_decision_points: list[str] = field(default_factory=list)
    related_io_sites: list[str] = field(default_factory=list)
    related_path_diffs: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from beaconflow.models import hex_addr
        return {
            "role": self.role,
            "function": self.function,
            "address": hex_addr(self.address),
            "confidence": self.confidence,
            "score": round(self.score, 3),
            "evidence": self.evidence,
            "matched_rules": self.matched_rules,
            "related_blocks": self.related_blocks,
            "related_decision_points": self.related_decision_points,
            "related_io_sites": self.related_io_sites,
            "related_path_diffs": self.related_path_diffs,
            "recommended_actions": self.recommended_actions,
        }


def _load_rules(rules_path: str | None = None) -> dict[str, Any]:
    if rules_path is None:
        rules_path = os.path.join(os.path.dirname(__file__), "role_rules.yaml")
    with open(rules_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _extract_function_features(
    func: Function,
    metadata: ProgramMetadata,
    rules_config: dict[str, Any],
) -> dict[str, Any]:
    # 从函数中提取特征，用于规则匹配
    features: dict[str, Any] = {
        "name": func.name,
        "start": func.start,
        "num_blocks": len(func.blocks),
        "num_succs": sum(len(b.succs) for b in func.blocks),
        "num_preds": 0,
        "has_decision_points": False,
        "has_loop_like_edges": False,
        "has_jump_table": False,
        "has_constants": False,
        "has_data_refs": False,
        "has_loops": False,
        "calls_io_function": False,
        "calls_string_compare": False,
        "calls_debug_api": False,
        "calls_print_or_write": False,
        "calls_many_functions": False,
        "many_bitwise_ops": False,
        "many_arithmetic_ops": False,
        "has_table_lookup": False,
        "no_decision_points": True,
        "library_function": False,
        "runtime_noise": False,
        "num_calls": 0,
        "all_calls": [],
        "all_instructions": [],
        "all_constants": [],
        "all_strings": [],
    }

    # 检查是否是库函数
    lib_prefixes = rules_config.get("library_prefixes", [])
    for prefix in lib_prefixes:
        if func.name.startswith(prefix):
            features["library_function"] = True
            features["runtime_noise"] = True
            break

    io_funcs = set(rules_config.get("io_functions", []))
    debug_funcs = set(rules_config.get("debug_api_functions", []))
    str_cmp_funcs = set(rules_config.get("string_compare_functions", []))
    print_funcs = {"printf", "puts", "fprintf", "sprintf", "snprintf", "cout", "write", "fwrite"}

    all_calls = set()
    all_instructions = []
    all_constants = []
    all_strings = []
    bitwise_count = 0
    arithmetic_count = 0
    has_table_lookup = False

    for block in func.blocks:
        ctx = block.context
        if not ctx.instructions:
            continue

        # 检查是否有环（loop）
        for succ in block.succs:
            if succ < block.start and succ >= func.start:
                features["has_loops"] = True
                features["has_loop_like_edges"] = True

        # 检查 decision points
        for insn in ctx.instructions:
            insn_upper = insn.upper()
            all_instructions.append(insn)

            # 检测 cmp/test + jcc
            if any(insn_upper.startswith(p) for p in ("CMP ", "TEST ")):
                features["has_decision_points"] = True
                features["no_decision_points"] = False

            # 检测 cmovcc / setcc
            if insn_upper.startswith("CMOV") or insn_upper.startswith("SET"):
                features["has_decision_points"] = True
                features["no_decision_points"] = False

            # 检测 jump table
            if "JMP" in insn_upper and ("[" in insn or "QWORD PTR" in insn.upper()):
                features["has_jump_table"] = True
                features["has_decision_points"] = True
                features["no_decision_points"] = False

            # 位运算计数
            if any(insn_upper.startswith(p) for p in ("XOR ", "AND ", "OR ", "SHL ", "SHR ", "SAL ", "SAR ", "ROL ", "ROR ", "NOT ")):
                bitwise_count += 1

            # 算术运算计数
            if any(insn_upper.startswith(p) for p in ("ADD ", "SUB ", "MUL ", "IMUL ", "DIV ", "IDIV ", "INC ", "DEC ")):
                arithmetic_count += 1

            # 表查找模式
            if "LEA" in insn_upper and ("+" in insn or "[" in insn):
                has_table_lookup = True

        # 收集调用
        for call in ctx.calls:
            all_calls.add(call)
            if call in io_funcs:
                features["calls_io_function"] = True
            if call in debug_funcs:
                features["calls_debug_api"] = True
            if call in str_cmp_funcs:
                features["calls_string_compare"] = True
            if call in print_funcs:
                features["calls_print_or_write"] = True

        # 收集常量和字符串
        if ctx.constants:
            features["has_constants"] = True
            all_constants.extend(ctx.constants)
        if ctx.strings:
            all_strings.extend(ctx.strings)
        if ctx.data_refs:
            features["has_data_refs"] = True

    features["many_bitwise_ops"] = bitwise_count >= 5
    features["many_arithmetic_ops"] = arithmetic_count >= 5
    features["has_table_lookup"] = has_table_lookup
    features["num_calls"] = len(all_calls)
    features["calls_many_functions"] = len(all_calls) >= 5
    features["all_calls"] = sorted(all_calls)
    features["all_instructions"] = all_instructions
    features["all_constants"] = all_constants
    features["all_strings"] = all_strings

    # 计算前驱数量（从整个 metadata 中统计有多少函数调用此函数）
    for other_func in metadata.functions:
        if other_func.name == func.name:
            continue
        for other_block in other_func.blocks:
            for call in other_block.context.calls:
                if call == func.name:
                    features["num_preds"] += 1

    features["many_predecessors"] = features["num_preds"] >= 3
    features["many_successors"] = features["num_succs"] >= 4

    return features


def _match_name_patterns(name: str, patterns: list[str]) -> list[str]:
    matched = []
    name_lower = name.lower()
    for pattern in patterns:
        if pattern.lower() in name_lower:
            matched.append(pattern)
    return matched


def _evaluate_role(
    role_name: str,
    role_config: dict[str, Any],
    features: dict[str, Any],
) -> tuple[float, list[str], list[str]]:
    # 评估函数对某个角色的匹配度，返回 (score, evidence, matched_rules)
    score = 0.0
    evidence = []
    matched_rules = []

    # 名称模式匹配
    name_patterns = role_config.get("name_patterns", [])
    name_matches = _match_name_patterns(features["name"], name_patterns)
    if name_matches:
        score += 0.4
        matched_rules.append("name_pattern")
        evidence.append(f"Name matches patterns: {', '.join(name_matches)}")

    # 正向特征匹配
    positive_features = role_config.get("positive_features", [])
    for feat in positive_features:
        if features.get(feat):
            score += 0.2
            matched_rules.append(feat)
            if feat == "has_decision_points":
                evidence.append("Contains decision points (cmp/test+jcc, cmovcc, setcc)")
            elif feat == "has_loop_like_edges":
                evidence.append("Contains loop-like edges")
            elif feat == "has_constants":
                evidence.append(f"Uses constants: {features['all_constants'][:5]}")
            elif feat == "has_data_refs":
                evidence.append("References data sections")
            elif feat == "calls_string_compare":
                cmp_calls = [c for c in features["all_calls"] if c in ("strcmp", "strncmp", "memcmp", "strlen")]
                evidence.append(f"Calls string comparison: {', '.join(cmp_calls)}")
            elif feat == "calls_io_function":
                io_calls = [c for c in features["all_calls"] if c in ("scanf", "gets", "fgets", "read", "recv", "getchar")]
                evidence.append(f"Calls I/O functions: {', '.join(io_calls)}")
            elif feat == "calls_debug_api":
                evidence.append("Calls debug detection APIs")
            elif feat == "calls_print_or_write":
                evidence.append("Calls print/write functions")
            elif feat == "many_bitwise_ops":
                evidence.append("Contains many bitwise operations (XOR, AND, OR, SHL, SHR...)")
            elif feat == "many_arithmetic_ops":
                evidence.append("Contains many arithmetic operations (ADD, SUB, MUL...)")
            elif feat == "has_loops":
                evidence.append("Contains loops")
            elif feat == "has_table_lookup":
                evidence.append("Contains table lookup patterns")
            elif feat == "many_predecessors":
                evidence.append(f"Called by {features['num_preds']} other functions")
            elif feat == "many_successors":
                evidence.append(f"Has {features['num_succs']} successor edges")
            elif feat == "has_jump_table":
                evidence.append("Contains jump table (switch dispatch)")
            elif feat == "calls_many_functions":
                evidence.append(f"Calls {features['num_calls']} different functions")
            elif feat == "no_decision_points":
                evidence.append("No decision points (linear control flow)")
            else:
                evidence.append(f"Feature matched: {feat}")

    # 负向特征惩罚
    negative_features = role_config.get("negative_features", [])
    for feat in negative_features:
        if features.get(feat):
            score -= 0.3
            matched_rules.append(f"-{feat}")
            evidence.append(f"Negative feature: {feat}")

    # 应用权重
    weight = role_config.get("score_weight", 1.0)
    score *= weight

    return score, evidence, matched_rules


def detect_roles(
    metadata: ProgramMetadata,
    rules_path: str | None = None,
    focus_function: str | None = None,
    min_score: float = 0.1,
) -> list[RoleCandidate]:
    rules_config = _load_rules(rules_path)
    roles_config = rules_config.get("roles", {})

    candidates: list[RoleCandidate] = []

    for func in metadata.functions:
        if focus_function and func.name != focus_function:
            addr_match = focus_function.startswith("0x") and func.start == int(focus_function, 16)
            if not addr_match:
                continue

        features = _extract_function_features(func, metadata, rules_config)

        # 跳过明显是库函数的（除非有强名称匹配）
        if features["library_function"] and features["num_blocks"] < 3:
            continue

        best_role = None
        best_score = 0.0
        best_evidence = []
        best_matched_rules = []

        for role_name, role_config in roles_config.items():
            score, evidence, matched_rules = _evaluate_role(role_name, role_config, features)
            if score > best_score:
                best_score = score
                best_role = role_name
                best_evidence = evidence
                best_matched_rules = matched_rules

        if best_role and best_score >= min_score:
            confidence = "high" if best_score >= 0.8 else ("medium" if best_score >= 0.4 else "low")

            # 收集关联信息
            related_blocks = [f"0x{b.start:x}" for b in func.blocks[:10]]
            related_dps = []
            related_io = []

            for block in func.blocks:
                ctx = block.context
                for call in ctx.calls:
                    if call in set(rules_config.get("io_functions", [])):
                        related_io.append(f"0x{block.start:x}:{call}")
                    if call in set(rules_config.get("string_compare_functions", [])):
                        related_dps.append(f"0x{block.start:x}:{call}")

            # 推荐操作
            actions = _generate_recommendations(best_role, features)

            candidate = RoleCandidate(
                role=best_role,
                function=func.name,
                address=func.start,
                confidence=confidence,
                score=best_score,
                evidence=best_evidence,
                matched_rules=best_matched_rules,
                related_blocks=related_blocks,
                related_decision_points=related_dps,
                related_io_sites=related_io,
                recommended_actions=actions,
            )
            candidates.append(candidate)

    # 按分数降序排序
    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates


def _generate_recommendations(role: str, features: dict[str, Any]) -> list[str]:
    actions = []

    if role == "validator":
        actions.append("Trace input data flow into this function")
        actions.append("Compare path differences between correct/wrong inputs")
        if features.get("calls_string_compare"):
            actions.append("Inspect string comparison arguments for expected values")
        if features.get("has_constants"):
            actions.append("Check constants for expected comparison values")

    elif role == "crypto_like":
        actions.append("Identify the algorithm from constants and operation patterns")
        if features.get("has_table_lookup"):
            actions.append("Look for S-box or lookup table references")
        actions.append("Trace key/IV input sources")

    elif role == "input_handler":
        actions.append("Identify input format and length constraints")
        actions.append("Trace data flow from input to processing functions")

    elif role == "dispatcher":
        actions.append("Map all dispatch targets and state values")
        if features.get("has_jump_table"):
            actions.append("Recover jump table bounds and case values")

    elif role == "success_handler":
        actions.append("Trace backward to find the condition that leads here")
        actions.append("Check for flag or success message strings")

    elif role == "failure_handler":
        actions.append("Trace backward to find the condition that leads here")
        actions.append("Check for error message strings")

    elif role == "anti_debug":
        actions.append("Identify and bypass anti-debug checks")
        actions.append("Patch conditional branches after detection calls")

    elif role == "transformer":
        actions.append("Determine the transformation algorithm")
        actions.append("Check if transformation is invertible")

    elif role == "unknown_interesting":
        actions.append("Investigate this function manually")
        actions.append("Check if it's a custom validation or transformation")

    return actions


def analyze_roles(
    metadata: ProgramMetadata,
    rules_path: str | None = None,
    focus_function: str | None = None,
    min_score: float = 0.1,
) -> dict[str, Any]:
    candidates = detect_roles(metadata, rules_path, focus_function, min_score)

    # 统计
    role_counts: dict[str, int] = {}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    for c in candidates:
        role_counts[c.role] = role_counts.get(c.role, 0) + 1
        confidence_counts[c.confidence] += 1

    return {
        "summary": {
            "total": len(candidates),
            "roles": role_counts,
            "confidence": confidence_counts,
            "focus_function": focus_function,
        },
        "candidates": [c.to_dict() for c in candidates],
    }


def inspect_role(
    metadata: ProgramMetadata,
    function_name: str | None = None,
    address: int | None = None,
    rules_path: str | None = None,
) -> dict[str, Any] | None:
    candidates = detect_roles(metadata, rules_path)

    for c in candidates:
        if function_name and c.function == function_name:
            return c.to_dict()
        if address is not None and c.address == address:
            return c.to_dict()

    return None
