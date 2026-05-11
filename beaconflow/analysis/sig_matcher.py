"""
Signature Matcher - 特征匹配器。

使用扩展特征库（sig_library.yaml）在 metadata 中识别
crypto/VM/packer/anti-debug 特征。

让 AI 能自动识别程序中使用的加密算法、虚拟机保护、加壳和反调试技术。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from beaconflow.models import ProgramMetadata, hex_addr

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class SignatureMatch:
    category: str
    name: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    address: int | None = None
    function: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category,
            "name": self.name,
            "confidence": self.confidence,
        }
        if self.evidence:
            result["evidence"] = self.evidence
        if self.address is not None:
            result["address"] = hex_addr(self.address)
        if self.function:
            result["function"] = self.function
        return result


def _load_sig_library(custom_path: str | None = None) -> dict[str, Any]:
    default_path = Path(__file__).parent / "sig_library.yaml"
    path = Path(custom_path) if custom_path else default_path
    if not path.exists():
        return {}
    if yaml is None:
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _match_name_patterns(name: str, patterns: list[str]) -> bool:
    name_lower = name.lower()
    for pat in patterns:
        if pat.lower() in name_lower:
            return True
    return False


def _match_instruction_patterns(instructions: tuple[str, ...], patterns: list[str]) -> list[str]:
    matched = []
    for insn in instructions:
        insn_upper = insn.upper()
        for pat in patterns:
            try:
                if re.search(pat, insn_upper):
                    matched.append(f"insn:{insn.strip()}")
            except re.error:
                if pat.upper() in insn_upper:
                    matched.append(f"insn:{insn.strip()}")
    return matched


def _match_constant_signatures(constants: tuple[int, ...], sigs: list[int]) -> list[str]:
    matched = []
    for c in constants:
        for sig in sigs:
            if c == sig:
                matched.append(f"const:0x{c:X}")
    return matched


def _match_string_signatures(strings: tuple[str, ...], sigs: list[str]) -> list[str]:
    matched = []
    for s in strings:
        for sig in sigs:
            if sig.lower() in s.lower():
                matched.append(f"str:{s}")
    return matched


def match_signatures(
    metadata: ProgramMetadata,
    sig_library_path: str | None = None,
) -> dict[str, Any]:
    lib = _load_sig_library(sig_library_path)
    if not lib:
        return {
            "summary": {"status": "no_sig_library", "matches": 0},
            "matches": [],
        }

    matches: list[SignatureMatch] = []

    crypto_sigs = lib.get("crypto_sigs", {})
    vm_sigs = lib.get("vm_sigs", {})
    packer_sigs = lib.get("packer_sigs", {})
    anti_debug_sigs = lib.get("anti_debug_sigs", {})

    for func in metadata.functions:
        for block in func.blocks:
            ctx = block.context

            # Crypto 特征匹配
            for crypto_name, sig in crypto_sigs.items():
                evidence: list[str] = []

                name_patterns = sig.get("name_patterns", [])
                if name_patterns and _match_name_patterns(func.name, name_patterns):
                    evidence.append(f"name_match:{func.name}")

                const_sigs = sig.get("constant_signatures", [])
                if const_sigs:
                    const_matches = _match_constant_signatures(ctx.constants, const_sigs)
                    evidence.extend(const_matches)

                insn_patterns = sig.get("instruction_patterns", [])
                if insn_patterns:
                    insn_matches = _match_instruction_patterns(ctx.instructions, insn_patterns)
                    evidence.extend(insn_matches)

                if evidence:
                    confidence = "high" if len(evidence) >= 2 else "medium"
                    matches.append(SignatureMatch(
                        category="crypto",
                        name=crypto_name,
                        confidence=confidence,
                        evidence=evidence,
                        address=block.start,
                        function=func.name,
                    ))

            # VM 特征匹配
            vm_generic = vm_sigs.get("generic_vm", {})
            vm_name_patterns = vm_generic.get("name_patterns", [])
            vm_insn_patterns = vm_generic.get("instruction_patterns", [])

            vm_evidence: list[str] = []
            if vm_name_patterns and _match_name_patterns(func.name, vm_name_patterns):
                vm_evidence.append(f"name_match:{func.name}")
            if vm_insn_patterns:
                vm_insn_matches = _match_instruction_patterns(ctx.instructions, vm_insn_patterns)
                vm_evidence.extend(vm_insn_matches)

            if len(vm_evidence) >= 2:
                matches.append(SignatureMatch(
                    category="vm",
                    name="generic_vm",
                    confidence="medium" if len(vm_evidence) >= 3 else "low",
                    evidence=vm_evidence,
                    address=block.start,
                    function=func.name,
                ))

            # Packer 特征匹配
            for packer_name, sig in packer_sigs.items():
                if packer_name == "packer_ids":
                    continue
                packer_evidence: list[str] = []

                name_patterns = sig.get("name_patterns", [])
                if name_patterns and _match_name_patterns(func.name, name_patterns):
                    packer_evidence.append(f"name_match:{func.name}")

                const_sigs = sig.get("constant_signatures", [])
                if const_sigs:
                    const_matches = _match_constant_signatures(ctx.constants, const_sigs)
                    packer_evidence.extend(const_matches)

                str_sigs = sig.get("string_signatures", [])
                if str_sigs:
                    str_matches = _match_string_signatures(ctx.strings, str_sigs)
                    packer_evidence.extend(str_matches)

                insn_patterns = sig.get("instruction_patterns", [])
                if insn_patterns:
                    insn_matches = _match_instruction_patterns(ctx.instructions, insn_patterns)
                    packer_evidence.extend(insn_matches)

                if packer_evidence:
                    confidence = "high" if len(packer_evidence) >= 2 else "medium"
                    matches.append(SignatureMatch(
                        category="packer",
                        name=packer_name,
                        confidence=confidence,
                        evidence=packer_evidence,
                        address=block.start,
                        function=func.name,
                    ))

            # Anti-debug 特征匹配
            for platform, sig in anti_debug_sigs.items():
                ad_evidence: list[str] = []

                api_calls = sig.get("api_calls", [])
                if api_calls:
                    for call in ctx.calls:
                        if call in api_calls:
                            ad_evidence.append(f"api:{call}")

                techniques = sig.get("techniques", [])
                if techniques:
                    for tech in techniques:
                        for insn in ctx.instructions:
                            if tech.lower() in insn.lower():
                                ad_evidence.append(f"tech:{tech}")

                if ad_evidence:
                    matches.append(SignatureMatch(
                        category="anti_debug",
                        name=platform,
                        confidence="high" if len(ad_evidence) >= 2 else "medium",
                        evidence=ad_evidence,
                        address=block.start,
                        function=func.name,
                    ))

    # Packer IDs 特殊匹配（基于字符串）
    packer_ids = packer_sigs.get("packer_ids", {})
    for packer_name, sig in packer_ids.items():
        str_sigs = sig.get("strings", [])
        for func in metadata.functions:
            for block in func.blocks:
                str_matches = _match_string_signatures(block.context.strings, str_sigs)
                const_sigs = sig.get("constants", [])
                const_matches = _match_constant_signatures(block.context.constants, const_sigs)
                all_evidence = str_matches + const_matches
                if all_evidence:
                    matches.append(SignatureMatch(
                        category="packer_id",
                        name=packer_name,
                        confidence="high",
                        evidence=all_evidence,
                        address=block.start,
                        function=func.name,
                    ))

    # 去重
    seen: set[tuple[str, str, str, int]] = set()
    unique_matches: list[SignatureMatch] = []
    for m in matches:
        key = (m.category, m.name, m.function or "", m.address or 0)
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)

    category_counts: dict[str, int] = {}
    for m in unique_matches:
        category_counts[m.category] = category_counts.get(m.category, 0) + 1

    return {
        "summary": {
            "total_matches": len(unique_matches),
            "by_category": category_counts,
        },
        "matches": [m.to_dict() for m in unique_matches],
    }


def sig_match_to_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    matches = result["matches"]
    lines = [
        "# BeaconFlow Signature Match",
        "",
        f"- Total matches: {summary.get('total_matches', 0)}",
        f"- By category: {summary.get('by_category', {})}",
        "",
    ]

    for category in ("crypto", "vm", "packer", "packer_id", "anti_debug"):
        cat_matches = [m for m in matches if m["category"] == category]
        if not cat_matches:
            continue
        lines.extend([f"## {category.upper()}", ""])
        for m in cat_matches:
            func_info = f"`{m['function']}:{m['address']}` " if m.get("function") else ""
            lines.append(
                f"- {func_info}`{m['name']}` confidence=`{m['confidence']}`"
            )
            for e in m.get("evidence", [])[:5]:
                lines.append(f"  - {e}")
        lines.append("")

    if not matches:
        lines.append("No signature matches found.")

    return "\n".join(lines) + "\n"
