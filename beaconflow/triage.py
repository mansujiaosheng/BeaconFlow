"""
一键 Triage 工作流 - native / qemu / wasm。

面向新人和 Agent 的快速入口：
- triage-native：PE/ELF 本地分析（Ghidra metadata + drcov + coverage + flow + decision_points + roles）
- triage-qemu：QEMU 远程分析（Ghidra/Ghidra metadata + QEMU trace + flow + branch_rank）
- triage-wasm：WASM 分析（WASM metadata + decision_points + sig_match）
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def triage_native(
    target_path: str | Path,
    output_dir: str | Path,
    stdin: str | None = None,
    target_args: list[str] | None = None,
    arch: str = "x64",
    timeout: int = 120,
) -> dict[str, Any]:
    """一键 PE/ELF 本地分析工作流。"""
    from beaconflow.ghidra import export_ghidra_metadata
    from beaconflow.coverage.runner import collect_drcov
    from beaconflow.analysis.coverage import analyze_coverage
    from beaconflow.analysis.flow import analyze_flow
    from beaconflow.analysis.decision_points import find_decision_points
    from beaconflow.analysis.roles import detect_roles
    from beaconflow.analysis.ai_digest import attach_ai_digest
    from beaconflow.address_range import detect_executable_address_range

    target = Path(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, str] = {}
    errors: list[str] = []

    # 步骤1: 自动地址范围检测
    addr_range = None
    if target.suffix.lower() in ("", ".elf", ".out"):
        addr_range = detect_executable_address_range(target)
        if addr_range:
            addr_path = out / "address_range.json"
            addr_path.write_text(json.dumps(addr_range, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts["address_range"] = str(addr_path)

    # 步骤2: Ghidra metadata
    metadata_path = out / "metadata.json"
    try:
        meta_result = export_ghidra_metadata(
            target=str(target),
            output=str(metadata_path),
            backend="pyghidra",
            timeout=600,
        )
        if meta_result.get("status") == "ok":
            artifacts["metadata"] = str(metadata_path)
        else:
            errors.append(f"Ghidra metadata: {meta_result.get('error', 'unknown')}")
    except Exception as e:
        errors.append(f"Ghidra metadata: {e}")

    # 步骤3: drcov 采集
    if not metadata_path.exists():
        return {
            "status": "partial",
            "errors": errors,
            "artifacts": artifacts,
            "message": "metadata generation failed, cannot continue",
        }

    from beaconflow.ida import load_metadata
    metadata = load_metadata(str(metadata_path))

    cov_result = None
    try:
        cov_result = collect_drcov(
            target_path=str(target),
            target_args=target_args or [],
            stdin=stdin,
            arch=arch,
            timeout=timeout,
            output_dir=str(out),
        )
        if cov_result.get("log_path"):
            artifacts["drcov"] = cov_result["log_path"]
    except Exception as e:
        errors.append(f"drcov collection: {e}")

    # 步骤4: 覆盖率分析
    if cov_result and cov_result.get("log_path"):
        from beaconflow.coverage import load_drcov
        try:
            coverage = load_drcov(cov_result["log_path"])
            cov_report = analyze_coverage(metadata, coverage)
            attach_ai_digest("coverage", cov_report)
            cov_path = out / "coverage_report.json"
            cov_path.write_text(json.dumps(cov_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            artifacts["coverage"] = str(cov_path)
        except Exception as e:
            errors.append(f"coverage analysis: {e}")

    # 步骤5: 执行流分析
    if cov_result and cov_result.get("log_path"):
        from beaconflow.coverage import load_drcov
        try:
            coverage = load_drcov(cov_result["log_path"])
            flow_report = analyze_flow(metadata, coverage)
            attach_ai_digest("flow", flow_report)
            flow_path = out / "flow_report.json"
            flow_path.write_text(json.dumps(flow_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            artifacts["flow"] = str(flow_path)
        except Exception as e:
            errors.append(f"flow analysis: {e}")

    # 步骤6: 决策点
    try:
        dp_report = find_decision_points(metadata)
        attach_ai_digest("decision_points", dp_report)
        dp_path = out / "decision_points.json"
        dp_path.write_text(json.dumps(dp_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["decision_points"] = str(dp_path)
    except Exception as e:
        errors.append(f"decision points: {e}")

    # 步骤7: 角色检测
    try:
        roles_report = detect_roles(metadata)
        attach_ai_digest("roles", roles_report)
        roles_path = out / "roles.json"
        roles_path.write_text(json.dumps(roles_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["roles"] = str(roles_path)
    except Exception as e:
        errors.append(f"roles: {e}")

    return {
        "status": "ok" if not errors else "partial",
        "target": str(target),
        "artifacts": artifacts,
        "errors": errors,
        "next_steps": [
            "用 inspect-function 深入可疑函数",
            "用 trace-compare / trace-values 获取运行时比较值",
            "用 suggest-hook 生成 Frida hook 模板",
            "用 export-annotations 标注回 IDA/Ghidra",
        ],
    }


def triage_qemu(
    target_path: str | Path,
    output_dir: str | Path,
    qemu_arch: str = "arm",
    stdin_cases: list[str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """一键 QEMU 远程分析工作流。"""
    from beaconflow.address_range import detect_executable_address_range
    from beaconflow.analysis.flow import analyze_flow
    from beaconflow.analysis.ai_digest import attach_ai_digest

    target = Path(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, str] = {}
    errors: list[str] = []

    # 步骤1: 自动地址范围
    addr_range = detect_executable_address_range(target)
    addr_min = None
    addr_max = None
    if addr_range:
        addr_min = addr_range.get("address_min")
        addr_max = addr_range.get("address_max")
        addr_path = out / "address_range.json"
        addr_path.write_text(json.dumps(addr_range, indent=2, ensure_ascii=False), encoding="utf-8")
        artifacts["address_range"] = str(addr_path)

    # 步骤2: Ghidra metadata
    metadata_path = out / "metadata.json"
    try:
        from beaconflow.ghidra import export_ghidra_metadata
        meta_result = export_ghidra_metadata(
            target=str(target),
            output=str(metadata_path),
            backend="pyghidra",
            timeout=600,
        )
        if meta_result.get("status") == "ok":
            artifacts["metadata"] = str(metadata_path)
        else:
            errors.append(f"Ghidra metadata: {meta_result.get('error', 'unknown')}")
    except Exception as e:
        errors.append(f"Ghidra metadata: {e}")

    if not metadata_path.exists():
        return {
            "status": "partial",
            "errors": errors,
            "artifacts": artifacts,
            "message": "metadata generation failed",
        }

    # 步骤3: QEMU 采集
    if not stdin_cases:
        stdin_cases = ["", "AAAA", "flag{test}"]

    from beaconflow.coverage import collect_qemu_trace
    from beaconflow.ida import load_metadata
    metadata = load_metadata(str(metadata_path))

    trace_files: list[str] = []
    for i, case in enumerate(stdin_cases):
        try:
            qemu_result = collect_qemu_trace(
                target=str(target),
                qemu_arch=qemu_arch,
                stdin_text=case,
                timeout=timeout,
                output_dir=str(out),
            )
            if hasattr(qemu_result, 'log_path') and qemu_result.log_path:
                trace_files.append(str(qemu_result.log_path))
                artifacts[f"qemu_trace_{i}"] = str(qemu_result.log_path)
        except Exception as e:
            errors.append(f"QEMU trace {i}: {e}")

    # 步骤4: 执行流分析
    if trace_files:
        from beaconflow.coverage import load_address_log
        for i, tf in enumerate(trace_files[:3]):
            try:
                trace = load_address_log(
                    tf,
                    min_address=int(addr_min, 16) if addr_min else None,
                    max_address=int(addr_max, 16) if addr_max else None,
                )
                flow_report = analyze_flow(metadata, trace)
                attach_ai_digest("flow", flow_report)
                flow_path = out / f"flow_report_{i}.json"
                flow_path.write_text(json.dumps(flow_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
                artifacts[f"flow_{i}"] = str(flow_path)
            except Exception as e:
                errors.append(f"flow analysis {i}: {e}")

    return {
        "status": "ok" if not errors else "partial",
        "target": str(target),
        "qemu_arch": qemu_arch,
        "artifacts": artifacts,
        "errors": errors,
        "next_steps": [
            "用 qemu-explore 测试更多输入",
            "用 diff-flow 对比不同输入的执行路径",
            "用 branch-rank 排序关键分支",
        ],
    }


def triage_wasm(
    target_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    """一键 WASM 分析工作流。"""
    from beaconflow.wasm_parser import analyze_wasm, wasm_to_metadata
    from beaconflow.analysis.decision_points import find_decision_points
    from beaconflow.analysis.sig_matcher import match_signatures
    from beaconflow.analysis.ai_digest import attach_ai_digest

    target = Path(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, str] = {}
    errors: list[str] = []

    # 步骤1: WASM triage
    try:
        wasm_report = analyze_wasm(wasm_path=str(target))
        wasm_path = out / "wasm_analyze.json"
        wasm_path.write_text(json.dumps(wasm_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["wasm_analyze"] = str(wasm_path)
    except Exception as e:
        errors.append(f"WASM analyze: {e}")

    # 步骤2: WASM metadata
    metadata_path = out / "metadata.json"
    try:
        meta_result = wasm_to_metadata(
            wasm_path=str(target),
            output_path=str(metadata_path),
        )
        if meta_result:
            artifacts["metadata"] = str(metadata_path)
        else:
            errors.append(f"WASM metadata: {meta_result.get('error', 'unknown')}")
    except Exception as e:
        errors.append(f"WASM metadata: {e}")

    if not metadata_path.exists():
        return {
            "status": "partial",
            "errors": errors,
            "artifacts": artifacts,
        }

    # 步骤3: 决策点
    from beaconflow.ida import load_metadata
    metadata = load_metadata(str(metadata_path))
    try:
        dp_report = find_decision_points(metadata)
        attach_ai_digest("decision_points", dp_report)
        dp_path = out / "decision_points.json"
        dp_path.write_text(json.dumps(dp_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["decision_points"] = str(dp_path)
    except Exception as e:
        errors.append(f"decision points: {e}")

    # 步骤4: 签名匹配
    try:
        sig_report = match_signatures(metadata)
        attach_ai_digest("sig_match", sig_report)
        sig_path = out / "sig_match.json"
        sig_path.write_text(json.dumps(sig_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["sig_match"] = str(sig_path)
    except Exception as e:
        errors.append(f"sig_match: {e}")

    return {
        "status": "ok" if not errors else "partial",
        "target": str(target),
        "artifacts": artifacts,
        "errors": errors,
        "next_steps": [
            "用 inspect-function 深入可疑函数",
            "用 normalize-ir 查看架构无关 IR",
            "用 suggest-hook 生成 hook 模板",
        ],
    }
