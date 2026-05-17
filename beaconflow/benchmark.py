"""
Benchmark Cases - 标准化测试用例框架。

用于验证 BeaconFlow 各功能在真实场景下的表现，
包括测试用例定义、自动运行、结果收集和报告生成。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


BENCHMARK_CASES: dict[str, dict[str, Any]] = {
    "simple_flagchecker": {
        "name": "simple_flagchecker",
        "description": "简单 flagchecker：使用 strcmp 比较输入",
        "category": "native",
        "features": ["coverage", "flow", "decision_points", "roles", "trace_calls"],
        "expected": {
            "min_functions": 5,
            "min_decision_points": 1,
            "validator_detected": True,
            "strcmp_exposed": True,
        },
    },
    "tea_encryption": {
        "name": "tea_encryption",
        "description": "TEA 加密 flagchecker：使用 SHL+SHR+XOR 模式",
        "category": "native",
        "features": ["coverage", "flow", "sig_match", "roles", "trace_calls"],
        "expected": {
            "min_functions": 5,
            "sig_match_found": True,
            "tea_detected": True,
        },
    },
    "loongarch_flagchecker": {
        "name": "loongarch_flagchecker",
        "description": "LoongArch 跨架构 flagchecker",
        "category": "qemu",
        "features": ["qemu_trace", "flow", "deflatten"],
        "expected": {
            "qemu_trace_ok": True,
            "min_blocks": 10,
        },
    },
    "wasm_vm": {
        "name": "wasm_vm",
        "description": "WebAssembly VM 解释器",
        "category": "wasm",
        "features": ["wasm_analyze", "metadata", "sig_match", "roles"],
        "expected": {
            "min_functions": 50,
            "dispatcher_detected": True,
        },
    },
    "pyc_check": {
        "name": "pyc_check",
        "description": "Python .pyc flagchecker",
        "category": "pyc",
        "features": ["pyc_identify", "code_analysis", "suspicious_functions"],
        "expected": {
            "python_version_detected": True,
            "min_suspicious": 1,
        },
    },
}


def run_benchmark(
    case_name: str,
    target_path: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """运行单个 benchmark 用例。"""
    case = BENCHMARK_CASES.get(case_name)
    if not case:
        return {"status": "error", "error": f"unknown benchmark: {case_name}"}

    out = Path(output_dir) if output_dir else Path("benchmark_results") / case_name
    out.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {
        "case": case_name,
        "description": case["description"],
        "category": case["category"],
        "features_tested": case["features"],
        "checks": {},
        "status": "ok",
        "errors": [],
    }

    start = time.time()

    try:
        if case["category"] == "native" and target_path:
            _run_native_benchmark(target_path, out, case, results)
        elif case["category"] == "qemu" and target_path:
            _run_qemu_benchmark(target_path, out, case, results)
        elif case["category"] == "wasm" and target_path:
            _run_wasm_benchmark(target_path, out, case, results)
        elif case["category"] == "pyc" and target_path:
            _run_pyc_benchmark(target_path, out, case, results)
        else:
            results["status"] = "skipped"
            results["errors"].append("no target_path provided")
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))

    results["elapsed_seconds"] = round(time.time() - start, 2)

    # 验证预期结果
    expected = case.get("expected", {})
    passed = 0
    failed = 0
    for key, expected_val in expected.items():
        actual_val = results["checks"].get(key)
        if actual_val == expected_val:
            passed += 1
        elif isinstance(expected_val, bool) and expected_val and actual_val:
            passed += 1
        elif isinstance(expected_val, (int, float)) and actual_val is not None and actual_val >= expected_val:
            passed += 1
        else:
            failed += 1
            results["checks"][f"_FAIL_{key}"] = f"expected {expected_val}, got {actual_val}"

    results["passed"] = passed
    results["failed"] = failed
    results["total_checks"] = len(expected)

    # 保存结果
    result_path = out / "benchmark_result.json"
    result_path.write_text(json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    return results


def _run_native_benchmark(target: str | Path, out: Path, case: dict, results: dict) -> None:
    """运行 native benchmark。"""
    from beaconflow.triage import triage_native

    triage_result = triage_native(target_path=str(target), output_dir=str(out))
    results["triage_result"] = {
        "status": triage_result.get("status"),
        "artifacts": list(triage_result.get("artifacts", {}).keys()),
        "errors": triage_result.get("errors", []),
    }

    # 检查覆盖率
    cov_path = out / "coverage_report.json"
    if cov_path.exists():
        cov = json.loads(cov_path.read_text(encoding="utf-8"))
        results["checks"]["min_functions"] = cov.get("total_functions", 0)

    # 检查决策点
    dp_path = out / "decision_points.json"
    if dp_path.exists():
        dp = json.loads(dp_path.read_text(encoding="utf-8"))
        dp_list = dp if isinstance(dp, list) else dp.get("decision_points", [])
        results["checks"]["min_decision_points"] = len(dp_list)

    # 检查角色
    roles_path = out / "roles.json"
    if roles_path.exists():
        roles = json.loads(roles_path.read_text(encoding="utf-8"))
        role_list = roles if isinstance(roles, list) else roles.get("roles", [])
        has_validator = any(
            r.get("role") == "validator" or "validator" in str(r.get("roles", []))
            for r in role_list
        )
        results["checks"]["validator_detected"] = has_validator


def _run_qemu_benchmark(target: str | Path, out: Path, case: dict, results: dict) -> None:
    """运行 QEMU benchmark。"""
    from beaconflow.triage import triage_qemu

    triage_result = triage_qemu(
        target_path=str(target),
        output_dir=str(out),
        qemu_arch="loongarch64",
        stdin_cases=["AAAA"],
    )
    results["triage_result"] = {
        "status": triage_result.get("status"),
        "artifacts": list(triage_result.get("artifacts", {}).keys()),
    }
    results["checks"]["qemu_trace_ok"] = "qemu_trace_0" in triage_result.get("artifacts", {})


def _run_wasm_benchmark(target: str | Path, out: Path, case: dict, results: dict) -> None:
    """运行 WASM benchmark。"""
    from beaconflow.triage import triage_wasm

    triage_result = triage_wasm(target_path=str(target), output_dir=str(out))
    results["triage_result"] = {
        "status": triage_result.get("status"),
        "artifacts": list(triage_result.get("artifacts", {}).keys()),
    }

    wasm_path = out / "wasm_analyze.json"
    if wasm_path.exists():
        wasm = json.loads(wasm_path.read_text(encoding="utf-8"))
        results["checks"]["min_functions"] = wasm.get("function_count", 0)

    roles_path = out / "roles.json"
    if roles_path.exists():
        roles = json.loads(roles_path.read_text(encoding="utf-8"))
        role_list = roles if isinstance(roles, list) else roles.get("roles", [])
        has_dispatcher = any("dispatcher" in str(r.get("role", "")) for r in role_list)
        results["checks"]["dispatcher_detected"] = has_dispatcher


def _run_pyc_benchmark(target: str | Path, out: Path, case: dict, results: dict) -> None:
    """运行 pyc benchmark。"""
    from beaconflow.triage import triage_pyc

    triage_result = triage_pyc(target_path=str(target), output_dir=str(out), disassemble=True)
    results["triage_result"] = {
        "status": triage_result.get("status"),
        "python_version": triage_result.get("python_version"),
        "total_functions": triage_result.get("total_functions"),
        "suspicious_functions": triage_result.get("suspicious_functions"),
    }

    results["checks"]["python_version_detected"] = triage_result.get("python_version", "未知") != "未知"
    results["checks"]["min_suspicious"] = triage_result.get("suspicious_functions", 0)


def run_all_benchmarks(
    targets: dict[str, str] | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """运行所有 benchmark 用例。"""
    targets = targets or {}
    out = Path(output_dir) if output_dir else Path("benchmark_results")
    out.mkdir(parents=True, exist_ok=True)

    all_results: dict[str, Any] = {}
    total_passed = 0
    total_failed = 0
    total_cases = 0

    for name, case in BENCHMARK_CASES.items():
        target = targets.get(name)
        result = run_benchmark(name, target_path=target, output_dir=out / name)
        all_results[name] = result
        total_passed += result.get("passed", 0)
        total_failed += result.get("failed", 0)
        total_cases += 1

    summary = {
        "total_cases": total_cases,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "results": all_results,
    }

    summary_path = out / "benchmark_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    return summary


def list_benchmarks() -> dict[str, Any]:
    """列出所有 benchmark 用例。"""
    return {
        "total": len(BENCHMARK_CASES),
        "cases": {
            name: {
                "description": case["description"],
                "category": case["category"],
                "features": case["features"],
            }
            for name, case in BENCHMARK_CASES.items()
        },
    }
