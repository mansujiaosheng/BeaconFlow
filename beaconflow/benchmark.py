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


def run_builtin_benchmarks(output_dir: str | Path | None = None) -> dict[str, Any]:
    """运行内置 benchmark，不需要外部目标文件。

    测试 BeaconFlow 核心功能是否正常工作：
    - 模板库加载和生成
    - 导入器解析
    - Schema 验证
    - 文件类型检测
    - HTML 报告生成
    - 建议引擎
    """
    import struct
    import sys

    out = Path(output_dir) if output_dir else Path("benchmark_builtin_results")
    out.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {
        "status": "ok",
        "checks": {},
        "errors": [],
        "passed": 0,
        "failed": 0,
    }

    start = time.time()

    # 测试1: 模板库加载
    try:
        from beaconflow.templates import FRIDA_TEMPLATES, ANGR_TEMPLATES, GDB_TEMPLATES, X64DBG_TEMPLATES
        total_templates = len(FRIDA_TEMPLATES) + len(ANGR_TEMPLATES) + len(GDB_TEMPLATES) + len(X64DBG_TEMPLATES)
        results["checks"]["templates_loaded"] = total_templates >= 10
        if total_templates >= 10:
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"templates: {e}")
        results["checks"]["templates_loaded"] = False
        results["failed"] += 1

    # 测试2: 模板生成
    try:
        from beaconflow.templates import generate_template
        tmpl_out = out / "test_template.js"
        result = generate_template("compare_strcmp_memcmp", str(tmpl_out))
        results["checks"]["template_generated"] = result.get("status") == "ok"
        if result.get("status") == "ok":
            results["passed"] += 1
        else:
            results["failed"] += 1
        tmpl_out.unlink(missing_ok=True)
    except Exception as e:
        results["errors"].append(f"template generate: {e}")
        results["checks"]["template_generated"] = False
        results["failed"] += 1

    # 测试3: 导入器解析
    try:
        from beaconflow.importers import import_frida_log, import_gdb_log, import_angr_result
        # 创建测试日志
        frida_log = out / "test_frida.log"
        frida_log.write_text('{"type":"compare","function":"strcmp","left":"A","right":"B"}\n', encoding="utf-8")
        result = import_frida_log(str(frida_log))
        results["checks"]["frida_import"] = result.get("status") == "ok" and result.get("total_events", 0) >= 1
        if results["checks"]["frida_import"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"importer: {e}")
        results["checks"]["frida_import"] = False
        results["failed"] += 1

    # 测试4: Schema 验证
    try:
        from beaconflow.schemas import list_schemas, get_schema
        schemas = list_schemas()
        results["checks"]["schema_available"] = len(schemas) >= 10
        if len(schemas) >= 10:
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"schema: {e}")
        results["checks"]["schema_available"] = False
        results["failed"] += 1

    # 测试5: 文件类型检测
    try:
        from beaconflow.triage import _detect_target_type
        # 创建临时 PE 文件头
        pe_stub = out / "test_pe_stub.exe"
        pe_stub.write_bytes(b"MZ" + b"\x00" * 258)
        info = _detect_target_type(pe_stub)
        results["checks"]["pe_detection"] = info.get("type") == "pe"
        if info.get("type") == "pe":
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"detection: {e}")
        results["checks"]["pe_detection"] = False
        results["failed"] += 1

    # 测试6: HTML 报告生成
    try:
        from beaconflow.reports.html_report import markdown_to_html, json_to_html
        html = markdown_to_html("# Test\nHello **world**", title="Test")
        results["checks"]["html_generation"] = "<h1>" in html and "world" in html
        if results["checks"]["html_generation"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"html: {e}")
        results["checks"]["html_generation"] = False
        results["failed"] += 1

    # 测试7: 建议引擎
    try:
        from beaconflow.templates import suggest_hook
        result = suggest_hook()
        results["checks"]["suggest_hook"] = result.get("status") == "ok"
        if result.get("status") == "ok":
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"suggest: {e}")
        results["checks"]["suggest_hook"] = False
        results["failed"] += 1

    # 测试8: triage-pyc (创建临时 .pyc)
    try:
        import marshal
        import types
        pyc_path = out / "test_builtin.pyc"
        # 创建简单 code object
        code = compile("x = 1 + 2", "<test>", "exec")
        # 写入 .pyc 格式
        import struct
        import sys
        pyc_data = struct.pack("<H", 0x0df3)  # magic
        pyc_data += struct.pack("<H", 0x0000)  # flags
        pyc_data += struct.pack("<I", 0)  # timestamp
        pyc_data += struct.pack("<I", 0)  # source size
        pyc_data += marshal.dumps(code)
        pyc_path.write_bytes(pyc_data)

        from beaconflow.triage import triage_pyc
        pyc_out = out / "pyc_output"
        result = triage_pyc(str(pyc_path), str(pyc_out))
        results["checks"]["pyc_triage"] = result.get("status") in ("ok", "partial")
        if result.get("status") in ("ok", "partial"):
            results["passed"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        results["errors"].append(f"pyc triage: {e}")
        results["checks"]["pyc_triage"] = False
        results["failed"] += 1

    results["elapsed_seconds"] = round(time.time() - start, 2)
    results["total_checks"] = results["passed"] + results["failed"]

    if results["failed"] > 0:
        results["status"] = "partial"

    # 保存结果
    result_path = out / "builtin_benchmark_result.json"
    result_path.write_text(json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    return results
