"""
Doctor - 环境诊断命令。

检查 BeaconFlow 依赖项是否可用，减少环境问题带来的使用成本。

检查内容：
- Python 版本
- beaconflow 是否可 import
- IDA / idat64 是否可用
- Ghidra / pyghidra 是否可用
- DynamoRIO / drrun 是否可用
- QEMU user-mode 是否可用
- WSL 是否可用
- MCP 配置是否正常
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CheckResult:
    name: str
    status: str  # OK, FAIL, WARN
    message: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        result = {"name": self.name, "status": self.status, "message": self.message}
        if self.detail:
            result["detail"] = self.detail
        return result


def _find_executable(name: str) -> str | None:
    return shutil.which(name)


def _find_in_wsl(name: str) -> str | None:
    try:
        result = subprocess.run(
            ["wsl", "-e", "which", name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _check_python() -> CheckResult:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        return CheckResult("Python", "OK", f"Python {version}")
    return CheckResult("Python", "FAIL", f"Python {version} (requires >= 3.10)")


def _check_beaconflow_import() -> CheckResult:
    try:
        import beaconflow
        version = getattr(beaconflow, "__version__", "unknown")
        return CheckResult("beaconflow", "OK", f"beaconflow {version} importable")
    except ImportError as e:
        return CheckResult("beaconflow", "FAIL", f"Cannot import beaconflow: {e}")


def _check_update() -> CheckResult:
    """检查 BeaconFlow 是否有新版本可用。"""
    try:
        from beaconflow.update_checker import check_for_update
        result = check_for_update()
        current = result.get("current", "unknown")
        latest = result.get("latest", "unknown")
        has_update = result.get("has_update", False)

        if has_update:
            return CheckResult(
                "update", "WARN",
                f"New version available: {current} → {latest}",
                detail="Run `check_update` tool or see update command in output",
            )
        if result.get("message") and "无法检查" in result["message"]:
            return CheckResult("update", "WARN", result["message"])
        return CheckResult("update", "OK", f"beaconflow {current} is up to date")
    except Exception as e:
        return CheckResult("update", "WARN", f"Update check failed: {e}")


def _check_drrun() -> list[CheckResult]:
    results = []
    repo_root = Path(__file__).resolve().parent.parent
    for arch, subdir in [("x64", "bin64"), ("x86", "bin32")]:
        # 先检查项目内嵌的 DynamoRIO
        bundled = repo_root / "third_party" / "dynamorio" / subdir / "drrun.exe"
        if bundled.exists():
            results.append(CheckResult(
                f"drrun {arch}", "OK",
                f"drrun {arch} found (bundled)",
                detail=str(bundled),
            ))
            continue

        # 检查 Linux 版本（通过 WSL）
        linux_bundled = repo_root / "third_party" / "dynamorio_linux" / subdir / "drrun"
        if linux_bundled.exists():
            wsl_path = _find_in_wsl("drrun")
            if wsl_path:
                results.append(CheckResult(
                    f"drrun {arch}", "OK",
                    f"drrun {arch} found (bundled Linux + WSL)",
                    detail=str(linux_bundled),
                ))
                continue

        # 检查系统 PATH
        found = _find_executable(f"drrun")
        if found:
            results.append(CheckResult(
                f"drrun {arch}", "OK",
                f"drrun found in PATH",
                detail=found,
            ))
        else:
            results.append(CheckResult(
                f"drrun {arch}", "FAIL",
                f"drrun {arch} not found",
            ))
    return results


def _check_qemu(qemu_arch: str | None = None) -> list[CheckResult]:
    results = []
    default_archs = ["loongarch64", "mips", "arm", "aarch64", "riscv64"]
    archs_to_check = [qemu_arch] if qemu_arch else default_archs

    for arch in archs_to_check:
        exe_name = f"qemu-{arch}"
        # Windows 原生
        found = _find_executable(exe_name)
        if found:
            results.append(CheckResult(
                f"qemu-{arch}", "OK",
                f"qemu-{arch} found",
                detail=found,
            ))
            continue

        # WSL 中查找
        wsl_path = _find_in_wsl(exe_name)
        if wsl_path:
            results.append(CheckResult(
                f"qemu-{arch}", "OK",
                f"qemu-{arch} found (WSL)",
                detail=wsl_path,
            ))
            continue

        results.append(CheckResult(
            f"qemu-{arch}", "WARN",
            f"qemu-{arch} not found",
        ))

    return results


def _check_ida() -> CheckResult:
    for name in ("idat64", "ida64", "idat", "ida"):
        found = _find_executable(name)
        if found:
            return CheckResult("IDA", "OK", f"{name} found in PATH", detail=found)

    ida_path = os.environ.get("IDA_PATH") or os.environ.get("IDALOG")
    if ida_path and Path(ida_path).exists():
        return CheckResult("IDA", "OK", f"IDA found via IDA_PATH", detail=ida_path)

    return CheckResult("IDA", "WARN", "IDA idat64 not in PATH")


def _check_ghidra() -> list[CheckResult]:
    results = []

    # 检查 pyghidra
    try:
        import pyghidra
        results.append(CheckResult("pyghidra", "OK", "pyghidra installed"))
    except ImportError:
        results.append(CheckResult("pyghidra", "WARN", "pyghidra not installed"))

    # 检查 Ghidra 安装路径
    ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    if ghidra_home and Path(ghidra_home).exists():
        results.append(CheckResult("Ghidra", "OK", f"Ghidra found", detail=ghidra_home))
    else:
        found = _find_executable("analyzeHeadless")
        if found:
            results.append(CheckResult("Ghidra", "OK", "analyzeHeadless found in PATH"))
        else:
            results.append(CheckResult("Ghidra", "WARN", "Ghidra not found (set GHIDRA_INSTALL_DIR)"))

    return results


def _check_wsl() -> CheckResult:
    found = _find_executable("wsl")
    if found:
        try:
            result = subprocess.run(
                ["wsl", "-e", "echo", "ok"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return CheckResult("WSL", "OK", "WSL available")
        except subprocess.TimeoutExpired:
            pass
    return CheckResult("WSL", "WARN", "WSL not available")


def _check_mcp() -> CheckResult:
    try:
        import mcp
        return CheckResult("MCP", "OK", "mcp package installed")
    except ImportError:
        return CheckResult("MCP", "WARN", "mcp package not installed (pip install mcp)")


def _check_yaml() -> CheckResult:
    try:
        import yaml
        return CheckResult("PyYAML", "OK", "PyYAML installed")
    except ImportError:
        return CheckResult("PyYAML", "WARN", "PyYAML not installed (pip install pyyaml)")


def run_doctor(
    qemu_arch: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    results: list[CheckResult] = []

    results.append(_check_python())
    results.append(_check_beaconflow_import())
    results.append(_check_update())
    results.append(_check_ida())
    results.extend(_check_ghidra())
    results.extend(_check_drrun())
    results.extend(_check_qemu(qemu_arch))
    results.append(_check_wsl())
    results.append(_check_mcp())
    results.append(_check_yaml())

    # 如果指定了 target，检查它是否存在
    if target:
        target_path = Path(target)
        if target_path.exists():
            results.append(CheckResult("target", "OK", f"Target file exists", detail=str(target_path)))
        else:
            results.append(CheckResult("target", "FAIL", f"Target file not found: {target}"))

    ok_count = sum(1 for r in results if r.status == "OK")
    fail_count = sum(1 for r in results if r.status == "FAIL")
    warn_count = sum(1 for r in results if r.status == "WARN")

    return {
        "summary": {
            "total": len(results),
            "ok": ok_count,
            "fail": fail_count,
            "warn": warn_count,
        },
        "checks": [r.to_dict() for r in results],
    }


def doctor_to_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    checks = result["checks"]
    lines = [
        "# BeaconFlow Doctor",
        "",
        f"- OK: {summary['ok']}",
        f"- FAIL: {summary['fail']}",
        f"- WARN: {summary['warn']}",
        "",
    ]

    for check in checks:
        status = check["status"]
        name = check["name"]
        message = check["message"]
        detail = check.get("detail", "")
        if detail:
            lines.append(f"[{status}] {name}: {message} ({detail})")
        else:
            lines.append(f"[{status}] {name}: {message}")

    lines.append("")
    if summary["fail"] > 0:
        lines.append("## Action Required")
        lines.append("")
        for check in checks:
            if check["status"] == "FAIL":
                lines.append(f"- **{check['name']}**: {check['message']}")
        lines.append("")

    if summary["warn"] > 0:
        lines.append("## Warnings (Optional)")
        lines.append("")
        for check in checks:
            if check["status"] == "WARN":
                lines.append(f"- **{check['name']}**: {check['message']}")
        lines.append("")

    return "\n".join(lines) + "\n"
