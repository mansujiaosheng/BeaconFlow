"""
一键 Triage 工作流 - native / qemu / wasm / pyc。

面向新人和 Agent 的快速入口：
- triage：统一总入口，自动判断文件类型并分发
- triage-native：PE/ELF 本地分析（Ghidra metadata + drcov + coverage + flow + decision_points + roles）
- triage-qemu：QEMU 远程分析（Ghidra/Ghidra metadata + QEMU trace + flow + branch_rank）
- triage-wasm：WASM 分析（WASM metadata + decision_points + sig_match）
- triage-pyc：Python .pyc 分析（magic 识别 + dis 反汇编 + code object 总结 + 可疑函数识别）
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any


# ELF magic: 0x7f454c46
_ELF_MAGIC = b"\x7fELF"
# PE magic: MZ
_PE_MAGIC = b"MZ"
# WASM magic: \0asm
_WASM_MAGIC = b"\x00asm"
# Python .pyc magic 范围
_PYC_MAGIC_RANGE = (0x0d00, 0x0e10)


def _detect_target_type(target: Path) -> dict[str, Any]:
    """检测目标文件类型和架构。"""
    info: dict[str, Any] = {
        "path": str(target),
        "size": target.stat().st_size if target.exists() else 0,
        "suffix": target.suffix.lower(),
    }

    if not target.exists():
        info["type"] = "unknown"
        info["error"] = "文件不存在"
        return info

    # 先根据后缀快速判断
    suffix = target.suffix.lower()
    if suffix == ".wasm":
        info["type"] = "wasm"
        info["arch"] = "wasm"
        info["bits"] = 32
        info["endian"] = "LE"
        return info
    elif suffix in (".pyc", ".pyo"):
        info["type"] = "pyc"
        data = target.read_bytes()[:4]
        if len(data) >= 2:
            magic = struct.unpack("<H", data[:2])[0]
            info["pyc_magic"] = magic
        info["arch"] = "python-bytecode"
        return info
    elif suffix == ".apk":
        info["type"] = "apk"
        info["arch"] = "android"
        return info

    data = target.read_bytes()[:264]

    if data[:4] == _ELF_MAGIC:
        info["type"] = "elf"
        # 读取 ELF 架构
        ei_class = data[4]  # 1=32bit, 2=64bit
        ei_data = data[5]   # 1=LE, 2=BE
        e_machine = struct.unpack("<H" if ei_data == 1 else ">H", data[18:20])[0]
        machine_map = {
            0x03: "x86", 0x3e: "x64", 0x28: "arm", 0xb7: "aarch64",
            0x08: "mips", 0x06: "mips", 0xf3: "riscv",
            0x102: "loongarch64",
        }
        info["arch"] = machine_map.get(e_machine, f"unknown(0x{e_machine:x})")
        info["bits"] = 64 if ei_class == 2 else 32
        info["endian"] = "LE" if ei_data == 1 else "BE"
    elif data[:2] == _PE_MAGIC:
        info["type"] = "pe"
        info["arch"] = "x64"  # 默认 x64，后续可精确检测
        info["bits"] = 64
        info["endian"] = "LE"
    elif data[:4] == _WASM_MAGIC:
        info["type"] = "wasm"
        info["arch"] = "wasm"
        info["bits"] = 32
        info["endian"] = "LE"
    elif target.suffix.lower() in (".pyc", ".pyo"):
        info["type"] = "pyc"
        magic = struct.unpack("<H", data[:2])[0]
        info["pyc_magic"] = magic
        info["arch"] = "python-bytecode"
    elif target.suffix.lower() in (".so", ".dll", ".pyd"):
        # 需要进一步判断是 ELF 还是 PE
        if data[:4] == _ELF_MAGIC:
            info["type"] = "elf"
        elif data[:2] == _PE_MAGIC:
            info["type"] = "pe"
        else:
            info["type"] = "library"
        info["arch"] = "native"
    else:
        info["type"] = "unknown"
        info["arch"] = "unknown"

    return info


def triage(
    target_path: str | Path,
    output_dir: str | Path,
    stdin: str | None = None,
    target_args: list[str] | None = None,
    qemu_arch: str | None = None,
    arch: str | None = None,
    timeout: int = 120,
    disassemble: bool = False,
) -> dict[str, Any]:
    """统一 triage 入口：自动判断文件类型并分发到对应工作流。"""
    target = Path(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 检测文件类型
    target_info = _detect_target_type(target)

    target_type = target_info.get("type", "unknown")
    detected_arch = target_info.get("arch", "unknown")

    # 决定分发到哪个工作流
    if target_type == "pe":
        effective_arch = arch or "x64"
        return triage_native(
            target_path=target_path,
            output_dir=output_dir,
            stdin=stdin,
            target_args=target_args,
            arch=effective_arch,
            timeout=timeout,
        )
    elif target_type == "elf":
        effective_arch = detected_arch
        if effective_arch in ("x86", "x64"):
            return triage_native(
                target_path=target_path,
                output_dir=output_dir,
                stdin=stdin,
                target_args=target_args,
                arch=effective_arch,
                timeout=timeout,
            )
        else:
            # 非 x86 架构，使用 QEMU
            qemu_arch_map = {
                "loongarch64": "loongarch64",
                "arm": "arm",
                "aarch64": "aarch64",
                "mips": "mips",
                "riscv": "riscv",
            }
            effective_qemu = qemu_arch or qemu_arch_map.get(effective_arch, effective_arch)
            return triage_qemu(
                target_path=target_path,
                output_dir=output_dir,
                qemu_arch=effective_qemu,
                stdin=stdin,
                timeout=timeout,
            )
    elif target_type == "wasm":
        return triage_wasm(
            target_path=target_path,
            output_dir=output_dir,
        )
    elif target_type == "pyc":
        return triage_pyc(
            target_path=target_path,
            output_dir=output_dir,
            disassemble=disassemble,
        )
    elif target_type == "apk":
        return triage_apk(
            target_path=target_path,
            output_dir=output_dir,
        )
    else:
        return {
            "status": "error",
            "target": str(target),
            "target_info": target_info,
            "errors": [f"无法识别目标文件类型: {target_info}"],
            "next_steps": [
                "确认文件是否为有效的 PE/ELF/WASM/.pyc 文件",
                "使用 doctor 检查环境",
                "手动指定工作流: triage-native / triage-qemu / triage-wasm / triage-pyc",
            ],
        }


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
    from beaconflow.analysis.coverage_mapper import analyze_coverage
    from beaconflow.analysis.flow import analyze_flow
    from beaconflow.analysis.decision_points import find_decision_points
    from beaconflow.analysis.role_detector import detect_roles
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
        if meta_result.get("returncode") == 0 or metadata_path.exists():
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
            target=str(target),
            target_args=target_args or [],
            stdin_text=stdin,
            arch=arch,
            timeout=timeout,
            output_dir=str(out),
        )
        if hasattr(cov_result, "log_path") and cov_result.log_path:
            artifacts["drcov"] = str(cov_result.log_path)
    except Exception as e:
        errors.append(f"drcov collection: {e}")

    # 步骤4: 覆盖率分析
    cov_log_path = None
    if cov_result and hasattr(cov_result, "log_path") and cov_result.log_path:
        cov_log_path = str(cov_result.log_path)
    if cov_log_path:
        from beaconflow.coverage import load_drcov
        try:
            coverage = load_drcov(cov_log_path)
            cov_report = analyze_coverage(metadata, coverage)
            cov_path = out / "coverage_report.json"
            cov_path.write_text(json.dumps(cov_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            artifacts["coverage"] = str(cov_path)
        except Exception as e:
            errors.append(f"coverage analysis: {e}")

    # 步骤5: 执行流分析
    if cov_log_path:
        from beaconflow.coverage import load_drcov
        try:
            coverage = load_drcov(cov_log_path)
            flow_report = analyze_flow(metadata, coverage)
            flow_path = out / "flow_report.json"
            flow_path.write_text(json.dumps(flow_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            artifacts["flow"] = str(flow_path)
        except Exception as e:
            errors.append(f"flow analysis: {e}")

    # 步骤6: 决策点
    try:
        dp_list = find_decision_points(metadata)
        dp_report = {"decision_points": dp_list}
        dp_path = out / "decision_points.json"
        dp_path.write_text(json.dumps(dp_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["decision_points"] = str(dp_path)
    except Exception as e:
        errors.append(f"decision points: {e}")

    # 步骤7: 角色检测
    try:
        roles_list = detect_roles(metadata)
        # 转换为可序列化格式
        roles_report = {
            "roles": [
                {
                    "function": r.function_name if hasattr(r, "function_name") else str(r),
                    "address": hex(r.address) if hasattr(r, "address") else "0x0",
                    "role": r.role if hasattr(r, "role") else "unknown",
                    "score": r.score if hasattr(r, "score") else 0.0,
                    "confidence": r.confidence if hasattr(r, "confidence") else "low",
                }
                for r in roles_list
            ]
        }
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
        dp_list = find_decision_points(metadata)
        dp_report = {"decision_points": dp_list}
        attach_ai_digest("decision_points", dp_report)
        dp_path = out / "decision_points.json"
        dp_path.write_text(json.dumps(dp_report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["decision_points"] = str(dp_path)
    except Exception as e:
        errors.append(f"decision points: {e}")

    # 步骤4: 签名匹配
    try:
        sig_report = match_signatures(metadata)
        if isinstance(sig_report, list):
            sig_report = {"matches": sig_report}
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


# Python .pyc magic number 表（部分常用版本）
_PYC_MAGIC: dict[int, str] = {
    3413: "Python 3.8",
    3423: "Python 3.8",
    3424: "Python 3.8",
    3425: "Python 3.8",
    3430: "Python 3.9",
    3431: "Python 3.9",
    3425: "Python 3.9",
    3435: "Python 3.10",
    3438: "Python 3.10",
    3439: "Python 3.10",
    3495: "Python 3.11",
    3531: "Python 3.11",
    3532: "Python 3.11",
    3550: "Python 3.12",
    3561: "Python 3.12",
    3571: "Python 3.13",
    3580: "Python 3.13",
    3590: "Python 3.14",
}

# 可疑函数名关键词
_SUSPICIOUS_KEYWORDS = (
    "check", "verify", "validate", "encrypt", "decrypt",
    "hash", "encode", "decode", "compare", "flag",
    "secret", "password", "key", "token", "license",
    "auth", "login", "serial", "crack", "solve",
)

# 可疑常量关键词
_SUSPICIOUS_CONST_KEYWORDS = (
    "flag{", "flag", "ctf{", "iscc{", "actf{",
    "correct", "wrong", "success", "fail", "error",
    "password", "secret", "key", "token",
    "base64", "aes", "des", "rsa", "md5", "sha",
    "marshal", "zlib", "exec", "eval", "compile",
)


def _identify_pyc(target: Path) -> dict[str, Any]:
    """识别 .pyc 文件基本信息：magic number、Python 版本、时间戳。"""
    import struct

    info: dict[str, Any] = {"path": str(target), "size": target.stat().st_size}

    data = target.read_bytes()
    if len(data) < 16:
        info["error"] = "文件太小，不是有效的 .pyc"
        return info

    # 读取 magic number（前 4 字节，小端序）
    magic = struct.unpack("<H", data[:2])[0]
    info["magic_number"] = magic
    info["magic_hex"] = f"0x{magic:04x}"

    # 匹配 Python 版本
    version = _PYC_MAGIC.get(magic)
    if not version:
        # 尝试匹配 magic/2 的范围
        for m, v in sorted(_PYC_MAGIC.items()):
            if abs(m - magic) <= 5:
                version = f"{v} (近似匹配)"
                break
    info["python_version"] = version or "未知版本"

    # 读取 flags（第 3-4 字节）
    flags = struct.unpack("<H", data[2:4])[0]
    info["flags"] = flags
    info["is_hash_based"] = bool(flags & 0x01)
    info["is_source_size_based"] = bool(flags & 0x02)

    # 读取时间戳或 hash（第 5-8 字节）
    if not info["is_hash_based"]:
        timestamp = struct.unpack("<I", data[4:8])[0]
        import time
        info["timestamp"] = timestamp
        if timestamp > 0:
            info["timestamp_readable"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp))
    else:
        source_hash = data[4:20].hex()
        info["source_hash"] = source_hash

    return info


def _analyze_code_object(code, prefix: str = "") -> list[dict[str, Any]]:
    """递归分析 code object，提取函数名、常量、可疑标记。"""
    results: list[dict[str, Any]] = []

    entry: dict[str, Any] = {
        "name": f"{prefix}{code.co_name}" if prefix else code.co_name,
        "filename": code.co_filename,
        "lineno": code.co_firstlineno,
        "arg_count": code.co_argcount,
        "local_vars": list(code.co_varnames[:code.co_argcount + code.co_nlocals]) if code.co_varnames else [],
        "names": list(code.co_names) if code.co_names else [],
        "constants_summary": [],
        "is_suspicious": False,
        "suspicion_reasons": [],
    }

    # 分析常量
    for c in code.co_consts:
        if isinstance(c, str) and len(c) > 0:
            entry["constants_summary"].append({"type": "str", "value": c[:200]})
            lower = c.lower()
            for kw in _SUSPICIOUS_CONST_KEYWORDS:
                if kw in lower:
                    entry["is_suspicious"] = True
                    entry["suspicion_reasons"].append(f"常量含关键词: {kw}")
                    break
        elif isinstance(c, bytes) and len(c) > 2:
            entry["constants_summary"].append({"type": "bytes", "length": len(c), "preview": c[:50].hex()})
        elif isinstance(c, int) and c not in (0, 1, -1, None, True, False):
            entry["constants_summary"].append({"type": "int", "value": c})
        elif isinstance(c, tuple) and len(c) > 0:
            # 嵌套常量元组
            entry["constants_summary"].append({"type": "tuple", "length": len(c)})

    # 检查函数名是否可疑
    name_lower = code.co_name.lower()
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in name_lower:
            entry["is_suspicious"] = True
            entry["suspicion_reasons"].append(f"函数名含关键词: {kw}")
            break

    # 检查调用的函数名
    for n in code.co_names:
        n_lower = n.lower()
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in n_lower:
                entry["is_suspicious"] = True
                if f"调用可疑函数: {n}" not in entry["suspicion_reasons"]:
                    entry["suspicion_reasons"].append(f"调用可疑函数: {n}")
                break

    results.append(entry)

    # 递归分析子 code object
    for c in code.co_consts:
        if hasattr(c, "co_name"):
            sub_results = _analyze_code_object(c, prefix=f"{entry['name']}.")
            results.extend(sub_results)

    return results


def _disassemble_code(code) -> list[dict[str, Any]]:
    """反汇编 code object，返回指令列表。"""
    import dis

    instructions: list[dict[str, Any]] = []
    try:
        for instr in dis.get_instructions(code):
            instructions.append({
                "offset": instr.offset,
                "opname": instr.opname,
                "arg": instr.arg,
                "argrepr": instr.argrepr,
            })
    except Exception:
        pass
    return instructions


def triage_pyc(
    target_path: str | Path,
    output_dir: str | Path,
    disassemble: bool = False,
) -> dict[str, Any]:
    """一键 Python .pyc 分析工作流。"""
    import marshal

    target = Path(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, str] = {}
    errors: list[str] = []

    # 步骤1: 识别 .pyc 文件
    try:
        pyc_info = _identify_pyc(target)
        info_path = out / "pyc_info.json"
        info_path.write_text(json.dumps(pyc_info, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["pyc_info"] = str(info_path)
    except Exception as e:
        errors.append(f"pyc 识别: {e}")
        return {
            "status": "error",
            "target": str(target),
            "errors": errors,
            "artifacts": artifacts,
        }

    # 步骤2: 反序列化 code object
    data = target.read_bytes()
    code = None
    try:
        # 跳过 magic(4) + flags(4) + timestamp/hash(4/16) + source_size(4)
        # Python 3.7+: magic(4) + flags(4) + [timestamp(4) or hash(16)] + source_size(4)
        if pyc_info.get("is_hash_based"):
            code_offset = 4 + 4 + 16 + 4  # magic + flags + hash + source_size
        else:
            code_offset = 4 + 4 + 4 + 4  # magic + flags + timestamp + source_size

        # Python 3.8+ 可能还有更长的头部
        # 尝试多个偏移量
        for offset in (code_offset, 16, 12, 8):
            try:
                code = marshal.loads(data[offset:])
                if hasattr(code, "co_name"):
                    break
                code = None
            except Exception:
                continue

        if code is None:
            errors.append("无法反序列化 code object，可能是不支持的 Python 版本或损坏的文件")
    except Exception as e:
        errors.append(f"反序列化: {e}")

    if code is None:
        return {
            "status": "partial",
            "target": str(target),
            "errors": errors,
            "artifacts": artifacts,
            "pyc_info": pyc_info,
        }

    # 步骤3: 分析 code object
    try:
        code_analysis = _analyze_code_object(code)
        analysis_path = out / "code_analysis.json"
        analysis_path.write_text(json.dumps(code_analysis, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        artifacts["code_analysis"] = str(analysis_path)
    except Exception as e:
        errors.append(f"code object 分析: {e}")
        code_analysis = []

    # 步骤4: 可疑函数汇总
    suspicious = [e for e in code_analysis if e.get("is_suspicious")]
    suspicious_path = out / "suspicious_functions.json"
    suspicious_path.write_text(json.dumps(suspicious, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    artifacts["suspicious_functions"] = str(suspicious_path)

    # 步骤5: 可选 dis 反汇编
    if disassemble:
        try:
            dis_result = _disassemble_code(code)
            dis_path = out / "disassembly.json"
            dis_path.write_text(json.dumps(dis_result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            artifacts["disassembly"] = str(dis_path)
        except Exception as e:
            errors.append(f"dis 反汇编: {e}")

    # 步骤6: 生成汇总报告
    summary = {
        "target": str(target),
        "python_version": pyc_info.get("python_version", "未知"),
        "magic_number": pyc_info.get("magic_hex", "未知"),
        "total_functions": len(code_analysis),
        "suspicious_functions": len(suspicious),
        "suspicious_list": [
            {"name": s["name"], "reasons": s.get("suspicion_reasons", [])}
            for s in suspicious
        ],
        "top_level_name": code.co_name if code else "未知",
        "top_level_consts": [
            c for c in code_analysis
            if c["name"] == (code.co_name if code else "")
        ],
        "recommended_tools": [],
    }

    # 根据发现推荐工具
    if suspicious:
        summary["recommended_tools"].append("uncompyle6 / pycdc 反编译查看可疑函数完整代码")
    if any("marshal" in str(s.get("suspicion_reasons", [])) or "marshal" in str(s.get("constants_summary", []))
           for s in suspicious):
        summary["recommended_tools"].append("检查 marshal.loads 调用，可能嵌套了加密的 code object")
    if any("zlib" in str(s.get("suspicion_reasons", [])) or "zlib" in str(s.get("constants_summary", []))
           for s in suspicious):
        summary["recommended_tools"].append("检查 zlib.decompress 调用，可能压缩了数据")
    if any("exec" in str(s.get("suspicion_reasons", [])) or "eval" in str(s.get("suspicion_reasons", []))
           for s in suspicious):
        summary["recommended_tools"].append("检查 exec/eval 调用，可能动态执行代码")

    summary_path = out / "triage_pyc_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    artifacts["summary"] = str(summary_path)

    return {
        "status": "ok" if not errors else "partial",
        "target": str(target),
        "python_version": pyc_info.get("python_version", "未知"),
        "total_functions": len(code_analysis),
        "suspicious_functions": len(suspicious),
        "artifacts": artifacts,
        "errors": errors,
        "next_steps": [
            "用 uncompyle6 / pycdc 反编译查看完整源码",
            "重点分析可疑函数的完整逻辑",
            "检查是否有 marshal/zlib/exec 嵌套加密",
        ],
    }


# APK 分析关键词
_APK_CRYPTO_APIS = (
    "Cipher", "SecretKey", "MessageDigest", "Mac", "Signature",
    "KeyGenerator", "KeyFactory", "AES", "DES", "RSA", "ECDSA",
)
_APK_BASE64_APIS = ("Base64", "android.util.Base64")
_APK_STRING_COMPARE_APIS = ("String.equals", "String.compareTo", "equalsIgnoreCase", "contains")
_APK_JNI_PATTERNS = ("System.loadLibrary", "System.load", "native ", "RegisterNatives")
_APK_SUSPICIOUS_CLASS_KEYWORDS = (
    "check", "verify", "validate", "encrypt", "decrypt",
    "flag", "secret", "password", "key", "token", "license",
    "auth", "login", "serial", "crack", "solve", "sign",
)


def _parse_axml_string_pool(data: bytes, offset: int) -> tuple[list[str], int]:
    """解析 AXML 字符串池，返回字符串列表和偏移量。"""
    if offset + 8 > len(data):
        return [], offset
    chunk_type = struct.unpack_from("<H", data, offset)[0]
    chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
    if chunk_type != 0x0001:
        return [], offset + chunk_size

    str_count = struct.unpack_from("<I", data, offset + 8)[0]
    # style_count: offset+12
    # flags: offset+16
    # strings_start: offset+20
    # styles_start: offset+24
    flags = struct.unpack_from("<I", data, offset + 16)[0]
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    is_utf8 = bool(flags & (1 << 8))

    strings: list[str] = []
    str_offsets_start = offset + 28
    for i in range(min(str_count, 500)):
        if str_offsets_start + i * 4 + 4 > len(data):
            break
        str_offset = struct.unpack_from("<I", data, str_offsets_start + i * 4)[0]
        abs_offset = offset + strings_start + str_offset
        if abs_offset >= len(data):
            strings.append("")
            continue
        try:
            if is_utf8:
                # UTF-8 编码: charLen(1-2字节) + byteLen(1字节) + UTF-8数据
                char_len = data[abs_offset]
                if char_len & 0x80:
                    char_len = ((char_len & 0x7F) << 8) | data[abs_offset + 1]
                    byte_len = data[abs_offset + 2]
                    raw = data[abs_offset + 3:abs_offset + 3 + byte_len]
                else:
                    byte_len = data[abs_offset + 1]
                    raw = data[abs_offset + 2:abs_offset + 2 + byte_len]
                strings.append(raw.decode("utf-8", errors="replace"))
            else:
                # UTF-16 编码: charLen(2-4字节) + UTF-16LE数据
                str_len = struct.unpack_from("<H", data, abs_offset)[0]
                if str_len & 0x8000:
                    str_len = ((str_len & 0x7FFF) << 16) | struct.unpack_from("<H", data, abs_offset + 2)[0]
                    raw = data[abs_offset + 4:abs_offset + 4 + str_len * 2]
                else:
                    raw = data[abs_offset + 2:abs_offset + 2 + str_len * 2]
                if str_len > 500:
                    str_len = 500
                    raw = raw[:1000]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except Exception:
            strings.append("")

    return strings, offset + chunk_size


def _parse_axml_manifest(data: bytes) -> dict[str, Any]:
    """解析 Android 二进制 XML (AXML) 格式的 AndroidManifest.xml。

    轻量级解析器，提取 package、permissions、main_activity 等关键字段。
    不依赖 aapt/apktool 等外部工具。
    """
    import struct as _struct

    result: dict[str, Any] = {
        "package": "",
        "main_activity": "",
        "permissions": [],
        "activities": [],
    }

    if len(data) < 8:
        return result

    # 检查 AXML magic
    magic = _struct.unpack_from("<I", data, 0)[0]
    if magic != 0x00080003:
        return result

    # 解析字符串池
    str_pool_offset = 8
    strings, next_offset = _parse_axml_string_pool(data, str_pool_offset)

    if not strings:
        return result

    # 跳过 Resource ID chunk (type=0x0180)
    res_id_offset = next_offset
    if res_id_offset + 8 <= len(data):
        res_type = _struct.unpack_from("<H", data, res_id_offset)[0]
        if res_type == 0x0180:
            res_size = _struct.unpack_from("<I", data, res_id_offset + 4)[0]
            next_offset = res_id_offset + res_size

    # TYPE_STRING = 0x03, TYPE_INT_DEC = 0x10, TYPE_INT_BOOLEAN = 0x12
    _TYPE_STRING = 0x03

    def _get_attr_value(attr_base: int) -> str:
        """从属性基址读取值，根据类型解析。"""
        if attr_base + 20 > len(data):
            return ""
        data_type = data[attr_base + 15]
        data_val = _struct.unpack_from("<I", data, attr_base + 16)[0]
        if data_type == _TYPE_STRING and data_val < len(strings):
            return strings[data_val]
        elif data_type == 0x10:
            return str(data_val)
        elif data_type == 0x12:
            return "true" if data_val else "false"
        return ""

    # 遍历 XML 元素 chunk
    pos = next_offset
    in_activity = False
    current_activity_name = ""
    has_main_action = False

    while pos + 8 <= len(data):
        chunk_type = _struct.unpack_from("<H", data, pos)[0]
        chunk_size = _struct.unpack_from("<I", data, pos + 4)[0]

        if chunk_size < 8 or pos + chunk_size > len(data):
            break

        # RES_XML_START_ELEMENT_TYPE = 0x0102
        if chunk_type == 0x0102:
            name_idx = _struct.unpack_from("<I", data, pos + 20)[0]
            attr_count = _struct.unpack_from("<H", data, pos + 28)[0]

            elem_name = strings[name_idx] if name_idx < len(strings) else ""

            if elem_name == "activity":
                in_activity = True
                current_activity_name = ""
                has_main_action = False

            # 解析属性
            for ai in range(min(attr_count, 20)):
                attr_base = pos + 36 + ai * 20
                if attr_base + 20 > len(data):
                    break
                attr_name_idx = _struct.unpack_from("<I", data, attr_base + 4)[0]
                attr_name = strings[attr_name_idx] if attr_name_idx < len(strings) else ""
                attr_val = _get_attr_value(attr_base)

                if elem_name == "manifest" and attr_name == "package":
                    result["package"] = attr_val
                elif elem_name == "uses-permission" and attr_name == "name":
                    if attr_val and attr_val not in result["permissions"]:
                        result["permissions"].append(attr_val)
                elif elem_name == "activity" and attr_name == "name":
                    current_activity_name = attr_val
                    if attr_val and attr_val not in result["activities"]:
                        result["activities"].append(attr_val)
                elif elem_name == "action" and attr_name == "name":
                    if "MAIN" in attr_val:
                        has_main_action = True

        # RES_XML_END_ELEMENT_TYPE = 0x0103
        elif chunk_type == 0x0103:
            name_idx = _struct.unpack_from("<I", data, pos + 20)[0]
            elem_name = strings[name_idx] if name_idx < len(strings) else ""
            if elem_name == "activity":
                if has_main_action and current_activity_name:
                    result["main_activity"] = current_activity_name
                in_activity = False
                current_activity_name = ""
                has_main_action = False

        pos += chunk_size

    return result


def triage_apk(
    target_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    """一键 APK 薄适配分析：解析 manifest、native libs、JADX summary。"""
    import zipfile
    import xml.etree.ElementTree as ET

    target = Path(target_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, str] = {}
    errors: list[str] = []
    warnings: list[str] = []

    summary: dict[str, Any] = {
        "target": str(target),
        "package": "",
        "main_activity": "",
        "permissions": [],
        "native_libs": [],
        "abis": [],
        "interesting_classes": [],
        "jni_methods": [],
        "crypto_apis": [],
        "base64_apis": [],
        "string_compare_apis": [],
        "recommended_hooks": [],
    }

    # 步骤1: 解析 APK（ZIP 格式）
    try:
        with zipfile.ZipFile(str(target), "r") as zf:
            names = zf.namelist()

            # 解析 AndroidManifest.xml（二进制格式，尝试文本解析）
            manifest_data = None
            for name in names:
                if name.endswith("AndroidManifest.xml"):
                    try:
                        manifest_data = zf.read(name)
                    except Exception:
                        pass
                    break

            # 列出 native libs
            lib_files = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            abis_set: set[str] = set()
            for lib in lib_files:
                parts = lib.split("/")
                if len(parts) >= 3:
                    abis_set.add(parts[1])
                    so_name = parts[-1]
                    if so_name not in summary["native_libs"]:
                        summary["native_libs"].append(so_name)
            summary["abis"] = sorted(abis_set)

            # 列出 DEX 文件
            dex_files = [n for n in names if n.endswith(".dex")]
            summary["dex_count"] = len(dex_files)

            # 列出 assets
            assets = [n for n in names if n.startswith("assets/")]
            summary["asset_count"] = len(assets)

            # 尝试解析 manifest（优先文本 XML，失败则尝试 AXML 二进制解析）
            if manifest_data:
                parsed = False
                try:
                    root = ET.fromstring(manifest_data.decode("utf-8"))
                    ns = {"android": "http://schemas.android.com/apk/res/android"}
                    pkg = root.get("package", "")
                    summary["package"] = pkg

                    perms = []
                    for perm_elem in root.iter("uses-permission"):
                        perm_name = perm_elem.get("{http://schemas.android.com/apk/res/android}name", "")
                        if not perm_name:
                            perm_name = perm_elem.get("name", "")
                        if perm_name:
                            perms.append(perm_name)
                    summary["permissions"] = perms

                    for activity in root.iter("activity"):
                        act_name = activity.get("{http://schemas.android.com/apk/res/android}name", "")
                        if not act_name:
                            act_name = activity.get("name", "")
                        intent_filter = activity.find("intent-filter")
                        if intent_filter is not None:
                            action = intent_filter.find("action")
                            if action is not None:
                                action_name = action.get("{http://schemas.android.com/apk/res/android}name", "")
                                if "MAIN" in action_name:
                                    summary["main_activity"] = act_name
                    parsed = True
                except (ET.ParseError, UnicodeDecodeError):
                    pass

                if not parsed:
                    axml_result = _parse_axml_manifest(manifest_data)
                    if axml_result.get("package"):
                        summary["package"] = axml_result["package"]
                    if axml_result.get("main_activity"):
                        summary["main_activity"] = axml_result["main_activity"]
                    if axml_result.get("permissions"):
                        summary["permissions"] = axml_result["permissions"]
                    if not axml_result.get("package") and not axml_result.get("main_activity"):
                        warnings.append("AndroidManifest.xml 解析失败，可安装 aapt 辅助解析")

    except zipfile.BadZipFile:
        errors.append("不是有效的 APK/ZIP 文件")
        return {
            "status": "error",
            "target": str(target),
            "errors": errors,
            "artifacts": artifacts,
        }
    except Exception as e:
        errors.append(f"APK 解析: {e}")

    # 步骤2: 尝试使用 aapt 解析 manifest（如果可用）
    if not summary["package"]:
        import subprocess
        for aapt_cmd in ("aapt", "aapt2"):
            try:
                result = subprocess.run(
                    [aapt_cmd, "dump", "badging", str(target)],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if line.startswith("package:"):
                            for part in line.split():
                                if part.startswith("name="):
                                    summary["package"] = part.split("=", 1)[1].strip("'")
                                if part.startswith("versionName="):
                                    summary["version"] = part.split("=", 1)[1].strip("'")
                        if "launchable-activity" in line:
                            for part in line.split():
                                if part.startswith("name="):
                                    summary["main_activity"] = part.split("=", 1)[1].strip("'")
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

    # 步骤3: 尝试导入 JADX summary（如果已有）
    jadx_dir = out / "jadx_output"
    jadx_summary_path = None
    if jadx_dir.exists():
        try:
            from beaconflow.importers import import_jadx_summary
            jadx_result = import_jadx_summary(str(jadx_dir))
            if jadx_result.get("status") == "ok":
                # 从 JADX 结果中提取信息
                for ev in jadx_result.get("evidence", []):
                    ev_str = str(ev).lower()
                    for api in _APK_CRYPTO_APIS:
                        if api.lower() in ev_str and api not in summary["crypto_apis"]:
                            summary["crypto_apis"].append(api)
                    for api in _APK_BASE64_APIS:
                        if api.lower() in ev_str and api not in summary["base64_apis"]:
                            summary["base64_apis"].append(api)
                    for api in _APK_STRING_COMPARE_APIS:
                        if api.lower() in ev_str and api not in summary["string_compare_apis"]:
                            summary["string_compare_apis"].append(api)
                    for pat in _APK_JNI_PATTERNS:
                        if pat.lower() in ev_str and pat not in summary["jni_methods"]:
                            summary["jni_methods"].append(pat)
                    for kw in _APK_SUSPICIOUS_CLASS_KEYWORDS:
                        if kw in ev_str:
                            class_name = ev.get("class_name", ev.get("name", ""))
                            if class_name and class_name not in summary["interesting_classes"]:
                                summary["interesting_classes"].append(class_name)
                jadx_summary_path = out / "jadx_summary.json"
                jadx_summary_path.write_text(
                    json.dumps(jadx_result, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
                artifacts["jadx_summary"] = str(jadx_summary_path)
        except Exception as e:
            warnings.append(f"JADX summary 导入: {e}")

    # 步骤4: 生成 hook 推荐
    hooks: list[dict[str, Any]] = []
    if summary["crypto_apis"]:
        hooks.append({
            "name": "hook_java_crypto",
            "reason": f"发现加密 API: {', '.join(summary['crypto_apis'][:5])}",
            "template": "android_crypto_hook",
            "confidence": 0.85,
        })
    if summary["base64_apis"]:
        hooks.append({
            "name": "hook_base64",
            "reason": "发现 Base64 编解码调用",
            "template": "android_base64_hook",
            "confidence": 0.8,
        })
    if summary["string_compare_apis"]:
        hooks.append({
            "name": "hook_string_equals",
            "reason": "发现字符串比较调用，可能用于验证",
            "template": "android_string_equals",
            "confidence": 0.78,
        })
    if summary["jni_methods"]:
        hooks.append({
            "name": "hook_jni_native",
            "reason": f"发现 JNI 调用: {', '.join(summary['jni_methods'][:3])}",
            "template": "android_jni_hook",
            "confidence": 0.82,
        })
    if summary["native_libs"]:
        for so in summary["native_libs"][:3]:
            hooks.append({
                "name": f"hook_native_{so.replace('.', '_').replace('lib', '')}",
                "reason": f"发现 native library: {so}",
                "template": "frida_native_interceptor",
                "confidence": 0.7,
            })
    summary["recommended_hooks"] = hooks

    # 保存结果
    summary_path = out / "apk_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    artifacts["summary"] = str(summary_path)

    return {
        "status": "ok" if not errors else "partial",
        "target": str(target),
        "package": summary["package"],
        "main_activity": summary["main_activity"],
        "native_libs": summary["native_libs"],
        "abis": summary["abis"],
        "recommended_hooks_count": len(hooks),
        "artifacts": artifacts,
        "errors": errors,
        "warnings": warnings,
        "next_steps": [
            "使用 jadx -d output app.apk 反编译 Java 层",
            "使用 import-jadx-summary --summary output 导入反编译结果",
            "使用 suggest-hook --target-type android 生成 Android hook 模板",
            "对 native .so 使用 triage-native 进行深度分析",
        ],
    }
