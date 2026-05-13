from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


def find_ghidra_headless() -> str | None:
    name = "analyzeHeadless"
    ext = ".bat" if platform.system().lower() == "windows" else ""
    candidate = shutil.which(name + ext) or shutil.which(name)
    if candidate:
        return candidate

    ghidra_home = _find_ghidra_install()
    if ghidra_home:
        script = ghidra_home / ("support/analyzeHeadless" + ext)
        if script.exists():
            return str(script)
    return None


def _find_ghidra_install() -> Path | None:
    env = os.environ
    ghidra_home = env.get("GHIDRA_HOME") or env.get("GHIDRA_INSTALL_DIR")
    if ghidra_home:
        return Path(ghidra_home)
    # 搜索常见安装目录
    search_roots = [Path("C:/"), Path.home(), Path("D:/TOOL"), Path("D:/")]
    for root in search_roots:
        if not root.exists():
            continue
        for candidate in root.glob("ghidra_*"):
            if (candidate / "support").exists():
                return candidate
    return None


def _safe_script_dir() -> Path:
    d = Path(tempfile.gettempdir()) / "beaconflow_ghidra_scripts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _prepare_script(script_path: Path) -> Path:
    safe_dir = _safe_script_dir()
    dest = safe_dir / script_path.name
    if not dest.exists() or dest.stat().st_mtime < script_path.stat().st_mtime:
        shutil.copy2(script_path, dest)
    return dest


def export_ghidra_metadata(
    target: str | Path,
    output: str | Path,
    ghidra_path: str | Path | None = None,
    project_dir: str | Path | None = None,
    project_name: str = "beaconflow_export",
    script_path: str | Path | None = None,
    timeout: int | None = 600,
    backend: str = "pyghidra",
    with_context: bool = True,
) -> dict[str, object]:
    if backend == "pyghidra":
        return export_ghidra_metadata_pyghidra(target=target, output=output, project_dir=project_dir, project_name=project_name, timeout=timeout, with_context=with_context)
    if backend != "headless":
        raise ValueError(f"unknown Ghidra export backend: {backend}")

    headless = ghidra_path or find_ghidra_headless()
    if not headless:
        raise FileNotFoundError(
            "Ghidra analyzeHeadless not found. "
            "Install Ghidra and set GHIDRA_HOME, or pass --ghidra-path."
        )

    target_path = Path(target).resolve()
    output_path = Path(output).resolve()

    script = Path(script_path) if script_path else Path(__file__).parent.parent.parent / "ghidra_scripts" / "ExportBeaconFlowMetadata.java"
    if not script.exists():
        py_script = script.with_suffix(".py")
        if py_script.exists():
            script = py_script
    script = script.resolve()

    if not script.exists():
        raise FileNotFoundError(f"Ghidra export script not found: {script}")

    safe_script = _prepare_script(script)

    work_dir = Path(project_dir) if project_dir else Path(tempfile.gettempdir()) / "beaconflow_ghidra_project"
    work_dir.mkdir(parents=True, exist_ok=True)

    command = [
        str(headless),
        str(work_dir),
        project_name,
        "-import", str(target_path),
        "-postScript", str(safe_script), str(output_path),
        "-deleteProject",
        "-overwrite",
    ]

    print(f"[ghidra-export] Running: {' '.join(command)}", flush=True)
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )

    if not output_path.exists():
        raise RuntimeError(
            f"Ghidra export did not produce output file: {output_path}\n"
            f"stdout: {completed.stdout[-2000:]}\n"
            f"stderr: {completed.stderr[-2000:]}"
        )

    from beaconflow.ida import load_metadata
    metadata = load_metadata(output_path)
    return {
        "output_path": str(output_path),
        "command": command,
        "returncode": completed.returncode,
        "functions": len(metadata.functions),
        "basic_blocks": sum(len(f.blocks) for f in metadata.functions),
    }


def export_ghidra_metadata_pyghidra(
    target: str | Path,
    output: str | Path,
    project_dir: str | Path | None = None,
    project_name: str = "beaconflow_export",
    timeout: int | None = 600,
    with_context: bool = True,
) -> dict[str, object]:
    """Export metadata through pyghidra, avoiding analyzeHeadless script loading."""
    if importlib.util.find_spec("pyghidra") is None:
        raise ImportError("pyghidra is required for the default Ghidra exporter. Install it with `pip install pyghidra`, or use --backend headless.")

    # 动态定位 ghidra_scripts 目录：优先从 beaconflow 包的父目录查找
    _repo_root = Path(__file__).resolve().parent.parent.parent
    _script_path = _repo_root / "ghidra_scripts" / "export_ghidra_metadata.py"
    if not _script_path.exists():
        raise FileNotFoundError(f"ghidra_scripts/export_ghidra_metadata.py not found at {_script_path}")

    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("ghidra_scripts.export_ghidra_metadata", _script_path)
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    export_metadata = _mod.export_metadata

    target_path = Path(target).resolve()
    output_path = Path(output).resolve()
    work_dir = Path(project_dir).resolve() if project_dir else Path(tempfile.mkdtemp(prefix="beaconflow_pyghidra_"))
    export_metadata(str(target_path), str(output_path), project_location=str(work_dir), project_name=project_name, with_context=with_context)

    from beaconflow.ida import load_metadata
    metadata = load_metadata(output_path)
    return {
        "output_path": str(output_path),
        "backend": "pyghidra",
        "returncode": 0,
        "functions": len(metadata.functions),
        "basic_blocks": sum(len(f.blocks) for f in metadata.functions),
    }


def decompile_ghidra(
    target: str | Path,
    output: str | Path | None = None,
    function: str | None = None,
    max_functions: int = 20,
    timeout: int = 30,
    project_dir: str | Path | None = None,
    project_name: str = "beaconflow_decompile",
) -> dict[str, object]:
    """Run Ghidra's decompiler through pyghidra and return pseudo-code.

    This requires Ghidra to have a loader/language for the target. Stock Ghidra
    installations usually do not load WebAssembly modules; in that case the
    returned error is intentional and the caller should use the pure Python WASM
    analyzer as fallback.
    """
    if importlib.util.find_spec("pyghidra") is None:
        raise ImportError("pyghidra is required. Install it with `pip install pyghidra`.")

    import pyghidra

    target_path = Path(target).resolve()
    result: dict[str, object] = {
        "input_path": str(target_path),
        "backend": "pyghidra",
        "functions": [],
    }

    try:
        with pyghidra.open_program(
            target_path,
            project_location=str(Path(project_dir).resolve()) if project_dir else tempfile.mkdtemp(prefix="beaconflow_ghidra_decompile_"),
            project_name=project_name,
            analyze=True,
        ) as api:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            program = api.currentProgram
            result["program_name"] = program.getName()
            result["language"] = str(program.getLanguageID())
            monitor = ConsoleTaskMonitor()
            decompiler = DecompInterface()
            decompiler.openProgram(program)

            funcs = []
            for func in program.getFunctionManager().getFunctions(True):
                name = str(func.getName())
                entry = str(func.getEntryPoint())
                if function and function not in {name, entry}:
                    continue
                decompiled = decompiler.decompileFunction(func, timeout, monitor)
                if decompiled and decompiled.decompileCompleted():
                    pseudo = str(decompiled.getDecompiledFunction().getC())
                    error = None
                else:
                    pseudo = ""
                    error = str(decompiled.getErrorMessage()) if decompiled else "decompiler returned no result"
                funcs.append({
                    "name": name,
                    "entry": entry,
                    "signature": str(func.getSignature()),
                    "pseudocode": pseudo,
                    "error": error,
                })
                if not function and max_functions > 0 and len(funcs) >= max_functions:
                    break
            result["functions"] = funcs
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    if output:
        Path(output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
