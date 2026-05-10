from __future__ import annotations

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
    for candidate in Path("C:/").glob("ghidra_*"):
        if (candidate / "support").exists():
            return candidate
    for candidate in Path.home().glob("ghidra_*"):
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
) -> dict[str, object]:
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
