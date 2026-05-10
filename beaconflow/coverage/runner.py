from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUNDLED_DYNAMORIO = ROOT / "third_party" / "dynamorio"


def bundled_drrun(arch: str = "x64") -> Path:
    if arch not in {"x86", "x64"}:
        raise ValueError("arch must be x86 or x64")
    subdir = "bin32" if arch == "x86" else "bin64"
    path = BUNDLED_DYNAMORIO / subdir / "drrun.exe"
    if not path.exists():
        raise FileNotFoundError(f"bundled drrun.exe not found: {path}")
    return path


def latest_drcov_log(output_dir: str | Path) -> Path:
    directory = Path(output_dir)
    logs = sorted(directory.glob("drcov.*.log"), key=lambda x: x.stat().st_mtime, reverse=True)
    if not logs:
        raise FileNotFoundError(f"no drcov logs generated in {directory}")
    return logs[0]


def collect_drcov(
    target: str | Path,
    target_args: list[str] | None = None,
    output_dir: str | Path = ".",
    arch: str = "x64",
    drrun_path: str | Path | None = None,
    stdin_text: str | None = None,
    run_cwd: str | Path | None = None,
) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    run_directory = Path(run_cwd).resolve() if run_cwd else output.resolve()

    args = list(target_args or [])
    if args and args[0] == "--":
        args = args[1:]

    drrun = (Path(drrun_path) if drrun_path else bundled_drrun(arch)).resolve()
    target_path = Path(target).resolve()
    command = [str(drrun), "-t", "drcov", "--", str(target_path), *args]
    before = {path.resolve() for path in run_directory.glob("drcov.*.log")}
    completed = subprocess.run(command, cwd=run_directory, input=stdin_text, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "drcov collection failed\n"
            f"command: {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    generated = [path for path in run_directory.glob("drcov.*.log") if path.resolve() not in before]
    log_path = max(generated, key=lambda x: x.stat().st_mtime) if generated else latest_drcov_log(run_directory)
    if output.resolve() == run_directory:
        return log_path
    destination = output / log_path.name
    shutil.copy2(log_path, destination)
    return destination


def dynamorio_available() -> bool:
    return bundled_drrun("x64").exists() or shutil.which("drrun") is not None
