from __future__ import annotations

import platform
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUNDLED_DYNAMORIO = ROOT / "third_party" / "dynamorio"
BUNDLED_DYNAMORIO_LINUX = ROOT / "third_party" / "dynamorio_linux"


@dataclass(frozen=True)
class DrcovRunResult:
    log_path: Path
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    backend: str

    def to_json(self) -> dict[str, object]:
        return {
            "log_path": str(self.log_path),
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "backend": self.backend,
        }


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _to_wsl_path(path: Path) -> str:
    text = str(path.resolve())
    match = re.match(r"^([A-Za-z]):\\(.*)$", text)
    if not match:
        return text.replace("\\", "/")
    drive = match.group(1).lower()
    rest = match.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def _clean_target_args(args: list[str]) -> list[str]:
    if args and args[0] == "--":
        return args[1:]
    return args


def bundled_drrun(arch: str = "x64", elf: bool = False) -> Path:
    if elf:
        base = BUNDLED_DYNAMORIO_LINUX
        subdir = "bin64" if arch in ("x64", "aarch64") else "bin32"
        name = "drrun"
    else:
        base = BUNDLED_DYNAMORIO
        subdir = "bin64" if arch in ("x64",) else "bin32"
        name = "drrun.exe"
    path = base / subdir / name
    if not path.exists():
        raise FileNotFoundError(f"bundled drrun not found: {path}")
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
    timeout: int | None = 120,
    name: str | None = None,
) -> DrcovRunResult:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    target_path = Path(target).resolve()
    run_directory = Path(run_cwd).resolve() if run_cwd else output.resolve()
    args = _clean_target_args(list(target_args or []))
    is_elf = _is_elf(target_path)

    command, backend = _build_drrun_command(
        target_path=target_path,
        run_cwd=run_directory,
        output_dir=output,
        arch=arch,
        drrun_path=Path(drrun_path) if drrun_path else None,
        is_elf=is_elf,
        target_args=args,
        name=name,
    )

    before = {p.resolve() for p in run_directory.glob("drcov.*.log")}
    try:
        completed = subprocess.run(
            command,
            cwd=run_directory if backend != "wsl" else None,
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        generated = [p for p in run_directory.glob("drcov.*.log") if p.resolve() not in before]
        if generated:
            log_path = max(generated, key=lambda x: x.stat().st_mtime)
            dest = output / log_path.name
            if output.resolve() != run_directory:
                shutil.copy2(log_path, dest)
            else:
                dest = log_path
            return DrcovRunResult(
                log_path=dest,
                command=command,
                returncode=-1,
                stdout="",
                stderr=f"timeout after {timeout}s (log preserved)",
                backend=backend,
            )
        raise RuntimeError(f"drcov collection timed out after {timeout}s, no log generated")

    generated = [p for p in run_directory.glob("drcov.*.log") if p.resolve() not in before]
    if not generated:
        try:
            log_path = latest_drcov_log(run_directory)
        except FileNotFoundError:
            if completed.returncode != 0:
                raise RuntimeError(
                    "drcov collection failed (no log generated)\n"
                    f"command: {' '.join(command)}\n"
                    f"returncode: {completed.returncode}\n"
                    f"stdout:\n{completed.stdout}\n"
                    f"stderr:\n{completed.stderr}"
                )
            raise
    else:
        log_path = max(generated, key=lambda x: x.stat().st_mtime)

    if output.resolve() != run_directory:
        destination = output / log_path.name
        shutil.copy2(log_path, destination)
        log_path = destination

    return DrcovRunResult(
        log_path=log_path,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        backend=backend,
    )


def _build_drrun_command(
    target_path: Path,
    run_cwd: Path,
    output_dir: Path,
    arch: str,
    drrun_path: Path | None,
    is_elf: bool,
    target_args: list[str],
    name: str | None,
) -> tuple[list[str], str]:
    if drrun_path:
        return (
            [str(drrun_path), "-t", "drcov", "--", str(target_path), *target_args],
            "custom",
        )

    if is_elf:
        return _build_elf_command(target_path, run_cwd, output_dir, arch, target_args, name)

    drrun = bundled_drrun(arch, elf=False)
    return (
        [str(drrun), "-t", "drcov", "--", str(target_path), *target_args],
        "windows-native",
    )


def _build_elf_command(
    target_path: Path,
    run_cwd: Path,
    output_dir: Path,
    arch: str,
    target_args: list[str],
    name: str | None,
) -> tuple[list[str], str]:
    # Linux 原生环境
    if platform.system().lower() == "linux":
        drrun = bundled_drrun(arch, elf=True)
        return (
            [str(drrun), "-t", "drcov", "--", str(target_path), *target_args],
            "linux-native",
        )

    # Windows + WSL
    if shutil.which("wsl"):
        drrun = bundled_drrun(arch, elf=True)
        wsl_drrun = _to_wsl_path(drrun)
        wsl_target = _to_wsl_path(target_path)
        wsl_cwd = _to_wsl_path(run_cwd)
        cmd = [
            "wsl",
            "--cd", wsl_cwd,
            "--",
            wsl_drrun,
            "-t", "drcov",
            "--",
            wsl_target,
            *target_args,
        ]
        return cmd, "wsl"

    raise FileNotFoundError(
        "cannot run ELF target: no WSL found on Windows, and not running on Linux. "
        "Install WSL or use a Linux host."
    )


def dynamorio_available(elf: bool = False) -> bool:
    if elf:
        return bundled_drrun("x64", elf=True).exists() or shutil.which("drrun") is not None
    return bundled_drrun("x64", elf=False).exists() or shutil.which("drrun") is not None
