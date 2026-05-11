from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class QemuRunResult:
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


def collect_qemu_trace(
    target: str | Path,
    output_dir: str | Path = ".",
    qemu_arch: str = "loongarch64",
    target_args: list[str] | None = None,
    stdin_text: str | None = None,
    run_cwd: str | Path | None = None,
    trace_mode: str = "in_asm",
    qemu_path: str | Path | None = None,
    timeout: int | None = 120,
    name: str | None = None,
) -> QemuRunResult:
    """Run a target under QEMU user-mode tracing."""

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    target_path = Path(target).resolve()
    run_directory = Path(run_cwd).resolve() if run_cwd else target_path.parent
    log_path = output / f"{name or target_path.name}.{trace_mode.replace(',', '_')}.qemu.log"
    args = _clean_target_args(target_args or [])
    command, backend = _build_qemu_command(
        target_path=target_path,
        run_cwd=run_directory,
        log_path=log_path.resolve(),
        qemu_arch=qemu_arch,
        qemu_path=Path(qemu_path) if qemu_path else None,
        trace_mode=trace_mode,
        target_args=args,
    )
    completed = subprocess.run(
        command,
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if not log_path.exists():
        raise FileNotFoundError(f"QEMU did not create trace log: {log_path}")
    return QemuRunResult(
        log_path=log_path,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        backend=backend,
    )


def qemu_available(qemu_arch: str) -> dict[str, str | None]:
    executable = f"qemu-{qemu_arch}"
    native = shutil.which(executable)
    wsl = None
    if shutil.which("wsl"):
        try:
            result = subprocess.run(
                ["wsl", "which", executable],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if result.returncode == 0:
                wsl = result.stdout.strip().splitlines()[0]
        except (subprocess.SubprocessError, OSError):
            wsl = None
    return {"native": native, "wsl": wsl}


def _build_qemu_command(
    target_path: Path,
    run_cwd: Path,
    log_path: Path,
    qemu_arch: str,
    qemu_path: Path | None,
    trace_mode: str,
    target_args: list[str],
) -> tuple[list[str], str]:
    qemu_name = f"qemu-{qemu_arch}"
    if qemu_path:
        return (
            [
                str(qemu_path),
                "-D",
                str(log_path),
                "-d",
                trace_mode,
                str(target_path),
                *target_args,
            ],
            "custom",
        )

    native = shutil.which(qemu_name)
    if native and platform.system().lower() != "windows":
        return (
            [native, "-D", str(log_path), "-d", trace_mode, str(target_path), *target_args],
            "native",
        )

    if shutil.which("wsl"):
        available = qemu_available(qemu_arch)["wsl"]
        if available:
            return (
                [
                    "wsl",
                    "--cd",
                    _to_wsl_path(run_cwd),
                    "--",
                    qemu_name,
                    "-D",
                    _to_wsl_path(log_path),
                    "-d",
                    trace_mode,
                    _to_wsl_path(target_path),
                    *target_args,
                ],
                "wsl",
            )

    raise FileNotFoundError(f"could not find {qemu_name} natively or in WSL")


def _clean_target_args(args: list[str]) -> list[str]:
    if args and args[0] == "--":
        return args[1:]
    return args


def _to_wsl_path(path: Path) -> str:
    text = str(path.resolve())
    match = re.match(r"^([A-Za-z]):\\(.*)$", text)
    if not match:
        return text.replace("\\", "/")
    drive = match.group(1).lower()
    rest = match.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{rest}"
