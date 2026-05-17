from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


PT_LOAD = 1
PF_X = 1


def detect_executable_address_range(path: str | Path) -> dict[str, Any] | None:
    """Detect the target executable code range from an ELF file.

    QEMU user-mode logs virtual addresses. For static ELF CTF binaries, filtering
    to executable LOAD segments removes most runtime/library noise before
    BeaconFlow clusters address logs into fallback metadata.
    """
    target = Path(path)
    try:
        data = target.read_bytes()
    except OSError as exc:
        return _failure(path, f"read failed: {exc}")

    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return _failure(path, "not an ELF file")

    elf_class = data[4]
    endian_id = data[5]
    if elf_class not in (1, 2):
        return _failure(path, f"unsupported ELF class: {elf_class}")
    if endian_id not in (1, 2):
        return _failure(path, f"unsupported ELF endian: {endian_id}")
    endian = "<" if endian_id == 1 else ">"

    try:
        if elf_class == 1:
            header = struct.unpack_from(endian + "16sHHIIIIIHHHHHH", data, 0)
            e_phoff = header[5]
            e_phentsize = header[9]
            e_phnum = header[10]
            ph_fmt = endian + "IIIIIIII"
            ph_size = struct.calcsize(ph_fmt)
        else:
            header = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
            e_phoff = header[5]
            e_phentsize = header[9]
            e_phnum = header[10]
            ph_fmt = endian + "IIQQQQQQ"
            ph_size = struct.calcsize(ph_fmt)
    except struct.error as exc:
        return _failure(path, f"truncated ELF header: {exc}")

    if e_phoff <= 0 or e_phentsize <= 0 or e_phnum <= 0:
        return _failure(path, "ELF has no program headers")
    if e_phentsize < ph_size:
        return _failure(path, f"unsupported program header size: {e_phentsize}")

    segments: list[dict[str, int]] = []
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + ph_size > len(data):
            return _failure(path, "truncated program header table")
        fields = struct.unpack_from(ph_fmt, data, offset)
        if elf_class == 1:
            p_type, _p_offset, p_vaddr, _p_paddr, _p_filesz, p_memsz, p_flags, _p_align = fields
        else:
            p_type, p_flags, _p_offset, p_vaddr, _p_paddr, _p_filesz, p_memsz, _p_align = fields
        if p_type == PT_LOAD and (p_flags & PF_X) and p_memsz:
            segments.append(
                {
                    "index": index,
                    "start": int(p_vaddr),
                    "end": int(p_vaddr + p_memsz),
                    "memsz": int(p_memsz),
                    "flags": int(p_flags),
                }
            )

    if not segments:
        return _failure(path, "ELF has no executable LOAD segments")

    address_min = min(segment["start"] for segment in segments)
    address_max = max(segment["end"] for segment in segments)
    return {
        "status": "ok",
        "source": "elf-executable-load",
        "path": str(target),
        "format": "ELF32" if elf_class == 1 else "ELF64",
        "endianness": "little" if endian_id == 1 else "big",
        "address_min": hex(address_min),
        "address_max": hex(address_max),
        "segments": [
            {
                "index": segment["index"],
                "start": hex(segment["start"]),
                "end": hex(segment["end"]),
                "memsz": segment["memsz"],
                "flags": segment["flags"],
            }
            for segment in segments
        ],
    }


def _failure(path: str | Path, reason: str) -> dict[str, Any]:
    return {
        "status": "unsupported",
        "source": "elf-executable-load",
        "path": str(path),
        "reason": reason,
    }
