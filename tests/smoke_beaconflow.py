from __future__ import annotations

import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from beaconflow.analysis import analyze_coverage, analyze_flow
from beaconflow.coverage import load_drcov
from beaconflow.coverage.runner import collect_drcov
from beaconflow.models import BasicBlock, Function, ProgramMetadata


FIXTURES = ROOT / "tests" / "fixtures"


def _run(command: list[str], cwd: Path = ROOT) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=cwd, check=True)


def _read_pe_image_base(path: Path) -> int:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x20B:
        return struct.unpack_from("<Q", data, optional_offset + 24)[0]
    if magic == 0x10B:
        return struct.unpack_from("<I", data, optional_offset + 28)[0]
    raise ValueError(f"unsupported PE optional header magic: 0x{magic:x}")


def _find_module_span(coverage_path: Path, module_name: str) -> tuple[int, int]:
    coverage = load_drcov(coverage_path)
    module_ids = {module_id for module_id, module in coverage.modules.items() if module.name == module_name.lower()}
    offsets = [
        (block.offset, block.offset + block.size)
        for block in coverage.blocks
        if block.module_id in module_ids
    ]
    if not offsets:
        raise AssertionError(f"coverage did not include target module {module_name}")
    return min(start for start, _ in offsets), max(end for _, end in offsets)


def _build_observed_metadata(exe: Path, coverage_path: Path, image_base: int) -> ProgramMetadata:
    coverage = load_drcov(coverage_path)
    module_ids = {module_id for module_id, module in coverage.modules.items() if module.name == exe.name.lower()}
    unique_blocks: dict[int, int] = {}
    ordered_offsets: list[int] = []

    for block in coverage.blocks:
        if block.module_id not in module_ids:
            continue
        unique_blocks.setdefault(block.offset, block.size)
        ordered_offsets.append(block.offset)

    if not unique_blocks:
        raise AssertionError("target module has no observed blocks")

    succs: dict[int, set[int]] = {offset: set() for offset in unique_blocks}
    previous: int | None = None
    for offset in ordered_offsets:
        if previous is not None and previous != offset:
            succs[previous].add(offset)
        previous = offset

    blocks = tuple(
        BasicBlock(
            start=image_base + offset,
            end=image_base + offset + size,
            succs=tuple(image_base + succ for succ in sorted(succs[offset])),
        )
        for offset, size in sorted(unique_blocks.items())
    )
    return ProgramMetadata(
        input_path=str(exe),
        image_base=image_base,
        functions=(
            Function(
                name="observed_flow",
                start=min(block.start for block in blocks),
                end=max(block.end for block in blocks),
                blocks=blocks,
            ),
        ),
    )


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)

    compiler = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("missing MinGW compiler")

    exe = FIXTURES / "simple_pe.exe"
    _run([compiler, "-O0", "-g0", "-o", str(exe), str(FIXTURES / "simple_pe.c")])

    run_dir = FIXTURES / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    for old_log in run_dir.glob("drcov.*.log"):
        old_log.unlink()

    coverage_path = collect_drcov(exe, ["alpha"], output_dir=run_dir)
    copied_generated = FIXTURES / "simple_pe.drcov.log"
    shutil.copy2(coverage_path, copied_generated)

    image_base = _read_pe_image_base(exe)
    start_offset, end_offset = _find_module_span(copied_generated, exe.name)
    metadata = ProgramMetadata(
        input_path=str(exe),
        image_base=image_base,
        functions=(
            Function(
                name="covered_region",
                start=image_base + start_offset,
                end=image_base + end_offset,
                blocks=(
                    BasicBlock(
                        start=image_base + start_offset,
                        end=image_base + end_offset,
                        succs=(),
                    ),
                ),
            ),
        ),
    )

    metadata_path = FIXTURES / "simple_pe.metadata.json"
    metadata_path.write_text(json.dumps(metadata.to_json(), indent=2), encoding="utf-8")

    result = analyze_coverage(metadata, load_drcov(copied_generated))
    print(json.dumps(result["summary"], indent=2))
    assert result["summary"]["covered_functions"] == 1
    assert result["summary"]["covered_basic_blocks"] == 1

    flow_metadata = _build_observed_metadata(exe, copied_generated, image_base)
    flow_metadata_path = FIXTURES / "simple_pe.flow.metadata.json"
    flow_metadata_path.write_text(json.dumps(flow_metadata.to_json(), indent=2), encoding="utf-8")
    flow_result = analyze_flow(flow_metadata, load_drcov(copied_generated), max_events=20)
    print(json.dumps(flow_result["summary"], indent=2))
    assert flow_result["summary"]["raw_target_events"] > 1
    assert flow_result["summary"]["unique_blocks"] > 1
    assert flow_result["summary"]["unique_transitions"] > 0
    print(f"generated PE: {exe}")
    print(f"generated drcov: {copied_generated}")
    print(f"generated metadata: {metadata_path}")
    print(f"generated flow metadata: {flow_metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
