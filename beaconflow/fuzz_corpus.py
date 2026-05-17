"""
Fuzz Corpus 管理 - AFL++/libFuzzer 接入。

BeaconFlow 不自己实现 fuzzer，而是负责：
1. 管理和最小化 fuzz corpus（种子集）
2. 从分析结果中提取有价值的种子
3. 生成 AFL++/libFuzzer harness 模板
4. 导入 fuzz 结果并关联已有分析证据
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:16]


def _bytes_hash(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()[:16]


def corpus_init(
    corpus_dir: str | Path,
    seeds: list[bytes] | None = None,
    seed_files: list[str | Path] | None = None,
) -> dict[str, Any]:
    """初始化 fuzz corpus 目录，支持从种子字节和文件导入。"""
    corpus = Path(corpus_dir)
    corpus.mkdir(parents=True, exist_ok=True)

    added = 0
    skipped = 0

    if seeds:
        for i, seed in enumerate(seeds):
            name = f"seed_{i:04d}_{_bytes_hash(seed)}"
            dest = corpus / name
            if dest.exists():
                skipped += 1
                continue
            dest.write_bytes(seed)
            added += 1

    if seed_files:
        for sf in seed_files:
            src = Path(sf)
            if not src.exists():
                continue
            name = f"{src.stem}_{_file_hash(src)}"
            dest = corpus / name
            if dest.exists():
                skipped += 1
                continue
            shutil.copy2(src, dest)
            added += 1

    existing = list(corpus.iterdir())
    return {
        "status": "ok",
        "corpus_dir": str(corpus),
        "added": added,
        "skipped_duplicates": skipped,
        "total_files": len(existing),
    }


def corpus_minimize(
    corpus_dir: str | Path,
    output_dir: str | Path | None = None,
    target_path: str | Path | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """最小化 corpus，移除不增加覆盖的种子。

    如果提供了 target_path，则通过运行目标来检测覆盖；
    否则使用文件大小和内容去重。
    """
    corpus = Path(corpus_dir)
    if not corpus.exists():
        return {"status": "error", "error": f"corpus dir not found: {corpus}"}

    out = Path(output_dir) if output_dir else corpus / "minimized"
    out.mkdir(parents=True, exist_ok=True)

    files = sorted(f for f in corpus.iterdir() if f.is_file() and f.parent.name != "minimized")
    if not files:
        return {"status": "ok", "corpus_dir": str(corpus), "minimized_dir": str(out), "original_count": 0, "minimized_count": 0}

    if target_path:
        target = Path(target_path)
        if not target.exists():
            return {"status": "error", "error": f"target not found: {target}"}
        return _minimize_by_coverage(files, out, target, timeout)

    return _minimize_by_dedup(files, out)


def _minimize_by_dedup(files: list[Path], out: Path) -> dict[str, Any]:
    seen_hashes: set[str] = set()
    kept: list[str] = []

    for f in files:
        content_hash = _file_hash(f)
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)
        dest = out / f.name
        shutil.copy2(f, dest)
        kept.append(f.name)

    return {
        "status": "ok",
        "method": "content_dedup",
        "original_count": len(files),
        "minimized_count": len(kept),
        "minimized_dir": str(out),
        "removed": len(files) - len(kept),
    }


def _minimize_by_coverage(files: list[Path], out: Path, target: Path, timeout: int) -> dict[str, Any]:
    try:
        from beaconflow.coverage.runner import collect_drcov
    except ImportError:
        return _minimize_by_dedup(files, out)

    seen_blocks: set[int] = set()
    kept: list[str] = []

    for f in files:
        stdin_data = f.read_text(encoding="utf-8", errors="replace")
        try:
            result = collect_drcov(
                target_path=str(target),
                stdin=stdin_data,
                timeout=timeout,
            )
            if "error" in result:
                continue
            cov_path = result.get("log_path", "")
            if not cov_path:
                continue
            from beaconflow.coverage.drcov import load_drcov
            cov = load_drcov(cov_path)
            current_blocks = set()
            for mod in cov.modules:
                for bb in mod.basic_blocks:
                    current_blocks.add((mod.module_id, bb.start, bb.size))
            new_blocks = current_blocks - seen_blocks
            if new_blocks:
                seen_blocks.update(current_blocks)
                dest = out / f.name
                shutil.copy2(f, dest)
                kept.append(f.name)
        except Exception:
            continue

    return {
        "status": "ok",
        "method": "coverage_minimize",
        "original_count": len(files),
        "minimized_count": len(kept),
        "minimized_dir": str(out),
        "total_unique_blocks": len(seen_blocks),
        "removed": len(files) - len(kept),
    }


def corpus_from_reports(
    output_dir: str | Path,
    qemu_explore_result: dict[str, Any] | None = None,
    auto_explore_result: dict[str, Any] | None = None,
    feedback_explore_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """从 BeaconFlow 分析报告中提取有价值的种子到 corpus 目录。"""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    seeds_added = 0

    if qemu_explore_result:
        for run in qemu_explore_result.get("runs", []):
            stdin_preview = run.get("stdin_preview")
            if stdin_preview:
                name = f"qemu_{run.get('name', 'unknown')}_{_bytes_hash(stdin_preview.encode())}"
                (out / name).write_text(stdin_preview, encoding="utf-8")
                seeds_added += 1

    if auto_explore_result:
        for rnd in auto_explore_result.get("rounds", []):
            best_input = rnd.get("best_input")
            if best_input:
                name = f"explore_r{rnd.get('round', 0)}_{_bytes_hash(best_input.encode() if isinstance(best_input, str) else best_input)}"
                data = best_input if isinstance(best_input, bytes) else best_input.encode()
                (out / name).write_bytes(data)
                seeds_added += 1

    if feedback_explore_result:
        plan = feedback_explore_result.get("plan", {})
        for rnd in plan.get("rounds", []):
            for patch in rnd.get("patches", []):
                suggested = patch.get("suggested_value", "")
                if suggested:
                    name = f"feedback_r{rnd.get('round', 0)}_off{patch.get('offset', 0)}"
                    (out / name).write_text(suggested, encoding="utf-8")
                    seeds_added += 1

    return {
        "status": "ok",
        "corpus_dir": str(out),
        "seeds_extracted": seeds_added,
    }


def generate_afl_harness(
    target_path: str | Path,
    output_path: str | Path,
    harness_type: str = "stdin",
    source_type: str = "c",
) -> dict[str, Any]:
    """生成 AFL++/libFuzzer harness 模板。"""
    target = Path(target_path)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if source_type == "c":
        if harness_type == "stdin":
            code = _afl_stdin_harness_c(target.name)
        elif harness_type == "argv":
            code = _afl_argv_harness_c(target.name)
        else:
            code = _libfuzzer_harness_c(target.name)
    else:
        code = _libfuzzer_harness_c(target.name)

    out.write_text(code, encoding="utf-8")

    return {
        "status": "ok",
        "harness_path": str(out),
        "harness_type": harness_type,
        "source_type": source_type,
        "compile_hint": _compile_hint(harness_type, out.name),
    }


def _afl_stdin_harness_c(target_name: str) -> str:
    return f"""\
// AFL++ stdin harness for {target_name}
// 编译: afl-clang-fast -o harness harness.c
// 运行: afl-fuzz -i corpus/ -o findings/ -- ./harness
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {{
    // AFL++ 通过 stdin 传递变异输入
    char buf[4096];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = 0;

    // TODO: 将 buf 传入目标程序的检查函数
    // 例如: check_flag(buf, n);

    return 0;
}}
"""


def _afl_argv_harness_c(target_name: str) -> str:
    return f"""\
// AFL++ argv harness for {target_name}
// 编译: afl-clang-fast -o harness harness.c
// 运行: afl-fuzz -i corpus/ -o findings/ -- ./hield @@
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {{
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    // TODO: 将 buf 传入目标程序的检查函数
    // 例如: check_flag(buf, n);

    return 0;
}}
"""


def _libfuzzer_harness_c(target_name: str) -> str:
    return f"""\
// libFuzzer harness for {target_name}
// 编译: clang -fsanitize=fuzzer -o harness harness.c
// 运行: ./hield corpus/
#include <stdint.h>
#include <stddef.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // TODO: 将 data/size 传入目标程序的检查函数
    // 例如: check_flag((const char *)data, size);

    // 示例: 最小长度检查
    if (size < 4) return 0;

    return 0;
}}
"""


def _compile_hint(harness_type: str, filename: str) -> str:
    if harness_type == "libfuzzer":
        base = filename.replace(".c", "")
        return f"clang -fsanitize=fuzzer -o {base} {filename}"
    base = filename.replace(".c", "")
    return f"afl-clang-fast -o {base} {filename}"


def import_fuzz_results(
    findings_dir: str | Path,
    metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """导入 AFL++/libFuzzer 的 fuzz 结果，关联到 BeaconFlow 分析。"""
    findings = Path(findings_dir)
    if not findings.exists():
        return {"status": "error", "error": f"findings dir not found: {findings}"}

    crashes: list[dict[str, Any]] = []
    hangs: list[dict[str, Any]] = []
    new_coverage: list[dict[str, Any]] = []

    for subdir_name in ["crashes", "hangs", "queue"]:
        subdir = findings / subdir_name
        if not subdir.exists():
            continue
        for f in sorted(subdir.iterdir()):
            if not f.is_file():
                continue
            if f.name.startswith("README"):
                continue
            entry = {
                "name": f.name,
                "path": str(f),
                "size": f.stat().st_size,
            }
            try:
                content = f.read_bytes()
                entry["preview"] = content[:64].hex()
                entry["hash"] = _bytes_hash(content)
            except Exception:
                pass

            if subdir_name == "crashes":
                crashes.append(entry)
            elif subdir_name == "hangs":
                hangs.append(entry)
            else:
                new_coverage.append(entry)

    result = {
        "status": "ok",
        "findings_dir": str(findings),
        "crashes": len(crashes),
        "hangs": len(hangs),
        "queue_entries": len(new_coverage),
        "crash_details": crashes[:20],
        "hang_details": hangs[:10],
    }

    return result
