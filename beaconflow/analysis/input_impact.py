"""
黑盒差分输入影响分析。

对指定输入的每个位置做扰动，观察哪些分支、块、边发生变化，
从而推断"哪个输入字节影响哪个分支"。

这是黑盒差分方法，不是完整 taint，但实现简单、不依赖插桩。
"""

from __future__ import annotations

import json
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


def _run_target(
    target: str,
    stdin_data: str,
    timeout: int = 10,
    run_cwd: str | None = None,
) -> dict[str, Any]:
    """运行目标程序并收集输出指纹。"""
    try:
        proc = subprocess.run(
            [target],
            input=stdin_data.encode() if stdin_data else b"",
            capture_output=True,
            timeout=timeout,
            cwd=run_cwd,
        )
        return {
            "returncode": proc.returncode,
            "stdout_hash": hash(proc.stdout) if proc.stdout else 0,
            "stderr_hash": hash(proc.stderr) if proc.stderr else 0,
            "stdout_preview": proc.stdout.decode(errors="replace")[:128] if proc.stdout else "",
            "stderr_preview": proc.stderr.decode(errors="replace")[:128] if proc.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout_hash": 0, "stderr_hash": 0, "timeout": True}
    except Exception as e:
        return {"returncode": -2, "error": str(e)}


def input_impact(
    target: str,
    seed: str,
    positions: str = "",
    alphabet: str = "0123456789abcdef",
    max_mutations_per_pos: int = 8,
    timeout: int = 10,
    run_cwd: str | None = None,
    metadata: dict[str, Any] | None = None,
    address_min: str = "",
    address_max: str = "",
) -> dict[str, Any]:
    """黑盒差分输入影响分析。

    参数:
        target: 目标二进制文件路径
        seed: 种子输入
        positions: 变异位置范围（如 "5:37" 表示位置 5 到 37）
        alphabet: 变异字符集
        max_mutations_per_pos: 每个位置最大变异数
        timeout: 每次运行超时时间
        run_cwd: 运行工作目录
        metadata: metadata 字典（可选，用于地址过滤）
        address_min: 最小地址
        address_max: 最大地址
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        return {"status": "error", "message": f"目标文件不存在: {target_path}"}

    # 解析位置范围
    if positions:
        parts = positions.split(":")
        if len(parts) == 2:
            pos_start = int(parts[0])
            pos_end = int(parts[1])
        else:
            pos_start = 0
            pos_end = int(parts[0])
    else:
        pos_start = 0
        pos_end = len(seed)

    pos_end = min(pos_end, len(seed))

    # 运行 baseline
    baseline = _run_target(str(target_path), seed, timeout, run_cwd)

    position_reports: list[dict[str, Any]] = []

    for pos in range(pos_start, pos_end):
        original_char = seed[pos] if pos < len(seed) else ""

        # 生成变异
        mutations_tested = 0
        changed_outputs: list[dict[str, Any]] = []

        for mut_char in alphabet[:max_mutations_per_pos]:
            if mut_char == original_char:
                continue

            mutated = seed[:pos] + mut_char + seed[pos + 1:]
            result = _run_target(str(target_path), mutated, timeout, run_cwd)

            mutations_tested += 1

            # 检查输出是否变化
            if result.get("returncode") != baseline.get("returncode"):
                changed_outputs.append({
                    "char": mut_char,
                    "returncode": result.get("returncode"),
                    "baseline_returncode": baseline.get("returncode"),
                    "stdout_preview": result.get("stdout_preview", ""),
                })
            elif result.get("stdout_hash") != baseline.get("stdout_hash"):
                changed_outputs.append({
                    "char": mut_char,
                    "stdout_changed": True,
                    "stdout_preview": result.get("stdout_preview", ""),
                })

        if changed_outputs:
            chars_causing_change = list(dict.fromkeys(c["char"] for c in changed_outputs))
            position_reports.append({
                "position": pos,
                "original_char": original_char,
                "mutations_tested": mutations_tested,
                "changes_detected": len(changed_outputs),
                "chars_causing_change": chars_causing_change,
                "change_details": changed_outputs[:5],
            })

    # 汇总
    total_positions = pos_end - pos_start
    affected_positions = len(position_reports)

    return {
        "status": "ok",
        "target": str(target_path),
        "seed": seed[:64],
        "seed_length": len(seed),
        "positions_scanned": f"{pos_start}:{pos_end}",
        "total_positions": total_positions,
        "affected_positions": affected_positions,
        "baseline": {
            "returncode": baseline.get("returncode"),
            "stdout_preview": baseline.get("stdout_preview", "")[:64],
        },
        "position_reports": position_reports,
    }


def input_impact_to_markdown(result: dict[str, Any]) -> str:
    """将 input-impact 结果转为 Markdown 格式。"""
    if result.get("status") == "error":
        return f"# Input Impact Error\n\n{result.get('message', '')}\n"

    lines = [
        "# BeaconFlow Input Impact Report",
        "",
        f"- **Target**: `{result.get('target', '')}`",
        f"- **Seed**: `{result.get('seed', '')}`",
        f"- **Positions scanned**: {result.get('positions_scanned', '')}",
        f"- **Affected positions**: {result.get('affected_positions', 0)} / {result.get('total_positions', 0)}",
        "",
    ]

    baseline = result.get("baseline", {})
    lines.append("## Baseline")
    lines.append("")
    lines.append(f"- Return code: {baseline.get('returncode', '?')}")
    lines.append(f"- Output: `{baseline.get('stdout_preview', '')}`")
    lines.append("")

    reports = result.get("position_reports", [])
    if reports:
        lines.append("## Affected Positions")
        lines.append("")
        for report in reports:
            pos = report["position"]
            orig = report["original_char"]
            chars = report.get("chars_causing_change", [])
            changes = report.get("changes_detected", 0)

            lines.append(f"### Position {pos} (original: `{orig}`)")
            lines.append("")
            lines.append(f"- Mutations tested: {report.get('mutations_tested', 0)}")
            lines.append(f"- Changes detected: {changes}")
            if chars:
                lines.append(f"- Characters causing change: `{', '.join(chars[:10])}`")

            # AI hint
            if changes > 0:
                lines.append("")
                lines.append(f"> **AI hint**: position {pos} likely participates in a branch condition. Changing it affects the program output.")

            lines.append("")
    else:
        lines.append("No affected positions found. The input may not reach any branch conditions, or the seed is already correct.")
        lines.append("")

    return "\n".join(lines)
