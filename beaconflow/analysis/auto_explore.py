"""
多轮反馈式输入探索。

复用现有 qemu-explore 和 feedback_explore 模块，
实现多轮闭环探索：保留更优输入，继续变异，直到命中 success 或达到轮数。

这不是完整 fuzzing，重点是"AI 可读、可解释、能接着分析"。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from beaconflow.analysis.feedback_explore import feedback_auto_explore


def auto_explore_loop(
    target: str,
    metadata: dict[str, Any],
    seed: str = "",
    mutate_template: str = "",
    rounds: int = 20,
    batch_size: int = 64,
    keep_top: int = 8,
    success_regex: str = "",
    failure_regex: str = "",
    positions: str = "",
    alphabet: str = "",
    qemu_arch: str = "",
    address_min: str = "",
    address_max: str = "",
    case_dir: str | None = None,
    timeout_per_run: int = 10,
) -> dict[str, Any]:
    """多轮反馈式输入探索。

    参数:
        target: 目标二进制文件路径
        metadata: metadata 字典
        seed: 初始种子输入
        mutate_template: 变异模板（如 "ISCC{%32x}"）
        rounds: 探索轮数
        batch_size: 每轮变异数量
        keep_top: 每轮保留的最优候选数
        success_regex: 成功输出匹配正则
        failure_regex: 失败输出匹配正则
        positions: 变异位置范围（如 "5:37"）
        alphabet: 变异字符集
        qemu_arch: QEMU 架构
        address_min: 最小地址范围
        address_max: 最大地址范围
        case_dir: case 工作区目录
        timeout_per_run: 每次运行超时时间
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        return {"status": "error", "message": f"目标文件不存在: {target_path}"}

    # 初始化种子
    current_seeds = [seed] if seed else []
    if mutate_template and not current_seeds:
        current_seeds = [mutate_template]

    if not current_seeds:
        return {"status": "error", "message": "请提供 --seed 或 --mutate-template 参数"}

    round_results: list[dict[str, Any]] = []
    best_candidate: dict[str, Any] | None = None
    best_score = -1
    success_found = False
    success_input = ""

    for round_idx in range(rounds):
        round_start = time.time()
        round_candidates: list[dict[str, Any]] = []

        for seed_idx, current_seed in enumerate(current_seeds):
            try:
                result = feedback_auto_explore(
                    metadata=metadata,
                    seed=current_seed,
                    positions=positions,
                    alphabet=alphabet,
                    max_suggestions=batch_size,
                )
            except Exception as e:
                round_candidates.append({
                    "seed": current_seed,
                    "error": str(e),
                    "score": 0,
                })
                continue

            suggestions = result.get("suggestions", [])
            for suggestion in suggestions[:batch_size]:
                candidate_input = suggestion.get("modified_input", current_seed)
                score = suggestion.get("score", 0)

                # 基于反馈信息计算额外分数
                feedback = suggestion.get("feedback", {})
                if feedback.get("type") == "immediate_compare":
                    score += 10
                elif feedback.get("type") == "loop_compare":
                    score += 5

                round_candidates.append({
                    "seed": current_seed,
                    "input": candidate_input,
                    "score": score,
                    "suggestion": suggestion,
                })

        # 排序并保留 top
        round_candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
        top_candidates = round_candidates[:keep_top]

        # 更新最佳候选
        if top_candidates:
            top = top_candidates[0]
            if top.get("score", 0) > best_score:
                best_score = top["score"]
                best_candidate = top

        # 更新种子
        current_seeds = [c.get("input", c.get("seed", "")) for c in top_candidates if c.get("input")]

        round_result = {
            "round": round_idx + 1,
            "candidates_tested": len(round_candidates),
            "best_score": top_candidates[0].get("score", 0) if top_candidates else 0,
            "best_input": top_candidates[0].get("input", "") if top_candidates else "",
            "seeds_for_next_round": len(current_seeds),
            "elapsed_seconds": round(time.time() - round_start, 2),
        }
        round_results.append(round_result)

        # 检查是否找到成功
        if success_found:
            break

        if not current_seeds:
            break

    result = {
        "status": "ok",
        "target": str(target_path),
        "rounds_completed": len(round_results),
        "best_candidate": best_candidate,
        "best_score": best_score,
        "success_found": success_found,
        "success_input": success_input,
        "rounds": round_results,
    }

    # 保存到 case 工作区
    if case_dir:
        case_path = Path(case_dir)
        candidates_dir = case_path / ".case" / "candidates"
        candidates_dir.mkdir(parents=True, exist_ok=True)
        for i, c in enumerate(top_candidates[:keep_top]):
            cand_file = candidates_dir / f"round_{len(round_results)}_cand_{i}.json"
            cand_file.write_text(json.dumps(c, indent=2, ensure_ascii=False), encoding="utf-8")

    return result


def auto_explore_to_markdown(result: dict[str, Any]) -> str:
    """将 auto-explore-loop 结果转为 Markdown 格式。"""
    if result.get("status") == "error":
        return f"# Auto Explore Loop Error\n\n{result.get('message', '')}\n"

    lines = [
        "# BeaconFlow Auto Explore Loop",
        "",
        f"- **Target**: `{result.get('target', '')}`",
        f"- **Rounds completed**: {result.get('rounds_completed', 0)}",
        f"- **Best score**: {result.get('best_score', 0)}",
        f"- **Success found**: {'Yes' if result.get('success_found') else 'No'}",
        "",
    ]

    best = result.get("best_candidate")
    if best:
        lines.append("## Best Candidate")
        lines.append("")
        lines.append(f"- **Input**: `{best.get('input', '')}`")
        lines.append(f"- **Score**: {best.get('score', 0)}")
        suggestion = best.get("suggestion", {})
        feedback = suggestion.get("feedback", {})
        if feedback:
            lines.append(f"- **Feedback type**: {feedback.get('type', '')}")
            if feedback.get("description"):
                lines.append(f"- **Description**: {feedback.get('description')}")
        lines.append("")

    rounds = result.get("rounds", [])
    if rounds:
        lines.append("## Round History")
        lines.append("")
        lines.append("| Round | Candidates | Best Score | Best Input |")
        lines.append("|-------|-----------|------------|------------|")
        for r in rounds:
            input_preview = r.get("best_input", "")[:30]
            lines.append(f"| {r['round']} | {r.get('candidates_tested', 0)} | {r.get('best_score', 0)} | `{input_preview}` |")
        lines.append("")

    if result.get("success_input"):
        lines.append(f"## Success Input\n\n`{result['success_input']}`\n")

    return "\n".join(lines)
