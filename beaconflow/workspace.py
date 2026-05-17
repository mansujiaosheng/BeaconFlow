"""
Case Workspace - 分析案例工作区管理。

为每个 CTF 题目或分析目标创建稳定工作区，
让 AI Agent 可以多轮分析而不需要每次重新猜路径。

目录结构:
  .case/
    manifest.json   # 工作区清单
    target          # 目标二进制文件（符号链接或拷贝）
    metadata/       # 元数据 JSON 文件
    runs/           # 运行/trace 结果
    reports/        # 分析报告
    notes/          # 用户/AI 笔记
"""

from __future__ import annotations

import json
import shutil
import platform
from datetime import datetime
from pathlib import Path
from typing import Any

CASE_DIR_NAME = ".case"
MANIFEST_FILE = "manifest.json"

DEFAULT_DIRS = [
    "metadata",
    "runs",
    "reports",
    "notes",
]


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _case_dir(root: Path) -> Path:
    return root / CASE_DIR_NAME


def _manifest_path(root: Path) -> Path:
    return _case_dir(root) / MANIFEST_FILE


def _resolve_root(root: str | None = None) -> Path:
    if root:
        return Path(root).resolve()
    return Path.cwd().resolve()


def init_case(
    target: str,
    arch: str = "x64",
    backend: str = "qemu",
    root: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """初始化一个分析案例工作区。

    参数:
        target: 目标二进制文件路径
        arch: 目标架构（如 x64, loongarch64, mips, arm）
        backend: 运行后端（qemu 或 dynamorio）
        root: 工作区根目录，默认为当前目录
        overwrite: 是否覆盖已存在的工作区
    """
    root_path = _resolve_root(root)
    case_path = _case_dir(root_path)
    target_path = Path(target).resolve()

    if not target_path.exists():
        return {
            "status": "error",
            "message": f"目标文件不存在: {target_path}",
        }

    if case_path.exists() and not overwrite:
        existing = load_manifest(root=str(root_path))
        if existing:
            return {
                "status": "already_exists",
                "message": f"工作区已存在: {case_path}",
                "manifest": existing,
            }

    # 创建目录结构
    case_path.mkdir(parents=True, exist_ok=True)
    for subdir in DEFAULT_DIRS:
        (case_path / subdir).mkdir(exist_ok=True)

    # 创建目标文件链接/拷贝
    target_link = case_path / "target"
    if target_link.exists() or target_link.is_symlink():
        target_link.unlink()

    try:
        # Windows 上优先拷贝（符号链接需要管理员权限）
        if platform.system() == "Windows":
            shutil.copy2(str(target_path), str(target_link))
        else:
            target_link.symlink_to(str(target_path))
    except OSError:
        shutil.copy2(str(target_path), str(target_link))

    # 生成 manifest
    manifest: dict[str, Any] = {
        "target": str(target_path),
        "target_name": target_path.name,
        "arch": arch,
        "backend": backend,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "metadata": {},
        "runs": [],
        "reports": [],
        "notes": [],
    }

    manifest_file = _manifest_path(root_path)
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "status": "initialized",
        "case_dir": str(case_path),
        "manifest": manifest,
    }


def load_manifest(root: str | None = None) -> dict[str, Any] | None:
    """加载工作区清单。"""
    root_path = _resolve_root(root)
    manifest_file = _manifest_path(root_path)
    if not manifest_file.exists():
        return None
    try:
        return json.loads(manifest_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_manifest(manifest: dict[str, Any], root: str | None = None) -> None:
    """保存工作区清单。"""
    root_path = _resolve_root(root)
    manifest_file = _manifest_path(root_path)
    manifest["updated_at"] = _now_iso()
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")


def add_metadata(
    name: str,
    path: str,
    description: str = "",
    root: str | None = None,
) -> dict[str, Any]:
    """向工作区添加元数据文件记录。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在，请先运行 init-case"}

    source_path = Path(path).resolve()
    case_path = _case_dir(_resolve_root(root))
    metadata_dir = case_path / "metadata"
    metadata_dir.mkdir(exist_ok=True)

    # 拷贝元数据文件到工作区
    dest_name = f"{name}.json" if not name.endswith(".json") else name
    dest_path = metadata_dir / dest_name
    if source_path.exists() and source_path != dest_path:
        shutil.copy2(str(source_path), str(dest_path))

    rel_path = f"metadata/{dest_name}"
    manifest.setdefault("metadata", {})[name] = {
        "path": rel_path,
        "source": str(source_path),
        "description": description,
        "added_at": _now_iso(),
    }
    save_manifest(manifest, root)

    return {
        "status": "added",
        "name": name,
        "path": rel_path,
    }


def add_run(
    name: str,
    path: str | None = None,
    stdin_preview: str | None = None,
    verdict: str | None = None,
    returncode: int | None = None,
    notes: str = "",
    root: str | None = None,
) -> dict[str, Any]:
    """向工作区添加运行记录。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在，请先运行 init-case"}

    case_path = _case_dir(_resolve_root(root))
    runs_dir = case_path / "runs"
    runs_dir.mkdir(exist_ok=True)

    run_entry: dict[str, Any] = {
        "name": name,
        "added_at": _now_iso(),
        "notes": notes,
    }

    if path:
        source_path = Path(path).resolve()
        dest_name = source_path.name
        dest_path = runs_dir / dest_name
        if source_path.exists() and source_path != dest_path:
            shutil.copy2(str(source_path), str(dest_path))
        run_entry["path"] = f"runs/{dest_name}"

    if stdin_preview is not None:
        run_entry["stdin_preview"] = stdin_preview
    if verdict is not None:
        run_entry["verdict"] = verdict
    if returncode is not None:
        run_entry["returncode"] = returncode

    manifest.setdefault("runs", []).append(run_entry)
    save_manifest(manifest, root)

    return {
        "status": "added",
        "name": name,
        "run_index": len(manifest["runs"]) - 1,
    }


def add_report(
    name: str,
    path: str,
    report_type: str = "",
    description: str = "",
    root: str | None = None,
) -> dict[str, Any]:
    """向工作区添加分析报告记录。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在，请先运行 init-case"}

    case_path = _case_dir(_resolve_root(root))
    reports_dir = case_path / "reports"
    reports_dir.mkdir(exist_ok=True)

    source_path = Path(path).resolve()
    dest_name = source_path.name
    dest_path = reports_dir / dest_name
    if source_path.exists() and source_path != dest_path:
        shutil.copy2(str(source_path), str(dest_path))

    report_entry = {
        "name": name,
        "path": f"reports/{dest_name}",
        "type": report_type,
        "description": description,
        "added_at": _now_iso(),
    }
    manifest.setdefault("reports", []).append(report_entry)
    save_manifest(manifest, root)

    return {
        "status": "added",
        "name": name,
        "report_index": len(manifest["reports"]) - 1,
    }


def add_note(
    content: str,
    title: str = "",
    root: str | None = None,
) -> dict[str, Any]:
    """向工作区添加笔记。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在，请先运行 init-case"}

    note_entry = {
        "title": title,
        "content": content,
        "added_at": _now_iso(),
    }
    manifest.setdefault("notes", []).append(note_entry)
    save_manifest(manifest, root)

    # 同时写入 notes 目录
    case_path = _case_dir(_resolve_root(root))
    notes_dir = case_path / "notes"
    notes_dir.mkdir(exist_ok=True)
    note_index = len(manifest["notes"]) - 1
    note_file = notes_dir / f"note_{note_index:03d}.md"
    note_file.write_text(f"# {title}\n\n{content}\n", encoding="utf-8")

    return {
        "status": "added",
        "note_index": note_index,
    }


def summarize_case(root: str | None = None) -> dict[str, Any]:
    """汇总工作区状态，供 AI Agent 快速了解当前分析进度。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {
            "status": "no_case",
            "message": "工作区不存在，请先运行 init-case",
        }

    root_path = _resolve_root(root)
    case_path = _case_dir(root_path)

    # 检查文件是否实际存在
    target_exists = (case_path / "target").exists()
    metadata_files = list((case_path / "metadata").glob("*.json")) if (case_path / "metadata").exists() else []
    run_files = list((case_path / "runs").iterdir()) if (case_path / "runs").exists() else []
    report_files = list((case_path / "reports").iterdir()) if (case_path / "reports").exists() else []
    note_files = list((case_path / "notes").glob("*.md")) if (case_path / "notes").exists() else []

    metadata_entries = manifest.get("metadata", {})
    runs = manifest.get("runs", [])
    reports = manifest.get("reports", [])
    notes = manifest.get("notes", [])

    # 统计运行结果
    verdict_counts: dict[str, int] = {}
    for run in runs:
        v = run.get("verdict", "unknown")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    # 统计报告类型
    report_type_counts: dict[str, int] = {}
    for report in reports:
        t = report.get("type", "unknown")
        report_type_counts[t] = report_type_counts.get(t, 0) + 1

    summary = {
        "status": "ok",
        "target": manifest.get("target_name", ""),
        "target_path": manifest.get("target", ""),
        "target_exists": target_exists,
        "arch": manifest.get("arch", ""),
        "backend": manifest.get("backend", ""),
        "created_at": manifest.get("created_at", ""),
        "updated_at": manifest.get("updated_at", ""),
        "metadata_count": len(metadata_entries),
        "metadata_files": [f.name for f in metadata_files],
        "runs_count": len(runs),
        "runs_on_disk": len(run_files),
        "verdict_summary": verdict_counts,
        "reports_count": len(reports),
        "reports_on_disk": len(report_files),
        "report_type_summary": report_type_counts,
        "notes_count": len(notes),
        "notes_on_disk": len(note_files),
        "case_dir": str(case_path),
    }

    return summary


def list_runs(root: str | None = None) -> dict[str, Any]:
    """列出工作区中的所有运行记录。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在"}

    runs = manifest.get("runs", [])
    return {
        "status": "ok",
        "total": len(runs),
        "runs": runs,
    }


def list_reports(root: str | None = None) -> dict[str, Any]:
    """列出工作区中的所有报告。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在"}

    reports = manifest.get("reports", [])
    return {
        "status": "ok",
        "total": len(reports),
        "reports": reports,
    }


def list_notes(root: str | None = None) -> dict[str, Any]:
    """列出工作区中的所有笔记。"""
    manifest = load_manifest(root)
    if manifest is None:
        return {"status": "error", "message": "工作区不存在"}

    notes = manifest.get("notes", [])
    return {
        "status": "ok",
        "total": len(notes),
        "notes": notes,
    }


def get_metadata_path(name: str = "default", root: str | None = None) -> str | None:
    """获取工作区中指定元数据文件的完整路径。"""
    manifest = load_manifest(root)
    if manifest is None:
        return None

    meta_info = manifest.get("metadata", {}).get(name)
    if meta_info is None:
        # 尝试按文件名查找
        for key, info in manifest.get("metadata", {}).items():
            if key == name:
                meta_info = info
                break

    if meta_info is None:
        return None

    root_path = _resolve_root(root)
    full_path = _case_dir(root_path) / meta_info["path"]
    if full_path.exists():
        return str(full_path)
    return None


def get_run_path(index: int, root: str | None = None) -> str | None:
    """获取工作区中指定运行文件的完整路径。"""
    manifest = load_manifest(root)
    if manifest is None:
        return None

    runs = manifest.get("runs", [])
    if index < 0 or index >= len(runs):
        return None

    run = runs[index]
    rel_path = run.get("path")
    if not rel_path:
        return None

    root_path = _resolve_root(root)
    full_path = _case_dir(root_path) / rel_path
    if full_path.exists():
        return str(full_path)
    return None


def destroy_case(root: str | None = None) -> dict[str, Any]:
    """删除整个工作区。"""
    root_path = _resolve_root(root)
    case_path = _case_dir(root_path)
    if not case_path.exists():
        return {"status": "not_found", "message": "工作区不存在"}

    shutil.rmtree(str(case_path))
    return {"status": "destroyed", "case_dir": str(case_path)}


def case_to_markdown(summary: dict[str, Any]) -> str:
    """将工作区摘要转为 Markdown 格式。"""
    if summary.get("status") == "no_case":
        return "# Case Workspace\n\nNo case workspace found. Run `beaconflow init-case` first.\n"

    lines = [
        "# BeaconFlow Case Workspace",
        "",
        f"- **Target**: `{summary.get('target', '')}`",
        f"- **Target Path**: `{summary.get('target_path', '')}`",
        f"- **Target Exists**: {'Yes' if summary.get('target_exists') else 'No'}",
        f"- **Arch**: `{summary.get('arch', '')}`",
        f"- **Backend**: `{summary.get('backend', '')}`",
        f"- **Created**: {summary.get('created_at', '')}",
        f"- **Updated**: {summary.get('updated_at', '')}",
        "",
    ]

    # 元数据
    lines.append(f"## Metadata ({summary.get('metadata_count', 0)})")
    lines.append("")
    meta_files = summary.get("metadata_files", [])
    if meta_files:
        for f in meta_files:
            lines.append(f"- `{f}`")
    else:
        lines.append("- No metadata files")
    lines.append("")

    # 运行记录
    runs_count = summary.get("runs_count", 0)
    lines.append(f"## Runs ({runs_count})")
    lines.append("")
    verdict_summary = summary.get("verdict_summary", {})
    if verdict_summary:
        for v, count in verdict_summary.items():
            lines.append(f"- {v}: {count}")
    else:
        lines.append("- No runs recorded")
    lines.append("")

    # 报告
    reports_count = summary.get("reports_count", 0)
    lines.append(f"## Reports ({reports_count})")
    lines.append("")
    report_type_summary = summary.get("report_type_summary", {})
    if report_type_summary:
        for t, count in report_type_summary.items():
            lines.append(f"- {t}: {count}")
    else:
        lines.append("- No reports generated")
    lines.append("")

    # 笔记
    notes_count = summary.get("notes_count", 0)
    lines.append(f"## Notes ({notes_count})")
    lines.append("")
    if notes_count == 0:
        lines.append("- No notes")
    lines.append("")

    lines.append(f"## Case Directory")
    lines.append("")
    lines.append(f"`{summary.get('case_dir', '')}`")
    lines.append("")

    return "\n".join(lines)


_LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10MB，超过此大小视为 AI 不友好


def case_check(root: str | None = None) -> dict[str, Any]:
    """对工作区进行全面质量检查。

    检查内容:
        1. metadata 是否存在
        2. run 信息是否存在
        3. report 是否存在
        4. report 是否包含 ai_digest
        5. report 是否包含 evidence_id
        6. report 是否包含 confidence
        7. artifact path 是否失效
        8. 是否存在过大的 AI 不友好文件
        9. 是否存在 schema 不匹配文件
        10. 是否缺少 next_actions
    """
    manifest = load_manifest(root)
    if manifest is None:
        return {
            "status": "error",
            "message": "工作区不存在，请先运行 init-case",
            "checks": [],
        }

    root_path = _resolve_root(root)
    case_path = _case_dir(root_path)
    checks: list[dict[str, Any]] = []

    # 检查1: metadata 是否存在
    metadata_entries = manifest.get("metadata", {})
    if metadata_entries:
        for name, info in metadata_entries.items():
            rel_path = info.get("path", "")
            full_path = case_path / rel_path
            if full_path.exists():
                checks.append({
                    "check": "metadata_exists",
                    "name": name,
                    "passed": True,
                    "detail": f"metadata '{name}' 存在",
                })
            else:
                checks.append({
                    "check": "metadata_exists",
                    "name": name,
                    "passed": False,
                    "detail": f"metadata '{name}' 路径失效: {rel_path}",
                })
    else:
        checks.append({
            "check": "metadata_exists",
            "name": None,
            "passed": False,
            "detail": "无 metadata 记录",
        })

    # 检查2: run 信息是否存在
    runs = manifest.get("runs", [])
    if runs:
        for i, run in enumerate(runs):
            rel_path = run.get("path")
            if rel_path:
                full_path = case_path / rel_path
                if full_path.exists():
                    checks.append({
                        "check": "run_exists",
                        "name": run.get("name", f"run_{i}"),
                        "passed": True,
                        "detail": f"run '{run.get('name', f'run_{i}')}' 文件存在",
                    })
                else:
                    checks.append({
                        "check": "run_exists",
                        "name": run.get("name", f"run_{i}"),
                        "passed": False,
                        "detail": f"run '{run.get('name', f'run_{i}')}' 路径失效: {rel_path}",
                    })
    else:
        checks.append({
            "check": "run_exists",
            "name": None,
            "passed": False,
            "detail": "无 run 记录",
        })

    # 检查3-6, 9-10: 报告质量检查
    reports = manifest.get("reports", [])
    if reports:
        for i, report in enumerate(reports):
            rel_path = report.get("path", "")
            full_path = case_path / rel_path
            report_name = report.get("name", f"report_{i}")

            # 检查3: report 文件是否存在
            if not full_path.exists():
                checks.append({
                    "check": "report_exists",
                    "name": report_name,
                    "passed": False,
                    "detail": f"报告 '{report_name}' 路径失效: {rel_path}",
                })
                continue

            checks.append({
                "check": "report_exists",
                "name": report_name,
                "passed": True,
                "detail": f"报告 '{report_name}' 文件存在",
            })

            # 读取报告内容进行深度检查
            try:
                report_data = json.loads(full_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                checks.append({
                    "check": "report_readable",
                    "name": report_name,
                    "passed": False,
                    "detail": f"报告 '{report_name}' 无法解析为 JSON",
                })
                continue

            if not isinstance(report_data, dict):
                continue

            # 检查4: report 是否包含 ai_digest
            has_ai_digest = "ai_digest" in report_data or "ai_report" in report_data
            checks.append({
                "check": "ai_digest",
                "name": report_name,
                "passed": has_ai_digest,
                "detail": f"报告 '{report_name}' {'包含' if has_ai_digest else '缺少'} ai_digest 字段",
            })

            # 检查5: report 是否包含 evidence_id（在 top_findings 中）
            top_findings = report_data.get("ai_digest", {}).get("top_findings", [])
            has_evidence_id = any("evidence_id" in f for f in top_findings) if top_findings else False
            checks.append({
                "check": "evidence_id",
                "name": report_name,
                "passed": has_evidence_id or not top_findings,
                "detail": f"报告 '{report_name}' {'包含' if has_evidence_id else '缺少'} evidence_id",
            })

            # 检查6: report 是否包含 confidence
            has_confidence = (
                "report_confidence" in report_data
                or "confidence" in report_data
                or "ai_digest" in report_data and "confidence" in report_data.get("ai_digest", {})
            )
            checks.append({
                "check": "confidence",
                "name": report_name,
                "passed": has_confidence,
                "detail": f"报告 '{report_name}' {'包含' if has_confidence else '缺少'} confidence 字段",
            })

            # 检查10: 是否缺少 next_actions / recommended_actions
            has_next_actions = (
                "recommended_actions" in report_data
                or "next_actions" in report_data
                or "ai_digest" in report_data and "recommended_actions" in report_data.get("ai_digest", {})
            )
            checks.append({
                "check": "next_actions",
                "name": report_name,
                "passed": has_next_actions,
                "detail": f"报告 '{report_name}' {'包含' if has_next_actions else '缺少'} next_actions/recommended_actions",
            })

            # 检查9: schema 验证
            from beaconflow.schemas import validate_all_reports as _validate_all
            schema_result = _validate_all(str(full_path.parent), recursive=False)
            matched = [r for r in schema_result.get("results", []) if r["filename"] == full_path.name and r["valid"] is False]
            if matched:
                checks.append({
                    "check": "schema_match",
                    "name": report_name,
                    "passed": False,
                    "detail": f"报告 '{report_name}' schema 不匹配: {matched[0].get('errors', [])[:3]}",
                })
            else:
                checks.append({
                    "check": "schema_match",
                    "name": report_name,
                    "passed": True,
                    "detail": f"报告 '{report_name}' schema 验证通过或跳过",
                })
    else:
        checks.append({
            "check": "report_exists",
            "name": None,
            "passed": False,
            "detail": "无 report 记录",
        })

    # 检查7: artifact path 是否失效
    target_path = case_path / "target"
    if not target_path.exists():
        checks.append({
            "check": "target_exists",
            "name": None,
            "passed": False,
            "detail": "目标文件(target)不存在或已失效",
        })
    else:
        checks.append({
            "check": "target_exists",
            "name": None,
            "passed": True,
            "detail": "目标文件(target)存在",
        })

    # 检查8: 是否存在过大的 AI 不友好文件
    large_files: list[str] = []
    for subdir in DEFAULT_DIRS:
        sub_path = case_path / subdir
        if sub_path.exists():
            for f in sub_path.rglob("*"):
                if f.is_file() and f.stat().st_size > _LARGE_FILE_THRESHOLD:
                    large_files.append(f"{f.relative_to(case_path)} ({f.stat().st_size // (1024*1024)}MB)")

    if large_files:
        checks.append({
            "check": "large_files",
            "name": None,
            "passed": False,
            "detail": f"发现过大文件(>{_LARGE_FILE_THRESHOLD // (1024*1024)}MB): {', '.join(large_files)}",
        })
    else:
        checks.append({
            "check": "large_files",
            "name": None,
            "passed": True,
            "detail": "未发现过大文件",
        })

    # 汇总
    total_checks = len(checks)
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])

    return {
        "status": "ok" if failed == 0 else "issues_found",
        "case_dir": str(case_path),
        "total_checks": total_checks,
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }
