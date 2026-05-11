"""
Update Checker - 非强制的更新提醒。

启动时后台检查 GitHub 仓库是否有新版本，如有则输出友好提醒。
不会阻塞主流程，不会自动更新，只是提示用户手动执行更新命令。

检查逻辑：
1. 读取本地版本号 (beaconflow.__version__)
2. 通过 GitHub API 获取最新 tag 或 commit
3. 比较版本差异，输出更新提示
4. 结果缓存到用户目录，避免频繁请求
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

import beaconflow

log = logging.getLogger("beaconflow.update")

GITHUB_REPO = "mansujiaosheng/BeaconFlow"
GITHUB_API_TAGS = f"https://api.github.com/repos/{GITHUB_REPO}/tags"
GITHUB_API_COMMITS = f"https://api.github.com/repos/{GITHUB_REPO}/commits/main"

# 缓存文件路径和有效期
_CACHE_DIR = Path.home() / ".cache" / "beaconflow"
_CACHE_FILE = _CACHE_DIR / "update_check.json"
_CACHE_TTL = 3600  # 1 小时内不重复检查


def _read_cache() -> dict[str, Any] | None:
    if not _CACHE_FILE.exists():
        return None
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        if time.time() - data.get("checked_at", 0) < _CACHE_TTL:
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _write_cache(data: dict[str, Any]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data["checked_at"] = time.time()
        _CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _fetch_latest_version() -> dict[str, Any] | None:
    """从 GitHub API 获取最新版本信息。优先查 tag，退回查 commit。"""
    headers = {"Accept": "application/vnd.github.v3+json"}

    # 尝试获取最新 tag
    try:
        req = Request(GITHUB_API_TAGS, headers=headers)
        with urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
            if tags:
                latest_tag = tags[0].get("name", "")
                return {
                    "latest": latest_tag,
                    "source": "tag",
                    "url": f"https://github.com/{GITHUB_REPO}/releases/tag/{latest_tag}",
                }
    except (URLError, json.JSONDecodeError, OSError):
        pass

    # 没有 tag 时查最新 commit
    try:
        req = Request(GITHUB_API_COMMITS, headers=headers)
        with urlopen(req, timeout=5) as resp:
            commit = json.loads(resp.read().decode("utf-8"))
            sha = commit.get("sha", "")[:7]
            date = commit.get("commit", {}).get("committer", {}).get("date", "")
            return {
                "latest": f"commit:{sha}",
                "source": "commit",
                "date": date,
                "url": f"https://github.com/{GITHUB_REPO}/commit/{sha}",
            }
    except (URLError, json.JSONDecodeError, OSError):
        pass

    return None


def _parse_version(version_str: str) -> tuple[int, ...]:
    """解析版本字符串为可比较的元组。"""
    version_str = version_str.lstrip("vV")
    parts = []
    for part in version_str.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _is_git_repo() -> bool:
    """检查当前安装是否来自 git clone。"""
    try:
        beaconflow_path = Path(beaconflow.__file__).resolve().parent
        git_dir = beaconflow_path.parent / ".git"
        return git_dir.exists()
    except Exception:
        return False


def _get_update_command() -> str:
    """根据安装方式返回对应的更新命令。"""
    if _is_git_repo():
        return "cd D:\\project\\BeaconFlow && git pull origin main"
    return "pip install --upgrade beaconflow"


def check_for_update(force: bool = False) -> dict[str, Any]:
    """检查是否有新版本可用。

    参数:
        force: 是否强制检查（忽略缓存）

    返回:
        包含更新信息的字典
    """
    current = beaconflow.__version__
    result: dict[str, Any] = {
        "current": current,
        "has_update": False,
        "latest": None,
        "message": None,
    }

    # 先查缓存
    if not force:
        cached = _read_cache()
        if cached:
            result.update({
                "latest": cached.get("latest"),
                "has_update": cached.get("has_update", False),
                "source": cached.get("source"),
                "from_cache": True,
            })
            if cached.get("has_update"):
                result["message"] = _build_message(current, cached.get("latest", ""), cached.get("source", ""))
            return result

    # 网络请求
    remote = _fetch_latest_version()
    if remote is None:
        result["message"] = "无法检查更新（网络不可达或 GitHub API 限流）"
        return result

    latest = remote.get("latest", "")
    source = remote.get("source", "")

    # 版本比较
    has_update = False
    if source == "tag":
        has_update = _parse_version(latest) > _parse_version(current)
    elif source == "commit":
        # commit 模式下总是提示有更新（无法精确比较）
        has_update = True

    result.update({
        "latest": latest,
        "has_update": has_update,
        "source": source,
        "url": remote.get("url"),
        "from_cache": False,
    })

    if has_update:
        result["message"] = _build_message(current, latest, source)

    # 写入缓存
    _write_cache({
        "latest": latest,
        "has_update": has_update,
        "source": source,
        "url": remote.get("url"),
    })

    return result


def _build_message(current: str, latest: str, source: str) -> str:
    """构建用户友好的更新提示消息。"""
    update_cmd = _get_update_command()
    lines = [
        f"BeaconFlow 有新版本可用！当前: {current} → 最新: {latest}",
        "",
        f"  更新命令: {update_cmd}",
        "",
        "此提醒为非强制，你可以继续使用当前版本。",
    ]
    return "\n".join(lines)


def check_and_notify(force: bool = False) -> None:
    """检查更新并输出提醒（同步，用于 MCP 启动时）。"""
    try:
        result = check_for_update(force=force)
        if result.get("has_update") and result.get("message"):
            # 输出到 stderr，不影响 MCP 的 stdio 通信
            print(f"\n{'='*50}", file=sys.stderr)
            print(result["message"], file=sys.stderr)
            print(f"{'='*50}\n", file=sys.stderr)
    except Exception:
        pass


def check_and_notify_async(force: bool = False) -> None:
    """在后台线程中检查更新，不阻塞主流程。"""
    t = threading.Thread(target=check_and_notify, args=(force,), daemon=True)
    t.start()


def update_check_to_markdown(result: dict[str, Any]) -> str:
    """将更新检查结果转为 Markdown 格式。"""
    lines = [
        "# BeaconFlow Update Check",
        "",
        f"- **Current version**: `{result.get('current', 'unknown')}`",
        f"- **Latest version**: `{result.get('latest', 'unknown')}`",
        f"- **Has update**: {'Yes' if result.get('has_update') else 'No'}",
        f"- **Source**: {result.get('source', 'unknown')}",
    ]

    if result.get("url"):
        lines.append(f"- **URL**: {result['url']}")

    if result.get("from_cache"):
        lines.append("- **From cache**: Yes (checked within the last hour)")

    if result.get("has_update"):
        lines.append("")
        lines.append("## Update Command")
        lines.append("")
        lines.append(f"```bash")
        lines.append(_get_update_command())
        lines.append("```")
        lines.append("")
        lines.append("> This is an optional update. You can continue using the current version.")

    if result.get("message") and not result.get("has_update"):
        lines.append("")
        lines.append(f"**Note**: {result['message']}")

    lines.append("")
    return "\n".join(lines)
