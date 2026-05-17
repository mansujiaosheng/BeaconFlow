"""
HTML 报告生成器 - 将 Markdown 报告转换为带样式的 HTML 页面。
"""
from __future__ import annotations

import html as html_lib
import re
from typing import Any


_CSS = """
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --orange: #db6d28;
  --purple: #bc8cff;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--text);
  line-height: 1.6; padding: 24px; max-width: 1200px; margin: 0 auto;
}
h1 { font-size: 1.8em; margin: 0 0 16px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 8px; }
h2 { font-size: 1.4em; margin: 24px 0 12px; color: var(--accent); }
h3 { font-size: 1.15em; margin: 16px 0 8px; color: var(--text); }
p { margin: 8px 0; }
code { background: var(--surface); padding: 2px 6px; border-radius: 4px; font-size: 0.9em; color: var(--purple); }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; margin: 8px 0; }
pre code { background: none; padding: 0; color: var(--text); }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th, td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; }
th { background: var(--surface); color: var(--accent); font-weight: 600; }
tr:nth-child(even) { background: rgba(22,27,34,0.5); }
tr:hover { background: rgba(88,166,255,0.08); }
ul, ol { margin: 8px 0 8px 24px; }
li { margin: 4px 0; }
blockquote { border-left: 3px solid var(--accent); padding: 8px 16px; margin: 8px 0; background: var(--surface); border-radius: 0 6px 6px 0; color: var(--text-muted); }
hr { border: none; border-top: 1px solid var(--border); margin: 24px 0; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
.badge-high { background: rgba(63,185,80,0.2); color: var(--green); }
.badge-medium { background: rgba(210,153,34,0.2); color: var(--yellow); }
.badge-low { background: rgba(248,81,73,0.2); color: var(--red); }
.badge-critical { background: rgba(248,81,73,0.3); color: var(--red); }
.badge-ok { background: rgba(63,185,80,0.2); color: var(--green); }
.badge-error { background: rgba(248,81,73,0.2); color: var(--red); }
.badge-partial { background: rgba(210,153,34,0.2); color: var(--yellow); }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 16px 0; }
.summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.summary-card .label { color: var(--text-muted); font-size: 0.85em; }
.summary-card .value { font-size: 1.5em; font-weight: 700; color: var(--accent); }
.footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.85em; }
</style>
"""


def _md_to_html(md_text: str) -> str:
    """将简单 Markdown 文本转换为 HTML（不依赖外部库）。"""
    lines = md_text.split("\n")
    out: list[str] = []
    in_table = False
    in_code = False
    in_list = False

    for line in lines:
        # 代码块
        if line.strip().startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                lang = line.strip()[3:].strip()
                cls = f' class="language-{html_lib.escape(lang)}"' if lang else ""
                out.append(f"<pre><code{cls}>")
                in_code = True
            continue

        if in_code:
            out.append(html_lib.escape(line))
            continue

        # 表格
        stripped = line.strip()
        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            # 分隔行跳过
            if all(set(c) <= {"-", ":", " "} for c in cells):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
                # 第一行是表头
                header = "".join(f"<th>{_inline_md(c)}</th>" for c in cells)
                out.append(f"<tr>{header}</tr>")
            else:
                row = "".join(f"<td>{_inline_md(c)}</td>" for c in cells)
                out.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            out.append("</table>")
            in_table = False

        # 标题
        if stripped.startswith("# "):
            out.append(f"<h1>{_inline_md(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            out.append(f"<h2>{_inline_md(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            out.append(f"<h3>{_inline_md(stripped[4:])}</h3>")
        elif stripped.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline_md(stripped[2:])}</li>")
        elif re.match(r"^\d+\.\s", stripped):
            if not in_list:
                out.append("<ol>")
                in_list = True
            content = re.sub(r"^\d+\.\s", "", stripped)
            out.append(f"<li>{_inline_md(content)}</li>")
        elif stripped == "---" or stripped == "***":
            out.append("<hr>")
        elif stripped == "":
            if in_list:
                out.append("</ul>" if stripped.startswith("-") else "</ol>")
                in_list = False
            out.append("")
        elif stripped.startswith("> "):
            out.append(f"<blockquote>{_inline_md(stripped[2:])}</blockquote>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{_inline_md(stripped)}</p>")

    if in_table:
        out.append("</table>")
    if in_code:
        out.append("</code></pre>")
    if in_list:
        out.append("</ul>")

    return "\n".join(out)


def _inline_md(text: str) -> str:
    """处理行内 Markdown：加粗、代码、链接。"""
    text = html_lib.escape(text)
    # **bold**
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # `code`
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    # [link](url)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2">\1</a>', text)
    return text


def markdown_to_html(
    md_text: str,
    title: str = "BeaconFlow Report",
) -> str:
    """将 Markdown 报告转换为带样式的 HTML 页面。"""
    body = _md_to_html(md_text)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_lib.escape(title)}</title>
{_CSS}
</head>
<body>
{body}
<div class="footer">
  Generated by <strong>BeaconFlow</strong> &mdash; AI-oriented binary analysis evidence summarizer
</div>
</body>
</html>"""


def json_to_html(
    data: dict[str, Any],
    title: str = "BeaconFlow Report",
) -> str:
    """将 JSON 报告转换为带样式的 HTML 页面。"""
    sections: list[str] = []

    # 状态徽章
    status = data.get("status", "unknown")
    badge_cls = {"ok": "badge-ok", "error": "badge-error", "partial": "badge-partial"}.get(status, "badge-partial")
    sections.append(f'<h1>{html_lib.escape(title)} <span class="badge {badge_cls}">{status.upper()}</span></h1>')

    # 摘要卡片
    cards: list[str] = []
    for key, value in data.items():
        if key in ("status", "errors", "next_steps", "ai_digest", "ai_report"):
            continue
        if isinstance(value, (int, float, str)):
            cards.append(f'<div class="summary-card"><div class="label">{html_lib.escape(key)}</div><div class="value">{html_lib.escape(str(value))}</div></div>')
    if cards:
        sections.append(f'<div class="summary-grid">{"".join(cards)}</div>')

    # AI Digest
    ai_digest = data.get("ai_digest") or data.get("ai_report")
    if ai_digest and isinstance(ai_digest, dict):
        sections.append("<h2>AI Digest</h2>")
        if ai_digest.get("summary"):
            sections.append(f"<p>{html_lib.escape(str(ai_digest['summary']))}</p>")
        if ai_digest.get("top_findings"):
            sections.append("<h3>Top Findings</h3><ul>")
            for f in ai_digest["top_findings"][:10]:
                sections.append(f"<li>{html_lib.escape(str(f))}</li>")
            sections.append("</ul>")
        if ai_digest.get("recommended_actions"):
            sections.append("<h3>Recommended Actions</h3><ul>")
            for a in ai_digest["recommended_actions"][:10]:
                sections.append(f"<li>{html_lib.escape(str(a))}</li>")
            sections.append("</ul>")

    # 错误
    errors = data.get("errors", [])
    if errors:
        sections.append("<h2>Errors</h2><ul>")
        for e in errors:
            sections.append(f'<li style="color:var(--red)">{html_lib.escape(str(e))}</li>')
        sections.append("</ul>")

    # 下一步
    next_steps = data.get("next_steps", [])
    if next_steps:
        sections.append("<h2>Next Steps</h2><ol>")
        for s in next_steps:
            sections.append(f"<li>{html_lib.escape(str(s))}</li>")
        sections.append("</ol>")

    # 原始 JSON（折叠）
    import json
    json_str = html_lib.escape(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    sections.append(f"""<h2>Raw JSON</h2>
<details><summary>Click to expand</summary>
<pre><code>{json_str}</code></pre>
</details>""")

    body = "\n".join(sections)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_lib.escape(title)}</title>
{_CSS}
</head>
<body>
{body}
<div class="footer">
  Generated by <strong>BeaconFlow</strong> &mdash; AI-oriented binary analysis evidence summarizer
</div>
</body>
</html>"""
