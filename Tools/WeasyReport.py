"""使用 Markdown → HTML/CSS → WeasyPrint 生成专业 A4 中文报告。

Summary Agent 只负责报告内容；本模块确定性负责封面、目录、分页、页眉页脚、
字体、表格、代码块、图片安全加载和 Mermaid 静态渲染。
"""
from __future__ import annotations

import html
import ipaddress
import logging
import mimetypes
import os
import re
import socket
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, select_autoescape
from markdown_it import MarkdownIt


logger = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"
_WORKDIR = _PROJECT_ROOT / "WorkDir"
_MERMAID_RENDERER = (
    _PROJECT_ROOT / "Skills" / "beautiful-mermaid" / "scripts" / "render.js"
)
_DEFAULT_REPORT_LOGO_URL = (
    "https://lingshuzhidun.oss-rg-china-mainland.aliyuncs.com/"
    "lingshu-logo-black.png?Expires=1787324974&"
    "OSSAccessKeyId=TMP.3Ky2ZiUuPiBWLM2SyujdSNFXmtfK1YuiVmHo4PXtNUQ6DXBVJWh3nzcUktTGY2Dz76eT9XqtTkCuww3rkDUuJ5SUd3WS36&"
    "Signature=p%2BtwaM%2BHrIXAQJzYBq7dqCLZY58%3D"
)
_REPORT_LOGO_URL = (
    os.getenv("LINGSHU_REPORT_LOGO_URL", "").strip()
    or _DEFAULT_REPORT_LOGO_URL
)
_PAGE_BREAK_MARKER = "LINGSHU_INTERNAL_PAGE_BREAK_8F4D1C"
_MERMAID_MARKER_PREFIX = "LINGSHU_INTERNAL_MERMAID_"
_DANGEROUS_HTML_BLOCK_RE = re.compile(
    r"<(script|style|iframe|object|embed|link|meta)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_PAGE_BREAK_RE = re.compile(
    r"<div\b[^>]*(?:page-break-(?:after|before)|break-(?:after|before))\s*:\s*"
    r"(?:always|page)[^>]*>\s*</div\s*>",
    re.IGNORECASE,
)
_REQUIRED_SECTIONS = (
    "一、概述",
    "二、测试结论",
    "三、测试综述",
    "四、测试结果",
    "五、安全等级与建议",
)


_REPORT_CSS = r"""
@font-face {
  font-family: "Lingshu YaHei";
  src: url("{{ regular_font_uri }}");
  font-weight: 400;
  font-style: normal;
}
@font-face {
  font-family: "Lingshu YaHei";
  src: url("{{ bold_font_uri }}");
  font-weight: 700;
  font-style: normal;
}

@page {
  size: A4;
  margin: 24mm 18mm 20mm 18mm;
  @top-left {
    content: "灵枢·利刃 Agent";
    color: #a30d15;
    font-size: 8.5pt;
    font-weight: 700;
  }
  @top-right {
    content: string(chapter);
    color: #666b73;
    font-size: 8pt;
  }
  @bottom-left {
    content: "授权安全测试报告 · {{ session_id }}";
    color: #70757d;
    font-size: 7.5pt;
  }
  @bottom-right {
    content: "第 " counter(page) " 页 / 共 " counter(pages) " 页";
    color: #70757d;
    font-size: 7.5pt;
  }
}
@page cover {
  margin: 0;
  @top-left { content: none; }
  @top-right { content: none; }
  @bottom-left { content: none; }
  @bottom-right { content: none; }
}
@page toc {
  @top-right { content: "目录"; }
}
@page back-cover {
  margin: 0;
  @top-left { content: none; }
  @top-right { content: none; }
  @bottom-left { content: none; }
  @bottom-right { content: none; }
}

* { box-sizing: border-box; }
html { color: #17191d; background: #fff; }
body {
  margin: 0;
  font-family: "Lingshu YaHei", "Microsoft YaHei", sans-serif;
  font-size: 10.5pt;
  line-height: 1.72;
  text-rendering: optimizeLegibility;
  overflow-wrap: anywhere;
}
.cover {
  page: cover;
  break-after: page;
  width: 210mm;
  height: 297mm;
  padding: 25mm 24mm 20mm;
  position: relative;
  background:
    radial-gradient(circle at 82% 14%, rgba(216, 25, 35, .13), transparent 28%),
    linear-gradient(145deg, #ffffff 0%, #fafafa 68%, #f3f3f3 100%);
  border-top: 7mm solid #d71920;
}
.cover::after {
  content: "";
  position: absolute;
  right: 0;
  bottom: 0;
  width: 70mm;
  height: 70mm;
  border-right: 2mm solid #111318;
  border-bottom: 2mm solid #d71920;
}
.cover-brand { width: 100%; text-align: center; }
.cover-logo { display: block; width: 114mm; height: auto; max-height: 54mm; margin: 0 auto; object-fit: contain; }
.cover-rule { height: 1px; background: linear-gradient(90deg, #d71920, #15171b, transparent); margin: 7mm 0 18mm; }
.cover-kicker { color: #d71920; font-size: 12pt; font-weight: 700; letter-spacing: 2px; }
.cover h1 { margin: 4mm 0 1mm; color: #111318; font-size: 27pt; line-height: 1.24; letter-spacing: 1px; }
.cover h2 { margin: 0; color: #d71920; font-size: 21pt; line-height: 1.3; }
.cover-meta { width: 100%; margin-top: 23mm; border-collapse: collapse; font-size: 9.5pt; }
.cover-meta th, .cover-meta td { padding: 3mm 3.5mm; border-bottom: .3mm solid #dedfe2; text-align: left; }
.cover-meta th { width: 31mm; color: #8f1117; font-weight: 700; }
.cover-footer { position: absolute; left: 24mm; right: 24mm; bottom: 22mm; color: #5e6269; font-size: 8.5pt; }

.toc { page: toc; break-after: page; }
.toc-title { margin: 0 0 10mm; color: #b5121b; font-size: 23pt; border-bottom: 1.2mm solid #d71920; padding-bottom: 4mm; }
.toc ol { margin: 0; padding: 0; list-style: none; }
.toc li { margin: 2.2mm 0; border-bottom: .25mm dotted #b8bbc0; }
.toc li.level-2 { margin-left: 8mm; color: #555a62; font-size: 9.5pt; }
.toc a { color: inherit; text-decoration: none; }
.toc a::after { content: leader("·") target-counter(attr(href), page); float: right; color: #858991; }

.report-body h1 {
  string-set: chapter content();
  color: #b5121b;
  font-size: 19pt;
  line-height: 1.35;
  margin: 0 0 7mm;
  padding: 0 0 3mm 4mm;
  border-left: 1.6mm solid #d71920;
  border-bottom: .35mm solid #e3e4e6;
  break-after: avoid;
}
.report-body h2 { color: #202329; font-size: 14pt; margin: 7mm 0 3mm; break-after: avoid; }
.report-body h3 { color: #a30d15; font-size: 11.5pt; margin: 5mm 0 2mm; break-after: avoid; }
.report-body h4, .report-body h5, .report-body h6 { color: #363a41; font-size: 10.5pt; margin: 4mm 0 1.5mm; break-after: avoid; }
.report-body p { margin: 0 0 3mm; text-align: justify; orphans: 3; widows: 3; }
.report-body strong { font-weight: 700; color: #25272c; }
.report-body a { color: #b5121b; text-decoration: none; }
.report-body hr { border: 0; border-top: .35mm solid #e0e1e4; margin: 7mm 0; }
.page-break { break-after: page; height: 0; }

table { width: 100%; border-collapse: collapse; margin: 4mm 0 6mm; font-size: 8.8pt; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th, td { border: .25mm solid #cfd1d5; padding: 2.2mm 2.5mm; vertical-align: top; text-align: left; }
th { background: #f8e8e9; color: #8f1117; font-weight: 700; }
tbody tr:nth-child(even) { background: #fafafa; }

pre {
  margin: 3mm 0 5mm;
  padding: 4mm;
  border-radius: 2mm;
  border-left: 1.2mm solid #d71920;
  background: #17191e;
  color: #f3f4f6;
  font-family: "Lingshu YaHei", monospace;
  font-size: 8.2pt;
  line-height: 1.5;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  break-inside: auto;
}
code { font-family: "Lingshu YaHei", monospace; font-size: .92em; background: #f3eeee; color: #9b1017; padding: .2mm 1mm; border-radius: 1mm; }
pre code { background: transparent; color: inherit; padding: 0; }
blockquote { margin: 4mm 0; padding: 3mm 4mm; border-left: 1.2mm solid #d71920; background: #fff5f5; color: #4f535a; break-inside: avoid; }
ul, ol { margin: 2mm 0 4mm 6mm; padding-left: 5mm; }
li { margin: 1.2mm 0; }
img { display: block; max-width: 100%; max-height: 180mm; margin: 4mm auto 2mm; object-fit: contain; }
figure { margin: 5mm 0 7mm; break-inside: avoid; text-align: center; }
figure img { width: 94%; max-height: 155mm; }
figcaption { margin-top: 2mm; color: #676b72; font-size: 8.5pt; }
.mermaid-fallback { text-align: left; }
.evidence-badge { color: #fff; background: #b5121b; padding: .4mm 1.4mm; border-radius: 2mm; font-size: 8pt; }

.back-cover {
  page: back-cover;
  break-before: page;
  width: 210mm;
  height: 297mm;
  padding: 48mm 28mm 35mm;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  background:
    radial-gradient(circle at 50% 35%, rgba(215, 25, 32, .10), transparent 32%),
    linear-gradient(180deg, #ffffff 0%, #f8f8f8 100%);
  border-top: 5mm solid #d71920;
  border-bottom: 3mm solid #15171b;
}
.back-cover-logo { display: block; width: 114mm; height: auto; max-height: 72mm; margin: 0 auto 18mm; object-fit: contain; }
.back-cover-description { max-width: 145mm; margin: 0 auto; color: #25282e; font-size: 12pt; line-height: 2; text-align: center; }
.back-cover-rule { width: 28mm; height: 1mm; margin: 12mm auto 8mm; background: #d71920; }
.back-cover-copyright { margin: 0; color: #a30d15; font-size: 10.5pt; font-weight: 700; letter-spacing: .5px; }
"""


_REPORT_TEMPLATE = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>{{ document_title }}</title>
  <style>{{ css | safe }}</style>
</head>
<body>
  <section class="cover">
    <div class="cover-brand">
      {% if logo_uri %}<img class="cover-logo" src="{{ logo_uri }}" alt="灵枢·利刃 Agent">{% endif %}
    </div>
    <div class="cover-rule"></div>
    <div class="cover-kicker">灵枢·利刃Agent</div>
    <h1>{{ target_title }}</h1>
    <h2>安全测试报告</h2>
    <table class="cover-meta">
      <tr><th>会话编号</th><td>{{ session_id }}</td></tr>
      <tr><th>任务目标</th><td>{{ goal }}</td></tr>
      <tr><th>执行结果</th><td>{{ outcome }}</td></tr>
      <tr><th>报告日期</th><td>{{ report_date }}</td></tr>
    </table>
    <div class="cover-footer">本报告由灵枢·利刃多专家协作智能体基于完整会话证据自动生成</div>
  </section>
  {% if toc_entries %}
  <section class="toc">
    <h1 class="toc-title">目录</h1>
    <ol>
      {% for item in toc_entries %}
      <li class="level-{{ item.level }}"><a href="#{{ item.id }}">{{ item.title }}</a></li>
      {% endfor %}
    </ol>
  </section>
  {% endif %}
  <main class="report-body">{{ report_html | safe }}</main>
  <section class="back-cover">
    {% if logo_uri %}<img class="back-cover-logo" src="{{ logo_uri }}" alt="灵枢·利刃 Agent">{% endif %}
    <p class="back-cover-description">灵枢·利刃Agent是广东交通职业技术学院信息与人工智能学院团队开发的多智能体协作网络安全渗透测试智能体。</p>
    <div class="back-cover-rule"></div>
    <p class="back-cover-copyright">灵枢利刃项目团队©2026</p>
  </section>
</body>
</html>"""


def _mission_phase(mission: dict[str, Any]) -> str:
    phase = mission.get("phase") or "未知"
    return str(getattr(phase, "value", phase))


def _target_title(mission: dict[str, Any]) -> str:
    target = str(mission.get("target") or "安全测试目标").strip()
    if target.startswith(("http://", "https://")):
        return target
    leaf = Path(target.rstrip("/")).name
    return leaf or target


def _fallback_section(title: str, mission: dict[str, Any]) -> str:
    """模型漏章时从结构化任务状态补齐最小、真实的章节内容。"""
    if title == "一、概述":
        return (
            f"# {title}\n\n## 项目目标\n\n"
            f"针对授权目标 `{mission.get('target') or '未记录'}` 执行："
            f"{mission.get('goal') or '未记录'}。"
        )
    if title == "二、测试结论":
        success = mission.get("success") is True
        return (
            f"# {title}\n\n任务最终状态为 **{'完成' if success else '失败或未完成'}**，"
            f"最终阶段为 `{_mission_phase(mission)}`。"
        )
    if title == "三、测试综述":
        plans = mission.get("plan_items") or []
        plan_text = "\n".join(
            f"- {item.get('content', '未命名步骤')}（{item.get('status', '未知')}）"
            for item in plans[:30] if isinstance(item, dict)
        ) or "- 未记录结构化计划。"
        return f"# {title}\n\n## 实施流程\n\n{plan_text}"
    if title == "四、测试结果":
        findings = mission.get("findings") or []
        attacks = mission.get("attack_chain") or []
        chunks = [f"# {title}"]
        for index, item in enumerate([*findings, *attacks][:50], 1):
            if isinstance(item, dict):
                name = item.get("source") or item.get("objective") or f"证据 {index}"
                content = item.get("report") or item.get("content") or "无正文"
            else:
                name, content = f"证据 {index}", str(item)
            chunks.append(f"## 4.{index} {name}\n\n{content}")
        if len(chunks) == 1:
            chunks.append("\n本次会话未形成可验证的漏洞结论。")
        return "\n\n".join(chunks)
    return (
        f"# {title}\n\n优先复核未完成计划项，并依据报告中的实际证据实施整改；"
        "整改后应进行针对性复测。"
    )


def validate_report_markdown(markdown: str) -> list[str]:
    """返回缺失的固定一级章节名称。"""
    source = markdown or ""
    return [
        title
        for title in _REQUIRED_SECTIONS
        if re.search(
            rf"(?m)^#\s+{re.escape(title)}\s*$",
            source,
        ) is None
    ]


def normalize_report_markdown(
    markdown: str,
    mission: dict[str, Any],
) -> tuple[str, list[str]]:
    """清理危险版式并确定性补齐章节、章节分页。"""
    source = (markdown or "").lstrip("\ufeff").strip()
    source = _DANGEROUS_HTML_BLOCK_RE.sub("", source)
    source = _HTML_PAGE_BREAK_RE.sub("\n\n---\n\n", source)
    # 兼容旧 Prompt 生成的 HTML 标题，但不接受其 style/align 等属性。
    source = re.sub(
        r"<h([1-6])\b[^>]*>(.*?)</h\1\s*>",
        lambda match: f"{'#' * int(match.group(1))} {re.sub(r'<[^>]+>', '', match.group(2)).strip()}",
        source,
        flags=re.IGNORECASE | re.DOTALL,
    )
    missing = validate_report_markdown(source)
    if missing:
        additions = [_fallback_section(title, mission) for title in missing]
        source = "\n\n---\n\n".join([source, *additions]) if source else "\n\n---\n\n".join(additions)

    # 固定章节必须按模板顺序输出。模型若换序，后端按精确 H1 边界重排；
    # 章节前的额外摘要并入“一、概述”，不让自由 H1 破坏目录与分页。
    heading_pattern = re.compile(
        r"(?m)^#\s+(" + "|".join(re.escape(item) for item in _REQUIRED_SECTIONS) + r")\s*$",
    )
    matches = list(heading_pattern.finditer(source))
    sections: dict[str, str] = {}
    preamble = source[:matches[0].start()].strip() if matches else ""
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        section = source[match.start():end].strip()
        section = re.sub(r"(?:\n\s*-{3,}\s*)+$", "", section).strip()
        sections.setdefault(match.group(1), section)
    if preamble:
        overview = sections.get("一、概述", "# 一、概述")
        heading, _, rest = overview.partition("\n")
        sections["一、概述"] = "\n\n".join(
            item for item in (heading, preamble, rest.strip()) if item
        )
    normalized = "\n\n---\n\n".join(
        sections.get(title, _fallback_section(title, mission))
        for title in _REQUIRED_SECTIONS
    ).strip() + "\n"
    return normalized, missing


def _render_mermaid(code: str, destination: Path) -> bool:
    """用项目内 beautiful-mermaid 渲染 SVG；失败时由调用方显示源码。"""
    if not _MERMAID_RENDERER.is_file() or not shutil_which("node"):
        return False
    source = destination.with_suffix(".mmd")
    source.write_text(code.strip() + "\n", encoding="utf-8")
    try:
        completed = subprocess.run(
            [
                "node", str(_MERMAID_RENDERER), str(source),
                "--format", "svg", "--theme", "github-light",
                "--preset", "modern", "--output", str(destination),
            ],
            cwd=destination.parent,
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
        return completed.returncode == 0 and destination.is_file() and destination.stat().st_size > 100
    except (OSError, subprocess.SubprocessError):
        return False


def shutil_which(command: str) -> str | None:
    """局部包装，避免仅为 which 污染模块命名空间。"""
    import shutil
    return shutil.which(command)


def _markdown_html(
    markdown: str,
    asset_dir: Path,
) -> tuple[str, list[dict[str, Any]]]:
    mermaid_blocks: list[tuple[str, str]] = []

    def stash_mermaid(match: re.Match[str]) -> str:
        index = len(mermaid_blocks)
        code = match.group(1).strip()
        marker = f"{_MERMAID_MARKER_PREFIX}{index}_END"
        mermaid_blocks.append((marker, code))
        return f"\n\n{marker}\n\n"

    prepared = re.sub(
        r"```mermaid\s*\n(.*?)```",
        stash_mermaid,
        markdown,
        flags=re.IGNORECASE | re.DOTALL,
    )
    prepared = re.sub(
        r"(?m)^\s*-{3,}\s*$",
        f"\n\n{_PAGE_BREAK_MARKER}\n\n",
        prepared,
    )
    renderer = MarkdownIt(
        "commonmark",
        {"html": False, "linkify": False, "typographer": False},
    ).enable("table")
    rendered = renderer.render(prepared)
    rendered = rendered.replace(
        f"<p>{_PAGE_BREAK_MARKER}</p>",
        '<div class="page-break"></div>',
    )

    for index, (marker, code) in enumerate(mermaid_blocks, 1):
        svg_path = asset_dir / f"mermaid-{index}.svg"
        if _render_mermaid(code, svg_path):
            replacement = (
                '<figure class="mermaid-diagram">'
                f'<img src="{svg_path.as_uri()}" alt="流程图 {index}">'
                f"<figcaption>图 {index} · 自动生成的流程图</figcaption></figure>"
            )
        else:
            replacement = (
                '<figure class="mermaid-fallback"><figcaption>流程图源码（渲染失败）</figcaption>'
                f"<pre><code>{html.escape(code)}</code></pre></figure>"
            )
        rendered = rendered.replace(f"<p>{marker}</p>", replacement)

    toc: list[dict[str, Any]] = []
    heading_index = 0

    def add_heading_id(match: re.Match[str]) -> str:
        nonlocal heading_index
        level = int(match.group(1))
        inner = match.group(2)
        heading_index += 1
        heading_id = f"section-{heading_index}"
        title = html.unescape(re.sub(r"<[^>]+>", "", inner)).strip()
        if level <= 2 and title:
            toc.append({"level": level, "id": heading_id, "title": title})
        return f'<h{level} id="{heading_id}">{inner}</h{level}>'

    rendered = re.sub(
        r"<h([1-6])>(.*?)</h\1>",
        add_heading_id,
        rendered,
        flags=re.DOTALL,
    )
    return rendered, toc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _public_remote_host(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        return False
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    if not addresses:
        return False
    for value in addresses:
        ip = ipaddress.ip_address(value)
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        ):
            return False
    return True


def _url_fetcher(allowed_roots: tuple[Path, ...]) -> Callable[..., Any]:
    roots = tuple(root.resolve() for root in allowed_roots if root.exists())

    def fetch(url: str, timeout: int = 10, ssl_context=None) -> Any:
        del ssl_context
        from weasyprint.urls import URLFetcherResponse
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "file":
            path = Path(urllib.request.url2pathname(parsed.path)).resolve()
            if not any(path == root or path.is_relative_to(root) for root in roots):
                raise ValueError(f"报告资源不在允许目录中: {path}")
            return URLFetcherResponse(
                path.as_uri(),
                body=path.open("rb"),
                headers={
                    "Content-Type": mimetypes.guess_type(path.name)[0]
                    or "application/octet-stream",
                },
            )
        if parsed.scheme == "data":
            if not url.lower().startswith("data:image/") or len(url) > 6 * 1024 * 1024:
                raise ValueError("仅允许不超过 6MB 的 data:image 报告资源")
            from weasyprint import default_url_fetcher
            return default_url_fetcher(url, timeout=timeout)
        if parsed.scheme in {"http", "https"}:
            if not _public_remote_host(url):
                raise ValueError("拒绝访问内网、环回或保留地址的报告资源")
            opener = urllib.request.build_opener(_NoRedirect())
            request = urllib.request.Request(url, headers={"User-Agent": "Lingshu-Report/1.0"})
            with opener.open(request, timeout=min(timeout, 15)) as response:
                mime = response.headers.get_content_type()
                if not mime.startswith("image/"):
                    raise ValueError("远程报告资源不是图片")
                data = response.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024:
                    raise ValueError("远程报告图片超过 4MB")
            return URLFetcherResponse(
                url,
                body=data,
                headers={"Content-Type": mime},
            )
        raise ValueError(f"报告资源协议不受支持: {parsed.scheme or 'relative'}")

    return fetch


def _font_path(name: str, fallback: str) -> Path:
    configured = os.getenv(name, "").strip()
    path = Path(configured) if configured else _FRONTEND_DIR / fallback
    if not path.is_file():
        raise RuntimeError(f"PDF 字体不存在: {path}")
    return path.resolve()


def _materialize_report_logo(asset_dir: Path) -> str:
    """把远程 Logo 固化为本地报告资源，失败时保留可见的项目 Logo。

    WeasyPrint 对图片加载失败默认只记录日志并继续生成，容易产生“PDF 成功但
    Logo 消失”的假成功。这里先显式校验并下载；部署方可通过
    ``LINGSHU_REPORT_LOGO_URL`` 更新 OSS 地址，无须再次改代码。
    """
    try:
        response = _url_fetcher((asset_dir,))(_REPORT_LOGO_URL)
        body = response.body
        data = body.read() if hasattr(body, "read") else bytes(body or b"")
        if not data:
            raise ValueError("远程 Logo 内容为空")
        mime = str(response.headers.get("Content-Type") or "image/png")
        suffix = mimetypes.guess_extension(mime.split(";", 1)[0]) or ".img"
        logo_path = asset_dir / f"report-logo{suffix}"
        logo_path.write_bytes(data)
        return logo_path.as_uri()
    except Exception as exc:
        fallback = (_PROJECT_ROOT / "webui" / "src" / "logo2.png").resolve()
        if not fallback.is_file():
            raise RuntimeError(f"报告 Logo 加载失败且本地回退不存在: {exc}") from exc
        logger.warning("远程报告 Logo 加载失败，使用本地回退: %s", exc)
        return fallback.as_uri()


def generate_weasyprint_pdf(
    session_id: str,
    summary: str,
    mission: dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """原子生成 WeasyPrint PDF，并返回最终文件路径。"""
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RuntimeError("WeasyPrint 未安装，请执行 pip install -r requirements.txt") from exc

    report_dir = Path(output_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    destination = report_dir / f"{session_id}.pdf"
    normalized, _missing = normalize_report_markdown(summary, mission)
    regular_font = _font_path("LINGSHU_PDF_FONT_REGULAR", "MSYH.TTC")
    bold_font = _font_path("LINGSHU_PDF_FONT_BOLD", "MSYHBD.TTC")

    from datetime import datetime
    raw_date = str(mission.get("updated_at") or "")
    date_match = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", raw_date)
    if date_match:
        year, month, day = (int(item) for item in date_match.groups())
    else:
        now = datetime.now()
        year, month, day = now.year, now.month, now.day

    with tempfile.TemporaryDirectory(prefix="lingshu-report-assets-") as asset_name:
        asset_dir = Path(asset_name).resolve()
        logo_uri = _materialize_report_logo(asset_dir)
        report_html, toc = _markdown_html(normalized, asset_dir)
        env = Environment(autoescape=select_autoescape(("html", "xml")))
        css = env.from_string(_REPORT_CSS).render(
            regular_font_uri=regular_font.as_uri(),
            bold_font_uri=bold_font.as_uri(),
            session_id=session_id,
        )
        outcome = "成功" if mission.get("success") is True else "失败或未完成"
        document_html = env.from_string(_REPORT_TEMPLATE).render(
            css=css,
            document_title=f"灵枢安全测试报告 {session_id}",
            logo_uri=logo_uri,
            target_title=_target_title(mission),
            session_id=session_id,
            goal=str(mission.get("goal") or "未记录"),
            outcome=outcome,
            report_date=f"{year}年 {month:02d}月 {day:02d}日",
            toc_entries=toc,
            report_html=report_html,
        )
        fd, temp_name = tempfile.mkstemp(
            dir=report_dir,
            prefix=f".{session_id}.",
            suffix=".pdf.tmp",
        )
        os.close(fd)
        try:
            HTML(
                string=document_html,
                base_url=_PROJECT_ROOT.as_uri() + "/",
                url_fetcher=_url_fetcher(
                    (asset_dir, _WORKDIR, _FRONTEND_DIR, _PROJECT_ROOT / "webui" / "src"),
                ),
            ).write_pdf(temp_name)
            if Path(temp_name).stat().st_size < 1024:
                raise RuntimeError("WeasyPrint 生成的 PDF 文件异常为空")
            os.replace(temp_name, destination)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
    return destination
