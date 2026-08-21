"""将任务总结和结构化证据生成可下载的中文 PDF 报告。

兼容「灵枢·利刃」安全测试报告模板（pentest-report-template skill）的
Markdown 产物：支持独占一行的 ``---`` 分页语义、``![alt](src)`` 图片
（远程 URL 自动下载、本地文件直接嵌入，SVG 无转换器时回退为引用文本）、
有序/无序列表、H1-H6 标题层级与按内容估算的表格列宽。
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

_IMAGE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_HR_RE = re.compile(r"^-{3,}$")
_IMAGE_LINE_RE = re.compile(r"^!\[([^\]]*)\]\((.+)\)$")
logger = logging.getLogger(__name__)


def prepare_mission_report_markdown(
    summary: str,
    mission: dict[str, Any],
) -> tuple[str, list[str]]:
    """规范 Summary Markdown，并返回由后端补齐的缺失章节。"""
    from Tools.WeasyReport import normalize_report_markdown
    return normalize_report_markdown(summary, mission)

# 灵枢·利刃 模板封面/封底要素（与 pentest-report-template skill 一致）
_COVER_LOGO_URL = (
    "https://bomeitongpicbed.oss-cn-guangzhou.aliyuncs.com/063e5a7a783845cd5fe381c807702783.jpg"
)
_COVER_AGENT_NAME = "灵枢·利刃 Agent"
_COVER_TEAM_INTRO = (
    "灵枢·利刃Agent是广东交通职业技术学院信息与人工智能学院团队开发的多智能体协作"
    "网络安全渗透测试智能体。"
)
_COVER_COPYRIGHT = "灵枢利刃项目团队©2026"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：图床应直连，避免被引导到内网/任意目标。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _is_safe_download_url(src: str) -> bool:
    """拒绝指向私网/环回/保留地址的图片 URL（SSRF 防护）。"""
    host = urllib.parse.urlsplit(src).hostname
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None:
        try:
            ip = ipaddress.ip_address(socket.getaddrinfo(host, None)[0][4][0])
        except Exception:
            return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _safe_text(value: Any) -> str:
    return escape(str(value or "")).replace("\n", "<br/>")


def _download_remote_image(src: str) -> Path | None:
    """下载远程图片到临时文件；失败返回 None（不阻塞报告生成）。"""
    if not _is_safe_download_url(src):
        return None
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        request = urllib.request.Request(
            src,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Lingshu/2.0; +report-generator)"},
        )
        with opener.open(request, timeout=15) as response:
            data = response.read(4 * 1024 * 1024)  # 上限 4MB
        fd, name = tempfile.mkstemp(prefix="lingshu-img-", suffix=".img")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return Path(name)
    except Exception:  # 网络不可用/超时/重定向/内容超限：报告生成不应被图片拖垮
        return None


def _register_pdf_fonts(pdfmetrics: Any, TTFont: Any, UnicodeCIDFont: Any) -> tuple[str, str]:
    """注册微软雅黑常规/粗体；部署环境未提供字体时安全回退中文 CID 字体。

    可通过 ``LINGSHU_PDF_FONT_REGULAR`` / ``LINGSHU_PDF_FONT_BOLD`` 指向
    msyh.ttf 与 msyhbd.ttf。项目不捆绑受版权保护的微软字体文件。
    """
    project_root = Path(__file__).resolve().parents[1]
    regular_candidates = [
        os.getenv("LINGSHU_PDF_FONT_REGULAR", ""),
        str(project_root / "frontend" / "MSYH.TTC"),
        "/usr/share/fonts/truetype/msttcorefonts/msyh.ttf",
        "/usr/share/fonts/truetype/microsoft/YaHei.ttf",
    ]
    bold_candidates = [
        os.getenv("LINGSHU_PDF_FONT_BOLD", ""),
        str(project_root / "frontend" / "MSYHBD.TTC"),
        "/usr/share/fonts/truetype/msttcorefonts/msyhbd.ttf",
        "/usr/share/fonts/truetype/microsoft/YaHeiBold.ttf",
    ]
    regular_path = next((Path(path) for path in regular_candidates if path and Path(path).is_file()), None)
    bold_path = next((Path(path) for path in bold_candidates if path and Path(path).is_file()), None)
    if regular_path is not None:
        pdfmetrics.registerFont(TTFont("LingshuYaHei", str(regular_path)))
        if bold_path is not None:
            pdfmetrics.registerFont(TTFont("LingshuYaHeiBold", str(bold_path)))
            pdfmetrics.registerFontFamily(
                "LingshuYaHei",
                normal="LingshuYaHei",
                bold="LingshuYaHeiBold",
                italic="LingshuYaHei",
                boldItalic="LingshuYaHeiBold",
            )
            return "LingshuYaHei", "LingshuYaHeiBold"
        return "LingshuYaHei", "LingshuYaHei"
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    return "STSong-Light", "STSong-Light"


def _generate_reportlab_pdf(
    session_id: str,
    summary: str,
    mission: dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """原子生成一份会话 PDF；中文使用 ReportLab 内置 CID 字体。

    Args:
        session_id: 会话编号，作为 PDF 文件名。
        summary: Summary Agent 输出的 Markdown 报告（兼容灵枢·利刃模板）。
        mission: 结构化任务状态（用于自由格式总结时的封面元信息与附加章节）。
        output_dir: PDF 输出目录。

    Returns:
        生成的 PDF 文件路径。
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            Image, ListFlowable, ListItem, PageBreak, Paragraph, Preformatted,
            SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PDF 依赖缺失，请执行 pip install -r requirements.txt") from exc

    report_dir = Path(output_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    destination = report_dir / f"{session_id}.pdf"
    fd, temporary_name = tempfile.mkstemp(dir=report_dir, prefix=f".{session_id}.", suffix=".pdf.tmp")
    os.close(fd)

    regular_font, bold_font = _register_pdf_fonts(pdfmetrics, TTFont, UnicodeCIDFont)
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "LingshuBody", parent=styles["BodyText"], fontName=regular_font,
        fontSize=10.5, leading=17, textColor=colors.HexColor("#181818"), spaceAfter=7,
    )
    title = ParagraphStyle(
        "LingshuTitle", parent=body, fontName=bold_font, alignment=TA_CENTER, fontSize=22, leading=28,
        textColor=colors.HexColor("#D71920"), spaceAfter=12,
    )
    heading = ParagraphStyle(
        "LingshuHeading", parent=body, fontName=bold_font, fontSize=14, leading=20,
        textColor=colors.HexColor("#B01218"), spaceBefore=10, spaceAfter=7,
    )
    heading_small = ParagraphStyle(
        "LingshuHeadingSmall", parent=heading, fontSize=12, leading=18,
        spaceBefore=8, spaceAfter=5,
    )
    heading_mini = ParagraphStyle(
        "LingshuHeadingMini", parent=heading_small, fontSize=10.5, leading=16,
        spaceBefore=6, spaceAfter=4,
    )
    quote = ParagraphStyle(
        "LingshuQuote", parent=body, leftIndent=10, borderColor=colors.HexColor("#D71920"),
        borderWidth=1.4, borderPadding=7, backColor=colors.HexColor("#FFF5F5"),
    )
    code = ParagraphStyle(
        "LingshuCode", parent=body, fontName=regular_font, fontSize=8.5,
        leading=13, leftIndent=5, rightIndent=5, backColor=colors.HexColor("#F4F4F4"),
    )
    caption = ParagraphStyle(
        "LingshuCaption", parent=body, alignment=TA_CENTER, fontSize=9,
        leading=13, textColor=colors.HexColor("#666666"), spaceBefore=2, spaceAfter=6,
    )

    def inline_markdown(value: Any) -> str:
        """保留少量安全的 ReportLab 行内标记，而非把 Markdown 原样打印。"""
        text = escape(str(value or ""))
        # 先抽离行内代码，避免其中的下划线被斜体规则再次匹配，破坏 XML 标签嵌套。
        code_parts: list[str] = []

        def save_code(match: re.Match[str]) -> str:
            code_parts.append(match.group(1))
            return f"@@LINGSHU_CODE_{len(code_parts) - 1}@@"

        text = re.sub(r"`([^`]+)`", save_code, text)
        text = re.sub(r"\*\*([^*]+)\*\*|__([^_]+)__", lambda m: f"<b>{m.group(1) or m.group(2)}</b>", text)
        # 技术报告中下划线几乎总是变量/工具/事件名的一部分（如
        # approval_resolved），不将其当斜体语法解析；星号斜体仍支持。
        text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)
        for index, item in enumerate(code_parts):
            text = text.replace(
                f"@@LINGSHU_CODE_{index}@@",
                f'<font name="{regular_font}" color="#A10E14">{item}</font>',
            )
        return text

    def _display_width(text: str) -> float:
        """估算文本渲染宽度：CJK 记 2 个单位，其余记 1 个单位。"""
        return float(sum(2.0 if ord(char) > 0x2E7F else 1.0 for char in text))

    def looks_like_table_start(lines: list[str], index: int) -> bool:
        """当前行像表格数据行：其后紧跟分隔行，且再后还有数据行。

        避免把「数据行 + 裸分隔行（无表头）」误当表格。
        """
        if "|" not in lines[index]:
            return False
        if index + 1 >= len(lines) or "|" not in lines[index + 1] or "---" not in lines[index + 1]:
            return False
        return index + 2 < len(lines) and "|" in lines[index + 2]

    def table_from_markdown(lines: list[str]) -> Table | None:
        raw_rows: list[list[str]] = []
        for line in lines:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            # Markdown 表头分隔行：| --- | :---: |
            if cells and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
                continue
            if cells:
                raw_rows.append(cells)
        if not raw_rows or len(raw_rows[0]) < 2:
            return None
        ncols = len(raw_rows[0])
        max_width = 152 * mm
        # 按每列最大内容宽度估算列宽，避免均分导致内容换行过多
        weights = [
            max((_display_width(row[col]) if col < len(row) else 0) for row in raw_rows)
            for col in range(ncols)
        ]
        total = sum(weights) or float(ncols)
        col_widths = [max(14 * mm, max_width * weight / total) for weight in weights]
        # 估算超宽时整体收缩；窄列多时下限会再次抬升总宽，需重查直至不溢出
        for _ in range(3):
            overflow = sum(col_widths) - max_width
            if overflow <= 0:
                break
            factor = max_width / sum(col_widths)
            col_widths = [max(12 * mm, width * factor) for width in col_widths]
        rows = [[Paragraph(inline_markdown(cell), body) for cell in row] for row in raw_rows]
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), regular_font),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FCEBEC")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#9E1118")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D7D7D7")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    def image_flowable(src: str, alt: str, *, max_width: float | None = None, max_height: float | None = None) -> Image | None:
        """把图片引用转为 ReportLab Image；无法解析/渲染时返回 None。

        远程 URL 自动下载到临时文件；本地 SVG 且未安装 cairosvg/svglib 时
        无法位图化，返回 None 由调用方回退为引用文本。
        """
        local = Path(src)
        if not local.is_file():
            if not _IMAGE_URL_RE.match(src):
                return None
            downloaded = _download_remote_image(src)
            if downloaded is None:
                return None
            downloaded_images.append(downloaded)
            local = downloaded
        try:
            from PIL import Image as PILImage
            with PILImage.open(local) as probe:
                probe.verify()
            with PILImage.open(local) as probe:
                width, height = probe.size
        except Exception:  # SVG / 损坏图片 / 格式不支持
            return None
        if not width or not height:
            return None
        if max_width is None:
            max_width = 120 * mm
        if max_height is None:
            max_height = 60 * mm
        scale = min(max_width / width, max_height / height, 1.0)
        flowable = Image(str(local), width=width * scale, height=height * scale)
        flowable.hAlign = "CENTER"
        return flowable

    downloaded_images: list[Path] = []

    def markdown_flowables(markdown: str) -> list[Any]:
        """将 Summary Agent 常用 Markdown（含灵枢·利刃模板）转为 ReportLab 组件。"""
        output: list[Any] = []
        lines = (markdown or "未生成总结").splitlines()
        index = 0
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            if not stripped:
                index += 1
                continue
            if stripped.startswith("```"):
                language = stripped[3:].strip()
                index += 1
                code_lines: list[str] = []
                while index < len(lines) and not lines[index].strip().startswith("```"):
                    code_lines.append(lines[index])
                    index += 1
                output.append(Preformatted("\n".join(code_lines) or " ", code))
                output.append(Spacer(1, 3 * mm))
                if index < len(lines):
                    index += 1
                continue
            heading_match = re.match(r"^(#{1,6})\s+(.+)$", stripped)
            if heading_match:
                level, heading_text = len(heading_match.group(1)), heading_match.group(2)
                style = title if level == 1 else (heading if level == 2 else (heading_small if level == 3 else heading_mini))
                output.append(Paragraph(inline_markdown(heading_text), style))
                index += 1
                continue
            # 模板分页语义：独占一行的 --- 在转 Word/PDF 时表示分页
            if _HR_RE.match(stripped):
                output.append(PageBreak())
                index += 1
                continue
            image_match = _IMAGE_LINE_RE.match(stripped)
            if image_match:
                alt, src = image_match.group(1), image_match.group(2)
                flowable = image_flowable(src, alt)
                if flowable is not None:
                    output.append(flowable)
                    if alt:
                        output.append(Paragraph(inline_markdown(alt), caption))
                    output.append(Spacer(1, 3 * mm))
                else:
                    output.append(Paragraph(f"[图片] {escape(alt)}：{escape(src)}", quote))
                    output.append(Spacer(1, 3 * mm))
                index += 1
                continue
            if looks_like_table_start(lines, index):
                table_lines = [line]
                index += 1
                while index < len(lines) and "|" in lines[index]:
                    table_lines.append(lines[index])
                    index += 1
                table = table_from_markdown(table_lines)
                if table is not None:
                    output.extend([table, Spacer(1, 3 * mm)])
                continue
            if stripped.startswith(">"):
                output.append(Paragraph(inline_markdown(stripped.lstrip("> ")), quote))
                index += 1
                continue
            ordered_match = re.match(r"^\d+[.)]\s+(.+)$", stripped)
            if ordered_match:
                entries = []
                while index < len(lines):
                    item = re.match(r"^\s*\d+[.)]\s+(.+)$", lines[index])
                    if not item:
                        break
                    entries.append(ListItem(Paragraph(inline_markdown(item.group(1)), body)))
                    index += 1
                output.extend([ListFlowable(entries, bulletType="1", leftIndent=16), Spacer(1, 2 * mm)])
                continue
            bullet_match = re.match(r"^[-*+]\s+(.+)$", stripped)
            if bullet_match:
                entries = []
                while index < len(lines):
                    item = re.match(r"^\s*[-*+]\s+(.+)$", lines[index])
                    if not item:
                        break
                    entries.append(ListItem(Paragraph(inline_markdown(item.group(1)), body)))
                    index += 1
                output.extend([ListFlowable(entries, bulletType="bullet", leftIndent=16), Spacer(1, 2 * mm)])
                continue
            paragraph = [stripped]
            index += 1
            while index < len(lines):
                candidate = lines[index].strip()
                if (
                    not candidate
                    or candidate.startswith("```")
                    or re.match(
                        r"^(#{1,6})\s+|^(?:[-*+]\s+|\d+[.)]\s+)|^>|^!\[[^\]]*\]\(.+\)$",
                        candidate,
                    )
                    or _HR_RE.match(candidate)
                ):
                    break
                if looks_like_table_start(lines, index):
                    break
                paragraph.append(candidate)
                index += 1
            output.append(Paragraph("<br/>".join(inline_markdown(part) for part in paragraph), body))
        return output

    def header_footer(canvas, document) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D71920"))
        canvas.setLineWidth(0.7)
        canvas.line(18 * mm, A4[1] - 15 * mm, A4[0] - 18 * mm, A4[1] - 15 * mm)
        canvas.setFont(regular_font, 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(18 * mm, 10 * mm, f"灵枢授权安全测试报告 · {session_id}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"第 {document.page} 页")
        canvas.restoreState()

    document = SimpleDocTemplate(
        temporary_name, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=23 * mm, bottomMargin=18 * mm,
        title=f"灵枢安全测试报告 {session_id}", author="灵枢 Summary Agent",
    )

    # 模板封面识别：Summary 自带 pentest-report-template 封面（以图片行开头）时
    # 直接渲染全文（含封面/目录/封底与 --- 分页）；自由格式总结（旧版 Summary 输出）
    # 自动补齐模板观感的封面、目录与封底，保证两类 md 产出的 PDF 风格一致。
    first_content = next(
        (line.strip() for line in (summary or "").lstrip("\ufeff").splitlines() if line.strip()),
        "",
    )
    template_cover = first_content.startswith("![")

    def _cover_date_text() -> str:
        """从 mission.updated_at 提取日期，格式化为「2026年 08月 14日」。"""
        raw = str(mission.get("updated_at") or "")
        match = re.search(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", raw)
        if match:
            year, month, day = (int(part) for part in match.groups())
        else:
            now = datetime.now()
            year, month, day = now.year, now.month, now.day
        return f"{year}年 {month:02d}月 {day:02d}日"

    def _cover_target_title() -> str:
        """自由格式总结的封面主标题：优先取 mission.target 末段，其次取 summary 首个 H1。"""
        target = str(mission.get("target") or "").strip()
        if target:
            if target.startswith(("http://", "https://")):
                return target
            leaf = target.rstrip("/").split("/")[-1]
            return leaf if leaf else target
        first_h1 = next(
            (line.strip() for line in (summary or "").splitlines() if re.match(r"^#\s+", line.strip())),
            "",
        )
        return first_h1.lstrip("# ").strip() or "安全测试目标"

    def _cover_meta_table() -> Table:
        rows = [
            ["会话编号", session_id],
            ["会话日期", _cover_date_text()],
            ["目标名称", _cover_target_title()],
            ["任务目标", mission.get("goal") or "未记录"],
            ["最终阶段", mission.get("phase") or "未知"],
            ["执行结果", "成功" if mission.get("success") is True else "失败/未完成"],
        ]
        table = Table(
            [[Paragraph(_safe_text(k), body), Paragraph(_safe_text(v), body)] for k, v in rows],
            colWidths=[38 * mm, 114 * mm],
        )
        table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), regular_font),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F2F2")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#B01218")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        return table

    def _template_cover() -> list[Any]:
        """模板观感封面：Logo + 元信息表 + 目标名 H1 + 「安全测试报告」H1 + 日期 + 署名。"""
        flow: list[Any] = []
        logo = image_flowable(_COVER_LOGO_URL, _COVER_AGENT_NAME, max_width=42 * mm, max_height=42 * mm)
        if logo is not None:
            flow.append(logo)
            flow.append(Paragraph(_COVER_AGENT_NAME, caption))
            flow.append(Spacer(1, 4 * mm))
        flow.append(_cover_meta_table())
        flow.append(Spacer(1, 10 * mm))
        flow.append(Paragraph(inline_markdown(_cover_target_title()), title))
        flow.append(Paragraph("安全测试报告", title))
        flow.append(Spacer(1, 8 * mm))
        flow.append(Paragraph(_cover_date_text(), body.clone("CoverDate", alignment=TA_CENTER)))
        flow.append(Paragraph(f"{_COVER_AGENT_NAME} 自动生成", body.clone("CoverBy", alignment=TA_CENTER)))
        return flow

    def _toc() -> list[Any]:
        """从 summary 的 H1/H2 标题自动生成目录页；无标题时返回空列表。"""
        entries: list[tuple[int, str]] = []
        for line in (summary or "").splitlines():
            match = re.match(r"^(#{1,2})\s+(.+)$", line.strip())
            if match:
                entries.append((len(match.group(1)), match.group(2).strip()))
        if not entries:
            return []
        # 自由格式总结的首个 H1 通常是报告总标题（封面主标题），不列入目录
        if len(entries) > 1 and entries[0][0] == 1:
            entries = entries[1:]
        flow: list[Any] = [Paragraph("目录", title.clone("TocTitle", spaceAfter=14))]
        for level, text in entries:
            if level == 1:
                flow.append(Paragraph(f"<b>{inline_markdown(text)}</b>", body))
            else:
                flow.append(Paragraph(inline_markdown(text), body.clone("TocSub", leftIndent=14)))
        flow.append(Spacer(1, 6 * mm))
        flow.append(PageBreak())
        return flow

    def _back_cover() -> list[Any]:
        """模板观感封底：Logo + 团队介绍 + 版权。"""
        flow: list[Any] = [PageBreak()]
        logo = image_flowable(_COVER_LOGO_URL, _COVER_AGENT_NAME, max_width=42 * mm, max_height=42 * mm)
        if logo is not None:
            flow.append(logo)
            flow.append(Paragraph(_COVER_AGENT_NAME, caption))
            flow.append(Spacer(1, 6 * mm))
        flow.append(Paragraph(_COVER_TEAM_INTRO, body.clone("BackIntro", alignment=TA_CENTER)))
        flow.append(Spacer(1, 12 * mm))
        flow.append(Paragraph(_COVER_COPYRIGHT, body.clone("BackCopyright", alignment=TA_CENTER)))
        return flow

    try:
        if template_cover:
            story = markdown_flowables(summary)
        else:
            story = _template_cover()
            story.append(PageBreak())
            story.extend(_toc())
            story.append(Paragraph("Summary Agent 总结", heading))
            story.extend(markdown_flowables(summary))
            for section_name, key in (("作战计划", "plan_items"), ("安全发现", "findings"), ("攻击链", "attack_chain")):
                values = mission.get(key) or []
                if values:
                    story.append(Paragraph(section_name, heading))
                    for index, value in enumerate(values, 1):
                        if isinstance(value, dict):
                            if key == "plan_items":
                                item_title = str(value.get("content") or f"计划项 {index}")
                                item_body = "\n\n".join(filter(None, [
                                    item_title,
                                    f"状态：{value.get('status', '未知')}；阶段：{value.get('phase', '未知')}",
                                    str(value.get("evidence") or "").strip(),
                                ]))
                            elif key == "findings":
                                item_title = str(value.get("source") or f"发现 {index}")
                                item_body = f"## {item_title}\n\n{value.get('report') or value.get('content') or ''}"
                            else:
                                item_title = str(value.get("objective") or f"攻击步骤 {index}")
                                item_body = f"## {item_title}\n\n{value.get('report') or value.get('content') or ''}"
                        else:
                            item_body = str(value)
                        story.append(Paragraph(f"{index}.", heading_small))
                        story.extend(markdown_flowables(item_body))
            story.extend(_back_cover())

        document.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
        os.replace(temporary_name, destination)
    finally:
        for temp_image in downloaded_images:
            try:
                temp_image.unlink()
            except OSError:
                pass
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return destination


def generate_mission_pdf(
    session_id: str,
    summary: str,
    mission: dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """优先用 WeasyPrint 生成专业 HTML/CSS 报告，故障时降级 ReportLab。

    ``LINGSHU_PDF_ENGINE=reportlab`` 可用于紧急回退或缺少系统图形库的部署。
    降级不改变 Summary 内容和报告下载路径。
    """
    engine = os.getenv("LINGSHU_PDF_ENGINE", "weasyprint").strip().lower()
    if engine != "reportlab":
        try:
            from Tools.WeasyReport import generate_weasyprint_pdf
            return generate_weasyprint_pdf(
                session_id,
                summary,
                mission,
                output_dir,
            )
        except Exception as exc:
            logger.exception(
                "WeasyPrint 报告生成失败，降级使用 ReportLab: %s",
                exc,
            )
    return _generate_reportlab_pdf(session_id, summary, mission, output_dir)
