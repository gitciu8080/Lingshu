"""将任务总结和结构化证据生成可下载的中文 PDF 报告。"""
from __future__ import annotations

import os
import re
import tempfile
from html import escape
from pathlib import Path
from typing import Any


def _safe_text(value: Any) -> str:
    return escape(str(value or "")).replace("\n", "<br/>")


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


def generate_mission_pdf(
    session_id: str,
    summary: str,
    mission: dict[str, Any],
    output_dir: str | Path,
) -> Path:
    """原子生成一份会话 PDF；中文使用 ReportLab 内置 CID 字体。"""
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
            ListFlowable, ListItem, PageBreak, Paragraph, Preformatted,
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
    quote = ParagraphStyle(
        "LingshuQuote", parent=body, leftIndent=10, borderColor=colors.HexColor("#D71920"),
        borderWidth=1.4, borderPadding=7, backColor=colors.HexColor("#FFF5F5"),
    )
    code = ParagraphStyle(
        "LingshuCode", parent=body, fontName=regular_font, fontSize=8.5,
        leading=13, leftIndent=5, rightIndent=5, backColor=colors.HexColor("#F4F4F4"),
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

    def table_from_markdown(lines: list[str]) -> Table | None:
        rows = []
        for line in lines:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            # Markdown 表头分隔行：| --- | :---: |
            if cells and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
                continue
            if cells:
                rows.append([Paragraph(inline_markdown(cell), body) for cell in cells])
        if not rows or len(rows[0]) < 2:
            return None
        width = 152 * mm / len(rows[0])
        table = Table(rows, colWidths=[width] * len(rows[0]), repeatRows=1)
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

    def markdown_flowables(markdown: str) -> list[Any]:
        """将 Summary Agent 常用 Markdown 转为 ReportLab 可排版组件。"""
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
                output.append(Paragraph(inline_markdown(heading_text), title if level == 1 else (heading if level == 2 else heading_small)))
                index += 1
                continue
            if "|" in stripped and index + 1 < len(lines) and "|" in lines[index + 1] and "---" in lines[index + 1]:
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
            bullet_match = re.match(r"^(?:[-*+]\s+|\d+[.)]\s+)(.+)$", stripped)
            if bullet_match:
                entries = []
                while index < len(lines):
                    item = re.match(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)(.+)$", lines[index])
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
                if not candidate or candidate.startswith("```") or re.match(r"^(#{1,6})\s+|^(?:[-*+]\s+|\d+[.)]\s+)|^>", candidate):
                    break
                if "|" in candidate and index + 1 < len(lines) and "---" in lines[index + 1]:
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
    story: list[Any] = [
        Paragraph("灵枢授权安全测试报告", title),
        Paragraph(f"会话编号：{_safe_text(session_id)}", body),
        Spacer(1, 5 * mm),
    ]
    metadata = [
        ["任务名称", mission.get("title") or "安全测试任务"],
        ["授权目标", mission.get("target") or "未记录"],
        ["任务目标", mission.get("goal") or "未记录"],
        ["最终阶段", mission.get("phase") or "未知"],
        ["执行结果", "成功" if mission.get("success") is True else "失败/未完成"],
        ["生成时间", mission.get("updated_at") or ""],
    ]
    table = Table(
        [[Paragraph(_safe_text(k), body), Paragraph(_safe_text(v), body)] for k, v in metadata],
        colWidths=[32 * mm, 120 * mm],
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
    story.extend([table, PageBreak(), Paragraph("Summary Agent 总结", heading)])
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

    try:
        document.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
        os.replace(temporary_name, destination)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return destination
