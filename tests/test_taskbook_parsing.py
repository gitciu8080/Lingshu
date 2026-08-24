"""任务书多格式解析与旧状态兼容测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from main import _extract_declared_network_targets, _read_taskbook_text


class TaskbookParsingTest(unittest.TestCase):
    def test_network_targets_from_markdown_report(self) -> None:
        report = "**目标服务器**：`10.8.128.122`\n**所在网段**：`10.8.128.0/24`"
        self.assertIn("10.8.128.122", _extract_declared_network_targets(report))

    def test_markdown_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            md = root / "task.md"
            md.write_text("# 渗透测试\n目标：10.8.128.122\n", encoding="utf-8")
            self.assertIn("10.8.128.122", _read_taskbook_text(md))
            html = root / "task.html"
            html.write_text("<h1>授权测试</h1><script>ignore()</script><p>10.8.128.123</p>", encoding="utf-8")
            parsed = _read_taskbook_text(html)
            self.assertIn("授权测试", parsed)
            self.assertNotIn("ignore", parsed)

    def test_xlsx_and_pptx(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            from openpyxl import Workbook
            workbook = Workbook()
            workbook.active["A1"] = "目标服务器"
            workbook.active["B1"] = "10.8.128.124"
            xlsx = root / "task.xlsx"
            workbook.save(xlsx)
            self.assertIn("10.8.128.124", _read_taskbook_text(xlsx))

            from pptx import Presentation
            from pptx.util import Inches
            presentation = Presentation()
            slide = presentation.slides.add_slide(presentation.slide_layouts[6])
            box = slide.shapes.add_textbox(Inches(1), Inches(1), Inches(5), Inches(1))
            box.text = "授权测试 10.8.128.125"
            pptx = root / "task.pptx"
            presentation.save(pptx)
            self.assertIn("10.8.128.125", _read_taskbook_text(pptx))


if __name__ == "__main__":
    unittest.main()
