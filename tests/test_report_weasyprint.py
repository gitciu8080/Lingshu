"""专业 PDF 报告渲染链回归测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader

from Tools.Report import generate_mission_pdf
from Tools.WeasyReport import (
    _url_fetcher,
    normalize_report_markdown,
    validate_report_markdown,
)


class ReportMarkdownContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mission = {
            "target": "本地排版测试",
            "goal": "验证专业 PDF 报告",
            "phase": "completed",
            "success": True,
            "updated_at": "2026-08-21T20:00:00",
            "plan_items": [],
            "findings": [],
            "attack_chain": [],
        }

    def test_missing_sections_are_deterministically_repaired(self) -> None:
        normalized, repaired = normalize_report_markdown(
            "# 执行摘要\n\n任务正常结束。",
            self.mission,
        )
        self.assertEqual(len(repaired), 5)
        self.assertEqual(validate_report_markdown(normalized), [])
        for section in (
            "一、概述", "二、测试结论", "三、测试综述",
            "四、测试结果", "五、安全等级与建议",
        ):
            self.assertIn(f"# {section}", normalized)

    def test_sections_are_required_as_h1_and_reordered(self) -> None:
        source = """# 五、安全等级与建议

建议正文。

# 一、概述

正文里提到二、测试结论，但这不是一级标题。

# 四、测试结果

没有漏洞。

# 三、测试综述

执行过程。
"""
        normalized, repaired = normalize_report_markdown(source, self.mission)
        self.assertEqual(repaired, ["二、测试结论"])
        positions = [normalized.index(f"# {title}") for title in (
            "一、概述", "二、测试结论", "三、测试综述",
            "四、测试结果", "五、安全等级与建议",
        )]
        self.assertEqual(positions, sorted(positions))

    def test_old_inline_page_break_and_dangerous_html_are_removed(self) -> None:
        source = (
            '<script>alert("x")</script>\n'
            '<div style="page-break-after: always;"></div>\n'
            '<h1 style="color:red">一、概述</h1>\n正文'
        )
        normalized, _ = normalize_report_markdown(source, self.mission)
        self.assertNotIn("<script", normalized)
        self.assertNotIn("page-break-after", normalized)
        self.assertNotIn("style=", normalized)
        self.assertIn("# 一、概述", normalized)

    def test_url_fetcher_rejects_local_files_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed:
            fetch = _url_fetcher((Path(allowed),))
            with self.assertRaises(ValueError):
                fetch(Path("/etc/passwd").as_uri())


class WeasyPrintPDFTest(unittest.TestCase):
    def test_pdf_contains_cover_sections_table_and_page_numbers(self) -> None:
        summary = """# 一、概述

这是中文字体渲染测试。

# 二、测试结论

| 项目 | 状态 |
|---|---|
| 中文字体 | 通过 |

# 三、测试综述

1. 汇总证据。
2. 生成报告。

# 四、测试结果

## 4.1 排版验证

```bash
python -m py_compile Tools/WeasyReport.py
```

# 五、安全等级与建议

保持内容与物理排版解耦。
"""
        mission = {
            "target": "灵枢·利刃报告测试",
            "goal": "验证 A4、中文字体、表格和代码块",
            "phase": "completed",
            "success": True,
            "updated_at": "2026-08-21T20:00:00",
            "plan_items": [],
            "findings": [],
            "attack_chain": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = generate_mission_pdf(
                "report-render-test",
                summary,
                mission,
                directory,
            )
            self.assertGreater(path.stat().st_size, 50_000)
            self.assertEqual(path.read_bytes()[:4], b"%PDF")
            reader = PdfReader(path)
            self.assertGreaterEqual(len(reader.pages), 6)
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            self.assertIn("灵枢·利刃 Agent", text)
            self.assertIn("中文字体", text)
            self.assertIn("五、安全等级与建议", text)
            self.assertIn("共", text)


if __name__ == "__main__":
    unittest.main()
