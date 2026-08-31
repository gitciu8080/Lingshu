"""CTF2 工作台的纯本地协议/选择逻辑测试。"""

from __future__ import annotations

import unittest

from workbench_ctf2 import _auto_challenge, _extract_flag


class Ctf2WorkbenchTest(unittest.TestCase):
    def test_auto_selection_skips_hidden_and_returns_first_visible_challenge(self) -> None:
        selected = _auto_challenge([
            {"id": "practice-a", "challenges": [
                {"id": "hidden", "title": "隐藏", "status": "hidden"},
                {"id": "challenge-a", "title": "Web 入门", "status": "active"},
            ]},
        ])
        self.assertEqual(selected, ("practice-a", "challenge-a", "Web 入门"))

    def test_flag_extraction_requires_single_brace_pair(self) -> None:
        self.assertEqual(_extract_flag("答案是 CTF2{safe_value}"), "CTF2{safe_value}")
        self.assertIsNone(_extract_flag("没有 Flag"))


if __name__ == "__main__":
    unittest.main()
