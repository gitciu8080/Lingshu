"""P1 长期记忆检索增强回归测试（c5ca9b2b 复盘）。

覆盖 query_experience 的包含匹配与种子经验可查询性：
- 大小写不敏感、双向包含匹配命中 techniques 键（精确匹配为特例不回退）；
- 种子 UPX 手册能被 "UPX"/"upx unpacking" 等查询命中；
- 无关服务查询不受影响。

真实记忆文件不可在测试中改写：用 patch 替换 _load 的返回值。
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from Tools import AgenticMemory

_SEED_TECHNIQUES = {
    "UPX 加壳/脱壳": [
        {
            "cve": "UPX 头篡改处置：恢复节名 UPX0/UPX1/UPX2 与 UPX! 魔数后重试 upx -d",
            "timestamp": "2026-08-27T12:00:00",
            "success": True,
        }
    ],
    "Apache 2.4.49": [
        {"cve": "CVE-2021-41773", "timestamp": "2026-01-01", "success": True}
    ],
}

_SEED_MISSIONS = [
    {
        "timestamp": "2026-08-27T12:00:00",
        "target": "[本地文件样本]",
        "goal": "UPX 加壳逆向",
        "plan": "UPX unpacking / UPX 脱壳：修复头部后手动脱壳",
        "attack_chain": [],
        "success": False,
        "summary": "upx -d 报 CantUnpackException 时修复节名与魔数后重试",
        "flag": None,
    }
]


class QueryExperienceContainmentTest(unittest.TestCase):
    def _query(self, service: str):
        data = {"missions": _SEED_MISSIONS, "techniques": _SEED_TECHNIQUES}
        with patch.object(AgenticMemory, "_load", return_value=data):
            return AgenticMemory.query_experience(service=service)

    def test_exact_key_match_still_works(self) -> None:
        result = self._query("Apache 2.4.49")
        self.assertEqual(len(result["known_exploits"]), 1)
        self.assertEqual(result["known_exploits"][0]["cve"], "CVE-2021-41773")

    def test_case_insensitive_containment_hits_seeded_manual(self) -> None:
        for query in ("UPX", "upx", "upx 加壳"):
            result = self._query(query)
            self.assertEqual(len(result["known_exploits"]), 1, query)
            self.assertIn("UPX 头篡改处置", result["known_exploits"][0]["cve"])

    def test_query_containing_key_hits(self) -> None:
        # 查询词包含键（查询更具体）也应命中
        result = self._query("如何做 UPX 加壳/脱壳 手动脱壳")
        self.assertEqual(len(result["known_exploits"]), 1)

    def test_unrelated_service_not_matched(self) -> None:
        result = self._query("nginx 1.20")
        self.assertEqual(result["known_exploits"], [])
        # 未命中时 related_missions 按 plan 子串匹配，不应误中种子任务
        self.assertEqual(result["related_missions"], [])

    def test_related_missions_matched_by_plan_substring(self) -> None:
        result = self._query("UPX unpacking")
        self.assertEqual(len(result["related_missions"]), 1)
        formatted = AgenticMemory._format_experience(result, "UPX unpacking")
        self.assertIn("CantUnpackException", formatted)

    def test_formatted_miss_keeps_guidance(self) -> None:
        result = self._query("nginx 1.20")
        formatted = AgenticMemory._format_experience(result, "nginx 1.20")
        self.assertIn("未找到", formatted)


if __name__ == "__main__":
    unittest.main()
