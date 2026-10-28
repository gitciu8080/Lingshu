"""验证闭环测试：verify 块提取、重放判定、Evidence schema 兼容、验证器三态。"""
from __future__ import annotations

import asyncio
import unittest

from agent.categorize import extract_verify_block, verify_output_matches
from core.TaskState import EvidenceRecord, MissionState


class ExtractVerifyBlockTest(unittest.TestCase):
    def test_full_block(self) -> None:
        report = """## 攻击报告
已验证 SQL 注入。

```verify
command: curl -s http://1.2.3.4/?id=1' --max-time 10
expected: SQL syntax
expected: mysql
```
"""
        block = extract_verify_block(report)
        self.assertIsNotNone(block)
        self.assertEqual(block["status"], "unverified")
        self.assertIn("curl -s http://1.2.3.4/", block["replay_command"])
        self.assertEqual(block["expected_lines"], ["SQL syntax", "mysql"])
        self.assertTrue(block["expected_fingerprint"])

    def test_multiline_command(self) -> None:
        report = """```verify
command: curl -s http://t/ -H 'X: 1'
command:   --max-time 5
expected: admin
```"""
        block = extract_verify_block(report)
        self.assertIsNotNone(block)
        self.assertIn("\n", block["replay_command"])

    def test_no_block_or_missing_command(self) -> None:
        self.assertIsNone(extract_verify_block("普通报告，无验证块"))
        self.assertIsNone(extract_verify_block("```verify\nexpected: only\n```"))
        self.assertIsNone(extract_verify_block(None))

    def test_short_expected_filtered(self) -> None:
        block = extract_verify_block(
            "```verify\ncommand: id\nexpected: ok\nexpected: uid=33(www-data)\n```")
        self.assertEqual(block["expected_lines"], ["uid=33(www-data)"])


class VerifyOutputMatchTest(unittest.TestCase):
    def test_all_lines_present(self) -> None:
        self.assertTrue(verify_output_matches(
            "uid=33(www-data)\nSQL syntax error", ["sql syntax", "uid=33"]))

    def test_missing_line_fails(self) -> None:
        self.assertFalse(verify_output_matches("mysql 5.7", ["SQL syntax"]))

    def test_empty_expected_passes(self) -> None:
        self.assertTrue(verify_output_matches("", []))


class EvidenceSchemaTest(unittest.TestCase):
    def test_verification_field_defaults_none(self) -> None:
        record = EvidenceRecord(id="e1", source="Attack", kind="attack_report",
                                summary="r", confidence=0.8)
        self.assertIsNone(record.verification)

    def test_old_json_without_verification_loads(self) -> None:
        # 旧任务 JSON 无 verification 键 → EvidenceRecord(**item) 走默认值
        item = {"id": "e1", "source": "Attack", "kind": "attack_report",
                "summary": "旧数据", "confidence": 0.8}
        record = EvidenceRecord(**item)
        self.assertIsNone(record.verification)

    def test_roundtrip_keeps_verification(self) -> None:
        from dataclasses import asdict
        record = EvidenceRecord(
            id="e1", source="Attack", kind="attack_report", summary="r",
            confidence=0.8, verification={"status": "verified",
                                          "replay_command": "id",
                                          "expected_fingerprint": "ab" * 8})
        data = asdict(record)
        restored = EvidenceRecord(**data)
        self.assertEqual(restored.verification["status"], "verified")


class VerifierPassTest(unittest.TestCase):
    """Orchestrator 内联 _verify_findings 的行为经 complete_mission 驱动。

    这里直接驱动核心逻辑等价路径：构造 mission + evidence，模拟 runner。
    完整 Orchestrator 工厂依赖较重，验证器行为用等价内核覆盖：
    """

    def _run(self, coro):  # noqa: ANN001
        return asyncio.run(coro)

    def test_verified_failed_and_unverified_states(self) -> None:
        mission = MissionState(target="1.2.3.4", goal="g", authorized=True)
        good = mission.add_evidence("Attack", "attack_report", "报告A",
                                    confidence=0.8)
        good.verification = extract_verify_block(
            "```verify\ncommand: curl -s http://1.2.3.4/\nexpected: welcome\n```")
        bad = mission.add_evidence("Attack", "attack_report", "报告B",
                                   confidence=0.8)
        bad.verification = extract_verify_block(
            "```verify\ncommand: curl -s http://1.2.3.4/gone\nexpected: secret_page\n```")
        none_poc = mission.add_evidence("Attack", "attack_report", "报告C",
                                        confidence=0.8)
        low = mission.add_evidence("Attack", "attack_report", "报告D",
                                   confidence=0.5)

        calls: list[str] = []

        async def runner(command: str) -> dict:
            calls.append(command)
            if "gone" in command:
                return {"returncode": 0, "stdout": "404 not found", "stderr": "",
                        "timed_out": False, "error": ""}
            return {"returncode": 0, "stdout": "welcome page", "stderr": "",
                    "timed_out": False, "error": ""}

        async def verify() -> None:
            for evidence in mission.evidence_records:
                if evidence.kind != "attack_report" or evidence.confidence < 0.8:
                    continue
                verification = evidence.verification
                if verification is None:
                    evidence.verification = {"status": "unverified"}
                    continue
                outcome = await runner(verification["replay_command"])
                passed = (outcome["returncode"] == 0 and verify_output_matches(
                    outcome["stdout"], verification.get("expected_lines") or []))
                verification["status"] = "verified" if passed else "failed"
                if not passed:
                    evidence.confidence = min(evidence.confidence, 0.5)

        self._run(verify())
        self.assertEqual(good.verification["status"], "verified")
        self.assertEqual(bad.verification["status"], "failed")
        self.assertLessEqual(bad.confidence, 0.5)
        self.assertEqual(none_poc.verification, {"status": "unverified"})
        self.assertIsNone(low.verification)
        self.assertEqual(len(calls), 2)   # 无 PoC / 低置信不重放


if __name__ == "__main__":
    unittest.main()
