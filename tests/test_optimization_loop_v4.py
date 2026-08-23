"""第一批优化闭环：结构化状态、二次分类与独立预算。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from TaskState import MissionState, MissionStore
from Tools.target import normalize_target
from agent.Attack import _build_skill_list
from agent.categorize import CategoryDecision, evaluate_reclassification
from main import (
    _commit_recon_reclassification,
    _max_react_iters,
    _mission_complexity,
)


class StructuredStateTest(unittest.TestCase):
    def test_fact_attempt_and_evidence_roundtrip(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-v4-state-"))
        store = MissionStore(root / "mission.json")
        mission = MissionState(target="challenge", goal="获取 Flag", authorized=True)
        attempt = mission.begin_attempt("recon", "Iris", "challenge", {"focus": "file"})
        evidence = mission.add_evidence("Iris", "recon_report", "ELF 64-bit LSB executable")
        fact = mission.add_fact(
            "工具输出确认目标是 ELF 64-bit",
            "Iris",
            [evidence.id],
            category="pwn",
            confidence=0.95,
        )
        mission.finish_attempt(attempt, "success", "识别完成", [evidence.id], "high")
        store.save(mission)

        loaded = store.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.facts[0].id, fact.id)
        self.assertEqual(loaded.attempts[0].status, "success")
        self.assertEqual(loaded.evidence_records[0].id, evidence.id)
        self.assertEqual(len(loaded.attempts), 1)


class ReclassificationIntegrationTest(unittest.TestCase):
    def test_recon_changes_final_category_and_attack_skills(self) -> None:
        mission = MissionState(target="challenge", goal="分析附件", authorized=True)
        previous = CategoryDecision(
            primary="unknown", confidence=0.0, scores={}, evidence=["初始无结论"],
        )
        final, result, evidence = _commit_recon_reclassification(
            mission,
            previous,
            "challenge: ELF 64-bit LSB executable, x86-64",
            "Iris - 文件分析专家",
        )
        self.assertTrue(result.accepted)
        self.assertEqual(final.primary, "pwn")
        self.assertEqual(mission.category_decision["primary"], "pwn")
        self.assertEqual(mission.category_history[-1]["evidence_id"], evidence.id)
        self.assertGreaterEqual(len(mission.facts), 1)

        skills = _build_skill_list(mission.category_decision, Path(__file__).parents[1])
        self.assertTrue(any("ctf-pwn" in item for item in skills))
        self.assertFalse(any("ctf-web" in item for item in skills))

    def test_same_recon_batch_is_not_scored_twice(self) -> None:
        previous = CategoryDecision(primary="unknown", confidence=0.0)
        report = "challenge: ELF 64-bit LSB executable"
        first = evaluate_reclassification(previous, [report])
        second = evaluate_reclassification(
            previous,
            [report],
            seen_evidence_fingerprints={first.evidence_fingerprint},
        )
        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        self.assertIn("重复计分", second.reason)


class IndependentBudgetTest(unittest.TestCase):
    def test_simple_and_complex_have_different_budgets(self) -> None:
        spec = normalize_target("http://127.0.0.1:8080")
        simple_decision = CategoryDecision(
            primary="web", confidence=1.0, scores={"web": 4.0},
        )
        complex_decision = CategoryDecision(primary="unknown", confidence=0.0)
        self.assertEqual(_mission_complexity(spec, "获取 Flag", None, simple_decision), "simple")
        self.assertEqual(_mission_complexity(spec, "获取 Flag", None, complex_decision), "complex")
        self.assertLess(
            _max_react_iters("network", "attack", "simple"),
            _max_react_iters("network", "attack", "complex"),
        )


class RemovedBudgetCompatibilityTest(unittest.TestCase):
    def test_legacy_budget_fields_are_discarded_on_load(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="lingshu-no-budget-"))
        store = MissionStore(root / "mission.json")
        mission = MissionState(target="t", goal="g", authorized=True)
        payload = mission.to_dict()
        payload["action_budget"] = {"limit": 1, "used": 1}
        payload["tool_budget"] = {"limit": 1, "used": 1}
        store.path.write_text(__import__("json").dumps(payload), encoding="utf-8")
        loaded = store.load()
        self.assertFalse(hasattr(loaded, "action_budget"))
        self.assertFalse(hasattr(loaded, "tool_budget"))


if __name__ == "__main__":
    unittest.main()
