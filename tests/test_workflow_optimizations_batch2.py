"""第二批标准模式优化（O7-O13）回归测试。

O7 resume 且已有计划时跳过 Brain 重规划（保住 plan_items 进度、防阶段回退）
O8 findings/attack_chain 摘要化、asset_updated 仅实质变化、未接受翻盘轻量历史
O9 context_layers 的 task 截断 1500
O10 Analysis 共享锁传入 Attack/Reserve 装配
O11 nudge/final_continuation 触发剔除纯 pending 残留（源码契约）
O12 pending hint 预算 3 次 + 耗尽代收（源码契约）
O13 SUMMARY_SCHEMA 增 key_runtime_state、plan_items/flag_submission 类型放宽、
    模板与 required 一一对应、分诊集合同步
"""
from __future__ import annotations

import ast
import re
import tempfile
import unittest
from pathlib import Path

from agent.context import SUMMARY_SCHEMA, SUMMARY_TEMPLATE
from core.TaskState import MissionState, MissionStore, Phase

ROOT = Path(__file__).resolve().parent.parent


class ResumeSkipPlanningTest(unittest.TestCase):
    """O7：主循环分叉含 resume 短路分支。"""

    def test_elif_guard_exists(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn(
            "elif resume and mission.plan_items and mission.phase != Phase.PLANNING:",
            src,
        )
        self.assertIn("brain_planning_skipped_on_resume", src)


class TaskStateSlimTest(unittest.TestCase):
    """O8：mission JSON 数据瘦身。"""

    def _mission(self) -> MissionState:
        m = MissionState(target="1.2.3.4", goal="g", authorized=True)
        m.transition(Phase.RECON, "t")
        m.transition(Phase.ANALYSIS, "t")
        return m

    def test_finding_truncated_to_2000(self) -> None:
        m = self._mission()
        m.add_finding("Recon", "x" * 5000)
        self.assertEqual(len(m.findings[-1]["report"]), 2000)

    def test_attack_step_truncated_to_800(self) -> None:
        m = self._mission()
        m.add_attack_step("目标", "y" * 3000)
        self.assertEqual(len(m.attack_chain[-1]["report"]), 800)

    def test_asset_updated_only_on_change(self) -> None:
        m = self._mission()
        m.add_asset(host="10.0.0.1", port=80, service="nginx", evidence_ids=[])
        before = len([e for e in m.events if getattr(e, "action", "") == "asset_updated"])
        # 纯 last_seen 刷新（无任何实质变化）不再记审计
        m.add_asset(host="10.0.0.1", port=80, service="nginx", evidence_ids=[])
        after = len([e for e in m.events if getattr(e, "action", "") == "asset_updated"])
        self.assertEqual(before, after)
        # service 变化 → 记审计
        m.add_asset(host="10.0.0.1", port=80, service="apache", evidence_ids=[])
        final = len([e for e in m.events if getattr(e, "action", "") == "asset_updated"])
        self.assertEqual(final, before + 1)

    def test_context_layers_task_truncated(self) -> None:
        m = MissionState(target="1.2.3.4", goal="长" * 5000, authorized=True)
        m.transition(Phase.RECON, "t")
        layers = m.context_layers(limit=2)
        self.assertLessEqual(len(layers["core_state"]["task"]), 1500)


class SummarySchemaTest(unittest.TestCase):
    """O13：压缩 Schema 契约。"""

    def test_required_and_template_aligned(self) -> None:
        required = set(SUMMARY_SCHEMA["required"])
        placeholders = set(re.findall(r"\{(\w+)\}", SUMMARY_TEMPLATE))
        self.assertEqual(required, placeholders)

    def test_key_runtime_state_present(self) -> None:
        self.assertIn("key_runtime_state", SUMMARY_SCHEMA["properties"])
        self.assertIn("key_runtime_state", SUMMARY_SCHEMA["required"])
        self.assertIn("Key Runtime State", SUMMARY_TEMPLATE)

    def test_relaxed_types(self) -> None:
        self.assertEqual(
            SUMMARY_SCHEMA["properties"]["plan_items"]["type"], ["array", "string"],
        )
        self.assertEqual(
            SUMMARY_SCHEMA["properties"]["flag_submission"]["type"], ["object", "string"],
        )

    def test_diagnosis_set_in_sync(self) -> None:
        src = (ROOT / "agent" / "Orchestrator.py").read_text(encoding="utf-8")
        self.assertIn('"key_runtime_state", "next_action"', src)


class AssemblyContractTest(unittest.TestCase):
    """O10/O11/O12：装配与主循环源码契约（AST 级断言）。"""

    def test_analysis_lock_wired(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("analysis_lock = asyncio.Lock()", src)
        self.assertEqual(src.count("analysis_lock=analysis_lock,"), 2)  # attack+reserve

    def test_nudge_excludes_pending_only(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        # 触发条件（stalled_nudge/final_continuation 两处）已收紧为仅 in_progress；
        # 剩余一处 {"pending","in_progress"} 是终局续跑的未决项展示清单（合法保留）
        self.assertEqual(
            src.count('item.get("status") in {"pending", "in_progress"}'), 1,
        )
        self.assertGreaterEqual(src.count('item.get("status") == "in_progress"'), 2)

    def test_pending_hint_budget(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("pending_hint_budget = 3", src)
        self.assertIn("pending_reports_force_collected", src)

    def test_resume_guard_compiles(self) -> None:
        ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
