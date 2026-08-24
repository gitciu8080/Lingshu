"""循环收敛测试：动作指纹、错误类型累计、熔断阈值、计划项 interrupted。

覆盖计划验收项：
- 循环测试：相同连接拒绝或相同 Payload 第三次被熔断，有新证据时允许新动作。
"""

from __future__ import annotations

import unittest

from core.TaskState import MissionState
from Tools.fingerprint import (
    MAX_ACTION_RETRIES,
    compute_action_fingerprint,
    error_type,
    mark_plan_item_blocked,
    should_meltdown,
)


class FingerprintTest(unittest.TestCase):
    def test_same_action_same_fingerprint(self) -> None:
        fp1 = compute_action_fingerprint(
            "dispatch_attack", "10.0.0.1:80",
            {"target_info": "Apache 2.4.49", "objective": "验证 CVE-2021-41773"},
            "验证 RCE", 3,
        )
        fp2 = compute_action_fingerprint(
            "dispatch_attack", "10.0.0.1:80",
            {"target_info": "Apache 2.4.49", "objective": "验证 CVE-2021-41773"},
            "验证 RCE", 3,
        )
        self.assertEqual(fp1, fp2)

    def test_equivalent_params_same_fingerprint(self) -> None:
        """规范化参数：键顺序不同但内容等价 → 同一指纹。"""
        fp1 = compute_action_fingerprint(
            "t", "h", {"a": 1, "b": 2}, "obj", 1,
        )
        fp2 = compute_action_fingerprint(
            "t", "h", {"b": 2, "a": 1}, "obj", 1,
        )
        self.assertEqual(fp1, fp2)

    def test_different_objective_or_target_changes_fingerprint(self) -> None:
        base = compute_action_fingerprint("t", "10.0.0.1", {}, "obj", 1)
        other_obj = compute_action_fingerprint("t", "10.0.0.1", {}, "改写后的措辞", 1)
        other_target = compute_action_fingerprint("t", "10.0.0.2", {}, "obj", 1)
        self.assertNotEqual(base, other_obj)
        self.assertNotEqual(base, other_target)

    def test_new_evidence_version_allows_new_action(self) -> None:
        """有新增证据（evidence_version 变化）→ 新指纹，允许新动作。"""
        fp1 = compute_action_fingerprint("t", "h", {}, "obj", 1)
        fp2 = compute_action_fingerprint("t", "h", {}, "obj", 2)
        self.assertNotEqual(fp1, fp2)


class ErrorTypeTest(unittest.TestCase):
    def test_deterministic_errors_identified(self) -> None:
        self.assertEqual(error_type("Connection refused to 10.0.0.1:80"), "connection_refused")
        self.assertEqual(error_type("命令超时 timeout after 300s"), "timeout")
        self.assertEqual(error_type("HTTP 404 Not Found"), "http_404")
        self.assertEqual(error_type("403 Forbidden"), "http_403")
        self.assertEqual(error_type("flag 错误 wrong flag"), "invalid_flag")
        self.assertEqual(error_type("authentication failed"), "auth_failed")

    def test_no_match_returns_none(self) -> None:
        self.assertIsNone(error_type("扫描完成，端口 80 开放"))
        self.assertIsNone(error_type(""))


class MeltdownTest(unittest.TestCase):
    def test_threshold_is_max_retries(self) -> None:
        fp = "fp1"
        counters = {fp: MAX_ACTION_RETRIES}
        self.assertTrue(should_meltdown(counters, fp))
        counters = {fp: MAX_ACTION_RETRIES - 1}
        self.assertFalse(should_meltdown(counters, fp))

    def test_third_failure_meltdown(self) -> None:
        """相同动作+相同错误：第 3 次调用前熔断（实际只执行 2 次）。"""
        fp = "fp-conn-refused"
        counters: dict[str, int] = {}
        # 第 1 次执行前（计数 0）→ 允许；失败后计数 1
        self.assertFalse(should_meltdown(counters, fp))
        counters[fp] = 1
        # 第 2 次执行前（计数 1）→ 允许；失败后计数 2
        self.assertFalse(should_meltdown(counters, fp))
        counters[fp] = 2
        # 第 3 次执行前（计数 2）→ 熔断
        self.assertTrue(should_meltdown(counters, fp))

    def test_mark_plan_item_interrupted(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.plan_items.append(
            {"id": "p1", "content": "验证漏洞", "phase": "exploitation",
             "status": "in_progress", "evidence": "", "origin": "orchestrator"},
        )
        marked = mark_plan_item_blocked(mission, "fp-x", "第三次熔断")
        self.assertEqual(marked, "p1")
        self.assertEqual(mission.plan_items[0]["status"], "interrupted")
        self.assertIn("interrupt_reason", mission.plan_items[0])
        # 审计记录熔断事件
        self.assertTrue(any(e.action == "plan_item_meltdown" for e in mission.events))


if __name__ == "__main__":
    unittest.main()
