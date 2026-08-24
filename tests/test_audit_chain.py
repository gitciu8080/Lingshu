"""审计链哈希测试：单调序号、previous_hash/event_hash、篡改检测、legacy 兼容。

覆盖计划验收项：
- 审计测试：更新计划后历史 plan_item_added 不变化；篡改事件导致 hash 校验失败。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.TaskState import (
    MissionState,
    MissionStore,
    AuditEvent,
    verify_audit_chain,
)


class AuditChainTest(unittest.TestCase):
    def test_chain_is_monotonic_and_linked(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.record("Brain", "plan_drafted", items=2)
        mission.record("Orchestrator", "phase_transition", previous="planning", current="recon")

        events = mission.events
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].seq, 1)
        self.assertEqual(events[1].seq, 2)
        # 链式：后一条的 previous_hash 是前一条的 event_hash
        self.assertEqual(events[1].previous_hash, events[0].event_hash)
        # 首条的 previous_hash 是创世锚
        self.assertTrue(events[0].previous_hash)

        ok, bad = verify_audit_chain(events)
        self.assertTrue(ok)
        self.assertEqual(bad, 0)

    def test_tampered_event_fails_verification(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.record("Brain", "plan_drafted", items=2)
        mission.record("Orchestrator", "phase_transition")

        # 篡改第一条事件的 details（模拟写入后修改/攻击）
        mission.events[0].details["items"] = 999
        ok, bad = verify_audit_chain(mission.events)
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_breaking_link_fails_verification(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.record("Brain", "a")
        mission.record("Brain", "b")
        mission.record("Brain", "c")
        # 删除中间事件 → 链接断裂
        del mission.events[1]
        ok, bad = verify_audit_chain(mission.events)
        self.assertFalse(ok)

    def test_details_deepcopied_on_record(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        details = {"nested": {"value": 1}}
        mission.record("Brain", "x", **details)
        details["nested"]["value"] = 2  # 调用方后续修改
        self.assertEqual(mission.events[0].details["nested"]["value"], 1)
        self.assertTrue(verify_audit_chain(mission.events)[0])

    def test_legacy_events_are_skipped(self) -> None:
        """旧事件（无 event_hash）作为 legacy 保留，不校验也不回写。"""
        legacy = [
            AuditEvent(timestamp="2026-01-01T00:00:00+08:00", actor="system",
                       action="mission_created", phase="planning", details={}),
            AuditEvent(timestamp="2026-01-01T00:00:01+08:00", actor="Brain",
                       action="plan_drafted", phase="planning", details={}),
        ]
        ok, bad = verify_audit_chain(legacy)
        self.assertTrue(ok)
        self.assertEqual(bad, 0)

    def test_mixed_legacy_and_hashed(self) -> None:
        mission = MissionState(target="t", goal="g", authorized=True)
        # 注入一条 legacy 事件再追加哈希事件
        mission.events.append(
            AuditEvent(timestamp="old", actor="system", action="legacy",
                       phase="planning", details={}),
        )
        mission.record("Brain", "new_event")
        ok, _ = verify_audit_chain(mission.events)
        self.assertTrue(ok)


class AuditChainPersistenceTest(unittest.TestCase):
    def test_roundtrip_preserves_hashes(self) -> None:
        path = Path(tempfile.mkdtemp(prefix="lingshu-audit-")) / "mission.json"
        store = MissionStore(path)
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.record("Brain", "plan_drafted", items=3)
        mission.record("Orchestrator", "phase_transition")
        store.save(mission)

        loaded = store.load()
        self.assertIsInstance(loaded.events[0], AuditEvent)
        self.assertEqual(loaded.events[0].seq, 1)
        self.assertEqual(loaded.events[1].previous_hash, loaded.events[0].event_hash)
        ok, bad = verify_audit_chain(loaded.events)
        self.assertTrue(ok)
        self.assertEqual(bad, 0)

    def test_tampered_persisted_file_fails_verification(self) -> None:
        path = Path(tempfile.mkdtemp(prefix="lingshu-audit-")) / "mission.json"
        store = MissionStore(path)
        mission = MissionState(target="t", goal="g", authorized=True)
        mission.record("Brain", "plan_drafted")
        store.save(mission)

        # 直接篡改磁盘 JSON 中的 details
        data = json.loads(path.read_text(encoding="utf-8"))
        data["events"][0]["details"]["tampered"] = True
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        loaded = store.load()
        ok, bad = verify_audit_chain(loaded.events)
        self.assertFalse(ok)
        self.assertEqual(bad, 1)


if __name__ == "__main__":
    unittest.main()
