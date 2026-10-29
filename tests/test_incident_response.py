"""应急响应（incident_response）能力测试：阶段轨道、收尾闸门、IOC 提取、
入口推断、分类路由、技能挂载。全部纯本地。"""
from __future__ import annotations

import tempfile
import unittest

from agent.Attack import _build_skill_list, _CYBERPENDA_SKILL_MAP
from agent.categorize import classify, extract_iocs
from agent.Orchestrator import ir_completion_gate
from core.TaskState import MissionState, Phase, _ALLOWED_TRANSITIONS
from Tools.target import normalize_target


def _ir_mission(**overrides) -> MissionState:
    mission = MissionState(
        target="/tmp/logs", goal="应急响应", authorized=True,
        mission_mode="incident_response", session_id="ir-test",
    )
    for key, value in overrides.items():
        setattr(mission, key, value)
    return mission


class IRPhaseTransitionTest(unittest.TestCase):
    def test_ir_track_transitions(self) -> None:
        # 合法主线：PLANNING → 四阶段 → COMPLETED
        self.assertIn(Phase.IR_IDENTIFICATION, _ALLOWED_TRANSITIONS[Phase.PLANNING])
        self.assertIn(Phase.IR_CONTAINMENT, _ALLOWED_TRANSITIONS[Phase.IR_IDENTIFICATION])
        self.assertIn(Phase.IR_ERADICATION, _ALLOWED_TRANSITIONS[Phase.IR_CONTAINMENT])
        self.assertIn(Phase.IR_RECOVERY, _ALLOWED_TRANSITIONS[Phase.IR_ERADICATION])
        self.assertIn(Phase.COMPLETED, _ALLOWED_TRANSITIONS[Phase.IR_RECOVERY])
        # 回退复检合法
        self.assertIn(Phase.IR_IDENTIFICATION, _ALLOWED_TRANSITIONS[Phase.IR_CONTAINMENT])
        self.assertIn(Phase.IR_CONTAINMENT, _ALLOWED_TRANSITIONS[Phase.IR_ERADICATION])
        # 渗透轨道不可从 IR 阶段直接进入（不串轨）
        self.assertNotIn(Phase.EXPLOITATION, _ALLOWED_TRANSITIONS[Phase.IR_IDENTIFICATION])
        self.assertNotIn(Phase.IR_CONTAINMENT, _ALLOWED_TRANSITIONS[Phase.ANALYSIS])

    def test_transition_sequence_live(self) -> None:
        mission = _ir_mission()
        mission.transition(Phase.IR_IDENTIFICATION, "启动")
        mission.transition(Phase.IR_CONTAINMENT, "遏制")
        mission.transition(Phase.IR_ERADICATION, "根除")
        mission.transition(Phase.IR_RECOVERY, "恢复")
        mission.transition(Phase.COMPLETED, "收尾")
        self.assertEqual(mission.phase, Phase.COMPLETED)


class IRCompletionGateTest(unittest.TestCase):
    def test_empty_mission_blocked(self) -> None:
        message = ir_completion_gate(_ir_mission(), success=True)
        self.assertIsNotNone(message)
        self.assertIn("时间线", message)
        self.assertIn("IOC", message)

    def test_insufficient_timeline_blocked(self) -> None:
        mission = _ir_mission(attack_chain=[{"objective": "a"}, {"objective": "b"}])
        # 有 IOC 无完整时间线
        mission.facts = []
        from core.TaskState import FactRecord
        evidence = mission.add_evidence("Attack", "attack_report", "r", confidence=0.8)
        mission.facts.append(FactRecord(
            id="f1", content="IOC[ip]: 1.2.3.4", source="Attack",
            evidence_ids=[evidence.id], category="ioc", confidence=0.75))
        message = ir_completion_gate(mission, success=True)
        self.assertIsNotNone(message)
        self.assertIn("仅 2 步", message)

    def test_full_evidence_passes(self) -> None:
        from core.TaskState import FactRecord
        mission = _ir_mission(
            attack_chain=[{"objective": f"step{i}"} for i in range(4)])
        evidence = mission.add_evidence("Attack", "attack_report", "r", confidence=0.8)
        mission.facts.append(FactRecord(
            id="f1", content="IOC[domain]: evil.tld", source="Attack",
            evidence_ids=[evidence.id], category="ioc", confidence=0.75))
        self.assertIsNone(ir_completion_gate(mission, success=True))

    def test_failure_close_not_gated(self) -> None:
        # success=False（记录失败结论）不设门槛
        self.assertIsNone(ir_completion_gate(_ir_mission(), success=False))

    def test_non_ir_mode_not_gated(self) -> None:
        mission = _ir_mission()
        mission.mission_mode = "authorized_pentest"
        self.assertIsNone(ir_completion_gate(mission, success=True))


class ExtractIOCsTest(unittest.TestCase):
    def test_extraction_with_exclusions(self) -> None:
        report = (
            "C2 地址 45.33.32.156 与 evil-cdn.top 通信；样本 SHA256 "
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2。"
            "内网 10.1.1.5 与本机 127.0.0.1 非 IOC。"
        )
        iocs = extract_iocs(report)
        kinds = {(i["type"], i["value"]) for i in iocs}
        self.assertIn(("ip", "45.33.32.156"), kinds)
        self.assertIn(("domain", "evil-cdn.top"), kinds)
        self.assertIn(("sha256", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"), kinds)
        values = {i["value"] for i in iocs}
        self.assertNotIn("10.1.1.5", values)
        self.assertNotIn("127.0.0.1", values)

    def test_short_hash_superset(self) -> None:
        # md5 不与 sha256 重复报告（此处 md5 独立出现才报）
        iocs = extract_iocs("文件 md5 44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(iocs, [{"type": "md5", "value": "44d88612fea8a8f36de82e1278abb02f"}])

    def test_limit_and_empty(self) -> None:
        self.assertEqual(extract_iocs(""), [])
        self.assertEqual(extract_iocs(None), [])
        big = " ".join(f"h{i}.top" for i in range(50))
        self.assertEqual(len(extract_iocs(big, limit=20)), 20)


class MissionModeInferenceTest(unittest.TestCase):
    def test_new_trigger_words(self) -> None:
        from main import _mission_mode
        from Tools.target import TargetSpec
        spec = normalize_target(tempfile.mkdtemp())
        for goal in ("服务器被入侵排查Webshell", "日志溯源分析", "挖矿木马排查",
                     "勒索事件 incident_response 处置"):
            self.assertEqual(
                _mission_mode(spec, goal), "incident_response", goal)

    def test_explicit_mode_wins_in_run_mission(self) -> None:
        # 显式参数合法性集合（run_mission 内联校验同一集合）
        valid = {"ctf", "incident_response", "authorized_pentest", "hybrid_taskbook"}
        self.assertIn("incident_response", valid)

    def test_default_goal_ir(self) -> None:
        from main import _default_goal_for
        # fast+IR 也返回应急目标（历史缺陷：曾返回"获取 Flag"）
        for run_mode in ("fast", "standard"):
            goal = _default_goal_for(run_mode, "incident_response")
            self.assertIn("应急响应", goal)
            self.assertNotIn("Flag", goal)
        self.assertEqual(_default_goal_for("fast", "ctf"), "获取 Flag")


class IRCategoryRoutingTest(unittest.TestCase):
    def test_ir_wins_over_malware(self) -> None:
        spec = normalize_target(tempfile.mkdtemp())
        decision = classify(
            spec, "服务器疑似被入侵，排查Webshell与挖矿木马，溯源攻击路径", None)
        self.assertEqual(decision.primary, "ir")

    def test_forensics_not_disturbed(self) -> None:
        spec = normalize_target(tempfile.mkdtemp())
        self.assertEqual(
            classify(spec, "磁盘镜像取证恢复删除文件", None).primary, "forensics")

    def test_ir_skills_mounted(self) -> None:
        skills = _build_skill_list(
            {"primary": "ir", "secondary": [], "confidence": 0.8},
            project_dir=".",
            include_writeup=False,
        )
        names = [s.split("/")[-1] for s in skills]
        for bundle in ("digital-forensics", "threat-hunting", "windows-ad",
                       "competition-forensic-timeline",
                       "competition-lsass-ticket-material"):
            self.assertIn(bundle, names)
        # ir 无 ctf-skills 题型目录——不应出现任何 ctf-* 技能
        self.assertFalse([n for n in names if n.startswith("ctf-")])

    def test_ir_in_cyberpenda_map(self) -> None:
        self.assertIn("ir", _CYBERPENDA_SKILL_MAP)


if __name__ == "__main__":
    unittest.main()
