"""第一批标准模式优化（O1-O6）回归测试。

O1 题型切换后 LazyAgent 未物化时差量注入走全量档案（防新专家失忆）
O2 check_experts 多份报告按份数动态切片（总量不超框架 tool_result_limit）
O3 view_evidence 默认 limit=4、总预算切片、关键词命中窗口
O4 PoC 验证按 host 分桶并行（同 host 串行、全局 120s 预算）
O5 续跑轮/空回复补轮迭代预算收紧
O6 RAG cache_key 去逐轮 focus、仅保留 CVE 技术实体
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent.Orchestrator import create_orchestrator_agent
from core.TaskState import MissionState, MissionStore, Phase
from Tools.KnowledgeBase import build_retrieval_request


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


def _mission() -> MissionState:
    mission = MissionState(
        target="10.10.10.5", goal="对授权目标完成渗透测试评估", authorized=True,
    )
    mission.transition(Phase.RECON, "t")
    mission.transition(Phase.ANALYSIS, "t")
    return mission


def _lazy_attack(name: str):
    """模拟 LazyAgent：loaded 属性在物化前为 False。"""
    return SimpleNamespace(name=name, loaded=False)


class FreshAgentArchiveTest(unittest.TestCase):
    """O1：未物化（首次派遣/题型切换重建）的 Attack 走全量档案。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()
        self.mission.exploitation_approved = True
        seed = self.mission.add_evidence("recon", "recon_report", "种子证据")
        for i in range(10):
            self.mission.add_fact(f"事实 {i}：端口 {1000+i} 开放", "recon", [seed.id])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_first_dispatch_gets_full_archive(self) -> None:
        captured = {}

        async def fake_reply(agent, msg, **kwargs):
            captured["content"] = msg.content
            return "Attack 报告：验证完成"

        agent = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=SimpleNamespace(name="Ethan"),
            attack_agent=_lazy_attack("Mike"),
            reserve_agent=SimpleNamespace(name="Ryan"),
            mission=self.mission, store=self.store, max_iters=5,
        )
        attack = asyncio.run(agent.toolkit.get_tool("dispatch_attack"))
        with patch(
            "agent.Orchestrator.run_expert_reply_with_continuation",
            new=fake_reply,
        ):
            result = _chunk_text(asyncio.run(attack.call(
                target_info="x", objective="漏洞验证",
            )))
        self.assertIn("Attack 报告", result)
        content = _chunk_text(type("M", (), {"content": captured["content"]})())
        # 全量档案：≥10 条事实可见且标注"任务档案"
        self.assertIn("任务档案", content)
        self.assertIn("事实 9", content)
        actions = [str(getattr(e, "action", "")) for e in self.mission.events]
        self.assertIn("attack_fresh_agent_archive", actions)


class CheckExpertsSlicingTest(unittest.TestCase):
    """O2：两份报告一次收取时每份切片 ≤1400，总量不超框架限值。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()
        self.orchestrator = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=SimpleNamespace(name="Ethan"),
            attack_agent=SimpleNamespace(name="Mike"),
            reserve_agent=SimpleNamespace(name="Ryan"),
            mission=self.mission, store=self.store, max_iters=5,
        )
        self.bg = self.orchestrator._lingshu_bg

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_two_reports_sliced_to_budget(self) -> None:
        self.bg["ready"] = [
            {"role": "recon", "objective": "A", "report": "R" * 3000},
            {"role": "reverse", "objective": "B", "report": "V" * 3000},
        ]
        check = asyncio.run(self.orchestrator.toolkit.get_tool("check_experts"))
        result = _chunk_text(asyncio.run(check.call(wait=False)))
        self.assertIn("已收取 2 份报告", result)
        # 每份 3000 → 1400；两份主体 ≤ 2800 + 头部说明，总量安全
        self.assertLessEqual(result.count("R") + result.count("V"), 2900)
        self.assertIn("view_evidence", result)

    def test_single_report_keeps_3000(self) -> None:
        self.bg["ready"] = [
            {"role": "recon", "objective": "A", "report": "R" * 2900},
        ]
        check = asyncio.run(self.orchestrator.toolkit.get_tool("check_experts"))
        result = _chunk_text(asyncio.run(check.call(wait=False)))
        self.assertGreaterEqual(result.count("R"), 2900)


class ViewEvidenceBudgetTest(unittest.TestCase):
    """O3：总预算切片与关键词命中窗口。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()
        self.orchestrator = create_orchestrator_agent(
            model=SimpleNamespace(),
            recon_agent=SimpleNamespace(name="Ethan"),
            attack_agent=SimpleNamespace(name="Mike"),
            reserve_agent=SimpleNamespace(name="Ryan"),
            mission=self.mission, store=self.store, max_iters=5,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _tool(self):
        return asyncio.run(self.orchestrator.toolkit.get_tool("view_evidence"))

    def test_default_budget_within_limit(self) -> None:
        for i in range(6):
            self.mission.add_evidence("recon", "recon_report", f"E{i}：" + "长" * 4000)
        result = _chunk_text(asyncio.run(self._tool().call()))
        # 4 条 × 700 字 + 头部 ≈ 3000，不会逼近框架 2400 est-token 限值
        self.assertLessEqual(len(result), 3600)
        self.assertIn("每条 ≤700", result)

    def test_keyword_returns_hit_window_not_head(self) -> None:
        body = "头部填充。" * 300 + "关键证据：SQL注入点位于/login。" + "尾部。" * 100
        self.mission.add_evidence("recon", "recon_report", body)
        result = _chunk_text(asyncio.run(self._tool().call(keyword="SQL注入")))
        self.assertIn("SQL注入", result)
        self.assertIn("命中窗口", result)  # 说明文案出现即走窗口分支


class VerifyBucketingTest(unittest.TestCase):
    """O4：不同 host 的 PoC 并行执行（同 host 串行由实现保证）。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = _mission()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _setup_evidence(self, hosts: list[str]) -> None:
        for host in hosts:
            ev = self.mission.add_evidence(
                "attack", "attack_report", f"报告 {host}", confidence=0.9,
            )
            ev.verification = {
                "status": "unverified",
                "replay_command": f"curl http://{host}/poc",
                "expected_lines": [],
            }

    def test_parallel_across_hosts(self) -> None:
        self._setup_evidence(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        concurrent_peak = {"n": 0, "max": 0}

        async def fake_runner(command: str) -> dict:
            concurrent_peak["n"] += 1
            concurrent_peak["max"] = max(concurrent_peak["max"], concurrent_peak["n"])
            await asyncio.sleep(0.15)
            concurrent_peak["n"] -= 1
            return {"returncode": 0, "stdout": "ok", "stderr": "", "timed_out": False, "error": None}

        async def run() -> str:
            # complete_mission 内部调用 _verify_findings；直接构造后调用私有函数
            agent = create_orchestrator_agent(
                model=SimpleNamespace(),
                recon_agent=SimpleNamespace(name="Ethan"),
                attack_agent=SimpleNamespace(name="Mike"),
                reserve_agent=SimpleNamespace(name="Ryan"),
                mission=self.mission, store=self.store, max_iters=5,
                verification_runner=fake_runner,
            )
            complete = await agent.toolkit.get_tool("complete_mission")
            return _chunk_text(await complete.call(success=True, summary="测试收尾"))

        with patch(
            "agent.Orchestrator.save_mission",
        ), patch("agent.Orchestrator.extract_lessons", return_value=[]):
            asyncio.run(run())
        # 三个不同 host 并发：峰值 >1 证明并行
        self.assertGreater(concurrent_peak["max"], 1)
        # 验证结论写入 mission.summary（complete_mission 返回值不含统计）
        self.assertIn("verified=3", str(self.mission.summary))


class ContinuationCapTest(unittest.TestCase):
    """O5：空回复补轮临时收紧 react_config.max_iters=3 并恢复。"""

    def test_empty_reply_continuation_caps_budget(self) -> None:
        from Tools.tooling import run_expert_reply_with_continuation

        agent = SimpleNamespace(react_config=SimpleNamespace(max_iters=30))
        calls = []

        async def fake_reply(a, msg, prefix="", on_event=None, **kw):
            calls.append(getattr(a.react_config, "max_iters", None))
            return SimpleNamespace(get_text_content=lambda: "")

        with patch(
            "Tools.tooling.run_interruptible_agent_reply", new=fake_reply,
        ), patch(
            "Tools.tooling._extract_last_substantive_assistant_text",
            return_value=None,
        ):
            result = asyncio.run(run_expert_reply_with_continuation(
                agent, SimpleNamespace(), label="T",
            ))
        self.assertEqual(result, "")
        self.assertEqual(calls, [30, 3])   # 首轮全预算 → 补轮被 cap
        self.assertEqual(agent.react_config.max_iters, 30)  # 已恢复


class RagCacheKeyTest(unittest.TestCase):
    """O6：focus 全文不进指纹，CVE 变化才换批。"""

    def _request(self, focus: str):
        mission = SimpleNamespace(
            goal="渗透测试",
            phase="analysis",
            category_decision={"primary": "web", "secondary": [], "confidence": 0.9},
            facts=["f1"], hypotheses=[], knowledge_context=None,
        )
        return build_retrieval_request(mission, consumer="Attack", focus=focus)

    def test_same_cve_different_wording_same_key(self) -> None:
        a = self._request("验证 CVE-2021-41773 路径穿越，目标 /uploads")
        b = self._request("本轮换种表述再验证一次 CVE-2021-41773")
        self.assertEqual(a["cache_key"], b["cache_key"])

    def test_different_cve_different_key(self) -> None:
        a = self._request("验证 CVE-2021-41773")
        b = self._request("验证 CVE-2022-22965")
        self.assertNotEqual(a["cache_key"], b["cache_key"])


if __name__ == "__main__":
    unittest.main()
