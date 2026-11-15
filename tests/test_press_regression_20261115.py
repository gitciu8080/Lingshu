"""20261115 压测回归（deepseek 0/6）修复测试。

Bug A fast experts 契约：triage/recon 映射急切 Agent → Captain._run_expert
  ``await lazy.get()`` 抛 ``'Agent' object has no attribute 'get'``——同步派遣
  裸异常喷回指挥官、后台派遣任务无声死亡（ready 永远为空 → 无限重派）。
  修复：main._as_lazy 包装 + _background_worker except 记失败报告。
轮询退避：check_experts(wait=false) 无就绪报告但有任务在跑时等 20s 再复查。
收割等待：fast 指挥官死于 max_iters 且后台专家在跑时有界等待 180s 并代收报告。
"""
from __future__ import annotations

import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent.Captain import FAST_CAPTAIN_EXPERT, create_fast_captain_agent
from core.TaskState import MissionState, MissionStore, Phase

ROOT = Path(__file__).resolve().parent.parent


def _chunk_text(chunk) -> str:
    content = getattr(chunk, "content", chunk)
    if isinstance(content, str):
        return content
    return "".join(getattr(b, "text", str(b)) for b in content)


class NonLazyExpertContractTest(unittest.TestCase):
    """Bug A：非 LazyAgent 专家条目不再让派遣裸炸，后台失败可收取。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = MissionState(
            target="1.2.3.4", goal="获取 Flag", authorized=True,
        )
        self.mission.transition(Phase.RECON, "t")
        self.mission.transition(Phase.ANALYSIS, "t")
        # 复刻 20261115 故障现场：triage 映射急切构造的真实 Agent（无 .get）
        self.experts = {
            "attack": SimpleNamespace(name="attack-lazy"),
            "triage": SimpleNamespace(name="Iris - 文件分析专家"),  # 无 .get
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _captain(self):
        return create_fast_captain_agent(
            model=SimpleNamespace(),
            experts=self.experts,
            mission=self.mission,
            store=self.store,
            event_callback=None,
            target="1.2.3.4",
            workdir=self.temp.name,
            timeout=5,
            max_iters=5,
        )

    def test_sync_spawn_returns_readable_error(self) -> None:
        captain = self._captain()
        spawn = asyncio.run(captain.toolkit.get_tool("spawn_expert"))
        result = _chunk_text(asyncio.run(spawn.call(
            role="triage", objective="分析附件", background=False,
        )))
        self.assertIn("专家执行失败", result)
        self.assertIn("has no attribute 'get'", result)

    def test_bg_failure_report_is_collectable(self) -> None:
        captain = self._captain()
        spawn = asyncio.run(captain.toolkit.get_tool("spawn_expert"))
        check = asyncio.run(captain.toolkit.get_tool("check_experts"))

        async def run() -> str:
            handle = _chunk_text(await spawn.call(
                role="triage", objective="分析附件", background=True,
            ))
            self.assertIn("triage#", handle)
            # 修复前：任务无声死亡 → ready 永远为空 → 永远"当前没有后台专家任务"
            collected = _chunk_text(await check.call(wait=True, timeout=5))
            return collected

        collected = asyncio.run(run())
        self.assertIn("已收取", collected)
        self.assertIn("has no attribute 'get'", collected)


class CheckExpertsBackoffTest(unittest.TestCase):
    """轮询退避：wait=false 无就绪报告但有任务在跑 → 等 20s 再复查。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = MissionStore(Path(self.temp.name) / "m.json")
        self.mission = MissionState(
            target="1.2.3.4", goal="获取 Flag", authorized=True,
        )
        self.mission.transition(Phase.RECON, "t")
        self.mission.transition(Phase.ANALYSIS, "t")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_wait_false_sleeps_when_tasks_running(self) -> None:
        slept = {"n": 0}

        async def fake_sleep(seconds):
            slept["n"] += 1
            slept["seconds"] = seconds
            # 模拟 20s 期间后台任务写入报告
            captain._lingshu_bg["ready"].append(
                {"role": "attack", "objective": "A", "report": "迟到的报告"}
            )

        captain = create_fast_captain_agent(
            model=SimpleNamespace(),
            experts={"attack": SimpleNamespace(name="lazy", get=AsyncMock())},
            mission=self.mission, store=self.store, event_callback=None,
            target="1.2.3.4", workdir=self.temp.name, timeout=5, max_iters=5,
        )
        bg = captain._lingshu_bg
        # 直接构造 running 状态（task.done()=False）
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            pending = loop.create_future()
            bg["running"]["attack#1"] = {
                "role": "attack", "objective": "A", "task": _PendingTask(pending),
            }
            check = loop.run_until_complete(captain.toolkit.get_tool("check_experts"))
            with patch("agent.Captain.asyncio.sleep", new=fake_sleep):
                result = _chunk_text(loop.run_until_complete(check.call(wait=False)))
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertEqual(slept["n"], 1)
        self.assertEqual(slept["seconds"], 20)
        self.assertIn("迟到的报告", result)


class _PendingTask:
    """task.done()=False 的最小鸭子类型（asyncio.wait 不可用时仅判 done）。"""

    def __init__(self, fut):
        self._fut = fut

    def done(self) -> bool:
        return self._fut.done()

    def __await__(self):
        return self._fut.__await__()


class FastHarvestContractTest(unittest.TestCase):
    """收割等待：max_iters 死亡路径在 fast 模式下等待后台并代收报告。"""

    def test_harvest_block_present_in_main(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("background_reports_harvested", src)
        self.assertIn("收割", src)

    def test_as_lazy_wraps_eager_agents(self) -> None:
        src = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("def _as_lazy(agent):", src)
        self.assertIn('"triage": _as_lazy(artifact_recon) or _as_lazy(recon),', src)
        self.assertIn('"recon": _as_lazy(network_recon) or _as_lazy(recon),', src)


class PollDisciplinePromptTest(unittest.TestCase):
    def test_prompt_has_polling_discipline(self) -> None:
        prompt = (ROOT / "agent" / "Prompt" / "FAST_CAPTAIN.md").read_text(
            encoding="utf-8",
        )
        self.assertIn("轮询纪律", prompt)
        self.assertIn("wait=true", prompt)


if __name__ == "__main__":
    unittest.main()
