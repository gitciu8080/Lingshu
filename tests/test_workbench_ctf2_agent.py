"""CTF2 Agent 工作台的纯本地协议测试（不访问网络）。"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

import httpx

from workbench_ctf2_agent import (
    CTF2Error,
    _submit_with_retry,
    build_goal,
    extract_flag,
    pick_next,
    prepare_environment,
    run_lingshu,
    source_of,
)
from workbench_ctf2_web import app


def _http_status_error(status: int) -> httpx.HTTPStatusError:
    response = httpx.Response(status, request=httpx.Request("POST", "http://ctf2.test/submit"))
    return httpx.HTTPStatusError(f"HTTP {status}", request=response.request, response=response)


class SubmitRetryTest(unittest.TestCase):
    """flag 提交瞬时失败重试：平台未收到请求不消耗 attempt，重试安全。"""

    def test_success_first_try(self) -> None:
        calls = mock.AsyncMock(side_effect=[{"accepted": True}])
        result = asyncio.run(_submit_with_retry(lambda s: None, calls))
        self.assertEqual(result, {"accepted": True})
        self.assertEqual(calls.call_count, 1)

    def test_retry_on_retryable_ctf2_error(self) -> None:
        flaky = mock.AsyncMock(side_effect=[
            CTF2Error({"code": "backend_unavailable", "retryable": True,
                       "retry_after_ms": 0}),
            {"accepted": True},
        ])
        with mock.patch("workbench_ctf2_agent.asyncio.sleep", new=_noop_sleep):
            result = asyncio.run(_submit_with_retry(lambda s: None, flaky))
        self.assertEqual(result, {"accepted": True})
        self.assertEqual(flaky.call_count, 2)

    def test_non_retryable_ctf2_error_raises_immediately(self) -> None:
        calls = mock.AsyncMock(side_effect=CTF2Error(
            {"code": "max_attempts_reached", "retryable": False}))
        with self.assertRaises(CTF2Error):
            asyncio.run(_submit_with_retry(lambda s: None, calls))
        self.assertEqual(calls.call_count, 1)

    def test_retry_on_5xx_then_success(self) -> None:
        flaky = mock.AsyncMock(side_effect=[_http_status_error(500), {"accepted": True}])
        with mock.patch("workbench_ctf2_agent.asyncio.sleep", new=_noop_sleep):
            result = asyncio.run(_submit_with_retry(lambda s: None, flaky))
        self.assertEqual(result, {"accepted": True})
        self.assertEqual(flaky.call_count, 2)

    def test_4xx_not_retried(self) -> None:
        calls = mock.AsyncMock(side_effect=_http_status_error(400))
        with self.assertRaises(httpx.HTTPStatusError):
            asyncio.run(_submit_with_retry(lambda s: None, calls))
        self.assertEqual(calls.call_count, 1)

    def test_exhausted_retries_raises_last(self) -> None:
        calls = mock.AsyncMock(side_effect=_http_status_error(502))
        with mock.patch("workbench_ctf2_agent.asyncio.sleep", new=_noop_sleep):
            with self.assertRaises(httpx.HTTPStatusError):
                asyncio.run(_submit_with_retry(lambda s: None, calls))
        self.assertEqual(calls.call_count, 3)


async def _noop_sleep(_seconds: float) -> None:
    return None


def _args_ns() -> "object":
    from types import SimpleNamespace
    return SimpleNamespace(environment_polls=1, environment_poll_interval=0,
                           practice_id="", source="all")


class AttachmentOnlyTest(unittest.TestCase):
    """附件题（has_container=false）不得调用环境接口——平台对其返回 NOT_FOUND。"""

    def test_build_goal_without_remote_env(self) -> None:
        goal = build_goal("看我回旋踢", "题面", "", [], "fast")
        self.assertIn("本题无远程环境", goal)
        self.assertIn("不得访问任何网络目标", goal)
        self.assertNotIn("【远程环境】", goal)

    def test_build_goal_with_remote_env_keeps_scope(self) -> None:
        goal = build_goal("web", "题面", "http://1.2.3.4:80", [], "fast")
        self.assertIn("仅测试本题启动的远程环境", goal)
        self.assertIn("【远程环境】http://1.2.3.4:80", goal)

    def test_prepare_environment_skips_env_for_containerless(self) -> None:
        import asyncio
        import shutil

        from workbench_ctf2_agent import WORKDIR

        calls: list[str] = []

        class FakeCTF2:
            async def start_environment(self, *a, **k):  # noqa: ANN002, ANN003
                calls.append("start_environment")
                raise AssertionError("附件题不得启动环境")

            async def attachment_url(self, *a, **k):  # noqa: ANN002, ANN003
                calls.append("attachment_url")
                return ""

        cid = "unittest-attachment-only"
        item = {"id": cid, "practice_id": "p1", "has_container": False}
        challenge = {"has_container": False, "files": []}
        try:
            access_url, dest, _ = asyncio.run(prepare_environment(
                FakeCTF2(), None, "http://x", _args_ns(), item, challenge))
            self.assertEqual(access_url, "")
            self.assertEqual(dest, WORKDIR / cid)
            self.assertEqual(calls, [])          # 既没启动环境也没请求附件签名（无文件）
            self.assertTrue((WORKDIR / cid).is_dir())
        finally:
            shutil.rmtree(WORKDIR / cid, ignore_errors=True)


class WorkbenchOutTest(unittest.TestCase):
    def test_web_module_out_defined(self) -> None:
        # 回归：run_queue 环境配额重试分支曾因 out 未定义令执行器崩溃
        from workbench_ctf2_web import out as web_out
        web_out("out() 冒烟")


class StreamWatchdogTest(unittest.TestCase):
    """SSE 流在会话结束后悬挂不发事件时，看门狗应轮询详情终态并快速收流。

    实测事故：会话 17:13 完成，流悬挂，job 拖到 30 分钟读超时才走兜底提交。
    """

    def test_hung_stream_recovered_by_watchdog(self) -> None:
        import time
        from types import SimpleNamespace

        class FakeLingshu:
            async def enabled_providers(self) -> list[str]:
                return ["zhipu"]

            async def start_session(self, **kwargs) -> str:  # noqa: ANN003
                return "sess-hung"

            async def stream(self, session_id: str, timeout: int):
                yield "phase_change", {"phase": "analysis"}
                # 模拟流悬挂：不再产出任何事件，也不结束
                await asyncio.sleep(600)

            async def detail(self, session_id: str) -> dict:
                return {"mission_state": {"phase": "completed"},
                        "flag": "flag{hung_stream_ok}"}

            async def send(self, session_id: str, text: str) -> None:
                return None

        args = SimpleNamespace(provider="zhipu", model="x", timeout=30)
        started = time.monotonic()
        flag, session_id = asyncio.run(run_lingshu(
            FakeLingshu(), args, title="t", description="d", access_url="",
            attachments=[], mode="fast", watchdog_interval=0.2))
        elapsed = time.monotonic() - started
        self.assertEqual(flag, "flag{hung_stream_ok}")
        self.assertEqual(session_id, "sess-hung")
        self.assertLess(elapsed, 10)   # 看门狗秒级收流，而非 30 分钟读超时


class QueueAddContainerFlagTest(unittest.TestCase):
    """附件题标记必须随队列条目存活到执行时（曾丢失导致误调环境接口 NOT_FOUND）。"""

    def _queue_add(self, payload_item: dict) -> dict:
        from fastapi.testclient import TestClient
        from workbench_ctf2_web import STATE

        previous = STATE["config"].ctf2_token
        STATE["config"].ctf2_token = "unit-test-token"
        cid = "unit-test-attach"
        try:
            with TestClient(app) as client:
                response = client.post("/api/queue/add", json={
                    "challenge_id": cid, "item": payload_item})
                self.assertEqual(response.status_code, 200)
                entry = STATE["queue"]["items"][-1]
                self.assertEqual(entry["challenge_id"], cid)
                return entry
        finally:
            STATE["config"].ctf2_token = previous
            STATE["queue"]["items"] = [q for q in STATE["queue"]["items"]
                                       if q["challenge_id"] != cid]

    def test_containerless_flag_survives_queue_add(self) -> None:
        entry = self._queue_add({"id": "unit-test-attach", "title": "zip伪加密",
                                 "practice_ground_id": "g1", "has_container": False})
        self.assertIs(entry["challenge"]["has_container"], False)
        self.assertIs(entry["item"]["has_container"], False)

    def test_container_flag_survives_queue_add(self) -> None:
        entry = self._queue_add({"id": "unit-test-attach", "title": "web题",
                                 "practice_ground_id": "g1", "has_container": True})
        self.assertIs(entry["challenge"]["has_container"], True)

    def test_absent_flag_not_fabricated(self) -> None:
        entry = self._queue_add({"id": "unit-test-attach", "title": "旧客户端",
                                 "practice_ground_id": "g1"})
        self.assertNotIn("has_container", entry["challenge"])


class AgentWorkbenchTest(unittest.TestCase):
    def test_extract_flag(self) -> None:
        self.assertEqual(extract_flag("flag{a_b-1}"), "flag{a_b-1}")
        self.assertIsNone(extract_flag("无 flag"))
        self.assertIsNone(extract_flag("flag{跨\n行}"))

    def test_source_of(self) -> None:
        self.assertEqual(source_of({"source": {"type": "competition",
                                               "competition_id": "c1", "stage_id": "s1"}}),
                         ("competition", "c1", "s1"))
        self.assertEqual(source_of({}), ("practice", "", ""))

    def test_pick_next_skips_solved_choice_and_excluded(self) -> None:
        items = [
            {"id": "a", "is_solved": True},
            {"id": "b", "submission_type": "choice"},
            {"id": "c"},
            {"id": "d"},
        ]
        picked = pick_next(items, {"c"})
        self.assertEqual(picked["id"], "d")
        self.assertIsNone(pick_next(items, {"c", "d"}))

    def test_build_goal_contains_scope_and_constraints(self) -> None:
        goal = build_goal("time-travel", "题面描述", "http://1.2.3.4:8000",
                          [], "fast")
        self.assertIn("仅测试本题启动的远程环境", goal)
        self.assertIn("不要调用任何外部平台提交接口", goal)
        self.assertIn("http://1.2.3.4:8000", goal)
        self.assertIn("time-travel", goal)


class WorkbenchWebTest(unittest.TestCase):
    def test_index_and_state_without_token(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            html = client.get("/").text
            self.assertIn("灵枢 × CTF 竞技场工作台", html)
            state = client.get("/api/state").json()
            self.assertIn("configured", state)
            self.assertIn("jobs", state)
            self.assertIn("auto", state)

    def test_challenges_require_token(self) -> None:
        from fastapi.testclient import TestClient

        # 临时清空 token，确保未配置时返回 400
        from workbench_ctf2_web import STATE

        previous = STATE["config"].ctf2_token
        STATE["config"].ctf2_token = ""
        try:
            with TestClient(app) as client:
                response = client.get("/api/challenges")
                self.assertEqual(response.status_code, 400)
        finally:
            STATE["config"].ctf2_token = previous


if __name__ == "__main__":
    unittest.main()
