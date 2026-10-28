"""NSSCTF Agent Arena 工作台的纯本地协议测试（不访问网络）。"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

import httpx

from workbench_nssctf_agent import (
    NSSCTFClient,
    NSSCTFError,
    NSS_WORKDIR,
    attempt_brief,
    download_annex,
    wait_container_ready,
)


def _attempt(state: str = "active", **problem_overrides) -> dict:
    problem = {
        "id": 200, "title": "example", "type": 1, "type_label": "Web",
        "content": "题目描述", "tag": ["web"], "rating": 1500,
        "container_enabled": True, "container": {"url": ["http://t:1"]},
        "annex": {"name": "a.zip", "size": 10, "url": "https://x/a.zip"},
    }
    problem.update(problem_overrides)
    return {"id": 100, "state_label": state, "wrong_count": 0,
            "max_wrong_count": 20, "remaining_seconds": 3500,
            "rating_delta": 0, "problem": problem}


class AttemptBriefTest(unittest.TestCase):
    def test_brief_flattens_problem(self) -> None:
        brief = attempt_brief(_attempt())
        self.assertEqual(brief["attempt_id"], 100)
        self.assertEqual(brief["state"], "active")
        p = brief["problem"]
        self.assertEqual(p["title"], "example")
        self.assertTrue(p["has_annex"])
        self.assertEqual(p["container_urls"], ["http://t:1"])

    def test_brief_none_attempt(self) -> None:
        self.assertIsNone(attempt_brief(None))


class ClientProtocolTest(unittest.TestCase):
    """NSSCTFClient.request 对 {code, data} 协议的解析（Mock transport）。"""

    def _client_with(self, status: int, payload: dict) -> NSSCTFClient:
        async def handler(request: httpx.Request) -> httpx.Response:  # noqa: ANN001
            return httpx.Response(status, json=payload)
        transport = httpx.MockTransport(handler)
        client = NSSCTFClient("nss_agent_test")
        client._transport = transport
        return client

    def _run(self, coro):  # noqa: ANN001
        return asyncio.run(coro)

    def test_ok_response_returns_data(self) -> None:
        nss = self._client_with(200, {"code": 200, "data": {"agent": {"id": 1}}})

        async def call() -> dict:
            async with httpx.AsyncClient(transport=nss._transport) as client:
                return await nss.current(client)
        self.assertEqual(self._run(call()), {"agent": {"id": 1}})

    def test_code_not_200_raises(self) -> None:
        nss = self._client_with(200, {"code": 400, "message": "no active"})

        async def call() -> None:
            async with httpx.AsyncClient(transport=nss._transport) as client:
                await nss.current(client)
        with self.assertRaises(NSSCTFError) as ctx:
            self._run(call())
        self.assertEqual(ctx.exception.code, 400)

    def test_http_401_raises_permission(self) -> None:
        nss = self._client_with(401, {"code": 401, "message": "bad token"})

        async def call() -> None:
            async with httpx.AsyncClient(transport=nss._transport) as client:
                await nss.current(client)
        with self.assertRaises(PermissionError):
            self._run(call())

    def test_submit_payload_carries_flag(self) -> None:
        captured: dict = {}
        nss = self._client_with(200, {"code": 200, "data": {"correct": True}})
        base_request = NSSCTFClient.request

        async def spy(self, client, method, path, payload=None, **kw):  # noqa: ANN001
            captured.update({"method": method, "path": path, "payload": payload})
            return await base_request(self, client, method, path, payload, **kw)
        NSSCTFClient.request = spy  # type: ignore[method-assign]
        try:
            async def call() -> dict:
                async with httpx.AsyncClient(transport=nss._transport) as client:
                    return await nss.submit_flag(client, 100, "NSSCTF{x}")
            data = self._run(call())
        finally:
            NSSCTFClient.request = base_request  # type: ignore[method-assign]
        self.assertTrue(data["correct"])
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/skill/agent/arena/attempt/100/submit/")
        self.assertEqual(captured["payload"], {"flag": "NSSCTF{x}"})


class AnnexAndContainerTest(unittest.TestCase):
    def test_download_annex_writes_file(self) -> None:
        import shutil
        attempt_id = "unittest-nss-annex"

        async def handler(request: httpx.Request) -> httpx.Response:  # noqa: ANN001
            return httpx.Response(200, content=b"ZIPDATA")

        async def call() -> list:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await download_annex(
                    client, {"annex": {"name": "evil/../附件.zip", "url": "https://x/a.zip"}},
                    attempt_id)
        try:
            paths = asyncio.run(call())
            self.assertEqual(len(paths), 1)
            self.assertTrue(paths[0].read_bytes() == b"ZIPDATA")
            self.assertEqual(paths[0].parent, NSS_WORKDIR / attempt_id)
            self.assertNotIn("/", paths[0].name)   # 文件名净化
        finally:
            shutil.rmtree(NSS_WORKDIR / attempt_id, ignore_errors=True)

    def test_no_annex_returns_empty(self) -> None:
        async def call() -> list:
            async with httpx.AsyncClient() as client:
                return await download_annex(client, {"annex": {}}, "x")
        self.assertEqual(asyncio.run(call()), [])

    def test_containerless_returns_empty_immediately(self) -> None:
        class NeverCall:
            async def detail(self, *a, **k):  # noqa: ANN002, ANN003
                raise AssertionError("无容器题不应轮询详情")
        nss = NeverCall()
        urls = asyncio.run(wait_container_ready(
            nss, None, _attempt(container_enabled=False), polls=1))
        self.assertEqual(urls, [])


class WebRouteTest(unittest.TestCase):
    def test_nss_state_requires_token(self) -> None:
        from fastapi.testclient import TestClient
        from workbench_ctf2_web import STATE

        previous = STATE["config"].nssctf_token
        STATE["config"].nssctf_token = ""
        try:
            with TestClient(workbench_web_app()) as client:
                response = client.get("/api/nss/state")
                self.assertEqual(response.status_code, 400)
        finally:
            STATE["config"].nssctf_token = previous

    def test_console_has_nss_tab(self) -> None:
        from fastapi.testclient import TestClient
        with TestClient(workbench_web_app()) as client:
            html = client.get("/").text
        for fragment in ("NSSCTF 竞技场", "page-nss", "c-nsstoken", "nss-stream"):
            self.assertIn(fragment, html)


def workbench_web_app():  # noqa: ANN202
    import workbench_ctf2_web
    return workbench_ctf2_web.app


if __name__ == "__main__":
    unittest.main()
