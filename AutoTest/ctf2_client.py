"""
CTF2 API 客户端 — 封装所有 User Open API 接口
"""
from __future__ import annotations

import time
import logging
from typing import Any
from urllib.parse import urljoin

import httpx

from .config import CTF2_BASE_URL, CTF2_API_KEY, CTF2_API_PREFIX

logger = logging.getLogger(__name__)


class CTF2Client:
    """CTF2 平台 API 客户端（使用 Personal Access Token 认证）"""

    def __init__(self, base_url: str = CTF2_BASE_URL, api_key: str = CTF2_API_KEY):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "X-CTF2-API-Key": self.api_key,
                "Accept": "application/json",
            },
            timeout=30,
        )

    # ------------------------------------------------------------------
    # 底层请求
    # ------------------------------------------------------------------
    def _get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        """GET 请求，自动处理错误响应和限流"""
        url = urljoin(CTF2_API_PREFIX + "/", path.lstrip("/"))
        resp = self._client.get(url, params=params)
        return self._handle_response(resp)

    def _post(self, path: str, json: dict | None = None) -> dict[str, Any]:
        """POST 请求"""
        url = urljoin(CTF2_API_PREFIX + "/", path.lstrip("/"))
        resp = self._client.post(url, json=json)
        return self._handle_response(resp)

    def _handle_response(self, resp: httpx.Response) -> dict[str, Any]:
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "5"))
            logger.warning("限流 429，等待 %d 秒重试...", retry_after)
            time.sleep(retry_after)
            # 简单重试一次
            new_resp = self._client.request(
                resp.request.method,
                str(resp.request.url),
                headers=dict(resp.request.headers),
                content=resp.request.content,
            )
            resp = new_resp

        body = resp.json()
        if resp.status_code >= 400:
            err = body.get("error", {})
            code = err.get("code", "UNKNOWN")
            key = err.get("key", "unknown_error")
            raise CTF2Error(resp.status_code, code, key, body)
        return body

    # ------------------------------------------------------------------
    # 练习场 / 题目
    # ------------------------------------------------------------------
    def get_practices(self, limit: int = 100) -> list[dict]:
        """获取公开练习场列表"""
        body = self._get("/practice/", {"limit": limit})
        return body.get("data", {}).get("items", [])

    def get_private_practices(self, limit: int = 100) -> list[dict]:
        """获取私有练习场列表"""
        body = self._get("/private-practice/", {"limit": limit})
        return body.get("data", {}).get("items", [])

    def get_challenge(self, practice_id: str, challenge_id: str) -> dict:
        """获取单个题目详情"""
        path = f"/practice/{practice_id}/challenges/{challenge_id}/"
        body = self._get(path)
        return body.get("data", {})

    # ------------------------------------------------------------------
    # 环境 / 提交
    # ------------------------------------------------------------------
    def start_environment(self, practice_id: str, challenge_id: str) -> dict:
        """启动靶机环境，返回 environment 对象"""
        path = f"/practice/{practice_id}/challenges/{challenge_id}/environment/start/"
        body = self._post(path, json={})
        return body.get("data", {}).get("environment", {})

    def submit_flag(self, practice_id: str, challenge_id: str, flag: str) -> dict:
        """提交 flag（需确认）"""
        path = f"/practice/{practice_id}/challenges/{challenge_id}/submit/"
        body = self._post(path, json={"flag": flag, "confirmation": True})
        return body.get("data", {})

    # ------------------------------------------------------------------
    # 提交记录
    # ------------------------------------------------------------------
    def get_submissions(self, limit: int = 100) -> list[dict]:
        """获取全局提交记录"""
        body = self._get("/submissions/", {"limit": limit})
        return body.get("data", {}).get("items", [])

    def get_private_submissions(self, limit: int = 100) -> list[dict]:
        """获取私有练习场提交记录"""
        body = self._get("/private-practice/submissions/", {"limit": limit})
        return body.get("data", {}).get("items", [])


class CTF2Error(Exception):
    """CTF2 API 错误"""

    def __init__(self, status: int, code: str, key: str, raw: dict):
        self.status = status
        self.code = code
        self.key = key
        self.raw = raw
        super().__init__(f"[{status}] {code}: {key}")
