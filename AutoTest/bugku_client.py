"""
Bugku CTF 平台 HTTP 客户端

Session 管理 + CSRF Token 自动刷新 + 限流重试
"""
from __future__ import annotations

import logging
import re
import time
from http.cookiejar import Cookie
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://ctf.bugku.com"
USER_AGENT = "Mozilla/5.0 AutoPwn/1.0"


class BugkuClient:
    """Bugku 平台 HTTP 客户端，保持 Session 状态"""

    def __init__(self, phpsessid: str, cookie_file: str | None = None):
        self.base_url = BASE_URL
        self._phpsessid = phpsessid
        self._csrf_token: str = ""
        self._cookie_file = cookie_file

        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/json,*/*",
            },
            timeout=30,
            follow_redirects=True,
        )
        # 设置初始 cookie
        self._client.cookies.set("PHPSESSID", phpsessid, domain="ctf.bugku.com")
        if cookie_file:
            self._load_cookie_file(cookie_file)

    def _load_cookie_file(self, path: str):
        """加载 Netscape 格式 cookie 文件中的关键 cookie"""
        try:
            for line in Path(path).read_text().splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    name, value = parts[5], parts[6]
                    if name in ("PHPSESSID", "X-CSRF-TOKEN", "autoLogin"):
                        self._client.cookies.set(name, value, domain="ctf.bugku.com")
                        if name == "X-CSRF-TOKEN":
                            self._csrf_token = value
            logger.debug("从 cookie 文件加载完成")
        except Exception:
            logger.debug("cookie 文件加载失败，使用 PHPSESSID 初始值")

    # ------------------------------------------------------------------
    # 低层请求
    # ------------------------------------------------------------------
    def _get_html(self, path: str, params: dict | None = None) -> str:
        """GET 请求，返回 HTML 文本，自动刷新 CSRF"""
        resp = self._request_with_retry("GET", path, params=params)
        self._update_csrf(resp)
        return resp.text

    def _post_json(self, path: str, data: dict) -> dict[str, Any]:
        """POST 请求，返回 JSON，自动带 CSRF"""
        resp = self._request_with_retry(
            "POST", path,
            data=data,
            headers={
                "X-CSRF-TOKEN": self._csrf_token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        self._update_csrf(resp)
        return resp.json()

    def _request_with_retry(self, method: str, path: str, **kwargs) -> httpx.Response:
        """请求 + 限流重试"""
        url = urljoin(self.base_url, path)
        for attempt in range(3):
            resp = self._client.request(method, url, **kwargs)
            if resp.status_code == 429:
                wait = 5 * (attempt + 1)
                logger.warning("限流 429，等待 %ds...", wait)
                time.sleep(wait)
                continue
            return resp
        return resp  # 最后尝试的结果

    def _update_csrf(self, resp: httpx.Response):
        """从响应 Set-Cookie 更新 CSRF Token"""
        for cookie_header in resp.headers.get_list("set-cookie"):
            if "X-CSRF-TOKEN" in cookie_header:
                m = re.search(r"X-CSRF-TOKEN=([^;]+)", cookie_header)
                if m:
                    new_token = m.group(1)
                    if new_token != self._csrf_token:
                        self._csrf_token = new_token
                        self._client.cookies.set(
                            "X-CSRF-TOKEN", new_token, domain="ctf.bugku.com"
                        )

    @property
    def csrf_token(self) -> str:
        # 如果没有 token，先发一个请求获取
        if not self._csrf_token:
            self._get_html("/challenges/index/gid/2.html")
        return self._csrf_token

    # ------------------------------------------------------------------
    # 题目列表 API
    # ------------------------------------------------------------------
    def get_challenge_list(self, page: int = 1, category_tid: int | None = None) -> str:
        """获取题目列表页 HTML"""
        if category_tid:
            path = f"/challenges/index/gid/2/tid/{category_tid}.html"
        else:
            path = "/challenges/index/gid/2.html"
        return self._get_html(path, {"page": page} if page > 1 else None)

    # ------------------------------------------------------------------
    # 题目详情
    # ------------------------------------------------------------------
    def get_challenge_detail(self, challenge_id: int) -> str:
        """获取题目详情页 HTML"""
        return self._get_html(f"/challenges/detail/id/{challenge_id}.html")

    # ------------------------------------------------------------------
    # 附件下载
    # ------------------------------------------------------------------
    def download_attachment(self, challenge_id: int, save_dir: str) -> Path | None:
        """下载题目附件到指定目录，返回文件路径"""
        url = f"/attachment/download/file/{challenge_id}.html"
        resp = self._client.get(urljoin(self.base_url, url), follow_redirects=True)
        self._update_csrf(resp)  # 刷新 CSRF token

        if resp.status_code != 200:
            logger.warning("附件下载失败: HTTP %d", resp.status_code)
            return None

        # 从 Content-Disposition 或 URL 提取文件名
        cd = resp.headers.get("content-disposition", "")
        filename = None
        m = re.search(r'filename[*]?=["\']?([^"\';]+)', cd)
        if m:
            filename = m.group(1)
        else:
            # 从 URL 推断或使用默认名
            filename = f"attachment_{challenge_id}.zip"

        save_path = Path(save_dir) / filename
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(resp.content)
        logger.info("附件下载完成: %s (%d bytes)", save_path, len(resp.content))
        return save_path

    # ------------------------------------------------------------------
    # Flag 提交
    # ------------------------------------------------------------------
    def submit_flag(self, challenge_id: int, flag: str) -> dict:
        """提交 flag，返回 {code, msg, data, url, wait}"""
        return self._post_json(
            "/challenges/checkFlag.html",
            data={"flag": flag, "id": str(challenge_id)},
        )

    # ------------------------------------------------------------------
    # 靶机管理（当前不可用，预留接口）
    # ------------------------------------------------------------------
    def get_scene_token(self, challenge_id: int) -> dict:
        """获取广告 token（当前暂停服务）"""
        return self._client.get(
            urljoin(self.base_url, f"/miniApp/getAdQr?challenge_id={challenge_id}"),
            headers={"X-Requested-With": "XMLHttpRequest"},
        ).json()

    def create_scene(self, token: str) -> dict:
        """启动靶机（当前暂停服务）"""
        return self._client.get(
            urljoin(self.base_url, f"/miniApp/createScene?token={token}"),
            headers={"X-Requested-With": "XMLHttpRequest"},
        ).json()

    def close(self):
        self._client.close()
