"""WebShot：授权 Web 页面截图工具。

用 headless 浏览器（chromium 系）对 ScopeRegistry 授权范围内的
http/https 页面截图，产物落盘 Workspace v2 的
``artifacts/{role}/screenshots/``，作为渗透测试报告"漏洞证明/页面取证"
的图像证据；截图可交给 analyze_image（视觉模型）研判页面内容。

安全模型：
- 仅允许 http/https 顶层 URL，且主机必须通过 ScopeRegistry 校验；
- 拒绝携带 userinfo 的 URL；
- 子资源（CDN 等）由浏览器按页面自然加载，不做逐域拦截——与
  scoped_shell 中 curl 拉取页面的授权粒度一致。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from Tools.ScopeRegistry import ScopeRegistry
from Tools.tooling import AllowedFunctionTool

# headless 浏览器候选：按序探测（Kali 主选 chromium，其余环境退回 chrome 系）
_BROWSER_CANDIDATES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
)

_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def resolve_headless_browser() -> str | None:
    """探测可用的 headless 浏览器可执行文件路径。"""
    for name in _BROWSER_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _append_manifest(manifest_path: Path, entry: dict) -> None:
    try:
        with manifest_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # manifest 仅审计辅助，失败不阻断截图产出


def create_web_screenshot_tool(
    scope_registry: ScopeRegistry | None,
    workspace_root: str | Path | None = None,
    workdir: str | Path | None = None,
    timeout: int = 60,
    *,
    role: str = "recon",
    browser_path: str | None = None,
) -> AllowedFunctionTool:
    """创建授权页面截图工具（webshot）。

    Args:
        scope_registry: 授权范围注册表；URL 主机不在范围内时拒绝。
        workspace_root: Workspace v2 根；提供时产物写入
            ``artifacts/{role}/screenshots/`` 并登记 manifest。
        workdir: 任务工作目录；legacy 模式（无 workspace_root）时的
            截图回退落盘位置（``{workdir}/screenshots/``）。
        timeout: 单次截图超时秒数。
        role: 产物归属角色目录（recon/attack）。
        browser_path: 显式指定浏览器可执行文件；缺省自动探测。
    """
    browser = browser_path or resolve_headless_browser()

    if workspace_root is not None:
        ws_root = Path(workspace_root).expanduser().resolve()
        shot_root = ws_root / "artifacts" / role / "screenshots"
        manifest_path = ws_root / "artifacts" / "manifest.jsonl"
        reference_base = ws_root
    else:
        base = Path(workdir).expanduser().resolve() if workdir else Path.cwd()
        shot_root = base / "screenshots"
        manifest_path = None
        reference_base = base

    async def webshot(url: str, width: int = 1280, height: int = 900, wait_ms: int = 8000) -> str:
        """对授权 Web 页面截图，产出 PNG 证据文件。

        Args:
            url: 完整页面地址（http/https），主机必须在授权范围内。
            width: 视口宽（像素，320~1920）。
            height: 视口高（像素，240~4096；长页面取大值可截更多内容）。
            wait_ms: 页面渲染等待毫秒（500~15000），JS 渲染重的页面取大。
        """
        if browser is None:
            return (
                "[不可用] 未找到 headless 浏览器（chromium/chrome）。"
                "请安装 chromium 或改用 scoped_shell 的 curl 保存页面源码作为证据。"
            )
        text = (url or "").strip()
        if not _URL_SCHEME_RE.match(text):
            return f"[拒绝] 仅支持 http/https 页面截图，收到: {text[:200]}"
        parts = urlsplit(text)
        if parts.username or parts.password:
            return "[拒绝] URL 不允许携带 userinfo（user:pass@host 形式）；凭据应通过页面表单验证。"
        if scope_registry is not None and not scope_registry.is_target_allowed(text):
            snap = scope_registry.snapshot()
            allowed = ", ".join(
                filter(None, [
                    ", ".join(snap.get("ips", [])),
                    ", ".join(snap.get("networks", [])),
                    ", ".join(snap.get("hostnames", [])),
                ]),
            ) or "（仅基础授权目标）"
            return (
                f"[拒绝] 截图目标不在授权范围内（当前授权: {allowed}）。"
                "如需新增目标，请由 Orchestrator 走 request_scope_expansion 审批后再试。"
            )
        try:
            width = max(320, min(int(width), 1920))
            height = max(240, min(int(height), 4096))
            wait_ms = max(500, min(int(wait_ms), 15000))
        except (TypeError, ValueError):
            return "[拒绝] width/height/wait_ms 必须是整数。"

        safe_host = re.sub(r"[^A-Za-z0-9.-]+", "_", parts.hostname or "host")[:60]
        port_suffix = f"-{parts.port}" if parts.port else ""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        out_path = shot_root / f"shot-{safe_host}{port_suffix}-{stamp}.png"
        shot_root.mkdir(parents=True, exist_ok=True)

        cmd = [
            browser,
            "--headless=new",
            "--no-sandbox",            # root/容器环境必需
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--hide-scrollbars",
            f"--window-size={width},{height}",
            f"--virtual-time-budget={wait_ms}",
            f"--screenshot={out_path}",
            text,
        ]
        started_at = datetime.now().astimezone().isoformat()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            return f"[不可用] 浏览器可执行文件不存在: {browser}"
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
            return f"[失败] 截图超时（>{timeout}s），目标可能无响应: {text[:200]}"

        if proc.returncode != 0 or not out_path.exists() or out_path.stat().st_size == 0:
            tail = (stderr or b"")[-600:].decode("utf-8", "replace").strip()
            out_path.unlink(missing_ok=True)
            return f"[失败] 截图未产出文件（exit={proc.returncode}）: {tail or '无 stderr 输出'}"

        size = out_path.stat().st_size
        try:
            rel_ref = str(out_path.relative_to(reference_base))
        except ValueError:
            rel_ref = str(out_path)
        if manifest_path is not None:
            _append_manifest(manifest_path, {
                "tool": "webshot",
                "role": role,
                "url": text,
                "file": rel_ref,
                "bytes": size,
                "started_at": started_at,
            })
        return (
            f"[截图成功] {text}\n"
            f"证据文件: {out_path}（{size} 字节，视口 {width}x{height}）\n"
            "工作区相对引用: " + rel_ref + "\n"
            "截图可作为页面取证/漏洞证明证据；如需研判页面内容，可调用 analyze_image 分析该文件。"
        )

    return AllowedFunctionTool(
        webshot,
        name="webshot",
        description=(
            "对授权范围内的 Web 页面截图（headless 浏览器渲染，含 JS），"
            "产出 PNG 证据文件并落盘工作区 artifacts，用于页面取证与漏洞证明。"
            "仅顶层 URL 需在授权范围内。"
        ),
        is_read_only=True,
        is_concurrency_safe=False,
    )
