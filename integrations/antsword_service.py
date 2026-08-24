"""AntSword GUI 与其 SSE MCP 服务的 API 生命周期托管。"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import time
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_EXECUTABLE = (
    _PROJECT_ROOT / "Tools" / "AntSword-Loader-v4.0.3-linux-x64" / "AntSword"
)


def _env_enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


class AntSwordService:
    """只管理由当前 API 进程启动的 AntSword 进程组。"""

    def __init__(
        self,
        executable: str | Path | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 30080,
        startup_timeout: float = 60.0,
    ) -> None:
        configured = executable or os.getenv("LINGSHU_ANTSWORD_EXECUTABLE", "").strip()
        self.executable = Path(configured or _DEFAULT_EXECUTABLE).expanduser().resolve()
        self.host = host
        self.port = port
        self.startup_timeout = startup_timeout
        self.process: asyncio.subprocess.Process | None = None
        self.process_group_id: int | None = None
        self.started_by_api = False
        self.using_existing_service = False
        self.last_error = ""
        self._log_handle: BinaryIO | None = None
        self._lock = asyncio.Lock()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/sse"

    async def is_ready(self) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=0.75,
            )
        except (OSError, asyncio.TimeoutError):
            return False
        del reader
        writer.close()
        with suppress(OSError, asyncio.TimeoutError, RuntimeError):
            await writer.wait_closed()
        return True

    def _launch_command(self) -> list[str]:
        """无图形会话时用 Xvfb 托管 Electron。"""
        if os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY"):
            return [str(self.executable)]
        xvfb_run = shutil.which("xvfb-run")
        if xvfb_run:
            return [xvfb_run, "-a", str(self.executable)]
        return [str(self.executable)]

    def _log_tail(self, max_bytes: int = 4000) -> str:
        path = _PROJECT_ROOT / "WorkDir" / "antsword-mcp.log"
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        return data[-max_bytes:].decode("utf-8", errors="replace").strip()

    async def start(self) -> bool:
        """启动一次 AntSword；已有 30080 服务时复用且不取得所有权。"""
        async with self._lock:
            if await self.is_ready():
                self.using_existing_service = True
                self.last_error = ""
                logger.info("复用已运行的 AntSword MCP: %s", self.url)
                return True
            if not _env_enabled("LINGSHU_ANTSWORD_AUTOSTART", True):
                self.last_error = "已通过 LINGSHU_ANTSWORD_AUTOSTART 禁用自动启动"
                logger.info(self.last_error)
                return False
            if not self.executable.is_file():
                raise FileNotFoundError(f"AntSword 启动器不存在: {self.executable}")
            if not os.access(self.executable, os.X_OK):
                raise PermissionError(f"AntSword 启动器不可执行: {self.executable}")

            log_path = _PROJECT_ROOT / "WorkDir" / "antsword-mcp.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = log_path.open("ab", buffering=0)
            command = self._launch_command()
            logger.info("正在启动 AntSword MCP: %s", " ".join(command))
            try:
                self.process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=str(self.executable.parent),
                    env={**os.environ, "AS_WORKDIR": str(_PROJECT_ROOT / "Tools" / "antSword-2.1.16")},
                    stdout=self._log_handle,
                    stderr=asyncio.subprocess.STDOUT,
                    start_new_session=True,
                )
            except Exception:
                self._close_log()
                raise

            self.process_group_id = self.process.pid
            self.started_by_api = True
            self.using_existing_service = False
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if await self.is_ready():
                    self.last_error = ""
                    logger.info("AntSword MCP 已就绪: %s", self.url)
                    return True
                if self.process.returncode is not None:
                    error = self._log_tail() or f"进程退出码 {self.process.returncode}"
                    await self._cleanup_owned_process()
                    raise RuntimeError(f"AntSword 启动失败: {error}")
                await asyncio.sleep(0.25)

            error = self._log_tail()
            await self._cleanup_owned_process()
            suffix = f"；日志：{error}" if error else ""
            raise TimeoutError(f"AntSword MCP 在 {self.startup_timeout:.0f} 秒内未就绪{suffix}")

    async def stop(self) -> None:
        """仅关闭本 API 启动的进程组；手工启动的实例保持运行。"""
        async with self._lock:
            if not self.started_by_api:
                self.using_existing_service = False
                return
            await self._cleanup_owned_process()
            logger.info("已关闭 API 托管的 AntSword MCP")

    async def _cleanup_owned_process(self) -> None:
        pgid = self.process_group_id
        process = self.process
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass

            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and await self.is_ready():
                await asyncio.sleep(0.1)
            if await self.is_ready():
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        if process is not None and process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                if pgid is not None:
                    with suppress(ProcessLookupError):
                        os.killpg(pgid, signal.SIGKILL)
                with suppress(OSError, asyncio.TimeoutError, RuntimeError):
                    await asyncio.wait_for(process.wait(), timeout=2.0)

        self.process = None
        self.process_group_id = None
        self.started_by_api = False
        self._close_log()

    def _close_log(self) -> None:
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    async def status(self) -> dict[str, object]:
        return {
            "ready": await self.is_ready(),
            "url": self.url,
            "started_by_api": self.started_by_api,
            "using_existing_service": self.using_existing_service,
            "pid": self.process.pid if self.process is not None else None,
            "last_error": self.last_error,
        }


_SERVICE = AntSwordService()


def get_antsword_service() -> AntSwordService:
    return _SERVICE
