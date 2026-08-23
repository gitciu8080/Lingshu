"""灵枢本地工作区服务（Workspace v2）。

统一供传统 API、Agent Service 与 CLI 使用：

- 工作区 ID 由 user_id + session_id 确定性生成（``u{user_id}/{session_id}``
  或 ``cli/{session_id}``），不依赖 AgentScope 内置 Manager 按 agent_id
  共用的目录推导，实现真正的 PER_SESSION 文件隔离。
- 内存缓存已初始化的 :class:`LocalWorkspace`；TTL 只 close（关闭 MCP、
  释放对象），**不删除磁盘文件**。
- 只有用户明确删除会话时才删除 Workspace（原子移动到内部 trash）。
- 上传文件先进入内容寻址 blob store（``blobs/{sha256}/source``），再
  reflink/copy 放入会话 ``input/``，不同会话写入互不影响。

目录布局（WorkDir/v2/）::

    WorkDir/v2/
    ├── blobs/{sha256}/source
    └── sessions/
        ├── u{user_id}/{session_id}/
        └── cli/{session_id}/
            ├── .mcp
            ├── skills/
            ├── data/
            ├── sessions/{role}/context.jsonl
            ├── input/
            ├── artifacts/{role}/
            ├── reports/
            └── mission/checkpoint.json

说明：
- ``.mcp``/``skills/``/``data/``/``sessions/`` 由 AgentScope LocalWorkspace
  自身创建与管理；``input/``/``artifacts/``/``reports/``/``mission/`` 是
  灵枢业务目录。
- Workspace v1 不复制全仓库 Skills；现有分类技能仍从项目目录加载，
  ``skills/`` 只保留未来动态技能。
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentscope.workspace import LocalWorkspace

logger = logging.getLogger(__name__)

# 默认工作区根目录固定在项目内，不依赖启动命令的当前目录。
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ROOT = _PROJECT_ROOT / "WorkDir" / "v2"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class _CachedWorkspace:
    """缓存条目：LocalWorkspace 实例 + 最近使用时间戳。"""

    workspace: LocalWorkspace
    last_used: float = field(default_factory=time.monotonic)
    generation: int = 0


class WorkspaceCapacityError(OSError):
    """The configured free-disk safety waterline would be crossed."""


class WorkspaceService:
    """按 (user_id, session_id) 隔离的 LocalWorkspace 生命周期管理器。"""

    def __init__(
        self,
        root: str | Path = _DEFAULT_ROOT,
        *,
        idle_ttl_seconds: float = 3600.0,
    ) -> None:
        candidate = Path(root).expanduser()
        self.root = (
            candidate if candidate.is_absolute() else _PROJECT_ROOT / candidate
        ).resolve()
        self.idle_ttl_seconds = idle_ttl_seconds
        self.min_free_disk_bytes = max(
            0, int(os.getenv("LINGSHU_MIN_FREE_DISK_BYTES", str(10 * 1024**3))),
        )
        self._cache: dict[str, _CachedWorkspace] = {}
        self._lock = asyncio.Lock()
        self._key_locks: dict[str, asyncio.Lock] = {}
        self._deleting: set[str] = set()
        self._pinned: set[str] = set()
        self._generation = 0
        self.last_cleanup_at: float | None = None
        self.cleanup_runs = 0
        self.cleanup_failures = 0
        self.cleaned_files = 0
        self.cleaned_bytes = 0
        self._health_lock = asyncio.Lock()
        self._health_cache: dict[str, Any] | None = None
        self._health_cache_key: tuple[tuple[str, str], ...] = ()
        self._health_cache_at = 0.0
        self.health_cache_seconds = max(
            1.0, float(os.getenv("LINGSHU_WORKSPACE_HEALTH_CACHE_SECONDS", "30")),
        )

    def ensure_capacity(self, required_bytes: int = 0) -> None:
        """Reject managed writes before the global free-space waterline is crossed."""
        self.root.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(self.root).free
        if free - max(0, required_bytes) < self.min_free_disk_bytes:
            raise WorkspaceCapacityError(
                f"磁盘可用空间不足，系统要求至少保留 "
                f"{self.min_free_disk_bytes // (1024**3)} GiB",
            )

    # ── 路径与 ID 推导（确定性） ──

    def workspace_id(self, user_id: int | None, session_id: str) -> str:
        """确定性工作区 ID：``u{user_id}-{session_id}`` 或 ``cli-{session_id}``。"""
        if user_id is not None:
            return f"u{user_id}-{session_id}"
        return f"cli-{session_id}"

    def workspace_dir(self, user_id: int | None, session_id: str) -> Path:
        """工作区物理目录（不含 agent_id，同一会话所有内部 Agent 共用）。"""
        if user_id is not None:
            return self.root / "sessions" / f"u{user_id}" / session_id
        return self.root / "sessions" / "cli" / session_id

    def mission_dir(self, user_id: int | None, session_id: str) -> Path:
        return self.workspace_dir(user_id, session_id) / "mission"

    def artifacts_dir(self, user_id: int | None, session_id: str) -> Path:
        return self.workspace_dir(user_id, session_id) / "artifacts"

    def input_dir(self, user_id: int | None, session_id: str) -> Path:
        return self.workspace_dir(user_id, session_id) / "input"

    def reports_dir(self, user_id: int | None, session_id: str) -> Path:
        return self.workspace_dir(user_id, session_id) / "reports"

    def checkpoint_path(self, user_id: int | None, session_id: str) -> Path:
        return self.mission_dir(user_id, session_id) / "checkpoint.json"

    # ── 生命周期 ──

    async def get(
        self,
        user_id: int | None,
        session_id: str,
        *,
        default_mcps: list[Any] | None = None,
        skill_paths: list[str | Path] | None = None,
    ) -> LocalWorkspace:
        """获取（必要时创建并初始化）会话的工作区。

        TTL 语义：缓存命中即刷新 last_used；空闲超过 TTL 的工作区由
        :meth:`close_idle` 关闭（仅释放资源，不删除磁盘数据）。
        """
        key = self.workspace_id(user_id, session_id)
        async with self._lock:
            if key in self._deleting:
                raise RuntimeError(f"工作区正在删除: {key}")
            cached = self._cache.get(key)
            if cached is not None:
                cached.last_used = time.monotonic()
                return cached.workspace
            key_lock = self._key_locks.setdefault(key, asyncio.Lock())

        async with key_lock:
            async with self._lock:
                if key in self._deleting:
                    raise RuntimeError(f"工作区正在删除: {key}")
                cached = self._cache.get(key)
                if cached is not None:
                    cached.last_used = time.monotonic()
                    return cached.workspace
            self.ensure_capacity()
            workdir = self.workspace_dir(user_id, session_id)
            workdir.mkdir(parents=True, exist_ok=True)
            # 业务目录（LocalWorkspace 只管理 .mcp/skills/data/sessions）
            for sub in ("input", "artifacts", "reports", "mission"):
                (workdir / sub).mkdir(parents=True, exist_ok=True)

            workspace = LocalWorkspace(
                workdir=str(workdir),
                workspace_id=key,
                default_mcps=default_mcps,
                skill_paths=[str(p) for p in (skill_paths or [])],
            )
            await workspace.initialize()
            reject_initialized = False
            async with self._lock:
                if key in self._deleting:
                    reject_initialized = True
                else:
                    self._generation += 1
                    self._cache[key] = _CachedWorkspace(workspace, generation=self._generation)
            if reject_initialized:
                await workspace.close()
                raise RuntimeError(f"工作区正在删除: {key}")
            return workspace

    async def touch(self, user_id: int | None, session_id: str) -> None:
        """刷新缓存条目的 TTL。"""
        key = self.workspace_id(user_id, session_id)
        async with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                cached.last_used = time.monotonic()

    async def pin(self, user_id: int | None, session_id: str) -> None:
        """Protect a running mission workspace from idle eviction."""
        key = self.workspace_id(user_id, session_id)
        async with self._lock:
            self._pinned.add(key)

    async def unpin(self, user_id: int | None, session_id: str) -> None:
        key = self.workspace_id(user_id, session_id)
        async with self._lock:
            self._pinned.discard(key)

    async def close_idle(self, *, ttl_seconds: float | None = None) -> int:
        """关闭并移除超过 TTL 未使用的工作区缓存条目。

        只释放对象与 MCP 连接，**不删除磁盘文件**。返回关闭数量。
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.idle_ttl_seconds
        now = time.monotonic()
        async with self._lock:
            stale = [
                self._cache.pop(key)
                for key, entry in tuple(self._cache.items())
                if key not in self._deleting
                and key not in self._pinned
                and now - entry.last_used > ttl
            ]
        await self._close_entries(stale)
        return len(stale)

    async def close_all(self) -> None:
        """关闭全部缓存工作区（服务停机时调用，不删磁盘数据）。"""
        async with self._lock:
            entries = list(self._cache.values())
            self._cache.clear()
            self._pinned.clear()
        await self._close_entries(entries)

    async def close_one(self, user_id: int | None, session_id: str) -> None:
        """只关闭指定会话的工作区并移除缓存条目（不删除磁盘数据）。"""
        key = self.workspace_id(user_id, session_id)
        async with self._lock:
            key_lock = self._key_locks.setdefault(key, asyncio.Lock())
        async with key_lock:
            async with self._lock:
                entry = self._cache.pop(key, None)
                self._pinned.discard(key)
            await self._close_entries([entry] if entry is not None else [])

    async def _close_entries(self, entries: list[_CachedWorkspace]) -> None:
        for entry in entries:
            try:
                await entry.workspace.close()
            except Exception:  # noqa: BLE001
                logger.exception("关闭 Workspace 失败")

    async def delete(self, user_id: int | None, session_id: str) -> Path:
        """删除会话工作区：关闭缓存 → 原子移动到 trash → 返回 trash 路径。

        磁盘文件不立即物理删除（后台清除由调用方决定），保证删除失败时
        可重试。返回 trash 中的目标路径。
        """
        key = self.workspace_id(user_id, session_id)
        async with self._lock:
            if key in self._deleting:
                raise RuntimeError(f"工作区已在删除: {key}")
            self._deleting.add(key)
            self._pinned.discard(key)
            key_lock = self._key_locks.setdefault(key, asyncio.Lock())
        try:
            async with key_lock:
                async with self._lock:
                    entry = self._cache.pop(key, None)
                await self._close_entries([entry] if entry is not None else [])
                src = self.workspace_dir(user_id, session_id)
                if not src.exists():
                    raise FileNotFoundError(f"工作区不存在: {src}")
                trash_root = self.root / "trash"
                trash_root.mkdir(parents=True, exist_ok=True)
                dst = trash_root / f"{src.name}-{int(time.time())}"
                os.replace(src, dst)
                return dst
        finally:
            async with self._lock:
                self._deleting.discard(key)

    # ── blob store（内容寻址 + 会话 input 链接） ──

    def put_blob(self, data: bytes) -> str:
        """把字节写入内容寻址 blob store，返回 sha256。

        相同内容只落盘一次；引用计数由调用方（SQLite blob 引用表）维护。
        """
        self.ensure_capacity(len(data))
        digest = _sha256_bytes(data)
        target = self.root / "blobs" / digest / "source"
        if target.exists():
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        # 原子写：临时文件 + rename，避免并发写同一 blob 产生半文件
        fd, temp_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=".tmp-",
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return digest

    def blob_path(self, sha256: str) -> Path:
        return self.root / "blobs" / sha256 / "source"

    def link_input(
        self,
        user_id: int | None,
        session_id: str,
        sha256: str,
        original_name: str,
    ) -> Path:
        """把 blob 以 reflink/copy 放入会话 input/（隔离写），返回目标路径。

        目标文件名为 ``{sha256[:12]}_{original_name}``，防止同名覆盖；
        不同会话写入互不影响。优先尝试 reflink（CoW），失败回退普通 copy。
        """
        source = self.blob_path(sha256)
        if not source.is_file():
            raise FileNotFoundError(f"blob 不存在: {sha256}")

        safe_name = Path(original_name).name  # 剥离任何路径成分
        target = self.input_dir(user_id, session_id) / f"{sha256[:12]}_{safe_name}"
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            return target
        self.ensure_capacity(source.stat().st_size)

        # reflink（同文件系统 CoW）→ 失败回退 copy
        try:
            _reflink(source, target)
        except OSError:
            shutil.copyfile(source, target)
        return target

    def remove_blob_if_unreferenced(self, sha256: str, referenced: bool) -> None:
        """删除不再被引用的 blob（由引用表判定后调用）。"""
        if referenced:
            return
        target = self.blob_path(sha256)
        try:
            if target.is_file():
                target.unlink()
        except FileNotFoundError:
            pass

    async def run_janitor(
        self,
        *,
        upload_root: str | Path | None = None,
        protected_uploads: set[Path] | None = None,
    ) -> dict[str, int]:
        """Close idle objects and purge expired trash/unclaimed upload staging."""
        closed = await self.close_idle()
        trash_retention = max(0, int(os.getenv("LINGSHU_TRASH_RETENTION_SECONDS", "604800")))
        upload_retention = max(0, int(os.getenv("LINGSHU_UPLOAD_RETENTION_SECONDS", "86400")))
        protected = {path.resolve() for path in (protected_uploads or set())}
        candidates: list[tuple[Path, int]] = [(self.root / "trash", trash_retention)]
        if upload_root is not None:
            candidates.append((Path(upload_root), upload_retention))
        removed_files, removed_bytes, failures = await asyncio.to_thread(
            _purge_expired, candidates, protected,
        )
        now = time.time()
        self.last_cleanup_at = now
        self.cleanup_runs += 1
        self.cleanup_failures += failures
        self.cleaned_files += removed_files
        self.cleaned_bytes += removed_bytes
        return {
            "closed_workspaces": closed, "removed_files": removed_files,
            "removed_bytes": removed_bytes, "failures": failures,
        }

    async def health(self, *, extra_paths: dict[str, Path] | None = None) -> dict[str, Any]:
        async with self._lock:
            active_workspaces = len(self._cache)
            deleting_workspaces = len(self._deleting)
            pinned_workspaces = len(self._pinned)
        cache_key = tuple(sorted(
            (name, str(path.resolve())) for name, path in (extra_paths or {}).items()
        ))
        now = time.monotonic()
        if (
            self._health_cache is not None
            and self._health_cache_key == cache_key
            and now - self._health_cache_at < self.health_cache_seconds
        ):
            cached = dict(self._health_cache)
            cached["active_workspaces"] = active_workspaces
            cached["deleting_workspaces"] = deleting_workspaces
            cached["pinned_workspaces"] = pinned_workspaces
            cached["cache_age_seconds"] = round(now - self._health_cache_at, 3)
            return cached
        async with self._health_lock:
            now = time.monotonic()
            if (
                self._health_cache is None
                or self._health_cache_key != cache_key
                or now - self._health_cache_at >= self.health_cache_seconds
            ):
                self._health_cache = await asyncio.to_thread(
                    self._health_sync, active_workspaces, deleting_workspaces, extra_paths,
                )
                self._health_cache_key = cache_key
                self._health_cache_at = now
            result = dict(self._health_cache)
            result["active_workspaces"] = active_workspaces
            result["deleting_workspaces"] = deleting_workspaces
            result["pinned_workspaces"] = pinned_workspaces
            result["cache_age_seconds"] = round(time.monotonic() - self._health_cache_at, 3)
            return result

    def _health_sync(
        self,
        active_workspaces: int,
        deleting_workspaces: int,
        extra_paths: dict[str, Path] | None,
    ) -> dict[str, Any]:
        usage = shutil.disk_usage(self.root)
        paths = {
            "workspace_sessions": self.root / "sessions",
            "workspace_blobs": self.root / "blobs",
            "workspace_trash": self.root / "trash",
            **(extra_paths or {}),
        }
        return {
            "active_workspaces": active_workspaces,
            "deleting_workspaces": deleting_workspaces,
            "idle_ttl_seconds": self.idle_ttl_seconds,
            "disk": {
                "total": usage.total, "used": usage.used, "free": usage.free,
                "minimum_free": self.min_free_disk_bytes,
                "waterline_reached": usage.free < self.min_free_disk_bytes,
            },
            "path_bytes": {name: _path_size(path) for name, path in paths.items()},
            "janitor": {
                "last_cleanup_at": self.last_cleanup_at, "runs": self.cleanup_runs,
                "failures": self.cleanup_failures, "removed_files": self.cleaned_files,
                "removed_bytes": self.cleaned_bytes,
            },
        }


def _path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except FileNotFoundError:
                continue
    return total


def _purge_expired(
    candidates: list[tuple[Path, int]],
    protected: set[Path],
) -> tuple[int, int, int]:
    removed_files = removed_bytes = failures = 0
    now = time.time()
    for directory, retention in candidates:
        if not directory.is_dir():
            continue
        for child in tuple(directory.iterdir()):
            try:
                resolved = child.resolve()
                if any(resolved == item or resolved in item.parents for item in protected):
                    continue
                if now - child.stat().st_mtime < retention:
                    continue
                size = _path_size(child)
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                removed_files += 1
                removed_bytes += size
            except FileNotFoundError:
                continue
            except Exception:  # noqa: BLE001
                failures += 1
                logger.exception("Workspace janitor 清理失败: %s", child)
    return removed_files, removed_bytes, failures


def _reflink(source: Path, target: Path) -> None:
    """尝试 Linux reflink（FICLONE），不支持时抛 OSError 由调用方回退。"""
    import fcntl

    FICLONE = 0x40049409  # linux/fs.h: _IOW(0x94, 9, int)
    with source.open("rb") as src_f, target.open("wb") as dst_f:
        fcntl.ioctl(dst_f.fileno(), FICLONE, src_f.fileno())


# 模块级单例（进程内复用）
_service: WorkspaceService | None = None


def get_workspace_service(
    root: str | Path | None = None,
    *,
    idle_ttl_seconds: float | None = None,
) -> WorkspaceService:
    """获取进程级 WorkspaceService 单例。"""
    global _service
    if _service is None:
        import os as _os

        effective_root = root or _os.getenv("LINGSHU_WORKSPACE_ROOT", _DEFAULT_ROOT)
        kwargs: dict[str, Any] = {}
        if idle_ttl_seconds is not None:
            kwargs["idle_ttl_seconds"] = idle_ttl_seconds
        else:
            kwargs["idle_ttl_seconds"] = float(
                _os.getenv("LINGSHU_WORKSPACE_IDLE_TTL_SECONDS", "3600"),
            )
        _service = WorkspaceService(effective_root, **kwargs)
    return _service
