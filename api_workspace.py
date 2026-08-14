"""api.py 的 Workspace v2 辅助：摘要、artifacts 枚举与防逃逸解析。

- ``workspace_summary``：会话查询返回的 Workspace 摘要（不暴露宿主绝对路径）。
- ``list_artifacts``：列出可下载产物（相对引用 + 大小 + 时间）。
- ``resolve_artifact_path``：把前端传来的相对路径解析为工作区内文件，拒绝逃逸。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from workspace_service import WorkspaceService

# artifacts 根下允许下载的顶层目录（角色产物）；input/ 由上传接口管理
_ALLOWED_ARTIFACT_ROOTS = ("artifacts", "input", "reports", "mission", "data", "skills")


def workspace_summary(
    svc: WorkspaceService,
    user_id: int | None,
    session_id: str,
) -> dict[str, Any] | None:
    """计算会话的 Workspace 摘要；工作区不存在时返回 None。

    摘要包含：workspace_id、产物数/字节数、恢复状态（fresh/running/
    resumable/uncertain/terminal）、checkpoint_seq、是否存在不确定动作。
    全部为相对/派生信息，不暴露宿主绝对路径。
    """
    ws_dir = svc.workspace_dir(user_id, session_id)
    if not ws_dir.is_dir():
        return None

    artifacts_root = ws_dir / "artifacts"
    artifact_count = 0
    artifact_bytes = 0
    if artifacts_root.is_dir():
        for p in artifacts_root.rglob("*"):
            if p.is_file() and p.name != "manifest.jsonl":
                artifact_count += 1
                try:
                    artifact_bytes += p.stat().st_size
                except OSError:
                    pass

    # 恢复状态：权威在 checkpoint.json（MissionStore 权威 JSON 的镜像）
    resume_status = "fresh"
    checkpoint_seq = 0
    uncertain = False
    checkpoint_path = svc.checkpoint_path(user_id, session_id)
    if checkpoint_path.is_file():
        try:
            data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            resume_status = data.get("resume_status", "fresh") or "fresh"
            checkpoint_seq = int(data.get("checkpoint_seq", 0) or 0)
            uncertain = resume_status == "uncertain"
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            resume_status = "uncertain"  # 损坏的 checkpoint 视为不确定
            uncertain = True

    return {
        "workspace_id": svc.workspace_id(user_id, session_id),
        "exists": True,
        "artifacts_count": artifact_count,
        "artifacts_bytes": artifact_bytes,
        "resume_status": resume_status,
        "checkpoint_seq": checkpoint_seq,
        "resumable": resume_status in ("running", "resumable"),
        "uncertain": uncertain,
    }


def list_artifacts(
    svc: WorkspaceService,
    user_id: int | None,
    session_id: str,
) -> list[dict[str, Any]]:
    """列出会话可下载的产物（相对路径、大小、修改时间，按路径排序）。"""
    ws_dir = svc.workspace_dir(user_id, session_id)
    if not ws_dir.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for root in _ALLOWED_ARTIFACT_ROOTS:
        base = ws_dir / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
                mtime = p.stat().st_mtime
            except OSError:
                continue
            items.append(
                {
                    "path": str(p.relative_to(ws_dir)),
                    "size": size,
                    "modified_at": mtime,
                },
            )
    return items


def resolve_artifact_path(
    svc: WorkspaceService,
    user_id: int | None,
    session_id: str,
    rel_path: str,
) -> Path:
    """把相对路径解析为工作区内文件；逃逸/不存在抛 ValueError/FileNotFoundError。

    与 Tools/workspace_tools 一致：resolve 后必须仍在工作区内，
    符号链接逃逸同样被拦截。
    """
    if not rel_path or "\x00" in rel_path:
        raise ValueError("路径为空或包含非法字符")
    ws_dir = svc.workspace_dir(user_id, session_id)
    if not ws_dir.is_dir():
        raise FileNotFoundError("工作区不存在")
    resolved = (ws_dir / rel_path).resolve()
    try:
        resolved.relative_to(ws_dir.resolve())
    except ValueError:
        raise PermissionError(f"路径超出工作区范围: {rel_path!r}") from None
    if not resolved.is_file():
        raise FileNotFoundError(f"产物不存在: {rel_path}")
    return resolved
