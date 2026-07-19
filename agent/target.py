"""灵枢结构化目标模型与规范化。

替代纯字符串 target，支持 IP、IP:端口、主机名、压缩包、直接文件、目录。
修复 Path.suffix 无法正确判断 .tar.gz 的问题。
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# 目标类型枚举
# ---------------------------------------------------------------------------

TargetKind = Literal["network", "archive", "single_file", "directory"]


# ---------------------------------------------------------------------------
# 支持的文件扩展名（用于判断归档类型）
# ---------------------------------------------------------------------------

_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar",
)


def _is_archive(path: Path) -> bool:
    """判断 path 是否为支持的归档文件，不依赖 Path.suffix。"""
    name = path.name.lower()
    if any(name.endswith(s) for s in _ARCHIVE_SUFFIXES):
        return True
    # 额外用标准库函数确认
    if zipfile.is_zipfile(path):
        return True
    try:
        if tarfile.is_tarfile(path):
            return True
    except (IOError, OSError):
        pass
    return False


def _compute_sha256(file_path: Path) -> str:
    """计算文件的 SHA-256 哈希值。"""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# IP / 主机名正则
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
)

_PORT_RE = re.compile(r"^:\d{1,5}$")


# ---------------------------------------------------------------------------
# TargetSpec 数据类
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetSpec:
    """结构化目标模型 — 单一事实来源。

    使用示例:
        TargetSpec.new_network("10.8.21.128", 49152)
        TargetSpec.new_archive(Path("challenge.zip"))
    """

    kind: TargetKind
    original_input: str

    # 网络目标专用
    host: str | None = None
    port: int | None = None

    # 文件 / 归档目标专用
    original_path: Path | None = None
    workspace: Path | None = None  # 解压后的工作目录
    sha256: str | None = None

    # 授权范围
    authorization_scope: str = ""

    @classmethod
    def new_network(cls, host: str, port: int | None = None) -> "TargetSpec":
        scope = f"host={host}"
        if port is not None:
            scope += f",port={port}"
        original = host if port is None else f"{host}:{port}"
        return cls(
            kind="network",
            original_input=original,
            host=host,
            port=port,
            authorization_scope=scope,
        )

    @classmethod
    def new_archive(cls, file_path: Path, workspace: Path, sha256: str) -> "TargetSpec":
        return cls(
            kind="archive",
            original_input=str(file_path),
            original_path=file_path,
            workspace=workspace,
            sha256=sha256,
            authorization_scope=f"file={file_path.name}",
        )

    @classmethod
    def new_single_file(cls, file_path: Path, sha256: str) -> "TargetSpec":
        return cls(
            kind="single_file",
            original_input=str(file_path),
            original_path=file_path,
            workspace=file_path.parent,
            sha256=sha256,
            authorization_scope=f"file={file_path.name}",
        )

    @classmethod
    def new_directory(cls, dir_path: Path) -> "TargetSpec":
        return cls(
            kind="directory",
            original_input=str(dir_path),
            workspace=dir_path,
            authorization_scope=f"directory={dir_path.name}",
        )


# ---------------------------------------------------------------------------
# 规范化入口
# ---------------------------------------------------------------------------


def normalize_target(target: str) -> TargetSpec:
    """验证并规范化目标字符串为 TargetSpec。

    支持:
        - 纯 IP: "10.8.21.128"
        - IP:端口: "10.8.21.128:49152"
        - 主机名: "example.com"
        - 归档文件: "challenge.zip", "forensics.tar.gz"
        - 直接文件: "capture.pcapng", "chall", "disk.img"
        - 目录: "WorkDir/some-dir/"

    Args:
        target: 原始目标字符串。

    Returns:
        结构化的 TargetSpec 实例。

    Raises:
        ValueError: 目标格式无效或文件不存在。
    """
    value = target.strip().rstrip(".")
    if not value:
        raise ValueError("目标不能为空")

    # ── 1. 文件/目录目标 ──
    target_path = Path(value)
    if target_path.exists():
        if target_path.is_dir():
            return TargetSpec.new_directory(target_path.resolve())
        if target_path.is_file():
            sha256 = _compute_sha256(target_path)
            if _is_archive(target_path):
                return TargetSpec.new_archive(target_path.resolve(), Path(""), sha256)
            return TargetSpec.new_single_file(target_path.resolve(), sha256)

    # ── 2. 网络目标（IP:端口, 纯IP, 主机名）──
    # 尝试拆出 :port 后缀
    port: int | None = None
    host_part = value
    if ":" in value and not value.startswith("["):
        *host_parts, port_str = value.rsplit(":", 1)
        host_part = ":".join(host_parts)
        if not port_str.isdigit():
            raise ValueError(f"端口必须是数字: {target!r}")
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError(f"端口超出范围 1-65535: {port}")
        if not host_part:
            raise ValueError(f"缺少主机部分: {target!r}")

    # 尝试解析为 IP
    try:
        ip = str(ipaddress.ip_address(host_part))
        return TargetSpec.new_network(ip, port)
    except ValueError:
        pass

    # 尝试匹配主机名
    if _HOSTNAME_RE.fullmatch(host_part):
        return TargetSpec.new_network(host_part.lower(), port)

    raise ValueError(f"无效的目标地址: {target!r}")


# ---------------------------------------------------------------------------
# 向后兼容
# ---------------------------------------------------------------------------


def validate_target(target: str) -> str:
    """验证并规范化目标为字符串（向后兼容）。

    Args:
        target: 原始目标字符串。

    Returns:
        规范化后的目标字符串（IP 或主机名）。

    Raises:
        ValueError: 目标为文件类型或不合法。
    """
    spec = normalize_target(target)
    if spec.kind != "network":
        raise ValueError(
            f"validate_target 只接受网络目标，收到: {spec.kind}. "
            f"请使用 normalize_target() 以支持文件和归档。",
        )
    if spec.port is not None:
        return f"{spec.host}:{spec.port}"
    return spec.host or spec.original_input
