"""安全解压模块 — 防路径穿越、压缩炸弹、符号链接逃逸、设备文件。

替代直接 extratall()，对不可信 CTF 文件强制安全边界。
"""
from __future__ import annotations

import json
import os
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

# ---------------------------------------------------------------------------
# 安全限制常量
# ---------------------------------------------------------------------------

MAX_ARCHIVE_SIZE = 500 * 1024 * 1024       # 500 MB
MAX_TOTAL_EXTRACTED = 2 * 1024 * 1024 * 1024  # 2 GB
MAX_SINGLE_FILE = 512 * 1024 * 1024         # 512 MB
MAX_FILE_COUNT = 20_000
MAX_PATH_DEPTH = 20
MAX_COMPRESSION_RATIO = 200                 # 压缩比 > 200 视为炸弹
MAX_NAME_LEN = 512

# 拒绝的 Tar 成员类型
_DENIED_TAR_TYPES = {
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
    tarfile.CHRTYPE,
    tarfile.BLKTYPE,
    tarfile.FIFOTYPE,
}


# ---------------------------------------------------------------------------
# 错误类型
# ---------------------------------------------------------------------------


class SafeExtractError(Exception):
    """安全解压错误基类。"""


class PathTraversalError(SafeExtractError):
    """路径穿越检测。"""


class CompressionBombError(SafeExtractError):
    """压缩炸弹检测。"""


class UnsupportedMemberError(SafeExtractError):
    """不支持的归档成员（符号链接/设备文件等）。"""


# ---------------------------------------------------------------------------
# 解压清单
# ---------------------------------------------------------------------------


@dataclass
class ExtractionManifest:
    archive_path: str
    archive_sha256: str
    file_count: int
    total_bytes: int
    files: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 路径安全
# ---------------------------------------------------------------------------


def _safe_path(workdir: Path, member_name: str) -> Path:
    """验证归档成员路径不会逃逸工作目录。

    Raises:
        PathTraversalError: 路径穿越或绝对路径。
    """
    # 拒绝绝对路径和 null 字节
    if os.path.isabs(member_name) or "\x00" in member_name:
        raise PathTraversalError(f"危险路径: {member_name!r}")
    # 规范化并检查深度
    parts = Path(member_name).parts
    if len(parts) > MAX_PATH_DEPTH:
        raise PathTraversalError(f"路径层级过深: {len(parts)} > {MAX_PATH_DEPTH}")
    if len(member_name) > MAX_NAME_LEN:
        raise PathTraversalError(f"路径名过长: {len(member_name)} > {MAX_NAME_LEN}")
    # 拒绝 .. 组件
    if ".." in parts:
        raise PathTraversalError(f"包含路径穿越组件: {member_name!r}")
    # 解析后必须位于 workdir 下
    destination = (workdir / member_name).resolve()
    if not str(destination).startswith(str(workdir.resolve()) + os.sep) and destination != workdir.resolve():
        raise PathTraversalError(
            f"路径逃逸: {member_name!r} → {destination}（不在 {workdir} 内）"
        )
    return destination


# ---------------------------------------------------------------------------
# ZIP 安全解压
# ---------------------------------------------------------------------------


def _extract_zip(archive_path: Path, workdir: Path) -> ExtractionManifest:
    """安全解压 ZIP 文件。

    Raises:
        CompressionBombError: 超过解压限制。
        PathTraversalError: 路径穿越。
    """
    manifest = ExtractionManifest(
        archive_path=str(archive_path),
        archive_sha256="",
        file_count=0,
        total_bytes=0,
    )

    with zipfile.ZipFile(archive_path, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > MAX_FILE_COUNT:
            raise CompressionBombError(
                f"文件数过多: {len(infolist)} > {MAX_FILE_COUNT}"
            )

        for info in infolist:
            # 跳过目录标记
            if info.is_dir():
                continue

            # 检查单个文件压缩比
            if info.compress_size > 0 and info.file_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise CompressionBombError(
                        f"压缩比异常: {info.filename} ({ratio:.0f}:1 > {MAX_COMPRESSION_RATIO}:1)"
                    )

            if info.file_size > MAX_SINGLE_FILE:
                raise CompressionBombError(
                    f"单文件过大: {info.filename} ({info.file_size} > {MAX_SINGLE_FILE})"
                )

            dest = _safe_path(workdir, info.filename)
            dest.parent.mkdir(parents=True, exist_ok=True)

            # 流式读取 + 累计大小检查
            with zf.open(info) as src:
                with open(dest, "wb") as dst:
                    copied = 0
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        copied += len(chunk)
                        manifest.total_bytes += len(chunk)
                        if manifest.total_bytes > MAX_TOTAL_EXTRACTED:
                            raise CompressionBombError(
                                f"解压总量超限: {manifest.total_bytes} > {MAX_TOTAL_EXTRACTED}"
                            )
                        dst.write(chunk)

            # 清除危险权限位
            os.chmod(dest, 0o644)

            manifest.file_count += 1
            manifest.files.append({
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "path": str(dest),
            })

    return manifest


# ---------------------------------------------------------------------------
# Tar 安全解压
# ---------------------------------------------------------------------------


def _extract_tar(archive_path: Path, workdir: Path) -> ExtractionManifest:
    """安全解压 Tar 文件。

    Raises:
        CompressionBombError: 超过解压限制。
        PathTraversalError: 路径穿越。
        UnsupportedMemberError: 符号链接/设备文件等。
    """
    manifest = ExtractionManifest(
        archive_path=str(archive_path),
        archive_sha256="",
        file_count=0,
        total_bytes=0,
    )

    with tarfile.open(archive_path, "r:*") as tf:
        members = tf.getmembers()
        if len(members) > MAX_FILE_COUNT:
            raise CompressionBombError(
                f"文件数过多: {len(members)} > {MAX_FILE_COUNT}"
            )

        for member in members:
            # 拒绝危险类型
            if member.type in _DENIED_TAR_TYPES:
                raise UnsupportedMemberError(
                    f"不支持的成员类型: {member.name} (type={member.type!r})"
                )

            if member.isdir():
                continue

            if member.size > MAX_SINGLE_FILE:
                raise CompressionBombError(
                    f"单文件过大: {member.name} ({member.size} > {MAX_SINGLE_FILE})"
                )

            dest = _safe_path(workdir, member.name)
            dest.parent.mkdir(parents=True, exist_ok=True)

            # 流式提取成员
            with tf.extractfile(member) as src:  # type: ignore[union-attr]
                if src is None:
                    continue
                with open(dest, "wb") as dst:
                    copied = 0
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        copied += len(chunk)
                        manifest.total_bytes += len(chunk)
                        if manifest.total_bytes > MAX_TOTAL_EXTRACTED:
                            raise CompressionBombError(
                                f"解压总量超限: {manifest.total_bytes} > {MAX_TOTAL_EXTRACTED}"
                            )
                        dst.write(chunk)

            # 清除危险权限位
            os.chmod(dest, 0o644)

            manifest.file_count += 1
            manifest.files.append({
                "name": member.name,
                "size": member.size,
                "path": str(dest),
            })

    return manifest


# ---------------------------------------------------------------------------
# 公共入口
# ---------------------------------------------------------------------------


def safe_extract(
    archive_path: Path,
    workdir: Path,
    archive_sha256: str = "",
) -> ExtractionManifest:
    """安全解压 CTF 归档文件到指定目录。

    自动检测 ZIP/Tar 格式，实施多重安全边界:
        - 路径穿越检测
        - 压缩炸弹检测（压缩比 / 总量 / 单文件上限）
        - 符号链接 / 设备文件拒绝
        - 清除 setuid / setgid 等危险权限位

    Args:
        archive_path: 归档文件路径。
        workdir: 解压目标目录（会被创建）。
        archive_sha256: 归档文件的 SHA-256（可选）。

    Returns:
        ExtractionManifest 包含解压文件清单。

    Raises:
        FileNotFoundError: 归档文件不存在。
        SafeExtractError: 安全规则违规。
    """
    if not archive_path.is_file():
        raise FileNotFoundError(f"归档文件不存在: {archive_path}")

    workdir.mkdir(parents=True, exist_ok=True)

    # 检查归档文件大小
    archive_size = archive_path.stat().st_size
    if archive_size > MAX_ARCHIVE_SIZE:
        raise CompressionBombError(
            f"归档文件过大: {archive_size} > {MAX_ARCHIVE_SIZE}"
        )

    # 分发到对应解压函数
    name = archive_path.name.lower()
    if name.endswith(".zip") or zipfile.is_zipfile(archive_path):
        manifest = _extract_zip(archive_path, workdir)
    elif any(name.endswith(s) for s in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")) or tarfile.is_tarfile(archive_path):
        manifest = _extract_tar(archive_path, workdir)
    else:
        raise SafeExtractError(f"不支持的归档格式: {archive_path.name}")

    manifest.archive_sha256 = archive_sha256
    return manifest
