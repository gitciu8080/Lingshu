"""安全解压模块 — 防路径穿越、压缩炸弹、符号链接逃逸、设备文件。

替代直接 extratall()，对不可信 CTF 文件强制安全边界。
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
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


class EncryptedArchiveError(SafeExtractError):
    """归档需要密码；调用方可保留原文件继续做口令分析。"""


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
    encrypted: bool = False
    warning: str = ""


# ---------------------------------------------------------------------------
# 路径安全
# ---------------------------------------------------------------------------


def _safe_path(workdir: Path, member_name: str) -> Path:
    """验证归档成员路径不会逃逸工作目录。

    Raises:
        PathTraversalError: 路径穿越或绝对路径。
    """
    portable_name = member_name.replace("\\", "/")
    if not portable_name or portable_name == ".":
        raise PathTraversalError(f"危险路径: {member_name!r}")
    # 按跨平台语义拒绝绝对路径、盘符、控制字符和 null 字节。
    if (
        portable_name.startswith(("/", "//"))
        or (len(portable_name) >= 2 and portable_name[1] == ":")
        or any(ord(char) < 32 for char in portable_name)
    ):
        raise PathTraversalError(f"危险路径: {member_name!r}")
    # 规范化并检查深度
    parts = tuple(part for part in portable_name.split("/") if part not in ("", "."))
    if len(parts) > MAX_PATH_DEPTH:
        raise PathTraversalError(f"路径层级过深: {len(parts)} > {MAX_PATH_DEPTH}")
    if len(member_name) > MAX_NAME_LEN:
        raise PathTraversalError(f"路径名过长: {len(member_name)} > {MAX_NAME_LEN}")
    # 拒绝 .. 组件
    if ".." in parts:
        raise PathTraversalError(f"包含路径穿越组件: {member_name!r}")
    # 解析后必须位于 workdir 下
    destination = workdir.joinpath(*parts).resolve()
    if not str(destination).startswith(str(workdir.resolve()) + os.sep) and destination != workdir.resolve():
        raise PathTraversalError(
            f"路径逃逸: {member_name!r} → {destination}（不在 {workdir} 内）"
        )
    return destination


def _validate_destination(names: list[str], workdir: Path) -> None:
    """预检重复路径及文件/目录前缀冲突，避免覆盖和顺序依赖。"""
    seen: set[str] = set()
    for name in names:
        relative = _safe_path(workdir, name).relative_to(workdir.resolve()).as_posix()
        folded = relative.casefold()
        if folded in seen:
            raise UnsupportedMemberError(f"归档包含重复路径: {name}")
        parts = relative.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]).casefold() in seen:
                raise UnsupportedMemberError(f"归档包含文件/目录路径冲突: {name}")
        seen.add(folded)


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

        file_infos = [info for info in infolist if not info.is_dir()]
        _validate_destination([info.filename for info in file_infos], workdir)
        for info in file_infos:
            # 跳过目录标记
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if info.create_system == 3 and file_type and file_type != stat.S_IFREG:
                raise UnsupportedMemberError(f"不支持的 ZIP 成员类型: {info.filename}")
            if info.flag_bits & 0x1:
                raise EncryptedArchiveError("ZIP 归档需要密码")

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
                        if copied > MAX_SINGLE_FILE:
                            raise CompressionBombError(
                                f"单文件实际大小超限: {info.filename} ({copied} > {MAX_SINGLE_FILE})"
                            )
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
                "size": copied,
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

        _validate_destination([member.name for member in members if member.isfile()], workdir)
        for member in members:
            # 对不可信归档采用类型白名单。
            if not (member.isfile() or member.isdir()):
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
                        if copied > MAX_SINGLE_FILE:
                            raise CompressionBombError(
                                f"单文件实际大小超限: {member.name} ({copied} > {MAX_SINGLE_FILE})"
                            )
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
                "size": copied,
                "path": str(dest),
            })

    return manifest


def _extract_7z(archive_path: Path, workdir: Path) -> ExtractionManifest:
    """用 7z CLI 安全解压 7z，提取前后均校验成员与容量限制。"""
    executable = shutil.which("7z")
    if executable is None:
        raise SafeExtractError("缺少 7z 命令，无法解压 .7z 归档")

    try:
        listing = subprocess.run(
            [executable, "l", "-slt", "--", str(archive_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafeExtractError(f"7z 归档列表读取失败: {exc}") from exc

    entries: list[tuple[str, int]] = []
    encrypted = False
    record: dict[str, str] = {}
    for line in listing.stdout.splitlines() + [""]:
        if not line.strip():
            name = record.get("Path")
            if name and "Size" in record and record.get("Folder") != "+":
                try:
                    size = int(record["Size"])
                except ValueError as exc:
                    raise SafeExtractError(f"7z 成员大小无效: {name}") from exc
                _safe_path(workdir, name)
                entries.append((name, size))
                encrypted = encrypted or record.get("Encrypted") == "+"
            record = {}
            continue
        key, separator, value = line.partition(" = ")
        if separator:
            record[key] = value

    if len(entries) > MAX_FILE_COUNT:
        raise CompressionBombError(f"文件数过多: {len(entries)} > {MAX_FILE_COUNT}")
    total_declared = 0
    for name, size in entries:
        if size > MAX_SINGLE_FILE:
            raise CompressionBombError(f"单文件过大: {name} ({size} > {MAX_SINGLE_FILE})")
        total_declared += size
        if total_declared > MAX_TOTAL_EXTRACTED:
            raise CompressionBombError(
                f"解压总量超限: {total_declared} > {MAX_TOTAL_EXTRACTED}"
            )
    _validate_destination([name for name, _ in entries], workdir)
    if encrypted:
        raise EncryptedArchiveError("7z 归档需要密码")

    manifest = ExtractionManifest(str(archive_path), "", 0, 0)
    with tempfile.TemporaryDirectory(prefix=".lingshu-7z-", dir=workdir.parent) as temp_dir:
        temp_path = Path(temp_dir)
        try:
            process = subprocess.Popen(
                [executable, "x", "-y", f"-o{temp_path}", "--", str(archive_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 300
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    process.kill()
                    process.communicate()
                    raise SafeExtractError("7z 解压超时")
                count = 0
                actual_total = 0
                for candidate in temp_path.rglob("*"):
                    if candidate.is_symlink():
                        process.kill()
                        process.communicate()
                        raise UnsupportedMemberError(
                            f"不支持的 7z 符号链接: {candidate.relative_to(temp_path)}"
                        )
                    if candidate.is_file():
                        count += 1
                        actual_total += candidate.stat().st_size
                if count > MAX_FILE_COUNT or actual_total > MAX_TOTAL_EXTRACTED:
                    process.kill()
                    process.communicate()
                    raise CompressionBombError("7z 解压过程超过文件数或总大小限制")
                time.sleep(0.05)
            stdout, stderr = process.communicate()
            if process.returncode:
                raise subprocess.CalledProcessError(
                    process.returncode, process.args, output=stdout, stderr=stderr,
                )
        except subprocess.CalledProcessError as exc:
            output = f"{exc.stdout or ''}\n{exc.stderr or ''}".lower()
            if "wrong password" in output or "encrypted" in output or "password" in output:
                raise EncryptedArchiveError("7z 归档需要密码") from exc
            raise SafeExtractError(f"7z 解压失败: {exc.stderr or exc}") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise SafeExtractError(f"7z 解压失败: {exc}") from exc

        for source in temp_path.rglob("*"):
            if source.is_symlink() or not (source.is_file() or source.is_dir()):
                raise UnsupportedMemberError(f"不支持的 7z 成员类型: {source.relative_to(temp_path)}")
            if not source.is_file():
                continue
            name = source.relative_to(temp_path).as_posix()
            size = source.stat().st_size
            if size > MAX_SINGLE_FILE:
                raise CompressionBombError(f"单文件过大: {name} ({size} > {MAX_SINGLE_FILE})")
            manifest.total_bytes += size
            if manifest.total_bytes > MAX_TOTAL_EXTRACTED:
                raise CompressionBombError(
                    f"解压总量超限: {manifest.total_bytes} > {MAX_TOTAL_EXTRACTED}"
                )
            destination = _safe_path(workdir, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o644)
            manifest.file_count += 1
            manifest.files.append({"name": name, "size": size, "path": str(destination)})

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

    # 检查归档文件大小
    archive_size = archive_path.stat().st_size
    if archive_size > MAX_ARCHIVE_SIZE:
        raise CompressionBombError(
            f"归档文件过大: {archive_size} > {MAX_ARCHIVE_SIZE}"
        )

    header = archive_path.read_bytes()[:8]
    if header.startswith(b"7z\xbc\xaf'\x1c"):
        extractor = _extract_7z
    elif zipfile.is_zipfile(archive_path):
        extractor = _extract_zip
    elif tarfile.is_tarfile(archive_path):
        extractor = _extract_tar
    else:
        raise SafeExtractError(f"归档损坏或格式不受支持: {archive_path.name}")

    workdir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{workdir.name}-", dir=workdir.parent))
    try:
        manifest = extractor(archive_path, staging)
        if workdir.exists():
            shutil.rmtree(workdir)
        os.replace(staging, workdir)
        for item in manifest.files:
            item["path"] = str(workdir / item["name"])
    except EncryptedArchiveError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        return ExtractionManifest(
            archive_path=str(archive_path),
            archive_sha256=archive_sha256,
            file_count=0,
            total_bytes=0,
            encrypted=True,
            warning=str(exc),
        )
    except (SafeExtractError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, SafeExtractError):
            raise
        raise SafeExtractError(f"归档解压失败: {exc}") from exc

    manifest.archive_sha256 = archive_sha256
    return manifest
