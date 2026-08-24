"""Volatility 2.6（Python 2）受限内存取证工具封装。"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from Tools.tooling import AllowedFunctionTool


_VOLATILITY_ROOT = Path(__file__).resolve().parent / "volatility"
_VOLATILITY_ENTRY = _VOLATILITY_ROOT / "vol.py"
_PLUGIN_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_BLOCKED_OPTIONS = (
    "--plugins", "--conf-file", "--cache-directory", "--output-file",
    "--location", "--filename", "--profile", "--dump-dir",
)
_MAX_OUTPUT_CHARS = 160_000


def _python2_executable() -> str:
    configured = os.getenv("LINGSHU_PYTHON2", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        raise RuntimeError(f"配置的 Python 2 不存在：{configured}")
    resolved = shutil.which("python2") or shutil.which("python2.7")
    if not resolved:
        raise RuntimeError("未安装 Python 2.7，Volatility 2 无法运行")
    return resolved


def _authorized_path(value: str, roots: tuple[Path, ...], *, must_exist: bool) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    candidate = candidate.resolve()
    if not any(candidate == root or candidate.is_relative_to(root) for root in roots):
        raise PermissionError("路径不在本任务授权工作区内")
    if must_exist and not candidate.is_file():
        raise FileNotFoundError(f"内存镜像不存在：{candidate}")
    return candidate


def _safe_plugin_options(options: list[str] | None) -> list[str]:
    if not options:
        return []
    if len(options) > 24:
        raise ValueError("plugin_options 最多 24 项")
    result: list[str] = []
    for raw in options:
        value = str(raw)
        lowered = value.lower()
        if not value or len(value) > 512 or any(char in value for char in "\x00\r\n"):
            raise ValueError("插件参数为空、过长或包含非法控制字符")
        if value in {"-f", "-l", "--profile"} or any(
            lowered == item or lowered.startswith(item + "=")
            for item in _BLOCKED_OPTIONS
        ):
            raise ValueError(f"插件参数由安全封装管理，禁止传入：{value}")
        result.append(value)
    return result


def create_volatility_tools(
    allowed_roots: Iterable[str | Path],
    timeout: int = 300,
) -> list[AllowedFunctionTool]:
    """创建仅可分析任务目录内镜像的 Volatility 2 工具。"""
    roots = tuple(dict.fromkeys(Path(root).expanduser().resolve() for root in allowed_roots))
    if not roots:
        raise ValueError("Volatility 至少需要一个授权目录")

    async def _execute(args: list[str], cache_root: Path) -> dict:
        python2 = _python2_executable()
        if not _VOLATILITY_ENTRY.is_file():
            raise RuntimeError(f"Volatility 入口不存在：{_VOLATILITY_ENTRY}")
        cache_root.mkdir(parents=True, exist_ok=True)
        command = [python2, str(_VOLATILITY_ENTRY), *args]
        # Python 3.14 的 asyncio 子进程 transport 等待部分 Python 2 程序
        # 退出时可能卡住；Popen 仍然不经过 shell，再由线程异步等待。
        # 不使用 asyncio 子进程 transport（Python 3.14 等待 Python 2 时存在
        # 兼容问题），也不依赖线程回调唤醒事件循环。输出先落临时文件，主
        # 循环以异步短轮询等待进程，既不会堵塞 SSE，也不会撑满 PIPE。
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                command,
                cwd=str(_VOLATILITY_ROOT),
                env={**os.environ, "XDG_CACHE_HOME": str(cache_root)},
                stdout=stdout_file,
                stderr=stderr_file,
            )
            deadline = asyncio.get_running_loop().time() + max(
                15, min(int(timeout), 1800),
            )
            timed_out = False
            try:
                while process.poll() is None:
                    if asyncio.get_running_loop().time() >= deadline:
                        timed_out = True
                        process.terminate()
                        break
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                process.terminate()
                raise
            if timed_out:
                for _ in range(30):
                    if process.poll() is not None:
                        break
                    await asyncio.sleep(0.1)
                if process.poll() is None:
                    process.kill()
                return {"ok": False, "error": "Volatility 分析超时", "timeout": timeout}

            stdout_file.seek(0)
            stdout = stdout_file.read(_MAX_OUTPUT_CHARS + 1)
            stderr_file.seek(0, os.SEEK_END)
            stderr_size = stderr_file.tell()
            stderr_file.seek(max(0, stderr_size - 20_001))
            stderr = stderr_file.read(20_001)

        output = stdout.decode("utf-8", errors="replace")
        error = stderr.decode("utf-8", errors="replace")
        truncated = len(output) > _MAX_OUTPUT_CHARS or len(error) > 20_000
        return {
            "ok": process.returncode == 0,
            "exit_code": process.returncode,
            "output": output[:_MAX_OUTPUT_CHARS],
            "stderr": error[-20_000:],
            "truncated": truncated,
        }

    async def volatility_status() -> dict:
        """检查 Python 2 与仓库内 Volatility 2.6 是否可以启动。"""
        try:
            python2 = _python2_executable()
            # ``--info`` 会完整加载并枚举数百个插件，在低配服务器上可能
            # 超过一分钟；``-h`` 同样完成框架初始化，适合作为健康检查。
            result = await _execute(["-h"], roots[0] / ".volatility_cache")
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc)}
        first_line = next(
            (
                line.strip()
                for line in (
                    str(result.get("stderr") or "")
                    + "\n"
                    + str(result.get("output") or "")
                ).splitlines()
                if line.strip()
                and "Volatility Foundation Volatility Framework" in line
            ),
            "unknown",
        )
        return {
            "ok": bool(result.get("ok")),
            "python2": python2,
            "entry": str(_VOLATILITY_ENTRY),
            "version": first_line,
            "note": "基础插件可用；依赖 yara 的插件需另行安装 Python 2 yara 模块。",
        }

    async def volatility_analyze(
        image_path: str,
        plugin: str,
        profile: str = "",
        plugin_options: list[str] | None = None,
        output_dir: str = "",
    ) -> dict:
        """对授权工作区内的内存镜像执行一个 Volatility 2 插件。

        推荐流程：先调用 imageinfo 或 kdbgscan 确定 Windows profile，再依次调用
        pslist/psscan、netscan、cmdline、consoles、filescan、malfind 等插件。

        Args:
            image_path: 当前任务目录内的内存镜像路径。
            plugin: Volatility 插件名，例如 imageinfo、pslist、netscan、malfind。
            profile: Windows profile，例如 Win7SP1x64；imageinfo/kdbgscan 时可留空。
            plugin_options: 插件专属参数列表，例如 ["-p", "1234"]。
            output_dir: 需要导出文件时使用的任务目录内输出子目录；为空则不传 dump-dir。
        """
        try:
            image = _authorized_path(image_path, roots, must_exist=True)
            plugin_name = plugin.strip().lower()
            if not _PLUGIN_RE.fullmatch(plugin_name) or plugin_name == "volshell":
                raise ValueError("插件名不合法或属于禁止的交互式插件")
            if profile and not _PROFILE_RE.fullmatch(profile.strip()):
                raise ValueError("profile 只能包含字母、数字、点、下划线和连字符")
            options = _safe_plugin_options(plugin_options)
            args = ["-f", str(image)]
            if profile.strip():
                args.extend(["--profile", profile.strip()])
            args.append(plugin_name)
            args.extend(options)
            resolved_output = None
            if output_dir.strip():
                raw_output = Path(output_dir).expanduser()
                resolved_output = (
                    raw_output.resolve()
                    if raw_output.is_absolute()
                    else (image.parent / raw_output).resolve()
                )
                if not any(
                    resolved_output == root or resolved_output.is_relative_to(root)
                    for root in roots
                ):
                    raise PermissionError("输出目录不在本任务授权工作区内")
                resolved_output.mkdir(parents=True, exist_ok=True)
                args.append(f"--dump-dir={resolved_output}")
        except (RuntimeError, PermissionError, FileNotFoundError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

        result = await _execute(args, image.parent / ".volatility_cache")
        result.update({
            "image": str(image),
            "plugin": plugin_name,
            "profile": profile.strip() or None,
            "output_dir": str(resolved_output) if resolved_output else None,
        })
        return result

    return [
        AllowedFunctionTool(volatility_status, is_read_only=True),
        AllowedFunctionTool(volatility_analyze, is_concurrency_safe=False),
    ]
