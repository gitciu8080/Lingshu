# Tools/SageMath.py
"""SageMath 跨环境执行工具 - 用于密码学、数论、符号计算等 CTF 场景

执行位置与 scoped_shell / OCR 保持一致：
- 提供 ``executor``（LingshuDockerExecutor）时，代码写入 Agent 工作区容器内执行，
  使用镜像内的 /usr/local/bin/sage（kali-full v3.0 起为 /opt/miniconda3/envs/sage）；
- 未提供 executor 时在宿主机执行，优先直接调用 ``sage`` 命令，
  找不到时才回退到 ``conda run -n <env> sage``（兼容旧部署）。

历史教训（2026-08 bouquet / d3fnv 会话故障）：旧镜像中 SageMath 是 conda-pack
解压目录（未注册进任何 conda），宿主机仅有 miniconda2 且无 sage 环境，
``conda run -n sage`` 必然失败并报 ``--no-banner`` 参数错误。因此本工具
不再依赖 conda 作为首选调用方式。
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from Tools.tooling import AllowedFunctionTool

logger = logging.getLogger(__name__)

# ⚠️ 仅宿主机 conda 回退模式使用
CONDA_CMD = os.getenv("LINGSHU_CONDA_CMD", "conda")
SAGE_ENV_NAME = os.getenv("LINGSHU_SAGE_ENV", "sage")
SAGE_TIMEOUT = int(os.getenv("LINGSHU_SAGE_TIMEOUT", "180"))

# 安全检查：禁止危险操作
FORBIDDEN_PATTERNS = ["os.system", "subprocess", "__import__", "open(", "eval(", "exec("]


def create_sagemath_tool(
    allowed_root: str | Path = "",
    timeout: int | None = None,
    *,
    executor: Any | None = None,
) -> AllowedFunctionTool:
    """创建 SageMath 代码执行工具。

    Args:
        allowed_root: 授权工作区根目录（保留参数，当前实现不限制代码内容，
            仅用于未来扩展）。
        timeout: 默认超时秒数；None 时使用 LINGSHU_SAGE_TIMEOUT。
        executor: LingshuDockerExecutor 实例。提供时 SageMath 在 Docker
            容器内执行（Agent 工作区镜像自带 sage）；None 时在宿主机执行。
    """
    default_timeout = timeout if timeout is not None else SAGE_TIMEOUT

    async def execute_sagemath(code: str, timeout: int | None = None) -> str:
        """在隔离 SageMath 环境中执行数学/密码学计算代码。

        适用场景：RSA/ECC/离散对数等密码学计算、大数运算、模逆、中国剩余定理、
        符号方程求解、多项式因式分解、矩阵运算、格密码 (LLL)、Coppersmith 等。

        Args:
            code: 合法的 SageMath/Python 代码。必须用 print() 输出结果。
                  每次调用都是全新会话，变量不持久化。
            timeout: 超时秒数，默认由服务端配置决定。

        Returns:
            str: 执行结果（stdout）或错误信息（stderr）。
        """
        for pattern in FORBIDDEN_PATTERNS:
            if pattern in code:
                return f"[BLOCKED] 代码包含禁止的模式: {pattern}"

        effective = timeout if timeout is not None else default_timeout
        effective = max(10, int(effective))

        if executor is not None:
            return await _run_in_container(code, effective, executor)
        return await _run_on_host(code, effective)

    async def _run_in_container(code: str, seconds: int, exe: Any) -> str:
        """把代码 base64 编码后送入容器 /tmp 执行，避免 shell 注入与编码问题。"""
        b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
        tmp = f"/tmp/lingshu_sage_{uuid.uuid4().hex}.sage"
        cmd = (
            f"printf %s '{b64}' | base64 -d > '{tmp}' && "
            f"sage '{tmp}'; rc=$?; rm -f '{tmp}'; exit $rc"
        )
        outcome = await exe.exec_shell(cmd, timeout=seconds)
        stdout = outcome.stdout.decode("utf-8", errors="replace").strip()
        stderr = outcome.stderr.decode("utf-8", errors="replace").strip()

        if outcome.timed_out:
            return (
                f"[SageMath Timeout] 执行超过 {seconds} 秒被强制终止，"
                f"请优化算法或减少计算量。\n\n[已有输出]\n{stdout}" if stdout
                else f"[SageMath Timeout] 执行超过 {seconds} 秒被强制终止，请优化算法或减少计算量"
            )
        # GNU timeout: 126/127 表示命令不存在
        if outcome.exit_code in (126, 127):
            return f"[SageMath Error] 容器内找不到 sage 命令。\n{stderr}"
        if outcome.exit_code != 0:
            if stdout:
                return f"[SageMath Error]\n{stderr}\n\n[Stdout]\n{stdout}"
            return f"[SageMath Error]\n{stderr}"
        return stdout or "[SageMath] 执行成功但无输出（请检查是否使用了 print()）"

    async def _run_on_host(code: str, seconds: int) -> str:
        """宿主机模式：优先直接调用 sage，其次回退 conda run（旧部署兼容）。"""
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".sage", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                f.flush()
                tmp_path = f.name

            sage_bin = shutil.which("sage")
            if sage_bin:
                cmd = [sage_bin, tmp_path]
            else:
                cmd = [CONDA_CMD, "run", "-n", SAGE_ENV_NAME, "sage", tmp_path]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=seconds
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                return f"[SageMath Timeout] 执行超过 {seconds} 秒，请优化算法或减少计算量"

            stdout = stdout_b.decode("utf-8", errors="replace").strip()
            stderr = stderr_b.decode("utf-8", errors="replace").strip()

            if proc.returncode == 0:
                return stdout or "[SageMath] 执行成功但无输出（请检查是否使用了 print()）"
            if not sage_bin and proc.returncode in (126, 127):
                return (
                    f"[SageMath Config Error] 宿主机既无 sage 命令也无法通过 "
                    f"'{CONDA_CMD}' 调用，请检查部署环境或改用容器内工作区。"
                )
            hint = "" if sage_bin else "\n\n[提示] 当前走的是 conda 回退模式，建议检查 sage 安装"
            if stdout:
                return f"[SageMath Error]\n{stderr}{hint}\n\n[Stdout]\n{stdout}"
            return f"[SageMath Error]\n{stderr}{hint}"

        except FileNotFoundError:
            return (
                f"[SageMath Config Error] 宿主机找不到 sage / '{CONDA_CMD}'，"
                f"请检查 LINGSHU_CONDA_CMD 环境变量、conda 安装或改用容器内工作区。"
            )
        except Exception as e:
            logger.exception("SageMath execution failed")
            return f"[SageMath Exception] {type(e).__name__}: {e}"
        finally:
            if tmp_path and Path(tmp_path).exists():
                Path(tmp_path).unlink(missing_ok=True)

    return AllowedFunctionTool(execute_sagemath, is_read_only=True)
