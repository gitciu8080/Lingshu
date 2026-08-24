# Tools/SageMath.py
"""SageMath 跨环境执行工具 - 用于密码学、数论、符号计算等 CTF 场景"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

SAGE_ENV_NAME = os.getenv("LINGSHU_SAGE_ENV", "sage")
SAGE_TIMEOUT = int(os.getenv("LINGSHU_SAGE_TIMEOUT", "120"))
_SINGULAR_NOISE = (
    "// ** Could not find dynamic library: p_Procs_FieldIndep.so",
    "// ** Singular will work properly, but much slower.",
    "// ** See the INSTALL section in the Singular manual for details.",
)


def _clean_success_output(value: str) -> str:
    """移除当前 Conda Sage 包已知且不影响计算结果的 Singular 启动噪声。"""
    return "\n".join(
        line for line in value.splitlines()
        if not any(line.strip().startswith(prefix) for prefix in _SINGULAR_NOISE)
    ).strip()


def _resolve_executable(value: str) -> Path | None:
    if not value.strip():
        return None
    candidate = Path(value).expanduser()
    if candidate.is_file():
        return candidate.resolve()
    resolved = shutil.which(value)
    return Path(resolved).resolve() if resolved else None


def _resolve_sage_command() -> tuple[list[str], str]:
    """返回不依赖 shell/conda activate 的 Sage 启动命令。"""
    configured_sage = os.getenv("LINGSHU_SAGE_CMD", "").strip()
    if configured_sage:
        executable = _resolve_executable(configured_sage)
        if executable is None:
            raise FileNotFoundError(
                f"LINGSHU_SAGE_CMD 指向的 Sage 不存在：{configured_sage}",
            )
        return [str(executable)], f"direct:{executable}"

    env_name = os.getenv("LINGSHU_SAGE_ENV", SAGE_ENV_NAME).strip() or "sage"
    candidates: list[Path] = []
    configured_prefix = os.getenv("LINGSHU_SAGE_PREFIX", "").strip()
    if configured_prefix:
        candidates.append(Path(configured_prefix).expanduser() / "bin" / "sage")

    # 当前 API Python 位于 <conda-root>/envs/agentscope/bin/python；优先查找
    # 同级 sage 环境，不依赖 systemd 的 PATH 或 conda shell 初始化。
    current_python = Path(sys.executable).resolve()
    if len(current_python.parents) >= 3 and current_python.parent.name == "bin":
        envs_dir = current_python.parent.parent.parent
        if envs_dir.name == "envs":
            candidates.append(envs_dir / env_name / "bin" / "sage")

    conda_exe = _resolve_executable(os.getenv("CONDA_EXE", ""))
    if conda_exe is not None:
        candidates.append(conda_exe.parent.parent / "envs" / env_name / "bin" / "sage")
    path_sage = _resolve_executable("sage")
    if path_sage is not None:
        candidates.append(path_sage)

    for candidate in dict.fromkeys(path.expanduser() for path in candidates):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = candidate.resolve()
            return [str(resolved)], f"direct:{resolved}"

    # 最后兼容自定义 Conda 安装；这里同样解析为绝对路径。
    configured_conda = os.getenv("LINGSHU_CONDA_CMD", "").strip()
    conda = _resolve_executable(configured_conda) if configured_conda else None
    if conda is None:
        conda = _resolve_executable("conda")
    if conda is not None:
        return [str(conda), "run", "--no-capture-output", "-n", env_name, "sage"], (
            f"conda:{conda} env={env_name}"
        )

    searched = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(
        "找不到 SageMath 可执行文件；请设置 LINGSHU_SAGE_CMD 或 "
        f"LINGSHU_SAGE_PREFIX。已检查：{searched}",
    )


def execute_sagemath(code: str, timeout: int | None = None) -> str:
    """在独立 Sage conda 环境中执行 SageMath 代码。

    适用场景：
    - RSA/ECC/离散对数等密码学计算
    - 大数运算、模逆、中国剩余定理
    - 符号方程求解、多项式因式分解
    - 矩阵运算、线性代数
    - 数论函数（欧拉函数、原根、二次剩余等）

    Args:
        code: 合法的 SageMath/Python 代码。必须用 print() 输出结果。
              每次调用都是全新会话，变量不持久化。
        timeout: 超时秒数，默认使用环境变量 LINGSHU_SAGE_TIMEOUT

    Returns:
        str: 执行结果（stdout）或错误信息（stderr）
    """
    if timeout is None:
        timeout = SAGE_TIMEOUT

    # 安全检查：禁止危险操作
    forbidden = ["os.system", "subprocess", "__import__", "open(", "eval(", "exec("]
    for pattern in forbidden:
        if pattern in code:
            return f"[BLOCKED] 代码包含禁止的模式: {pattern}"

    tmp_path = None
    runtime_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        runtime_dir = tempfile.TemporaryDirectory(prefix="lingshu-sage-")
        dot_sage = Path(runtime_dir.name) / "dot_sage"
        dot_sage.mkdir(mode=0o700)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sage", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            f.flush()
            tmp_path = f.name

        command, command_source = _resolve_sage_command()
        cmd = [*command, tmp_path]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "DOT_SAGE": str(dot_sage)},
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode == 0:
            stdout = _clean_success_output(stdout)
            return stdout if stdout else (
                "[SageMath] 执行成功但无输出（请检查是否使用了 print()）"
            )
        else:
            # 返回 stderr 帮助 Agent 自我修正
            detail = (
                f"[SageMath Error] runtime={command_source}\n{stderr}"
            )
            return f"{detail}\n\n[Stdout]\n{stdout}" if stdout else detail

    except subprocess.TimeoutExpired:
        return f"[SageMath Timeout] 执行超过 {timeout} 秒，请优化算法或减少计算量"
    except FileNotFoundError as exc:
        return f"[SageMath Config Error] {exc}"
    except Exception as e:
        logger.exception("SageMath execution failed")
        return f"[SageMath Exception] {type(e).__name__}: {e}"
    finally:
        if tmp_path and Path(tmp_path).exists():
            Path(tmp_path).unlink(missing_ok=True)
        if runtime_dir is not None:
            runtime_dir.cleanup()
