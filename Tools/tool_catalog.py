"""运行时攻防能力目录。

AgentScope 会自动向模型公开已经注册的 Function/MCP 工具。本模块补齐系统
命令的发现能力，并确保模型只看到“已安装、已启用、分配给当前角色”的交集。
"""
from __future__ import annotations

import json
import importlib
import importlib.metadata
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from Tools.tooling import AllowedFunctionTool

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_MANIFEST = _PROJECT_ROOT / "config" / "tool_catalog.json"
_DEFAULT_REQUIREMENTS = _PROJECT_ROOT / "requirements.txt"


def python_environment_snapshot(
    requirements_path: str | Path = _DEFAULT_REQUIREMENTS,
) -> dict[str, Any]:
    """Return the running interpreter's distribution inventory and lock coverage.

    The API process is the authority here: checking ``python3`` or a distro
    package database can report a different environment from the AgentScope
    Conda environment that actually imports the project.
    """
    declared: dict[str, Requirement] = {}
    ignored_lines: list[str] = []
    path = Path(requirements_path)
    if path.is_file():
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(("-r", "--")):
                continue
            try:
                requirement = Requirement(line)
            except InvalidRequirement:
                ignored_lines.append(line[:160])
                continue
            declared[canonicalize_name(requirement.name)] = requirement

    installed: dict[str, tuple[str, str]] = {}
    for distribution in importlib.metadata.distributions():
        name = str(distribution.metadata.get("Name") or "").strip()
        if not name:
            continue
        key = canonicalize_name(name)
        # 同名 distribution 不应出现；若出现则保留版本号较长的可读记录，
        # 不尝试导入或比较版本，避免状态面板产生副作用。
        installed.setdefault(key, (name, str(distribution.version)))

    packages: list[dict[str, str]] = []
    matched = mismatched = untracked = 0
    for key, (name, version) in installed.items():
        requirement = declared.get(key)
        if requirement is None:
            state, required = "untracked", ""
            untracked += 1
        elif not requirement.specifier or requirement.specifier.contains(version, prereleases=True):
            state, required = "matched", str(requirement)
            matched += 1
        else:
            state, required = "version_mismatch", str(requirement)
            mismatched += 1
        packages.append({
            "name": name,
            "version": version,
            "required": required,
            "status": state,
        })

    missing = 0
    for key, requirement in declared.items():
        if key not in installed:
            missing += 1
            packages.append({
                "name": requirement.name,
                "version": "",
                "required": str(requirement),
                "status": "missing",
            })
    packages.sort(key=lambda item: (item["status"] != "missing", item["name"].lower()))
    return {
        "interpreter": f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "package_count": len(installed),
        "requirements_count": len(declared),
        "counts": {
            "matched": matched,
            "untracked": untracked,
            "missing": missing,
            "version_mismatch": mismatched,
        },
        "packages": packages,
        "ignored_requirement_lines": ignored_lines,
    }


@dataclass(frozen=True, slots=True)
class ToolCapability:
    id: str
    category: str
    command_candidates: tuple[str, ...]
    version_args: tuple[str, ...]
    roles: tuple[str, ...]
    risk: str
    approval_required: bool
    description: str
    usage_hint: str
    alternatives: tuple[str, ...]
    # Python 库并不是 shell 命令。将它们登记到同一目录，可让状态面板
    # 使用运行 API 的解释器检测依赖，而不是误用系统 Python 的安装状态。
    python_modules: tuple[tuple[str, str], ...] = ()
    # 可执行文件存在并不等于运行组件完整，例如 tesseract 的语言数据包。
    # 通过无副作用命令检查其输出中是否存在指定能力标记。
    health_check_args: tuple[str, ...] = ()
    health_check_contains: tuple[str, ...] = ()
    # 例如 PDF 模板字体等项目内资源。路径相对项目根目录，避免客户机绝对
    # 路径差异导致环境面板误报。
    required_files: tuple[str, ...] = ()
    # 某项功能往往依赖多个命令（例如 PDF OCR 的 pdftoppm+tesseract）。
    # command_candidates 表示替代项，required_commands 表示必须同时存在。
    required_commands: tuple[str, ...] = ()
    # ``find_spec`` 只能说明文件存在，无法发现 WeasyPrint 缺少 Pango/Cairo
    # 等动态库的情况，因此支持安全的实际 import 健康检查。
    import_check_modules: tuple[str, ...] = ()
    # 少数系统能力需要端到端验证；当前仅支持 PDF 报告链路，执行结果有缓存。
    runtime_check: str = ""
    # 个别便携式工具会携带自己的动态库（如客户机本地 QEMU）。仅用于
    # 无副作用的版本/健康检查；实际 Agent 子进程由 tooling.py 使用相同配置。
    environment: tuple[tuple[str, str], ...] = ()
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolCapability":
        tool_id = str(data.get("id", "")).strip().lower()
        if not tool_id or not tool_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"非法工具 id: {tool_id!r}")
        candidates = tuple(str(item).strip() for item in data.get("command_candidates", []) if str(item).strip())
        modules: list[tuple[str, str]] = []
        for raw_module in data.get("python_modules", []):
            if isinstance(raw_module, str):
                module = raw_module.strip()
                distribution = module
            elif isinstance(raw_module, dict):
                module = str(raw_module.get("module", "")).strip()
                distribution = str(raw_module.get("distribution") or module).strip()
            else:
                raise ValueError(f"工具 {tool_id} 的 python_modules 项格式无效")
            if not module or not distribution:
                raise ValueError(f"工具 {tool_id} 的 Python 模块声明不完整")
            modules.append((module, distribution))
        health_args = tuple(str(item).strip() for item in data.get("health_check_args", []) if str(item).strip())
        health_contains = tuple(str(item).strip() for item in data.get("health_check_contains", []) if str(item).strip())
        if bool(health_args) != bool(health_contains):
            raise ValueError(f"工具 {tool_id} 的健康检查必须同时声明参数和预期输出")
        required_files = tuple(str(item).strip() for item in data.get("required_files", []) if str(item).strip())
        required_commands = tuple(str(item).strip() for item in data.get("required_commands", []) if str(item).strip())
        import_check_modules = tuple(
            str(item).strip() for item in data.get("import_check_modules", []) if str(item).strip()
        )
        runtime_check = str(data.get("runtime_check", "")).strip().lower()
        if runtime_check not in {
            "", "pdf_report_generation", "pdf_mermaid_rendering", "pdf_font_resources",
            "antsword_electron_loader", "uv_runtime",
        }:
            raise ValueError(f"工具 {tool_id} 声明了未知运行时健康检查: {runtime_check}")
        if not candidates and not modules and not required_files and not required_commands and not runtime_check:
            raise ValueError(f"工具 {tool_id} 至少需要一种可检测的能力声明")
        raw_environment = data.get("environment", {})
        if not isinstance(raw_environment, dict):
            raise ValueError(f"工具 {tool_id} 的 environment 必须为对象")
        environment: list[tuple[str, str]] = []
        for raw_name, raw_value in raw_environment.items():
            name = str(raw_name).strip()
            value = str(raw_value).strip()
            if not name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError(f"工具 {tool_id} 的环境变量名无效: {name!r}")
            if value:
                environment.append((name, value))
        return cls(
            id=tool_id,
            category=str(data.get("category", "other")).strip().lower() or "other",
            command_candidates=candidates,
            version_args=tuple(str(item) for item in data.get("version_args", ["--version"])),
            roles=tuple(str(item).strip().lower() for item in data.get("roles", []) if str(item).strip()),
            risk=str(data.get("risk", "local_analysis")).strip().lower(),
            approval_required=bool(data.get("approval_required", False)),
            description=str(data.get("description", "")).strip(),
            usage_hint=str(data.get("usage_hint", "")).strip(),
            alternatives=tuple(str(item).strip().lower() for item in data.get("alternatives", []) if str(item).strip()),
            python_modules=tuple(modules),
            health_check_args=health_args,
            health_check_contains=health_contains,
            required_files=required_files,
            required_commands=required_commands,
            import_check_modules=import_check_modules,
            runtime_check=runtime_check,
            environment=tuple(environment),
            enabled=bool(data.get("enabled", True)),
        )


def _resolve_required_file(candidate: str) -> Path:
    """Resolve a manifest resource path without depending on process CWD."""
    expanded = os.path.expandvars(candidate).strip()
    path = Path(expanded).expanduser()
    if not path.is_absolute():
        path = _PROJECT_ROOT / path
    return path.resolve()


def _validate_pdf_file(path: Path) -> None:
    """Ensure a generated report is non-empty and parseable before marking ready."""
    if not path.is_file() or path.stat().st_size < 1024:
        raise RuntimeError("生成文件不存在或大小异常")
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    if not reader.pages:
        raise RuntimeError("生成文件没有可读取页面")


def _check_pdf_report_generation() -> tuple[str, str, list[str]]:
    """Exercise both PDF engines in a temporary directory, never touching session data."""
    mission = {
        "goal": "PDF 报告运行环境健康检查",
        "updated_at": "2026-01-01T00:00:00+08:00",
        "success": True,
        "target": "local-healthcheck",
    }
    summary = "# PDF 报告环境检查\n\n## 一、概述\n\n运行环境自检。\n\n```mermaid\nflowchart LR\nA[输入] --> B[报告]\n```"
    errors: list[str] = []
    primary_ok = fallback_ok = False
    try:
        from Tools.WeasyReport import generate_weasyprint_pdf
        with TemporaryDirectory(prefix="lingshu-pdf-health-") as directory:
            primary = generate_weasyprint_pdf("weasyprint-health", summary, mission, directory)
            _validate_pdf_file(primary)
        primary_ok = True
    except Exception as exc:  # 调用方仅用于可观测性，不能让状态接口失败
        errors.append(f"WeasyPrint 主引擎不可用: {str(exc)[:300]}")
    try:
        from Tools.Report import _generate_reportlab_pdf
        with TemporaryDirectory(prefix="lingshu-pdf-health-") as directory:
            fallback = _generate_reportlab_pdf("reportlab-health", summary, mission, directory)
            _validate_pdf_file(fallback)
        fallback_ok = True
    except Exception as exc:  # 同上
        errors.append(f"ReportLab 回退引擎不可用: {str(exc)[:300]}")

    if primary_ok and fallback_ok:
        return "available", "WeasyPrint 主引擎 + ReportLab 回退引擎验证通过", errors
    if primary_ok:
        return "degraded", "WeasyPrint 主引擎验证通过（ReportLab 回退不可用）", errors
    if fallback_ok:
        return "degraded", "ReportLab 回退引擎验证通过（WeasyPrint 主引擎不可用）", errors
    return "missing", "PDF 报告双引擎均不可用", errors


def _check_pdf_mermaid_rendering() -> tuple[str, str, list[str]]:
    """Verify the optional Mermaid-to-SVG enhancement without session writes."""
    renderer = _PROJECT_ROOT / "Skills" / "beautiful-mermaid" / "scripts" / "render.js"
    if not renderer.is_file():
        return "missing", "Mermaid 渲染器缺失", [f"未找到: {renderer}"]
    node = shutil.which("node")
    if not node:
        return "missing", "Mermaid 渲染器不可用", ["未找到 node"]
    try:
        with TemporaryDirectory(prefix="lingshu-mermaid-health-") as directory:
            root = Path(directory)
            source = root / "health.mmd"
            destination = root / "health.svg"
            source.write_text("flowchart LR\nA[输入] --> B[报告]\n", encoding="utf-8")
            completed = subprocess.run(
                [node, str(renderer), str(source), "--format", "svg", "--theme", "github-light", "--preset", "modern", "--output", str(destination)],
                capture_output=True, text=True, errors="replace", timeout=25, check=False,
            )
            if completed.returncode != 0 or not destination.is_file() or destination.stat().st_size <= 100:
                detail = (completed.stderr or completed.stdout or "未生成 SVG").strip()[:300]
                return "missing", "Mermaid SVG 渲染不可用", [detail]
        return "available", "Mermaid SVG 渲染验证通过", []
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "degraded", "Mermaid SVG 渲染检查失败", [str(exc)[:300]]


def _check_pdf_font_resources() -> tuple[str, str, list[str]]:
    """Resolve the active font configuration, including .env path overrides."""
    try:
        from Tools.WeasyReport import _font_path

        regular = _font_path("LINGSHU_PDF_FONT_REGULAR", "MSYH.TTC")
        bold = _font_path("LINGSHU_PDF_FONT_BOLD", "MSYHBD.TTC")
        return "available", f"中文字体已就绪（{regular.name}、{bold.name}）", []
    except Exception as exc:
        return "missing", "PDF 中文字体资源不可用", [str(exc)[:300]]


def _check_antsword_electron_loader() -> tuple[str, str, list[str]]:
    """Check the bundled Electron launcher without starting a GUI process."""
    executable = _PROJECT_ROOT / "Tools" / "AntSword-Loader-v4.0.3-linux-x64" / "AntSword"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        return "missing", "AntSword Electron 启动器不可用", [f"未找到或不可执行: {executable}"]
    try:
        completed = subprocess.run(
            ["ldd", str(executable)], capture_output=True, text=True,
            errors="replace", timeout=8, check=False,
        )
        missing = [line.strip() for line in (completed.stdout or "").splitlines() if "not found" in line]
        if completed.returncode != 0:
            return "degraded", "AntSword Electron 依赖检查失败", [(completed.stderr or "ldd 执行失败")[:300]]
        if missing:
            return "missing", "AntSword Electron 缺少系统动态库", missing[:8]
        return "available", "AntSword Electron 动态库验证通过", []
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "degraded", "AntSword Electron 依赖检查失败", [str(exc)[:300]]


def _check_uv_runtime() -> tuple[str, str, list[str]]:
    """Resolve uv/uvx at the same per-user location used by the installer."""
    configured_dir = os.getenv("LINGSHU_UV_BIN_DIR", "").strip()
    bin_dir = Path(configured_dir).expanduser() if configured_dir else Path.home() / ".local" / "bin"
    uv = bin_dir / "uv"
    uvx = bin_dir / "uvx"
    if not uv.is_file():
        resolved = shutil.which("uv")
        uv = Path(resolved) if resolved else uv
    if not uvx.is_file():
        resolved = shutil.which("uvx")
        uvx = Path(resolved) if resolved else uvx
    missing = [name for name, path in (("uv", uv), ("uvx", uvx)) if not path.is_file() or not os.access(path, os.X_OK)]
    if missing:
        return "missing", "uv/uvx 运行环境不可用", ["未找到: " + ", ".join(missing)]
    try:
        completed = subprocess.run([str(uv), "--version"], capture_output=True, text=True, errors="replace", timeout=4)
        version = (completed.stdout or completed.stderr).strip().splitlines()[0][:160]
        if completed.returncode != 0:
            return "degraded", "uv/uvx 运行环境检查失败", [version or "uv --version 失败"]
        return "available", f"{version}；uvx 已就绪", []
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "degraded", "uv/uvx 运行环境检查失败", [str(exc)[:300]]


class ToolCatalog:
    """加载声明式目录并解析当前主机上的有效工具。"""

    def __init__(self, manifest_path: str | Path = _DEFAULT_MANIFEST, *, cache_ttl: float = 60.0) -> None:
        self.manifest_path = Path(manifest_path).resolve()
        self.cache_ttl = max(float(cache_ttl), 0.0)
        self._tools = self._load()
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_at = 0.0
        self._lock = threading.Lock()

    def _load(self) -> dict[str, ToolCapability]:
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1 or not isinstance(payload.get("tools"), list):
            raise ValueError("工具目录 schema_version 必须为 1，tools 必须为数组")
        tools: dict[str, ToolCapability] = {}
        for raw in payload["tools"]:
            spec = ToolCapability.from_dict(raw)
            if spec.id in tools:
                raise ValueError(f"工具目录包含重复 id: {spec.id}")
            tools[spec.id] = spec
        return tools

    @staticmethod
    def _resolve_candidate(candidate: str) -> str | None:
        # 目录清单允许使用 ${VAR}，将客户机差异放入 .env；未设置的
        # 占位符直接视为不可用，不把占位符误报给 Agent。
        candidate = os.path.expandvars(candidate).strip()
        if not candidate or "$" in candidate:
            return None
        if "/" in candidate:
            path = Path(candidate).expanduser()
            return str(path.resolve()) if path.is_file() and path.stat().st_mode & 0o111 else None
        return shutil.which(candidate)

    @staticmethod
    def _execution_environment(spec: ToolCapability) -> dict[str, str]:
        """构造目录声明的命令探测环境，未配置项保持宿主环境不变。"""
        environment = os.environ.copy()
        for name, raw_value in spec.environment:
            value = os.path.expandvars(raw_value).strip()
            # 未配置的 ${VAR} 不应传递为字面量，健康检查将自然失败并提示。
            if value and "$" not in value:
                environment[name] = value
        return environment

    def _inspect_one(self, spec: ToolCapability, *, include_version: bool) -> dict[str, Any]:
        path = next((resolved for item in spec.command_candidates if (resolved := self._resolve_candidate(item))), None)
        missing_modules = [
            (module, distribution)
            for module, distribution in spec.python_modules
            if importlib.util.find_spec(module) is None
        ]
        command_ready = not spec.command_candidates or path is not None
        modules_ready = not missing_modules
        ready = command_ready and modules_ready
        status = "available" if spec.enabled and ready else ("disabled" if not spec.enabled else "missing")
        version = ""
        errors: list[str] = []
        if spec.command_candidates and not path:
            errors.append("未找到可执行文件")
        if missing_modules:
            errors.append("缺少 Python 模块: " + ", ".join(distribution for _, distribution in missing_modules))
        missing_files = [
            str(resource_path)
            for candidate in spec.required_files
            if not (resource_path := _resolve_required_file(candidate)).is_file()
        ]
        if missing_files:
            ready = False
            if spec.enabled:
                status = "missing"
            errors.append("缺少必需资源: " + ", ".join(missing_files))
        missing_commands = [
            command for command in spec.required_commands if self._resolve_candidate(command) is None
        ]
        if missing_commands:
            ready = False
            if spec.enabled:
                status = "missing"
            errors.append("缺少必需命令: " + ", ".join(missing_commands))
        if ready and spec.import_check_modules:
            failed_imports: list[str] = []
            for module in spec.import_check_modules:
                try:
                    importlib.import_module(module)
                except Exception as exc:  # 动态库/ABI 失败也应在面板可见
                    failed_imports.append(f"{module} ({str(exc)[:180]})")
            if failed_imports:
                if spec.enabled:
                    status = "degraded"
                errors.append("运行时导入失败: " + ", ".join(failed_imports))
        if path and spec.health_check_args:
            try:
                checked = subprocess.run(
                    [path, *spec.health_check_args], capture_output=True, text=True,
                    errors="replace", timeout=4, check=False,
                    env=self._execution_environment(spec),
                )
                health_output = "\n".join((checked.stdout or "", checked.stderr or "")).lower()
                unavailable = [
                    item for item in spec.health_check_contains
                    if item.lower() not in health_output
                ]
                if unavailable:
                    if spec.enabled:
                        status = "missing"
                    errors.append("缺少运行时组件: " + ", ".join(unavailable))
            except (OSError, subprocess.TimeoutExpired) as exc:
                if spec.enabled:
                    status = "degraded"
                errors.append(f"健康检查失败: {exc}")
        if path and include_version and spec.version_args:
            try:
                completed = subprocess.run(
                    [path, *spec.version_args], capture_output=True, text=True,
                    errors="replace", timeout=4, check=False,
                    env=self._execution_environment(spec),
                )
                output = (completed.stdout or completed.stderr).strip()
                version = output.splitlines()[0][:240] if output else ""
                # 许多安全工具的 --help 会以非零码退出；存在可执行文件仍算健康。
                if completed.returncode < 0:
                    status = "degraded"
                    errors.append(f"版本检测被信号终止: {completed.returncode}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                # 某些 Kali 工具（如 wpscan/msfconsole）仅加载运行时就可能
                # 超过探测时限。可执行文件存在仍可提供给 Agent，版本探测
                # 失败作为诊断告警返回，不能反向污染能力缓存使工具消失。
                errors.append(f"版本检测失败: {exc}")
        if ready and spec.runtime_check == "pdf_report_generation":
            runtime_status, runtime_version, runtime_errors = _check_pdf_report_generation()
            version = runtime_version
            errors.extend(runtime_errors)
            if spec.enabled and runtime_status != "available":
                status = runtime_status
        if ready and spec.runtime_check == "pdf_mermaid_rendering":
            runtime_status, runtime_version, runtime_errors = _check_pdf_mermaid_rendering()
            version = runtime_version
            errors.extend(runtime_errors)
            if spec.enabled and runtime_status != "available":
                status = runtime_status
        if ready and spec.runtime_check == "pdf_font_resources":
            runtime_status, runtime_version, runtime_errors = _check_pdf_font_resources()
            version = runtime_version
            errors.extend(runtime_errors)
            if spec.enabled and runtime_status != "available":
                status = runtime_status
        if ready and spec.runtime_check == "antsword_electron_loader":
            runtime_status, runtime_version, runtime_errors = _check_antsword_electron_loader()
            version = runtime_version
            errors.extend(runtime_errors)
            if spec.enabled and runtime_status != "available":
                status = runtime_status
        if ready and spec.runtime_check == "uv_runtime":
            runtime_status, runtime_version, runtime_errors = _check_uv_runtime()
            version = runtime_version
            errors.extend(runtime_errors)
            if spec.enabled and runtime_status != "available":
                status = runtime_status
        if not version and include_version and spec.python_modules and modules_ready:
            versions: list[str] = []
            for module, distribution in spec.python_modules:
                try:
                    versions.append(f"{distribution} {importlib.metadata.version(distribution)}")
                except importlib.metadata.PackageNotFoundError:
                    versions.append(module)
            version = "; ".join(versions)[:240]
        command = (
            Path(path).name if path
            else (f"Python · {', '.join(distribution for _, distribution in spec.python_modules)}"
                  if spec.python_modules else ("项目资源检查" if spec.required_files else "运行时自检"))
        )
        return {
            "id": spec.id,
            "category": spec.category,
            "kind": "python_module" if not spec.command_candidates else "shell_command",
            "status": status,
            "version": version,
            "command": command,
            "path": path or "",
            "roles": list(spec.roles),
            "risk": spec.risk,
            "approval_required": spec.approval_required,
            "description": spec.description,
            "usage_hint": spec.usage_hint,
            "alternatives": list(spec.alternatives),
            "error": "；".join(errors),
        }

    def snapshot(self, *, refresh: bool = False, include_version: bool = False) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            if refresh or not self._cache or now - self._cache_at >= self.cache_ttl:
                if include_version:
                    with ThreadPoolExecutor(max_workers=min(8, len(self._tools) or 1)) as pool:
                        inspected = pool.map(
                            lambda pair: (pair[0], self._inspect_one(pair[1], include_version=True)),
                            self._tools.items(),
                        )
                        self._cache = dict(inspected)
                else:
                    self._cache = {
                        tool_id: self._inspect_one(spec, include_version=False)
                        for tool_id, spec in self._tools.items()
                    }
                self._cache_at = now
            elif include_version and any(not item.get("version") for item in self._cache.values() if item["status"] == "available"):
                with ThreadPoolExecutor(max_workers=min(8, len(self._tools) or 1)) as pool:
                    inspected = pool.map(
                        lambda pair: (pair[0], self._inspect_one(pair[1], include_version=True)),
                        self._tools.items(),
                    )
                    self._cache = dict(inspected)
                self._cache_at = now
            return [dict(item) for item in self._cache.values()]

    def for_role(
        self,
        role: str,
        *,
        include_unavailable: bool = False,
        categories: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        normalized = role.strip().lower()
        items = [item for item in self.snapshot() if normalized in item["roles"]]
        normalized_categories = {
            str(item).strip().lower() for item in (categories or set()) if str(item).strip()
        }
        if normalized_categories:
            items = [item for item in items if item["category"] in normalized_categories]
        if not include_unavailable:
            items = [item for item in items if item["status"] == "available"]
        return sorted(items, key=lambda item: (item["category"], item["id"]))

    def capability_summary(
        self,
        role: str,
        *,
        max_items: int = 18,
        categories: set[str] | None = None,
    ) -> str:
        items = self.for_role(role, categories=categories)[:max_items]
        if not items:
            return "\n\n## 动态工具能力\n当前运行环境没有检测到分配给本角色的系统命令；只使用 Toolkit 中实际注册的函数/MCP 工具。"
        groups: dict[str, list[str]] = {}
        for item in items:
            suffix = "（需审批）" if item["approval_required"] else ""
            groups.setdefault(item["category"], []).append(f"{item['id']}{suffix}")
        lines = ["\n\n## 动态工具能力（任务启动时实机检测）"]
        lines.extend(f"- {category}: {', '.join(names)}" for category, names in groups.items())
        lines.append("仅可使用以上系统命令及 Toolkit 中实际出现的函数/MCP 工具；需要参数说明时调用 get_tool_usage。")
        return "\n".join(lines)

    def get(
        self,
        tool_id: str,
        role: str,
        *,
        categories: set[str] | None = None,
    ) -> dict[str, Any] | None:
        normalized = tool_id.strip().lower()
        return next((
            item for item in self.for_role(
                role, include_unavailable=True, categories=categories,
            ) if item["id"] == normalized
        ), None)


_DEFAULT_CATALOG: ToolCatalog | None = None
_DEFAULT_LOCK = threading.Lock()


def get_tool_catalog() -> ToolCatalog:
    global _DEFAULT_CATALOG
    with _DEFAULT_LOCK:
        if _DEFAULT_CATALOG is None:
            _DEFAULT_CATALOG = ToolCatalog()
        return _DEFAULT_CATALOG


def create_tool_catalog_tools(
    role: str,
    catalog: ToolCatalog | None = None,
    *,
    categories: set[str] | None = None,
) -> list[AllowedFunctionTool]:
    """创建仅展示当前角色有效能力的查询工具。"""
    active_catalog = catalog or get_tool_catalog()
    normalized_role = role.strip().lower()

    async def list_available_tools(category: str = "", keyword: str = "") -> str:
        """列出当前 Agent 实际可用的系统命令。

        Args:
            category: 可选分类，如 recon/web/ad/crypto/forensics/reverse。
            keyword: 可选工具名称或用途关键词。
        """
        category_key = category.strip().lower()
        keyword_key = keyword.strip().lower()
        items = active_catalog.for_role(normalized_role, categories=categories)
        if category_key:
            items = [item for item in items if item["category"] == category_key]
        if keyword_key:
            items = [item for item in items if keyword_key in " ".join((item["id"], item["description"], item["usage_hint"])).lower()]
        if not items:
            return "当前筛选条件下没有可用系统命令。"
        return json.dumps([
            {
                "id": item["id"], "category": item["category"],
                "command": item["command"], "description": item["description"],
                "risk": item["risk"], "approval_required": item["approval_required"],
            }
            for item in items
        ], ensure_ascii=False, indent=2)

    async def get_tool_usage(tool_id: str) -> str:
        """查询当前 Agent 某个系统命令的安全用法、风险和替代项。

        Args:
            tool_id: list_available_tools 返回的工具 id。
        """
        item = active_catalog.get(
            tool_id, normalized_role, categories=categories,
        )
        if item is None:
            return "该工具未分配给当前 Agent。"
        if item["status"] != "available":
            return f"工具 {item['id']} 当前不可用：{item['error'] or item['status']}"
        return json.dumps({
            "id": item["id"], "command": item["command"],
            "description": item["description"], "usage_hint": item["usage_hint"],
            "risk": item["risk"], "approval_required": item["approval_required"],
            "alternatives": item["alternatives"],
        }, ensure_ascii=False, indent=2)

    return [
        AllowedFunctionTool(list_available_tools, is_read_only=True),
        AllowedFunctionTool(get_tool_usage, is_read_only=True),
    ]


def append_capability_summary(
    system_prompt: str,
    role: str,
    catalog: ToolCatalog | None = None,
    *,
    categories: set[str] | None = None,
) -> str:
    return system_prompt.rstrip() + (catalog or get_tool_catalog()).capability_summary(
        role, categories=categories,
    )
