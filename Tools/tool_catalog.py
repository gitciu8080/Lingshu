"""运行时攻防能力目录。

AgentScope 会自动向模型公开已经注册的 Function/MCP 工具。本模块补齐系统
命令的发现能力，并确保模型只看到“已安装、已启用、分配给当前角色”的交集。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Tools.tooling import AllowedFunctionTool

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_MANIFEST = _PROJECT_ROOT / "config" / "tool_catalog.json"


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
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolCapability":
        tool_id = str(data.get("id", "")).strip().lower()
        if not tool_id or not tool_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"非法工具 id: {tool_id!r}")
        candidates = tuple(str(item).strip() for item in data.get("command_candidates", []) if str(item).strip())
        if not candidates:
            raise ValueError(f"工具 {tool_id} 缺少 command_candidates")
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
            enabled=bool(data.get("enabled", True)),
        )


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

    def _inspect_one(self, spec: ToolCapability, *, include_version: bool) -> dict[str, Any]:
        path = next((resolved for item in spec.command_candidates if (resolved := self._resolve_candidate(item))), None)
        status = "available" if spec.enabled and path else ("disabled" if not spec.enabled else "missing")
        version = ""
        error = "" if path else "未找到可执行文件"
        if path and include_version and spec.version_args:
            try:
                completed = subprocess.run(
                    [path, *spec.version_args], capture_output=True, text=True,
                    errors="replace", timeout=4, check=False,
                )
                output = (completed.stdout or completed.stderr).strip()
                version = output.splitlines()[0][:240] if output else ""
                # 许多安全工具的 --help 会以非零码退出；存在可执行文件仍算健康。
                if completed.returncode < 0:
                    status, error = "degraded", f"版本检测被信号终止: {completed.returncode}"
            except (OSError, subprocess.TimeoutExpired) as exc:
                # 某些 Kali 工具（如 wpscan/msfconsole）仅加载运行时就可能
                # 超过探测时限。可执行文件存在仍可提供给 Agent，版本探测
                # 失败作为诊断告警返回，不能反向污染能力缓存使工具消失。
                error = f"版本检测失败: {exc}"
        return {
            "id": spec.id,
            "category": spec.category,
            "kind": "shell_command",
            "status": status,
            "version": version,
            "command": Path(path).name if path else spec.command_candidates[0],
            "path": path or "",
            "roles": list(spec.roles),
            "risk": spec.risk,
            "approval_required": spec.approval_required,
            "description": spec.description,
            "usage_hint": spec.usage_hint,
            "alternatives": list(spec.alternatives),
            "error": error,
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
