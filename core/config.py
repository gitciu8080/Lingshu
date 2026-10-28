"""灵枢运行配置与目标范围校验。"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path


logger = logging.getLogger(__name__)
_WARNED_REPEAT_PENALTIES: set[float] = set()


def _lookup_is_superadmin(user_id: int) -> bool:
    """查询用户角色是否为超级管理员；查询失败按普通用户处理（更保守）。"""
    try:
        from core.auth import get_user_role  # 延迟导入避免环

        return get_user_role(user_id) == "superadmin"
    except Exception as exc:  # noqa: BLE001
        logger.warning("查询用户 %s 角色失败，按普通用户加载模型池: %s", user_id, exc)
        return False


def _load_dotenv(dotenv_path: str | Path = ".env") -> None:
    """加载 .env 文件到 os.environ（不覆盖已有的环境变量）。"""
    path = Path(dotenv_path).resolve()
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = val


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
)


def validate_target(target: str) -> str:
    """验证并规范化单个 IP 或主机名目标。"""
    value = target.strip().rstrip(".")
    if not value or any(char in value for char in "/\\:@?#[]"):
        raise ValueError("目标必须是单个 IP 地址或主机名，不能包含 URL、端口或路径")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(value):
            raise ValueError(f"无效的目标地址: {target!r}") from None
        return value.lower()


@dataclass(frozen=True)
class RuntimeConfig:
    """从环境变量加载的模型与运行配置。

    同时支持 DeepSeek 和 Qwen (OpenAI 兼容 API) 两个提供商。
    通过 --provider 参数在运行时选择。
    """

    # ── DeepSeek ──
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    # base_url: AgentScope 自动请求 /responses；full_endpoint: 平台把完整
    # /responses 端点注册为网关，实际请求网关根路径以避免重复追加。
    deepseek_gateway_mode: str = "base_url"
    deepseek_model_low: str = "deepseek-v4-flash"       # 低推理（chat 已弃用合并为 flash）
    deepseek_model_min: str = "deepseek-v4-flash"       # 默认
    deepseek_model_max: str = "deepseek-v4-pro"         # 深度推理
    deepseek_web_search: bool = False                   # Responses API 服务端联网搜索开关
    # V4 Flash / Pro 均走 OpenAI Responses 协议；可由环境变量覆盖，兼容
    # 尚未提供 Responses 端点的私有网关。
    deepseek_responses_models: tuple[str, ...] = (
        "deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp",
    )
    deepseek_native_tools: tuple[str, ...] = ()
    deepseek_model_settings: dict[str, object] = field(default_factory=dict)

    # ── 智谱 GLM（OpenAI 兼容 API）──
    zhipu_api_key: str = ""
    zhipu_base_url: str = "https://open.bigmodel.cn/api/paas/v4"
    zhipu_model_low: str = "glm-5.3"
    zhipu_model_min: str = "glm-5.3"
    zhipu_model_max: str = "glm-5.3"
    # 兼容旧配置字段；内置 Zhipu 工厂现已固定使用 Responses。
    zhipu_responses_models: tuple[str, ...] = ("glm-5.3",)
    zhipu_native_tools: tuple[str, ...] = ()
    zhipu_gateway_mode: str = "base_url"
    zhipu_model_settings: dict[str, object] = field(default_factory=dict)

    # ── Qwen (llama.cpp OpenAI 兼容) ──
    qwen_api_key: str = ""
    qwen_base_url: str = "http://10.8.128.100:8200/v1"
    qwen_model: str = "/mnt/nvme0n1p1/llama.cppModels/Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf"
    # llama.cpp repeat_penalty：>1.0 惩罚重复 token，越高抑制越强。
    # 默认保持温和惩罚；显式配置超过 1.2 仅告警，不静默篡改操作员配置。
    qwen_repeat_penalty: float = 1.08
    # simple 使用扁平、逐条工具参数，适配 AgentWorld 等本地 Qwen；
    # standard 使用当前的批量嵌套参数协议，适合工具 JSON 能力更强的模型。
    qwen_tool_call_mode: str = "simple"
    qwen_model_settings: dict[str, object] = field(default_factory=dict)
    # Superadmin 注册的其它 OpenAI-compatible Provider。
    custom_llm_configs: dict[str, dict[str, object]] = field(default_factory=dict)

    # ── RAG embedding (OpenAI compatible) ──
    # 留空时知识库功能以“未配置”状态降级，不影响主任务系统启动。
    embedding_api_key: str = ""
    embedding_base_url: str = ""
    embedding_model: str = ""
    embedding_dimensions: int = 0
    embedding_pass_dimensions: bool = True
    # base_url: SDK 自动向 {base_url}/embeddings 发请求；
    # full_endpoint: 注册地址即完整 embeddings 端点，请求发往根路径。
    embedding_gateway_mode: str = "base_url"
    embedding_model_settings: dict[str, object] = field(default_factory=dict)

    command_timeout: int = 300
    # Token 软预算（会话累计 total_tokens 超过即自动降思考档；0=不限）。
    # 软限制：只降档不硬停，任务仍可继续。
    token_soft_budget: int = 0

    # ── Workspace v2 模式（v0.3.0）──
    # local: 新会话默认使用按 (user_id, session_id) 隔离的 LocalWorkspace；
    # legacy: 旧行为（全局 WorkDir），仅用于打开旧会话，不新建 Workspace v2。
    workspace_mode: str = "local"

    @classmethod
    def from_env(cls, user_id: int | None = None) -> "RuntimeConfig":
        """构建运行时配置；注册表覆盖按 ``user_id`` 划定的模型池加载。

        - ``user_id=None``（CLI / 无用户上下文）：仅平台池（owner_id 为
          null 的注册表条目）+ .env 回退；
        - ``user_id=<uid>``：按用户可见性过滤（普通用户仅自己的私有池；
          超级管理员为平台池 + 自己的私有池），角色由 users.db 查询。
        """
        _load_dotenv()
        workspace_mode = os.getenv("LINGSHU_WORKSPACE_MODE", "local").strip().lower()
        if workspace_mode not in {"local", "legacy"}:
            workspace_mode = "local"
        repeat_penalty_raw = os.getenv("QWEN_REPEAT_PENALTY")
        qwen_repeat_penalty = float(repeat_penalty_raw or "1.08")
        if qwen_repeat_penalty <= 0:
            raise ValueError("QWEN_REPEAT_PENALTY 必须大于 0")
        qwen_tool_call_mode = os.getenv("QWEN_TOOL_CALL_MODE", "simple").strip().lower()
        if qwen_tool_call_mode not in {"simple", "standard"}:
            raise ValueError("QWEN_TOOL_CALL_MODE 仅支持 simple 或 standard")
        if (
            repeat_penalty_raw is not None
            and qwen_repeat_penalty > 1.2
            and qwen_repeat_penalty not in _WARNED_REPEAT_PENALTIES
        ):
            logger.warning(
                "QWEN_REPEAT_PENALTY=%s 超过建议上限 1.2；保留显式配置，不自动修改",
                qwen_repeat_penalty,
            )
            _WARNED_REPEAT_PENALTIES.add(qwen_repeat_penalty)
        values = dict(
            # DeepSeek
            deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", "").strip(),
            deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
            deepseek_gateway_mode=os.getenv("DEEPSEEK_GATEWAY_MODE", "base_url").strip().lower(),
            deepseek_model_low=os.getenv("DEEPSEEK_MODEL_LOW", "deepseek-v4-flash"),
            deepseek_model_min=os.getenv("DEEPSEEK_MODEL_MIN", "deepseek-v4-flash"),
            deepseek_model_max=os.getenv("DEEPSEEK_MODEL_MAX", "deepseek-v4-pro"),
            deepseek_web_search=os.getenv("DEEPSEEK_WEB_SEARCH", "0").strip().lower()
            in ("1", "true", "yes", "on"),
            deepseek_responses_models=tuple(
                m.strip()
                for m in os.getenv(
                    "DEEPSEEK_RESPONSES_MODELS",
                    "deepseek-v4-flash,deepseek-v4-pro,deepseek-v4-flash-vision-exp",
                ).split(",")
                if m.strip()
            ),
            # 智谱 GLM
            zhipu_api_key=os.getenv("ZHIPU_API_KEY", os.getenv("ZAI_API_KEY", "")).strip(),
            zhipu_base_url=os.getenv(
                "ZHIPU_BASE_URL", "https://open.bigmodel.cn/api/paas/v4",
            ).rstrip("/"),
            zhipu_model_low=os.getenv("ZHIPU_MODEL_LOW", "glm-5.3"),
            zhipu_model_min=os.getenv("ZHIPU_MODEL_MIN", "glm-5.3"),
            zhipu_model_max=os.getenv("ZHIPU_MODEL_MAX", "glm-5.3"),
            zhipu_responses_models=tuple(
                m.strip() for m in os.getenv("ZHIPU_RESPONSES_MODELS", "glm-5.3").split(",") if m.strip()
            ),
            zhipu_native_tools=tuple(
                m.strip().lower() for m in os.getenv("ZHIPU_NATIVE_TOOLS", "").split(",") if m.strip()
            ),
            zhipu_gateway_mode=os.getenv("ZHIPU_GATEWAY_MODE", "base_url").strip().lower(),
            # Qwen
            qwen_api_key=os.getenv("QWEN_API_KEY", "sk-placeholder").strip(),
            qwen_base_url=os.getenv("QWEN_BASE_URL", "http://10.8.128.108:8200/v1").rstrip("/"),
            qwen_model=os.getenv(
                "QWEN_MODEL",
                "/mnt/nvme0n1p1/llama.cppModels/Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf",
            ),
            qwen_repeat_penalty=qwen_repeat_penalty,
            qwen_tool_call_mode=qwen_tool_call_mode,
            embedding_api_key=os.getenv("LINGSHU_EMBEDDING_API_KEY", "").strip(),
            embedding_base_url=os.getenv("LINGSHU_EMBEDDING_BASE_URL", "").strip().rstrip("/"),
            embedding_model=os.getenv("LINGSHU_EMBEDDING_MODEL", "").strip(),
            embedding_dimensions=max(0, int(os.getenv("LINGSHU_EMBEDDING_DIMENSIONS", "0"))),
            embedding_pass_dimensions=os.getenv("LINGSHU_EMBEDDING_PASS_DIMENSIONS", "1").strip().lower()
            in ("1", "true", "yes", "on"),
            embedding_gateway_mode=os.getenv(
                "LINGSHU_EMBEDDING_GATEWAY_MODE", "base_url",
            ).strip().lower(),
            # 通用
            command_timeout=max(10, min(int(os.getenv("LINGSHU_COMMAND_TIMEOUT", "300")), 600)),
            token_soft_budget=max(0, int(os.getenv("LINGSHU_TOKEN_SOFT_BUDGET", "0"))),
            # Workspace 模式：默认 local；legacy 仅用于打开旧会话
            workspace_mode=workspace_mode,
        )
        # Web 管理界面启用的注册表配置优先于 .env，且按 user_id 划定的
        # 模型池加载（详见 from_env docstring）。注册表故障不能阻断主服务，
        # 此时保留环境变量配置并记录原因，便于运维恢复加密密钥或数据库。
        try:
            from core.model_registry import load_runtime_overrides

            owner_is_superadmin = False
            if user_id is not None:
                owner_is_superadmin = _lookup_is_superadmin(user_id)
            values.update(load_runtime_overrides(
                owner_user_id=user_id,
                owner_is_superadmin=owner_is_superadmin,
            ))
        except Exception as exc:  # noqa: BLE001
            logger.warning("读取模型 API 注册表失败，继续使用环境变量配置: %s", exc)
        return cls(**values)

    def embedding_error(self) -> str | None:
        """Return a user-safe configuration error for the optional RAG service."""
        if not self.embedding_api_key:
            return "未配置 LINGSHU_EMBEDDING_API_KEY"
        if not self.embedding_base_url:
            return "未配置 LINGSHU_EMBEDDING_BASE_URL"
        if not self.embedding_model:
            return "未配置 LINGSHU_EMBEDDING_MODEL"
        if self.embedding_dimensions <= 0:
            return "LINGSHU_EMBEDDING_DIMENSIONS 必须为正整数"
        return None

    def model_name(self, version: str, provider: str = "deepseek") -> str:
        """根据提供商和思考级别返回模型名称。"""
        if provider == "qwen":
            return self.qwen_model  # 单一模型，不随级别变化
        if provider == "zhipu":
            mapping = {
                "Low": self.zhipu_model_low,
                "Min": self.zhipu_model_min,
                "Max": self.zhipu_model_max,
            }
            try:
                return mapping[version]
            except KeyError as exc:
                raise ValueError(f"不支持的思考级别: {version}，可选 Low/Min/Max") from exc
        if provider != "deepseek":
            config = self.custom_llm_configs.get(provider)
            if not config:
                raise ValueError(f"模型提供商未启用或不存在: {provider}")
            key = {"Low": "model_low", "Min": "model_min", "Max": "model_max"}.get(version)
            if key is None:
                raise ValueError(f"不支持的思考级别: {version}，可选 Low/Min/Max")
            return str(config.get(key) or "")
        mapping = {
            "Low": self.deepseek_model_low,
            "Min": self.deepseek_model_min,
            "Max": self.deepseek_model_max,
        }
        try:
            return mapping[version]
        except KeyError as exc:
            raise ValueError(f"不支持的思考级别: {version}，可选 Low/Min/Max") from exc

    def _llm_entry(self, provider: str) -> dict[str, object] | None:
        """查注册表条目：键为 provider 或 provider::配置ID。

        ``provider::id`` 形态的键精确命中 custom_llm_configs；纯 provider
        键在多条启用时由注册表层解析为首条启用配置，不会落到这里。
        """
        entry = self.custom_llm_configs.get(provider)
        if entry is not None:
            return entry
        if "::" in provider:
            base = provider.split("::", 1)[0]
            return self.custom_llm_configs.get(base)
        return None

    def model_settings(self, provider: str) -> dict[str, object]:
        """返回管理员为对应提供商启用的 AgentScope 构造/生成参数。"""
        entry = self._llm_entry(provider)
        if entry is not None:
            return dict(entry.get("settings") or {})
        if provider == "qwen":
            return self.qwen_model_settings
        if provider == "deepseek":
            return self.deepseek_model_settings
        if provider == "zhipu":
            return self.zhipu_model_settings
        return {}

    def get_api_key(self, provider: str) -> str:
        """返回对应提供商（或 provider::配置ID）的 API Key。"""
        entry = self._llm_entry(provider)
        if entry is not None:
            return str(entry.get("api_key") or "")
        if provider == "qwen":
            return self.qwen_api_key
        if provider == "zhipu":
            return self.zhipu_api_key
        if provider != "deepseek":
            return ""
        return self.deepseek_api_key

    def get_base_url(self, provider: str) -> str:
        """返回对应提供商（或 provider::配置ID）的 Base URL。"""
        entry = self._llm_entry(provider)
        if entry is not None:
            return str(entry.get("base_url") or "")
        if provider == "qwen":
            return self.qwen_base_url
        if provider == "zhipu":
            return self.zhipu_base_url
        if provider != "deepseek":
            return ""
        return self.deepseek_base_url

    def resolve_llm_entry(self, key: str) -> dict[str, Any] | None:
        """把运行时 key（provider 或 provider::配置ID）解析为统一条目。

        注册表条目直接返回；内置 provider（deepseek/zhipu/qwen）在注册表
        未启用时按 .env 字段合成等价条目，保证旧部署路径可用。
        """
        from core.providers import get_provider_spec  # 延迟导入避免环

        entry = self._llm_entry(key)
        if entry is not None:
            resolved = dict(entry)
            resolved.setdefault("gateway_mode", "base_url")
            resolved.setdefault("native_tools", [])
            resolved.setdefault("models", [])
            resolved["model_name"] = (resolved.get("models") or [str(resolved.get("model_name") or "")])[0]
            return resolved
        base = str(key or "").strip().lower()
        if "::" in base:
            base = base.split("::", 1)[0]
        spec = get_provider_spec(base)
        if spec is None or base not in {"deepseek", "zhipu", "qwen"}:
            return None
        models: list[str] = []
        if base == "deepseek":
            models = [m for m in (self.deepseek_model_min, self.deepseek_model_max, self.deepseek_model_low) if m]
            api_style = "responses" if base in self.deepseek_responses_models or self.deepseek_responses_models else (
                "responses" if self.deepseek_responses_models else "chat_completions"
            )
            return {
                "id": 0, "name": spec["label"], "provider": base,
                "api_style": "responses" if self.deepseek_responses_models else "chat_completions",
                "base_url": self.deepseek_base_url, "api_key": self.deepseek_api_key,
                "gateway_mode": self.deepseek_gateway_mode,
                "native_tools": list(self.deepseek_native_tools),
                "settings": dict(self.deepseek_model_settings), "models": models,
                "model_name": models[0] if models else self.deepseek_model_min,
            }
        if base == "zhipu":
            models = [m for m in (self.zhipu_model_min, self.zhipu_model_max, self.zhipu_model_low) if m]
            return {
                "id": 0, "name": spec["label"], "provider": base,
                "api_style": "responses" if self.zhipu_responses_models else "chat_completions",
                "base_url": self.zhipu_base_url, "api_key": self.zhipu_api_key,
                "gateway_mode": self.zhipu_gateway_mode,
                "native_tools": list(self.zhipu_native_tools),
                "settings": dict(self.zhipu_model_settings), "models": models,
                "model_name": models[0] if models else self.zhipu_model_min,
            }
        return {
            "id": 0, "name": spec["label"], "provider": "qwen",
            "api_style": "chat_completions",
            "base_url": self.qwen_base_url, "api_key": self.qwen_api_key,
            "gateway_mode": "base_url", "native_tools": [],
            "settings": dict(self.qwen_model_settings), "models": [self.qwen_model],
            "model_name": self.qwen_model,
        }
