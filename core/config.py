"""灵枢运行配置与目标范围校验。"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)
_WARNED_REPEAT_PENALTIES: set[float] = set()

# 项目根目录（core/ 的上一级）；.env 锚定在此，不依赖启动时的当前目录。
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(dotenv_path: str | Path | None = None) -> None:
    """加载 .env 文件到 os.environ（不覆盖已有的环境变量）。"""
    path = Path(dotenv_path or _PROJECT_ROOT / ".env").resolve()
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


def _normalize_embedding_base_url(value: str) -> str:
    """补齐 Ollama OpenAI 兼容端点的 ``/v1`` 前缀。

    Ollama 原生 API 使用 ``/api``，而 AgentScope 的
    :class:`OpenAIEmbeddingModel` 使用 OpenAI ``/v1/embeddings`` 协议。模型
    注册表中常将 Ollama 地址填为 ``http://host:11434``，此处仅对该默认端口
    且根路径地址规范化；其它兼容网关保持原样。
    """
    normalized = value.strip().rstrip("/")
    if not normalized:
        return normalized
    try:
        parsed = urlsplit(normalized)
        if parsed.port == 11434 and parsed.path in ("", "/"):
            return f"{normalized}/v1"
    except ValueError:
        # URL 的可达性由嵌入客户端给出明确错误，配置加载不应因格式抢先中断。
        pass
    return normalized


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
    deepseek_model_low: str = "deepseek-v4-flash"       # 可选模型之一
    deepseek_model_min: str = "deepseek-v4-flash"       # 默认模型
    deepseek_model_max: str = "deepseek-v4-pro"         # 可选模型之一
    deepseek_model_default: str = "deepseek-v4-flash"   # 未指定模型时的回退
    # 视觉模型；vision 请求未显式指定模型时回退到它。
    deepseek_vision_model: str = "deepseek-v4-flash-vision-exp"
    deepseek_web_search: bool = False                   # Responses API 服务端联网搜索开关
    # V4 Flash / Pro / 视觉均走 OpenAI Responses 协议；可由环境变量覆盖，兼容
    # 尚未提供 Responses 端点的私有网关。
    deepseek_responses_models: tuple[str, ...] = ("deepseek-v4-flash", "deepseek-v4-pro")
    deepseek_native_tools: tuple[str, ...] = ()
    deepseek_model_settings: dict[str, object] = field(default_factory=dict)

    # Superadmin 注册的其它 OpenAI-compatible Provider。
    custom_llm_configs: dict[str, dict[str, object]] = field(default_factory=dict)

    # ── RAG embedding (OpenAI compatible) ──
    # 留空时知识库功能以“未配置”状态降级，不影响主任务系统启动。
    embedding_api_key: str = ""
    embedding_base_url: str = ""
    embedding_model: str = ""
    embedding_dimensions: int = 0
    embedding_pass_dimensions: bool = True
    embedding_model_settings: dict[str, object] = field(default_factory=dict)
    # Qdrant 是 RAG 的容器化向量后端。应用运行在宿主机时使用回环地址；
    # API 未来进入 compose 后可将其改为 http://qdrant:6333。
    qdrant_url: str = "http://127.0.0.1:6333"

    command_timeout: int = 300

    # ── Docker 工作区 ──
    # 每个会话使用按 (user_id, session_id) 隔离的 DockerWorkspace
    # （基于 kali-full 镜像，所有工具在容器内执行）。
    # 基础镜像必须提供 python3（agentscope 会构建带网关 venv 的派生镜像）。
    workspace_base_image: str = "kali-full:latest"
    workspace_gateway_port: int | None = None
    workspace_docker_extra_pip: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        _load_dotenv()
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
            deepseek_model_default=os.getenv(
                "DEEPSEEK_MODEL_DEFAULT", "deepseek-v4-flash",
            ),
            deepseek_vision_model=os.getenv(
                "DEEPSEEK_VISION_MODEL", "deepseek-v4-flash-vision-exp",
            ),
            deepseek_web_search=os.getenv("DEEPSEEK_WEB_SEARCH", "0").strip().lower()
            in ("1", "true", "yes", "on"),
            deepseek_responses_models=tuple(
                m.strip()
                for m in os.getenv(
                    "DEEPSEEK_RESPONSES_MODELS", "deepseek-v4-flash,deepseek-v4-pro",
                ).split(",")
                if m.strip()
            ),
            embedding_api_key=os.getenv("LINGSHU_EMBEDDING_API_KEY", "").strip(),
            embedding_base_url=_normalize_embedding_base_url(
                os.getenv("LINGSHU_EMBEDDING_BASE_URL", ""),
            ),
            embedding_model=os.getenv("LINGSHU_EMBEDDING_MODEL", "").strip(),
            embedding_dimensions=max(0, int(os.getenv("LINGSHU_EMBEDDING_DIMENSIONS", "0"))),
            embedding_pass_dimensions=os.getenv("LINGSHU_EMBEDDING_PASS_DIMENSIONS", "1").strip().lower()
            in ("1", "true", "yes", "on"),
            qdrant_url=os.getenv("LINGSHU_QDRANT_URL", "http://127.0.0.1:6333").strip().rstrip("/"),
            # 通用
            command_timeout=max(10, min(int(os.getenv("LINGSHU_COMMAND_TIMEOUT", "300")), 600)),
            workspace_base_image=os.getenv(
                "LINGSHU_WORKSPACE_BASE_IMAGE", "kali-full:latest",
            ).strip(),
            workspace_gateway_port=(
                int(os.environ["LINGSHU_WORKSPACE_GATEWAY_PORT"])
                if os.getenv("LINGSHU_WORKSPACE_GATEWAY_PORT", "").strip()
                else None
            ),
            workspace_docker_extra_pip=tuple(
                p.strip()
                for p in os.getenv("LINGSHU_WORKSPACE_DOCKER_EXTRA_PIP", "").split(",")
                if p.strip()
            ),
        )
        # 超级管理员启用的数据库配置优先于 .env。注册表故障不能阻断主服务，
        # 此时保留环境变量配置并记录原因，便于运维恢复加密密钥或数据库。
        try:
            from core.model_registry import load_runtime_overrides

            values.update(load_runtime_overrides())
        except Exception as exc:  # noqa: BLE001
            logger.warning("读取模型 API 注册表失败，继续使用环境变量配置: %s", exc)
        values["embedding_base_url"] = _normalize_embedding_base_url(
            str(values["embedding_base_url"]),
        )
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

    def default_model(self, provider: str) -> str:
        """返回提供商未指定模型时的回退模型名。"""
        if provider == "deepseek":
            return self.deepseek_model_default
        config = self.custom_llm_configs.get(provider)
        if not config:
            raise ValueError(f"模型提供商未启用或不存在: {provider}")
        return str(config.get("model_name") or "")

    def vision_model(self, provider: str) -> str:
        """返回提供商的视觉模型名（未指定 vision 模型时回退）。"""
        if provider == "deepseek":
            return self.deepseek_vision_model
        return ""

    def model_settings(self, provider: str) -> dict[str, object]:
        """返回管理员为对应提供商启用的 AgentScope 构造/生成参数。"""
        if provider == "deepseek":
            return self.deepseek_model_settings
        return dict(self.custom_llm_configs.get(provider, {}).get("settings") or {})

    def get_api_key(self, provider: str) -> str:
        """返回对应提供商的 API Key。"""
        if provider == "deepseek":
            return self.deepseek_api_key
        return str(self.custom_llm_configs.get(provider, {}).get("api_key") or "")

    def get_base_url(self, provider: str) -> str:
        """返回对应提供商的 Base URL。"""
        if provider == "deepseek":
            return self.deepseek_base_url
        return str(self.custom_llm_configs.get(provider, {}).get("base_url") or "")
