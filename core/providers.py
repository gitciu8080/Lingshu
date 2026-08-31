"""内置模型供应商目录 — 大模型管理模块的单一事实来源。

目录驱动四件事：
  1. 添加向导：可选供应商、默认 Base URL、API 协议、模型列表拉取方式
     （models_endpoint / models_probe）与各供应商支持的超参数矩阵；
  2. 模型工厂（LLM/model.py）：每个供应商的驱动（AgentScope 模型类）
     与受支持的超参数；
  3. 原生工具：供应商 API 内置工具的线协议格式
     （DeepSeek/OpenAI web_search / 智谱 web_search / DashScope enable_search）；
  4. 思考控制风格（thinking_style）：
     - ``effort`` → 请求参数 ``reasoning_effort``（OpenAI / DeepSeek / 通用兼容）；
     - ``zhipu``  → 请求参数 ``thinking: {"type": enabled|disabled}``（智谱，
       effort 不下发）；
     - ``none``   → 不发送思考参数（本地 llama.cpp 等自行处理）。

drivers（工厂分发）：
  chat_completions / responses  → OpenAI 兼容网关模型（GatewayChatModel /
                                  DeepSeekResponsesModel，支持网关端点模式、
                                  智谱 thinking 线协议与原生工具注入）
  anthropic / gemini / ollama / xai
                                → AgentScope 原生模型类 + 对应 Credential

工具线协议（wire）：
- ``responses``  → ``tools: [{"type": "web_search"}]``（Responses 协议）；
- ``chat``       → 智谱 chat 扩展 ``tools: [{"type": "web_search",
  "web_search": {...}}]``（函数、知识库、联网搜索互斥）；
- ``extra_body`` → DashScope ``extra_body: {"enable_search": True}``。
"""
from __future__ import annotations

import copy
from typing import Any

# AgentScope 构造与生成参数的默认集合（注册表 settings 的超集校验基准）。
DEFAULT_LLM_SETTINGS: dict[str, Any] = {
    "temperature": 0.7,
    "top_p": 0.95,
    "top_k": None,
    "max_tokens": 0,
    "max_retries": 3,
    "context_size": 128000,
    "timeout_seconds": 600,
    "thinking_enabled": True,
    "thinking_budget": 0,
}

PARAM_KEYS = (
    "temperature", "top_p", "top_k", "max_tokens",
    "max_retries", "context_size", "timeout_seconds",
    "thinking_enabled", "thinking_budget",
)

# ── 工具线协议 ──
TOOL_WIRE_RESPONSES = "responses"
TOOL_WIRE_CHAT = "chat"
TOOL_WIRE_EXTRA_BODY = "extra_body"

_WEB_SEARCH = {
    "web_search": {
        "label": "联网搜索",
        "description": "服务端执行的模型内置联网搜索，无需本地实现。",
        "wire": TOOL_WIRE_RESPONSES,
    },
}


def _spec(
    key: str,
    label: str,
    driver: str,
    *,
    api_styles: tuple[str, ...],
    default_api_style: str,
    default_base_url: str = "",
    models_endpoint: str | None = "/models",
    models_probe: str = "openai",
    temperature: bool = True,
    top_p: bool = True,
    top_k: bool = False,
    max_tokens: bool = True,
    thinking_budget: bool = False,
    reasoning_efforts: tuple[str, ...] = (),
    thinking_style: str = "effort",
    native_tools: dict[str, Any] | None = None,
    default_models: tuple[str, ...] = (),
    default_settings: dict[str, Any] | None = None,
    docs_url: str = "",
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "driver": driver,
        "api_styles": list(api_styles),
        "default_api_style": default_api_style,
        "default_base_url": default_base_url,
        "models_endpoint": models_endpoint,
        "models_probe": models_probe,
        "params": {
            "temperature": temperature,
            "top_p": top_p,
            "top_k": top_k,
            "max_tokens": max_tokens,
            "thinking_budget": thinking_budget,
            "reasoning_efforts": list(reasoning_efforts),
        },
        "thinking_style": thinking_style,
        "native_tools": dict(native_tools or {}),
        "default_models": list(default_models),
        "default_settings": default_settings or {},
        "docs_url": docs_url,
    }


PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "deepseek": _spec(
        "deepseek", "DeepSeek", "responses",
        api_styles=("responses", "chat_completions"),
        default_api_style="responses",
        default_base_url="https://api.deepseek.com",
        # DeepSeek Responses 接受 none/minimal/low/medium/high/xhigh；
        # chat_completions 仅 high/max。统一集合取超集，chat 侧再收敛。
        reasoning_efforts=("none", "minimal", "low", "medium", "high", "xhigh", "max"),
        native_tools=dict(_WEB_SEARCH),
        default_models=(
            "deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp",
        ),
        default_settings={"context_size": 200000},
        docs_url="https://api-docs.deepseek.com/zh-cn/guides/responses_api",
    ),
    "zhipu": _spec(
        "zhipu", "智谱 GLM", "chat_completions",
        api_styles=("chat_completions", "responses"),
        default_api_style="chat_completions",
        default_base_url="https://open.bigmodel.cn/api/paas/v4",
        # 智谱思考控制是 thinking.type 开关（enabled/disabled），
        # reasoning_effort 不作为独立参数下发。
        reasoning_efforts=(),
        thinking_style="zhipu",
        native_tools={
            "web_search": {
                "label": "联网搜索",
                "description": "智谱内置 web_search 工具（chat tools 线协议，search_pro）。",
                "wire": TOOL_WIRE_CHAT,
            },
        },
        default_models=("glm-5.3", "glm-4.7", "glm-4.6", "glm-5.3-flash"),
        default_settings={"context_size": 200000},
        docs_url="https://docs.bigmodel.cn/cn/guide/tools/web-search",
    ),
    "dashscope": _spec(
        "dashscope", "阿里云百炼 (Qwen)", "chat_completions",
        api_styles=("chat_completions",),
        default_api_style="chat_completions",
        default_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        top_k=True,
        thinking_budget=True,
        reasoning_efforts=("none", "low", "medium", "high"),
        native_tools={
            "web_search": {
                "label": "联网搜索",
                "description": "百炼 Qwen 服务端联网搜索（enable_search 请求扩展）。",
                "wire": TOOL_WIRE_EXTRA_BODY,
            },
        },
        default_models=("qwen3-max", "qwen3-plus", "qwq-plus"),
        default_settings={"temperature": 0.7, "context_size": 131072},
        docs_url="https://bailian.console.aliyun.com/",
    ),
    "qwen": _spec(
        "qwen", "Qwen (llama.cpp)", "chat_completions",
        api_styles=("chat_completions",),
        default_api_style="chat_completions",
        default_base_url="http://10.8.128.108:8200/v1",
        models_endpoint="/v1/models",
        # 本地 llama.cpp 自行控制思考模板，灵枢不发送思考参数。
        reasoning_efforts=(),
        thinking_style="none",
        default_models=(),
        default_settings={"context_size": 32768},
    ),
    "openai": _spec(
        "openai", "OpenAI", "chat_completions",
        api_styles=("responses", "chat_completions"),
        default_api_style="responses",
        default_base_url="https://api.openai.com/v1",
        reasoning_efforts=("none", "minimal", "low", "medium", "high", "xhigh"),
        native_tools=dict(_WEB_SEARCH),
        default_models=("gpt-5.2", "gpt-5-mini"),
        default_settings={"context_size": 400000},
        docs_url="https://platform.openai.com/docs/api-reference",
    ),
    "anthropic": _spec(
        "anthropic", "Anthropic Claude", "anthropic",
        api_styles=("anthropic",),
        default_api_style="anthropic",
        default_base_url="https://api.anthropic.com",
        models_endpoint="/v1/models",
        models_probe="anthropic",
        thinking_budget=True,
        reasoning_efforts=("low", "medium", "high", "xhigh", "max"),
        default_models=("claude-sonnet-4-6", "claude-opus-4-6"),
        default_settings={"context_size": 200000},
        docs_url="https://docs.agentscope.io/versions/2.0.6/zh/building-blocks/model/llm",
    ),
    "gemini": _spec(
        "gemini", "Google Gemini", "gemini",
        api_styles=("gemini",),
        default_api_style="gemini",
        default_base_url="https://generativelanguage.googleapis.com",
        models_endpoint="/v1beta/models",
        models_probe="gemini",
        thinking_budget=True,
        default_models=("gemini-3-pro-preview", "gemini-2.5-pro"),
        default_settings={"context_size": 1048576},
        docs_url="https://docs.agentscope.io/versions/2.0.6/zh/building-blocks/model/llm",
    ),
    "moonshot": _spec(
        "moonshot", "Moonshot Kimi", "chat_completions",
        api_styles=("chat_completions",),
        default_api_style="chat_completions",
        default_base_url="https://api.moonshot.cn/v1",
        reasoning_efforts=("low", "high", "max"),
        default_models=("kimi-k3", "kimi-k2-0905-preview"),
        default_settings={"context_size": 256000},
        docs_url="https://docs.agentscope.io/versions/2.0.6/zh/building-blocks/model/llm",
    ),
    "xai": _spec(
        "xai", "xAI Grok", "xai",
        api_styles=("chat_completions",),
        default_api_style="chat_completions",
        default_base_url="https://api.x.ai/v1",
        reasoning_efforts=("low", "medium", "high"),
        default_models=("grok-4-1-fast", "grok-4"),
        default_settings={"context_size": 2000000},
        docs_url="https://docs.agentscope.io/versions/2.0.6/zh/building-blocks/model/llm",
    ),
    "ollama": _spec(
        "ollama", "Ollama 本地推理", "ollama",
        api_styles=("chat_completions",),
        default_api_style="chat_completions",
        default_base_url="http://127.0.0.1:11434",
        models_endpoint="/api/tags",
        models_probe="ollama",
        top_p=False,
        default_models=("qwen3:32b", "llama3.3:70b"),
        default_settings={"context_size": 32768},
        docs_url="https://docs.agentscope.io/versions/2.0.6/zh/building-blocks/model/llm",
    ),
    # 自定义 OpenAI 兼容网关（含中转/企业代理）：api_style 自由选择。
    "openai-compatible": _spec(
        "openai-compatible", "OpenAI 兼容网关", "chat_completions",
        api_styles=("chat_completions", "responses"),
        default_api_style="chat_completions",
        default_base_url="",
        reasoning_efforts=("none", "minimal", "low", "medium", "high", "xhigh"),
        default_settings={"context_size": 128000},
        docs_url="https://docs.agentscope.io/versions/2.0.6/zh/building-blocks/model/llm",
    ),
}


def get_provider_spec(key: str) -> dict[str, Any] | None:
    """按 key 取供应商规格；未登记返回 None。"""
    return PROVIDER_CATALOG.get(str(key or "").strip().lower())


def catalog_for_client() -> list[dict[str, Any]]:
    """前端供应商选择步骤使用的目录快照（深拷贝，防篡改）。"""
    return [copy.deepcopy(spec) for spec in PROVIDER_CATALOG.values()]


def _spec_efforts(spec: dict[str, Any]) -> tuple[str, ...]:
    """读取供应商 reasoning_effort 取值集合（兼容 params 与顶层两种布局）。"""
    allowed = (spec.get("params") or {}).get("reasoning_efforts")
    if allowed is None:
        allowed = spec.get("reasoning_efforts")
    return tuple(allowed or ())


def supported_native_tools(spec: dict[str, Any], api_style: str) -> list[str]:
    """某供应商在指定 API 协议下可启用的原生工具键列表。"""
    return [
        key for key, entry in spec.get("native_tools", {}).items()
        if tool_wire(spec, api_style, key) is not None
    ]


def tool_wire(spec: dict[str, Any], api_style: str, tool_key: str) -> str | None:
    """解析供应商 + 协议 + 工具键对应的线协议；不支持时返回 None。

    每个目录条目在 ``native_tools[tool]["wire"]`` 声明其线协议：
    responses 工具仅在 responses 协议可用；chat / extra_body 工具仅在
    chat_completions 协议可用。
    """
    entry = spec.get("native_tools", {}).get(tool_key)
    if not entry:
        return None
    wire = entry.get("wire")
    if api_style == "responses":
        return wire if wire == TOOL_WIRE_RESPONSES else None
    if api_style == "chat_completions":
        return wire if wire in {TOOL_WIRE_CHAT, TOOL_WIRE_EXTRA_BODY} else None
    return None


def clamp_reasoning_effort(spec: dict[str, Any], effort: str | None) -> str | None:
    """把通用思考强度映射值收敛到该供应商支持的取值集合。"""
    allowed = _spec_efforts(spec)
    if not effort or not allowed:
        return None
    if effort == "none" and "none" not in allowed:
        # 该供应商不支持显式关闭档位：由 thinking_enable=False 承担。
        return None
    if effort in allowed:
        return effort
    # 优先向下取最近的合法档位；同距时取更强档位（深度请求不降档）。
    order = ["none", "minimal", "low", "medium", "high", "xhigh", "max"]
    requested = order.index(effort) if effort in order else len(order) - 1
    candidates = sorted(
        (
            (abs(order.index(item) - requested), -order.index(item), item)
            for item in allowed if item in order
        ),
    )
    return candidates[0][2] if candidates else None


def resolve_provider_thinking(
    spec: dict[str, Any],
    intensity: str | None,
) -> tuple[bool, str | None]:
    """把 Web 思考强度（off/low/medium/high）映射为该供应商的思考参数。

    Returns:
        ``(thinking_enable, reasoning_effort)``。zhipu 的 effort 恒为 None
        （思考开关经 ``thinking.type`` 线协议下发，由驱动层负责）。
    """
    normalized = (intensity or "medium").strip().lower()
    if normalized not in {"off", "low", "medium", "high"}:
        normalized = "medium"
    thinking_style = str(spec.get("thinking_style") or "effort")
    if normalized == "off":
        return False, None
    if thinking_style == "zhipu":
        return True, None
    if thinking_style == "none":
        return True, None
    mapping = {"low": "low", "medium": "medium", "high": "high"}
    return True, clamp_reasoning_effort(spec, mapping[normalized])


def native_tool_wire_payloads(
    spec: dict[str, Any],
    api_style: str,
    enabled_tools: list[str] | tuple[str, ...],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """把启用的原生工具名转换为该供应商/协议的线协议负载。

    Returns:
        ``(tools, extra_body)``：tools 直接并入请求 ``tools``（仅当无函数
        工具时由驱动注入）；extra_body 并入请求体（DashScope 风格）。

    - responses 协议：tools 注入 ``[{"type": "web_search"}]``；
    - 智谱 chat：tools 注入 ``[{"type": "web_search", "web_search": {...}}]``
      （search_pro 引擎 + 结果回传，函数/知识库/联网搜索互斥由驱动保证）；
    - DashScope chat：不注入 tools，改用 extra_body ``{"enable_search": True}``。
    """
    tools: list[dict[str, Any]] = []
    extra_body: dict[str, Any] = {}
    for name in dict.fromkeys(str(item).strip().lower() for item in enabled_tools or []):
        if not name:
            continue
        wire = tool_wire(spec, api_style, name)
        if wire == TOOL_WIRE_RESPONSES:
            tools.append({"type": name})
        elif wire == TOOL_WIRE_CHAT:
            payload: dict[str, Any] = {"type": name, name: {"enable": True}}
            if name == "web_search":
                payload[name] = {
                    "enable": True,
                    "search_engine": "search_pro",
                    "search_result": True,
                    "count": 10,
                    "content_size": "medium",
                }
            tools.append(payload)
        elif wire == TOOL_WIRE_EXTRA_BODY and name == "web_search":
            extra_body["enable_search"] = True
    return tools, extra_body
