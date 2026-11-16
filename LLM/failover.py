"""LLM 熔断链（20261115 压测 0/6 复盘 → 移植自 ARTEX llmpool/health.go）。

进程级熔断注册表：按 runtime_key 记录连续失败与冷却截止（退避梯子
60s/300s/1800s），主 profile 因配额（429/使用上限）、掉 key（401/403）、
网关 5xx、连接错误/断流导致调用失败时自动切换到同池下一个启用的 profile；
成功后重置。全部候选耗尽才把异常抛回调用方。

分类判据见 ``_is_tripable``——配置类错误（400/404/422）与项目自定义
``QwenModelUnavailableError`` 不触发切换（切了也会同样失败）；
``asyncio.CancelledError`` 永不拦截（agentscope 用它表达中断）。
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# 退避梯子：第 1 次 trip 冷却 60s，第 2 次 300s，之后 1800s
_LADDER = (60, 300, 1800)
_BREAKERS: dict[str, dict[str, Any]] = {}
_BREAKERS_LOCK = threading.Lock()


def failover_enabled() -> bool:
    """环境开关：LINGSHU_LLM_FAILOVER=0 关闭（默认开启）。"""
    return os.environ.get("LINGSHU_LLM_FAILOVER", "1").strip() != "0"


def _is_tripable(exc: BaseException) -> bool:
    """判定异常是否值得切换 profile（服务端/瞬时故障）。"""
    if isinstance(exc, asyncio.CancelledError):
        return False
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        if status in (429, 401, 403):
            return True
        if status >= 500:
            return True
    if name in {
        "RateLimitError", "InternalServerError", "APIConnectionError",
        "APITimeoutError",
    }:
        return True
    text = str(exc)[:400].lower()
    markers = (
        "429", "rate limit", "rate_limit", "quota", "余额不足", "使用上限",
        "out of credit", "insufficient_quota", "upstream stream interrupted",
        "connection error", "connection reset", "stream interrupted",
        "timed out",
    )
    return any(marker in text for marker in markers)


def _breaker_state(key: str) -> dict[str, Any]:
    """取（或建）key 的熔断状态；调用方必须已持有 _BREAKERS_LOCK。"""
    return _BREAKERS.setdefault(
        key, {"fails": 0, "trips": 0, "open_until": 0.0, "last_error": ""},
    )


def breaker_open(key: str) -> bool:
    with _BREAKERS_LOCK:
        return _breaker_state(key)["open_until"] > time.monotonic()


def _record_failure(key: str, exc: BaseException) -> float:
    with _BREAKERS_LOCK:
        state = _breaker_state(key)
        state["fails"] += 1
        state["trips"] += 1
        cool = _LADDER[min(state["trips"] - 1, len(_LADDER) - 1)]
        state["open_until"] = time.monotonic() + cool
        state["last_error"] = str(exc)[:300]
        return cool


def _record_success(key: str) -> None:
    with _BREAKERS_LOCK:
        state = _breaker_state(key)
        state["fails"] = 0
        state["trips"] = 0
        state["open_until"] = 0.0
        state["last_error"] = ""


def _record_failure(key: str, exc: BaseException) -> float:
    with _BREAKERS_LOCK:
        state = _breaker_state(key)
        state["fails"] += 1
        state["trips"] += 1
        cool = _LADDER[min(state["trips"] - 1, len(_LADDER) - 1)]
        state["open_until"] = time.monotonic() + cool
        state["last_error"] = str(exc)[:300]
        return cool


def _record_success(key: str) -> None:
    with _BREAKERS_LOCK:
        state = _breaker_state(key)
        state["fails"] = 0
        state["trips"] = 0
        state["open_until"] = 0.0
        state["last_error"] = ""


def breaker_snapshot() -> dict[str, dict[str, Any]]:
    """熔断状态快照（调试/未来 UI 用）。"""
    with _BREAKERS_LOCK:
        return json_safe({k: dict(v) for k, v in _BREAKERS.items()})


def reset_breakers() -> None:
    """清空全部熔断状态（测试隔离用；生产代码勿调）。"""
    with _BREAKERS_LOCK:
        _BREAKERS.clear()


def json_safe(payload: Any) -> Any:
    import copy
    return copy.deepcopy(payload)


def build_chain_keys(runtime, current_key: str, max_alts: int = 3) -> list[str]:
    """同 owner 池内的 failover 候选链：当前 key 优先，其余按注册表顺序。

    runtime.custom_llm_configs 已按 owner 池过滤（config.from_env →
    load_runtime_overrides），任务内零成本枚举；.env-only 部署（池为空）
    自然无链、行为与现状一致。
    """
    try:
        keys = [k for k in runtime.custom_llm_configs.keys() if k != current_key]
    except AttributeError:
        return []
    return [current_key] + keys[:max_alts]


# ── FailoverChatModel：熔断链模型包装器 ──────────────────────────────
try:
    from agentscope.model import ChatModelBase
except ImportError:  # pragma: no cover - 兼容不同 agentscope 导出面
    from agentscope.model._base import ChatModelBase

# 允许经 __getattr__ 透传给 active backend 的私有属性
_FORWARD_PRIVATE = {"_lingshu_usage_meta", "_lingshu_usage_ctx"}


class FailoverChatModel(ChatModelBase):
    """熔断链模型包装器：主 profile 失败（可切换类异常/熔断开启）时
    自动落到同池下一个启用的 profile；全部候选耗尽才抛回最后一个异常。

    属性面（model/stream/context_size/formatter/parameters/...）经
    __getattr__ 透传给最近一次成功的 backend——``_downgrade_thinking_intensity``
    对 ``model.parameters`` 的属性级突变因此天然落在正确的 backend 上；
    ``_lingshu_usage_ctx`` 写入经 __setattr__ 转发到全部已构建 backend，
    保证用量落库归属不随切池漂移。
    """

    def __init__(
        self,
        primary: Any,
        runtime: Any,
        chain_keys: list[str],
        intensity: str,
        temperature: float | None,
        model_name: str | None = None,
        web_search: bool | None = None,
        vision: bool = False,
    ) -> None:
        self._runtime = runtime
        self._intensity = intensity
        self._temperature = temperature
        self._model_name = model_name
        self._web_search = web_search
        self._vision = vision
        self._keys = list(chain_keys)
        self._backends: list[Any | None] = [primary]
        self._last_ok = 0
        self._pending_ctx: dict[str, Any] | None = None

    # ── backend 构建 ──
    def _build(self, idx: int) -> Any:
        if idx < len(self._backends) and self._backends[idx] is not None:
            return self._backends[idx]
        from LLM.model import create_model, set_usage_context  # 延迟导入防环

        inner = create_model(
            provider=self._keys[idx],
            thinking_intensity=self._intensity,
            temperature=self._temperature,
            web_search=self._web_search,
            vision=self._vision,
            config=self._runtime,
        )
        if self._pending_ctx:
            set_usage_context(inner, **self._pending_ctx)
        while len(self._backends) <= idx:
            self._backends.append(None)
        self._backends[idx] = inner
        return inner

    def _active(self) -> Any:
        idx = self._last_ok
        if idx < len(self._backends) and self._backends[idx] is not None:
            return self._backends[idx]
        for backend in self._backends:
            if backend is not None:
                return backend
        raise RuntimeError("failover 链中没有任何可用 backend")

    # ── 调用面 ──
    async def __call__(
        self, messages: list, tools: list | None = None,
        tool_choice: Any = None, **kwargs: Any,
    ) -> Any:
        last_exc: BaseException | None = None
        for idx in range(len(self._keys)):
            if breaker_open(self._keys[idx]):
                continue
            try:
                backend = self._build(idx)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - 构建失败（未启用等）按熔断处理
                if _is_tripable(exc):
                    _record_failure(self._keys[idx], exc)
                    last_exc = last_exc or exc
                logger.warning("[LLM熔断] %s 构建失败: %s", self._keys[idx], str(exc)[:160])
                continue
            try:
                result = await backend(
                    messages, tools=tools, tool_choice=tool_choice, **kwargs,
                )
                _record_success(self._keys[idx])
                if idx != self._last_ok:
                    logger.warning(
                        "[LLM熔断] 主 profile 不可用，已切换至 %s", self._keys[idx],
                    )
                self._last_ok = idx
                return result
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                if not _is_tripable(exc):
                    raise
                cool = _record_failure(self._keys[idx], exc)
                last_exc = last_exc or exc
                logger.warning(
                    "[LLM熔断] %s 调用失败（%s），熔断 %.0fs 并尝试下一 profile",
                    self._keys[idx], str(exc)[:160], cool,
                )
        raise last_exc or RuntimeError("LLM failover 链全部候选失败")

    async def _call_api(self, model_name: str, messages: list, tools=None,
                        tool_choice=None, **kwargs: Any) -> Any:
        return await self._active()._call_api(
            model_name, messages, tools=tools, tool_choice=tool_choice, **kwargs,
        )

    async def count_tokens(self, messages: list, tools: list | None = None) -> int:
        return await self._active().count_tokens(messages, tools)

    async def generate_structured_output(
        self, messages: list, structured_model: Any, **kwargs: Any,
    ) -> Any:
        return await self._active().generate_structured_output(
            messages, structured_model, **kwargs,
        )

    # ── 属性透传 ──
    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") and name not in _FORWARD_PRIVATE:
            raise AttributeError(name)
        try:
            return getattr(self._active(), name)
        except AttributeError:
            raise AttributeError(
                f"{type(self).__name__} has no attribute {name!r}",
            ) from None

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_lingshu_usage_ctx":
            object.__setattr__(self, name, value)
            self._pending_ctx = dict(value or {})
            for backend in getattr(self, "_backends", []) or []:
                if backend is not None:
                    try:
                        backend._lingshu_usage_ctx = value
                    except Exception:  # noqa: BLE001
                        pass
            return
        object.__setattr__(self, name, value)
