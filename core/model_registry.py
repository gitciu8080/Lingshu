"""由 Web 超级管理员维护的模型注册表（本地 JSON 存储，v2 逻辑结构）。

供应商 → 模型列表 → 每模型超参数 的三层结构（与 Docker 版 PostgreSQL
表结构字段一一对应，落盘为单个 JSON 文件）::

    data/model_api_configs.json
      ├─ version=2
      ├─ providers[]      一条 = 一次"添加供应商"向导（凭据 + 启用工具）
      │   └─ models[]     每个模型独立：name / enabled / vision / settings
      ├─ embeddings[]     知识库向量模型（全局仅允许启用一条）
      └─ audit[]          配置变更审计（最近 500 条）

- API Key 使用 Fernet 加密后存储（``api_key_ciphertext``），列表/API 永不
  返回明文；加密密钥来自 ``LINGSHU_MODEL_CONFIG_KEY`` 或 ``data/model_api.key``。
- providers[] 条目携带 ``owner_id``（null=平台池，整数=用户私有池）：普通用户
  仅可见/可用自己的私有池；超级管理员额外可见平台池；CLI（无用户上下文）
  仅平台池。embeddings[] 保持全局语义，不划分归属。
- 历史遗留的 v1 扁平 ``configs`` 结构在首次读取时自动升级为 v2，并把
  原文件备份为 ``model_api_configs.v1-<时间戳>.bak.json``；更早的
  ``users.db`` 模型表沿用既有的一次性迁移入口。
- 所有写入走 tempfile + os.replace 原子替换（0600），进程内 RLock 串行化。
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken

from core.providers import (
    DEFAULT_LLM_SETTINGS,
    PROVIDER_CATALOG,
    catalog_for_client,
    get_provider_spec,
    supported_native_tools,
)

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parent.parent  # 项目根（core/ 的上一级）
REGISTRY_PATH = _ROOT / "data" / "model_api_configs.json"
LEGACY_DB_PATH = _ROOT / "data" / "users.db"
KEY_PATH = _ROOT / "data" / "model_api.key"
_LOCK = threading.RLock()
_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_MODEL_NAME_MAX = 300
_MAX_MODELS_PER_PROVIDER = 64
_PROBE_TIMEOUT = 15.0
_AUDIT_KEEP = 500
_UNSET: Any = object()  # 作用域哨兵：_UNSET=不过滤（旧行为）；显式 None=仅平台池（CLI）


def _owner_visible(
    item: dict[str, Any], owner_user_id: int | None, owner_is_superadmin: bool,
) -> bool:
    """按作用域判断 provider 条目对调用方是否可见。

    - 无用户上下文（CLI）：仅平台池（owner_id 为 null）；
    - 普通用户：仅自己的私有池；
    - 超级管理员：平台池 + 自己的私有池。
    """
    owner = item.get("owner_id")
    if owner_user_id is None:
        return owner is None
    if owner is None:
        return owner_is_superadmin
    return int(owner) == int(owner_user_id)


def _require_provider_owner(
    item: dict[str, Any], actor_user_id: int | None, actor_is_superadmin: bool,
) -> None:
    """变更类操作的归属校验；未提供执行者上下文时保持旧行为（不校验）。"""
    if actor_user_id is None:
        return
    if actor_is_superadmin:
        return
    owner = item.get("owner_id")
    if owner is None or int(owner) != int(actor_user_id):
        raise ModelRegistryError("无权访问该模型配置")


class ModelRegistryError(ValueError):
    """可安全返回给超级管理员的配置错误。"""


# ────────────────────────────────────────────────────────────────
# 存储层（JSON v2）
# ────────────────────────────────────────────────────────────────

def _empty_registry() -> dict[str, Any]:
    return {
        "version": 2,
        "next_provider_id": 1,
        "next_embedding_id": 1,
        "providers": [],
        "embeddings": [],
        "audit": [],
    }


def _fernet_key(*, create: bool) -> bytes:
    raw = os.getenv("LINGSHU_MODEL_CONFIG_KEY", "").strip()
    if raw:
        try:
            key = raw.encode("ascii")
            if len(base64.urlsafe_b64decode(key)) != 32:
                raise ValueError
            return key
        except Exception as exc:  # noqa: BLE001
            raise ModelRegistryError(
                "LINGSHU_MODEL_CONFIG_KEY 必须是 Fernet URL-safe base64 32 字节密钥",
            ) from exc
    if KEY_PATH.is_file():
        key = KEY_PATH.read_bytes().strip()
        try:
            if len(base64.urlsafe_b64decode(key)) != 32:
                raise ValueError
            return key
        except Exception as exc:  # noqa: BLE001
            raise ModelRegistryError("模型 API 加密密钥文件无效") from exc
    if not create:
        raise ModelRegistryError("模型 API 加密密钥尚未初始化")
    key = Fernet.generate_key()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _fernet_key(create=False)
    try:
        os.write(fd, key + b"\n")
    finally:
        os.close(fd)
    return key


def _encrypt(secret: str) -> str:
    return (
        Fernet(_fernet_key(create=True)).encrypt(secret.encode("utf-8")).decode("ascii")
        if secret else ""
    )


def _decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return Fernet(_fernet_key(create=False)).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ModelRegistryError("模型 API Key 无法解密，请检查模型配置加密密钥") from exc


def _api_key_status(ciphertext: str) -> str:
    """推导 API Key 的健康状态。

    ``ok``      密文可解密；``invalid`` 加密密钥已丢失/轮换；``unset`` 未配置。
    """
    if not ciphertext:
        return "unset"
    try:
        _decrypt(ciphertext)
    except ModelRegistryError:
        return "invalid"
    return "ok"


def _write_unlocked(data: dict[str, Any]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = REGISTRY_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, REGISTRY_PATH)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(data: dict[str, Any], subject: str, actor_id: int, action: str, detail: str) -> None:
    data.setdefault("audit", []).append({
        "subject": subject, "actor_id": int(actor_id), "action": action,
        "detail": detail, "created_at": _now(),
    })
    data["audit"] = data["audit"][-_AUDIT_KEEP:]


# ────────────────────────────────────────────────────────────────
# 历史数据迁移（users.db → v1 扁平 → v2 三层）
# ────────────────────────────────────────────────────────────────

def _migrate_legacy_db() -> dict[str, Any] | None:
    """从旧 SQLite 表构建 v1 扁平结构；密文沿用相同 Fernet key。"""
    if not LEGACY_DB_PATH.is_file():
        return None
    conn = sqlite3.connect(LEGACY_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='model_api_configs'",
        ).fetchone()
        if not table:
            return None
        rows = conn.execute("SELECT * FROM model_api_configs ORDER BY id").fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not rows:
        return None
    data = {
        "version": 1, "next_id": 1, "configs": [], "audit": [],
    }
    for row in rows:
        item = dict(row)
        try:
            item["settings"] = json.loads(item.pop("settings_json", "{}"))
        except (TypeError, json.JSONDecodeError):
            item["settings"] = {}
        data["configs"].append(item)
    data["next_id"] = max(int(item["id"]) for item in data["configs"]) + 1
    data["audit"].append({
        "action": "migrated_from_sqlite", "count": len(rows),
        "created_at": _now(),
    })
    return data


def _safe_clean_url(value: object, fallback: str = "") -> str:
    """迁移专用：非法 URL 不阻断迁移，回退到默认地址。"""
    try:
        cleaned = _clean_url(value)
    except ModelRegistryError:
        return fallback
    return cleaned or fallback


def _migrate_v1(data: dict[str, Any]) -> dict[str, Any]:
    """把 v1 扁平 configs 升级为 v2 三层结构（providers + embeddings）。"""
    configs = data.get("configs") or []
    providers: list[dict[str, Any]] = []
    embeddings: list[dict[str, Any]] = []
    max_provider_id = 0
    max_embedding_id = 0
    for item in configs:
        item = dict(item)
        config_id = int(item.get("id") or 0)
        created_at = item.get("created_at") or _now()
        updated_at = item.get("updated_at") or created_at
        ciphertext = str(item.get("api_key_ciphertext") or "")
        hint = str(item.get("api_key_hint") or "")
        if item.get("category") == "embedding":
            raw_models = [str(m or "").strip() for m in (item.get("models") or [])]
            model_name = (
                str(item.get("model_name") or "").strip()
                or next((m for m in raw_models if m), "")
            )
            provider = str(item.get("provider") or "").strip().lower() or "openai-compatible"
            if not _PROVIDER_RE.fullmatch(provider):
                provider = "openai-compatible"
            raw_settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
            settings = {
                "temperature": float(raw_settings.get("temperature", 0.7)),
                "top_p": float(raw_settings.get("top_p", 0.95)),
                "max_tokens": int(raw_settings.get("max_tokens", 0) or 0),
                "max_retries": int(raw_settings.get("max_retries", 3) or 3),
                "context_size": int(raw_settings.get("context_size", 8191) or 8191),
                "timeout_seconds": float(raw_settings.get("timeout_seconds", 600) or 600),
                "thinking_enabled": bool(raw_settings.get("thinking_enabled", False)),
            }
            embeddings.append({
                "id": config_id,
                "name": str(item.get("name") or f"embedding-{config_id}"),
                "provider": provider,
                "base_url": _safe_clean_url(item.get("base_url")),
                "model_name": model_name,
                "dimensions": int(item.get("dimensions") or 0),
                "pass_dimensions": bool(item.get("pass_dimensions", True)),
                "enabled": bool(item.get("enabled")),
                "api_key_ciphertext": ciphertext,
                "api_key_hint": hint,
                "settings": settings,
                "created_at": created_at,
                "updated_at": updated_at,
            })
            max_embedding_id = max(max_embedding_id, config_id)
            continue

        # LLM 配置 → 供应商条目。目录外的历史 provider 键（如自定义网关
        # zhipu1）统一映射为 openai-compatible，保留原名称与密文。
        provider_key = str(item.get("provider") or "").strip().lower()
        spec = get_provider_spec(provider_key)
        if spec is None:
            provider_key = "openai-compatible"
            spec = get_provider_spec(provider_key)
        assert spec is not None
        api_style = str(item.get("api_style") or "").strip().lower()
        if api_style not in spec["api_styles"]:
            api_style = spec["default_api_style"]
        gateway_mode = str(item.get("gateway_mode") or "base_url").strip().lower()
        if gateway_mode not in {"base_url", "full_endpoint"}:
            gateway_mode = "base_url"
        base_url = _safe_clean_url(item.get("base_url"), spec["default_base_url"])
        available = supported_native_tools(spec, api_style)
        enabled_tools = [
            str(tool).strip().lower()
            for tool in (item.get("native_tools") or [])
            if str(tool).strip().lower() in available
        ]
        raw_settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
        merged_settings = {**DEFAULT_LLM_SETTINGS, **spec.get("default_settings", {})}
        try:
            settings = {
                "temperature": float(raw_settings.get("temperature", merged_settings["temperature"])),
                "top_p": float(raw_settings.get("top_p", merged_settings["top_p"])),
                "top_k": raw_settings.get("top_k"),
                "max_tokens": int(raw_settings.get("max_tokens", merged_settings["max_tokens"]) or 0),
                "max_retries": int(raw_settings.get("max_retries", merged_settings["max_retries"]) or 3),
                "context_size": int(
                    raw_settings.get("context_size", merged_settings["context_size"]) or 128000,
                ),
                "timeout_seconds": float(
                    raw_settings.get("timeout_seconds", merged_settings["timeout_seconds"]) or 600,
                ),
                "thinking_enabled": bool(raw_settings.get("thinking_enabled", True)),
                "thinking_budget": int(raw_settings.get("thinking_budget", 0) or 0),
            }
        except (TypeError, ValueError):
            settings = dict(merged_settings)
        vision_names = {str(v).strip() for v in (item.get("vision_models") or [])}
        if str(item.get("vision_model") or "").strip():
            # 兼容 Docker 版 v1 导出格式：单数 vision_model 字段。
            vision_names.add(str(item["vision_model"]).strip())
        models: list[dict[str, Any]] = []
        seen: set[str] = set()
        for candidate in (item.get("models") or []):
            name = str(candidate or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            models.append({
                "name": name, "enabled": True, "vision": name in vision_names,
                "settings": dict(settings),
            })
        if not models:
            for key in ("model_name", "model_min", "model_max", "model_low", "vision_model"):
                name = str(item.get(key) or "").strip()
                if name and name not in seen:
                    seen.add(name)
                    models.append({
                        "name": name, "enabled": True,
                        "vision": name in vision_names, "settings": dict(settings),
                    })
        providers.append({
            "id": config_id,
            "name": str(item.get("name") or f"provider-{config_id}"),
            "provider": provider_key,
            "api_style": api_style,
            "base_url": base_url,
            "gateway_mode": gateway_mode,
            "enabled": bool(item.get("enabled")),
            "enabled_tools": enabled_tools,
            "api_key_ciphertext": ciphertext,
            "api_key_hint": hint,
            "models": models,
            "created_at": created_at,
            "updated_at": updated_at,
        })
        max_provider_id = max(max_provider_id, config_id)

    upgraded = _empty_registry()
    upgraded["providers"] = providers
    upgraded["embeddings"] = embeddings
    upgraded["next_provider_id"] = max_provider_id + 1
    upgraded["next_embedding_id"] = max_embedding_id + 1
    upgraded["audit"] = list(data.get("audit") or [])[-_AUDIT_KEEP:]
    _audit(upgraded, "registry", 0, "migrated_v1_to_v2",
           f"providers={len(providers)} embeddings={len(embeddings)}")
    return upgraded


def _backup_v1_file() -> str | None:
    """把 v1 原文件备份为带时间戳的 .bak.json；失败仅告警不阻断。"""
    try:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = REGISTRY_PATH.with_name(f"model_api_configs.v1-{stamp}.bak.json")
        shutil.copy2(REGISTRY_PATH, target)
        os.chmod(target, 0o600)
        return target.name
    except OSError as exc:
        logger.warning("v1 模型注册表备份失败（继续迁移）: %s", exc)
        return None


def _read_unlocked() -> dict[str, Any]:
    if not REGISTRY_PATH.is_file():
        legacy = _migrate_legacy_db()
        data = _migrate_v1(legacy) if legacy is not None else _empty_registry()
        _write_unlocked(data)
        return data
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelRegistryError(f"本地模型配置 JSON 无法读取: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelRegistryError("本地模型配置 JSON 结构无效")
    if data.get("version") == 2 and isinstance(data.get("providers"), list):
        return data
    if data.get("version") == 1 or isinstance(data.get("configs"), list):
        backup = _backup_v1_file()
        upgraded = _migrate_v1(data)
        _write_unlocked(upgraded)
        logger.info(
            "模型注册表已从 v1 升级为 v2（providers=%d embeddings=%d），"
            "原文件备份为 %s",
            len(upgraded["providers"]), len(upgraded["embeddings"]), backup,
        )
        return upgraded
    raise ModelRegistryError("本地模型配置 JSON 结构无效")


def init_model_registry() -> None:
    """确保注册表文件存在并完成历史结构迁移（幂等）。"""
    with _LOCK:
        _read_unlocked()


# ────────────────────────────────────────────────────────────────
# 校验（与存储无关，保持 v2 语义）
# ────────────────────────────────────────────────────────────────

def _clean_url(value: object) -> str:
    url = str(value or "").strip().rstrip("/")
    if not url:
        return ""
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"} or not parsed.netloc
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ModelRegistryError("API 地址必须是合法 HTTP(S) 基础地址，不能包含凭据、查询或片段")
    return url


def _normalize_provider(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    provider = str(payload.get("provider") or "").strip().lower()
    api_style = str(payload.get("api_style") or "").strip().lower()
    spec = get_provider_spec(provider)
    if spec is None:
        raise ModelRegistryError(
            f"不支持的供应商: {provider}；可选: {', '.join(PROVIDER_CATALOG)}"
        )
    if not 2 <= len(name) <= 80:
        raise ModelRegistryError("配置名称长度必须为 2~80 个字符")
    if api_style not in spec["api_styles"]:
        raise ModelRegistryError(
            f"供应商 {provider} 的 API 协议仅支持: {', '.join(spec['api_styles'])}"
        )
    gateway_mode = str(payload.get("gateway_mode") or "base_url").strip().lower()
    if gateway_mode not in {"base_url", "full_endpoint"}:
        raise ModelRegistryError("网关端点模式仅支持 base_url 或 full_endpoint")

    available = supported_native_tools(spec, api_style)
    enabled_tools: list[str] = []
    for item in payload.get("enabled_tools") or []:
        key = str(item).strip().lower()
        if not key:
            continue
        if key not in available:
            raise ModelRegistryError(
                f"供应商 {provider} 在 {api_style} 协议下不支持原生工具: {key}"
            )
        if key not in enabled_tools:
            enabled_tools.append(key)

    base_url = _clean_url(payload.get("base_url"))
    if not base_url and not spec["default_base_url"] and spec["driver"] in {"chat_completions", "responses"}:
        raise ModelRegistryError("OpenAI 兼容供应商必须填写 API 地址")
    return {
        "provider": provider, "name": name, "api_style": api_style,
        "base_url": base_url or spec["default_base_url"],
        "gateway_mode": gateway_mode,
        "enabled_tools": enabled_tools,
        "enabled": bool(payload.get("enabled", False)),
    }


def _normalize_model_settings(raw: object, spec: dict[str, Any] | None) -> dict[str, Any]:
    values = raw if isinstance(raw, dict) else {}
    merged = {**DEFAULT_LLM_SETTINGS, **((spec or {}).get("default_settings") or {})}
    try:
        settings = {
            "temperature": float(values.get("temperature", merged["temperature"])),
            "top_p": float(values.get("top_p", merged["top_p"])),
            "top_k": (
                None if values.get("top_k") in (None, "")
                else int(values.get("top_k"))
            ),
            "max_tokens": int(values.get("max_tokens", merged["max_tokens"]) or 0),
            "max_retries": int(values.get("max_retries", merged["max_retries"])),
            "context_size": int(values.get("context_size", merged["context_size"])),
            "timeout_seconds": float(values.get("timeout_seconds", merged["timeout_seconds"])),
            "thinking_enabled": bool(values.get("thinking_enabled", merged["thinking_enabled"])),
            "thinking_budget": int(values.get("thinking_budget", merged["thinking_budget"]) or 0),
        }
    except (TypeError, ValueError) as exc:
        raise ModelRegistryError("模型运行参数格式无效") from exc
    if not 0 <= settings["temperature"] <= 2:
        raise ModelRegistryError("temperature 必须在 0~2 之间")
    if not 0 < settings["top_p"] <= 1:
        raise ModelRegistryError("top_p 必须在 0~1 之间")
    if settings["top_k"] is not None and not 1 <= settings["top_k"] <= 128:
        raise ModelRegistryError("top_k 必须在 1~128 之间")
    if not 0 <= settings["max_tokens"] <= 1048576:
        raise ModelRegistryError("max_tokens 必须为 0~1048576")
    if not 0 <= settings["max_retries"] <= 10:
        raise ModelRegistryError("max_retries 必须在 0~10 之间")
    if not 1024 <= settings["context_size"] <= 10485760:
        raise ModelRegistryError("context_size 必须在 1024~10485760 之间")
    if not 1 <= settings["timeout_seconds"] <= 3600:
        raise ModelRegistryError("timeout_seconds 必须在 1~3600 之间")
    if settings["thinking_budget"] < 0:
        raise ModelRegistryError("thinking_budget 不能为负数")
    return settings


def _normalize_model_entry(payload: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > _MODEL_NAME_MAX:
        raise ModelRegistryError("模型名称不能为空且长度需在 1~300 字符")
    if any(ch in name for ch in "\x00\r\n\\"):
        raise ModelRegistryError("模型名称包含非法字符")
    return {
        "name": name,
        "enabled": bool(payload.get("enabled", True)),
        "vision": bool(payload.get("vision", False)),
        "settings": _normalize_model_settings(payload.get("settings"), spec),
    }


def _mask_provider(item: dict[str, Any]) -> dict[str, Any]:
    output = dict(item)
    ciphertext = str(output.pop("api_key_ciphertext", "") or "")
    hint = str(output.pop("api_key_hint", "") or "")
    output["has_api_key"] = bool(hint)
    output["api_key_masked"] = f"••••••••{hint}" if hint else "未设置"
    output["api_key_status"] = _api_key_status(ciphertext)
    output["enabled"] = bool(output.get("enabled"))
    output["models"] = [dict(m) for m in (output.get("models") or [])]
    return output


# ────────────────────────────────────────────────────────────────
# 供应商（LLM）CRUD
# ────────────────────────────────────────────────────────────────

def provider_catalog() -> list[dict[str, Any]]:
    """内置供应商目录（添加向导第一步的数据源）。"""
    return catalog_for_client()


def _name_taken(
    data: dict[str, Any], name: str, owner_id: int | None, exclude_id: int = 0,
) -> bool:
    """配置名称在同一个归属池内唯一（跨用户可重名，仅作展示标签）。"""
    for item in data["providers"]:
        if int(item["id"]) == int(exclude_id):
            continue
        if item.get("name") == name and item.get("owner_id", None) == owner_id:
            return True
    return False


def list_llm_providers(
    *,
    owner_user_id: Any = _UNSET,
    owner_is_superadmin: bool = False,
) -> list[dict[str, Any]]:
    with _LOCK:
        data = _read_unlocked()
        items = [dict(p) for p in data["providers"]]
        if owner_user_id is not _UNSET:
            items = [
                p for p in items
                if _owner_visible(p, owner_user_id, owner_is_superadmin)
            ]
        items.sort(key=lambda p: (not p.get("enabled"), -int(p["id"])))
        items = [_mask_provider(item) for item in items]
        for item in items:
            item["enabled_models"] = [
                m["name"] for m in item.get("models", []) if m.get("enabled")
            ]
        return items


def _find_provider(data: dict[str, Any], provider_id: int) -> dict[str, Any] | None:
    return next(
        (p for p in data["providers"] if int(p["id"]) == int(provider_id)), None,
    )


def get_llm_provider(
    provider_id: int,
    *,
    include_secret: bool = False,
    actor_user_id: int | None = None,
    actor_is_superadmin: bool = False,
) -> dict[str, Any] | None:
    with _LOCK:
        item = _find_provider(_read_unlocked(), provider_id)
        if item is None:
            return None
        _require_provider_owner(item, actor_user_id, actor_is_superadmin)
        item = dict(item)
        if include_secret:
            output = dict(item)
            output["api_key"] = _decrypt(output.pop("api_key_ciphertext", ""))
            return output
        return _mask_provider(item)


def create_llm_provider(
    payload: dict[str, Any], actor_id: int, owner_id: int | None = None,
) -> dict[str, Any]:
    normalized = _normalize_provider(payload)
    secret = str(payload.get("api_key") or "").strip()
    spec = get_provider_spec(normalized["provider"])
    assert spec is not None
    owner: int | None = int(owner_id) if owner_id is not None else None
    with _LOCK:
        data = _read_unlocked()
        if _name_taken(data, normalized["name"], owner):
            raise ModelRegistryError("配置名称已存在")
        provider_id = int(data["next_provider_id"])
        data["next_provider_id"] = provider_id + 1
        raw_models = payload.get("models")
        models_raw = raw_models if isinstance(raw_models, list) else []
        models = [_normalize_model_entry(m, spec) for m in models_raw]
        if not models:
            # 未提供模型列表时，若目录有默认建议模型则预填一个禁用条目。
            for suggestion in spec.get("default_models", ())[:1]:
                models.append({
                    "name": suggestion, "enabled": False, "vision": False,
                    "settings": _normalize_model_settings({}, spec),
                })
        now = _now()
        item = {
            "id": provider_id, **normalized,
            "owner_id": owner,
            "api_key_ciphertext": _encrypt(secret),
            "api_key_hint": secret[-4:] if secret else "",
            "models": models,
            "created_at": now, "updated_at": now,
        }
        data["providers"].append(item)
        _audit(data, f"provider:{provider_id}", actor_id, "created", normalized["name"])
        _write_unlocked(data)
        return _mask_provider(item)


def update_llm_provider(
    provider_id: int,
    payload: dict[str, Any],
    actor_id: int,
    *,
    actor_user_id: int | None = None,
    actor_is_superadmin: bool = False,
) -> dict[str, Any]:
    normalized = _normalize_provider(payload)
    spec = get_provider_spec(normalized["provider"])
    assert spec is not None
    with _LOCK:
        data = _read_unlocked()
        item = _find_provider(data, provider_id)
        if item is None:
            raise ModelRegistryError("模型 API 配置不存在")
        _require_provider_owner(item, actor_user_id, actor_is_superadmin)
        if _name_taken(
            data, normalized["name"], item.get("owner_id", None), exclude_id=provider_id,
        ):
            raise ModelRegistryError("配置名称已存在")
        if payload.get("clear_api_key"):
            ciphertext = hint = ""
        elif str(payload.get("api_key") or "").strip():
            secret = str(payload["api_key"]).strip()
            ciphertext, hint = _encrypt(secret), secret[-4:]
        else:
            ciphertext = str(item.get("api_key_ciphertext") or "")
            hint = str(item.get("api_key_hint") or "")
        # 模型列表独立维护（更新供应商本身不覆盖模型条目）；
        # 协议/供应商变化时，剔除当前组合不再支持的原生工具。
        enabled_tools = [
            t for t in list(item.get("enabled_tools") or [])
            if t in supported_native_tools(spec, normalized["api_style"])
        ]
        item.update(
            name=normalized["name"], provider=normalized["provider"],
            api_style=normalized["api_style"], base_url=normalized["base_url"],
            gateway_mode=normalized["gateway_mode"], enabled=normalized["enabled"],
            enabled_tools=enabled_tools,
            api_key_ciphertext=ciphertext, api_key_hint=hint,
            updated_at=_now(),
        )
        _audit(data, f"provider:{provider_id}", actor_id, "updated", normalized["name"])
        _write_unlocked(data)
        return _mask_provider(item)


def delete_llm_provider(
    provider_id: int,
    actor_id: int,
    *,
    actor_user_id: int | None = None,
    actor_is_superadmin: bool = False,
) -> None:
    with _LOCK:
        data = _read_unlocked()
        item = _find_provider(data, provider_id)
        if item is None:
            raise ModelRegistryError("模型 API 配置不存在")
        _require_provider_owner(item, actor_user_id, actor_is_superadmin)
        data["providers"] = [
            p for p in data["providers"] if int(p["id"]) != int(provider_id)
        ]
        _audit(data, f"provider:{provider_id}", actor_id, "deleted",
               str(item.get("name") or ""))
        _write_unlocked(data)


# ────────────────────────────────────────────────────────────────
# 供应商下的模型列表 CRUD
# ────────────────────────────────────────────────────────────────


def _owned_provider_from_data(
    data: dict[str, Any],
    provider_id: int,
    actor_user_id: int | None,
    actor_is_superadmin: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """定位 provider 条目并做归属校验，返回 (条目, 供应商目录 spec)。"""
    item = _find_provider(data, provider_id)
    if item is None:
        raise ModelRegistryError("模型 API 配置不存在")
    _require_provider_owner(item, actor_user_id, actor_is_superadmin)
    spec = get_provider_spec(str(item.get("provider") or ""))
    if spec is None:
        raise ModelRegistryError(f"不支持的供应商: {item.get('provider')}")
    return item, spec


def add_provider_model(
    provider_id: int,
    payload: dict[str, Any],
    actor_id: int,
    *,
    actor_user_id: int | None = None,
    actor_is_superadmin: bool = False,
) -> dict[str, Any]:
    with _LOCK:
        data = _read_unlocked()
        item, spec = _owned_provider_from_data(
            data, provider_id, actor_user_id, actor_is_superadmin,
        )
        entry = _normalize_model_entry(payload, spec)
        if any(m.get("name") == entry["name"] for m in item.get("models") or []):
            raise ModelRegistryError(f"模型 {entry['name']} 已存在于该供应商配置中")
        if len(item.get("models") or []) >= _MAX_MODELS_PER_PROVIDER:
            raise ModelRegistryError(f"单个供应商最多维护 {_MAX_MODELS_PER_PROVIDER} 个模型")
        item.setdefault("models", []).append(entry)
        item["updated_at"] = _now()
        _audit(data, f"provider:{provider_id}", actor_id, "model_added", entry["name"])
        _write_unlocked(data)
        return dict(entry)


def update_provider_model(
    provider_id: int,
    model_name: str,
    payload: dict[str, Any],
    actor_id: int,
    *,
    actor_user_id: int | None = None,
    actor_is_superadmin: bool = False,
) -> dict[str, Any]:
    with _LOCK:
        data = _read_unlocked()
        item, spec = _owned_provider_from_data(
            data, provider_id, actor_user_id, actor_is_superadmin,
        )
        models = item.get("models") or []
        current = next((m for m in models if m.get("name") == model_name), None)
        if current is None:
            raise ModelRegistryError(f"模型 {model_name} 不存在")
        merged = dict(current)
        merged.update(payload)
        entry = _normalize_model_entry(merged, spec)
        if any(
            m.get("name") == entry["name"] and m is not current
            for m in models
        ):
            raise ModelRegistryError(f"模型 {entry['name']} 已存在于该供应商配置中")
        models[models.index(current)] = entry
        item["updated_at"] = _now()
        _audit(data, f"provider:{provider_id}", actor_id, "model_updated", entry["name"])
        _write_unlocked(data)
        return dict(entry)


def delete_provider_model(
    provider_id: int,
    model_name: str,
    actor_id: int,
    *,
    actor_user_id: int | None = None,
    actor_is_superadmin: bool = False,
) -> None:
    with _LOCK:
        data = _read_unlocked()
        item, _spec = _owned_provider_from_data(
            data, provider_id, actor_user_id, actor_is_superadmin,
        )
        models = item.get("models") or []
        if not any(m.get("name") == model_name for m in models):
            raise ModelRegistryError(f"模型 {model_name} 不存在")
        item["models"] = [m for m in models if m.get("name") != model_name]
        item["updated_at"] = _now()
        _audit(data, f"provider:{provider_id}", actor_id, "model_deleted", model_name)
        _write_unlocked(data)


# ────────────────────────────────────────────────────────────────
# 模型列表拉取（/models 探测）
# ────────────────────────────────────────────────────────────────

def fetch_provider_models(
    provider: str, base_url: str, api_key: str,
) -> dict[str, Any]:
    """访问供应商 models 端点拉取模型列表。

    Args:
        provider: 供应商目录键（决定探测协议）。
        base_url: API 基础地址（向导中未保存时由前端传入）。
        api_key: 明文 API Key（仅用于本次请求，不落盘）。

    Returns:
        {"models": [name, ...], "endpoint": 实际请求的地址}
    """
    spec = get_provider_spec(provider)
    if spec is None:
        raise ModelRegistryError(f"不支持的供应商: {provider}")
    probe = spec.get("models_probe") or "openai"
    base = _clean_url(base_url)
    headers: dict[str, str] = {}
    params: dict[str, str] | None = None
    if probe == "ollama":
        base = base or spec["default_base_url"]
        url = f"{base}{spec.get('models_endpoint') or '/api/tags'}"
    elif probe == "anthropic":
        if not base:
            raise ModelRegistryError("请先填写 API 地址")
        url = f"{base}/v1/models"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    elif probe == "gemini":
        if not api_key:
            raise ModelRegistryError("请先填写 API Key")
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        params = {"key": api_key}
    else:  # openai 兼容
        if not base:
            raise ModelRegistryError("请先填写 API 地址")
        url = f"{base}{spec.get('models_endpoint') or '/models'}"
        if api_key:
            headers = {"Authorization": f"Bearer {api_key}"}

    try:
        response = httpx.get(url, headers=headers, params=params, timeout=_PROBE_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPStatusError as exc:
        raise ModelRegistryError(
            f"模型列表拉取失败（HTTP {exc.response.status_code}），请检查 API 地址与密钥",
        ) from exc
    except ModelRegistryError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ModelRegistryError(f"模型列表拉取失败: {exc}") from exc

    names: list[str] = []
    if probe == "ollama":
        names = [str(m.get("name") or "") for m in payload.get("models") or []]
    elif probe == "gemini":
        for m in payload.get("models") or []:
            name = str(m.get("name") or "")
            methods = m.get("supportedGenerationMethods") or []
            if methods and "generateContent" not in methods:
                continue
            names.append(name.removeprefix("models/"))
    elif probe == "anthropic":
        names = [str(m.get("id") or m.get("name") or "") for m in payload.get("data") or []]
    else:
        entries = payload.get("data")
        if entries is None and isinstance(payload.get("models"), list):
            entries = payload["models"]
        for m in entries or []:
            if isinstance(m, str):
                names.append(m)
            else:
                names.append(str(m.get("id") or m.get("model") or m.get("name") or ""))
    unique = list(dict.fromkeys(n.strip() for n in names if n.strip()))
    return {"models": unique, "endpoint": url}


# ────────────────────────────────────────────────────────────────
# 运行时视图（任务系统消费）
# ────────────────────────────────────────────────────────────────

_BAD_KEY_WARNED: set[Any] = set()


def _decrypt_or_skip(item: dict[str, Any]) -> str | None:
    """返回 API Key；加密密钥丢失时隔离该配置而不是拖垮其他供应商。"""
    try:
        return _decrypt(str(item.get("api_key_ciphertext") or ""))
    except ModelRegistryError as exc:
        marker = item.get("id")
        if marker in _BAD_KEY_WARNED:
            logger.debug(
                "跳过无法解密的模型配置 id=%s provider=%s: %s",
                item.get("id"), item.get("provider"), exc,
            )
        else:
            _BAD_KEY_WARNED.add(marker)
            logger.warning(
                "跳过无法解密的模型配置 id=%s provider=%s: %s"
                "（请在超级管理页该配置上重新填写 API Key 保存）",
                item.get("id"), item.get("provider"), exc,
            )
        return None


def _runtime_key(item: dict[str, Any], llm_items: list[dict[str, Any]]) -> str:
    provider = str(item.get("provider") or "")
    duplicates = sum(1 for x in llm_items if x.get("provider") == provider)
    if duplicates <= 1:
        return provider
    return f"{provider}::{int(item['id'])}"


def active_llm_providers(
    *,
    include_secrets: bool = False,
    usable_only: bool = False,
    owner_user_id: Any = _UNSET,
    owner_is_superadmin: bool = False,
) -> list[dict[str, Any]]:
    """已启用的 LLM 供应商运行时视图。

    每条返回项包含 ``runtime_key``（provider 唯一时即 provider 名，重复时
    ``provider::id``）、``models``（已启用模型名列表）、``models_detail``
    （含 vision 标记与每模型 settings）与默认 ``model_name``/``vision_model``；
    同时附带本地运行时兼容字段 ``native_tools``（= enabled_tools）、
    ``vision_models``（视觉模型名列表）。

    ``owner_user_id`` 传 ``_UNSET``（默认）时不过滤（历史行为）；显式传
    ``None`` 表示 CLI/无用户上下文（仅平台池）；传用户 id 时按
    ``_owner_visible`` 规则过滤，且 runtime_key 在过滤后的集合内计算。
    """
    with _LOCK:
        data = _read_unlocked()
        items = [
            dict(p) for p in sorted(data["providers"], key=lambda p: int(p["id"]))
            if p.get("enabled")
        ]
    if owner_user_id is not _UNSET:
        items = [
            p for p in items
            if _owner_visible(p, owner_user_id, owner_is_superadmin)
        ]
    prepared: list[dict[str, Any]] = []
    for item in items:
        if include_secrets or usable_only:
            api_key = _decrypt_or_skip(item)
            if api_key is None:
                continue
            item["api_key_status"] = "ok"
            item.pop("api_key_ciphertext", None)
            if include_secrets:
                item["api_key"] = api_key
        public = _mask_provider(item)
        if include_secrets or usable_only:
            # _mask_provider 依据密文重算状态，而密文已在校验步骤弹出；
            # 恢复为已验证状态，避免运行时视图误报 unset。
            public["api_key_status"] = "ok"
        prepared.append(public)
    for item in prepared:
        item["runtime_key"] = _runtime_key(item, prepared)
        models = [
            dict(m) for m in item.get("models", [])
            if m.get("enabled", True)
        ]
        item["models_detail"] = models
        item["models"] = [m["name"] for m in models]
        item["model_name"] = models[0]["name"] if models else ""
        vision_models = [m["name"] for m in models if m.get("vision")]
        item["vision_model"] = vision_models[0] if vision_models else ""
        # ── 本地运行时兼容字段 ──
        item["native_tools"] = list(item.get("enabled_tools") or [])
        item["vision_models"] = vision_models
        item["settings"] = {}
    return prepared


def load_runtime_overrides(
    *,
    owner_user_id: Any = _UNSET,
    owner_is_superadmin: bool = False,
) -> dict[str, Any]:
    """把注册表转换为 RuntimeConfig 覆盖值。

    - 每条启用的 LLM 供应商以 ``runtime_key``（provider 或 provider::配置ID）
      注册进 ``custom_llm_configs``，供统一模型工厂解析；条目同时携带
      models_detail（每模型超参）与旧读取方兼容的 models/vision_models/
      native_tools/model_low/model_min/model_max 字段；
    - ``owner_user_id`` 语义同 ``active_llm_providers``：_UNSET 不过滤（历史
      行为，供旧测试与无用户上下文的调用方）；None=CLI 平台池；用户 id=
      按可见性过滤。embedding 始终全局，不参与过滤；
    - deepseek/qwen/zhipu 的全局字段沿用该 provider 首条启用配置，保持
      .env 回退与旧调用路径兼容；
    - API Key 无法解密的配置（invalid）整条跳过，不影响其他配置；
    - embedding 保持全局单条启用，并透出 gateway_mode。
    """
    overrides: dict[str, Any] = {}
    custom: dict[str, dict[str, Any]] = {}
    first_by_provider: dict[str, dict[str, Any]] = {}
    for item in active_llm_providers(
        include_secrets=True,
        owner_user_id=owner_user_id,
        owner_is_superadmin=owner_is_superadmin,
    ):
        provider = item["provider"]
        models = list(item.get("models") or [])
        first_model = models[0] if models else ""
        second_model = models[1] if len(models) > 1 else first_model
        third_model = models[2] if len(models) > 2 else first_model
        entry = {
            key: item.get(key) for key in (
                "id", "name", "provider", "api_style", "base_url", "api_key",
                "gateway_mode", "enabled_tools", "native_tools", "settings",
                "model_name", "vision_model", "models", "models_detail",
                "vision_models",
            )
        }
        entry["gateway_mode"] = entry.get("gateway_mode") or "base_url"
        entry["model_low"] = third_model
        entry["model_min"] = first_model
        entry["model_max"] = second_model
        custom[item["runtime_key"]] = entry
        first_by_provider.setdefault(provider, item)

    for provider, item in first_by_provider.items():
        models = list(item.get("models") or [])
        first_model = models[0] if models else ""
        second_model = models[1] if len(models) > 1 else first_model
        third_model = models[2] if len(models) > 2 else first_model
        first_detail = next(
            (m for m in item.get("models_detail") or [] if m.get("name") == first_model),
            None,
        ) or {}
        if provider == "deepseek":
            overrides.update(
                deepseek_api_key=item["api_key"], deepseek_base_url=item["base_url"],
                deepseek_gateway_mode=item.get("gateway_mode", "base_url"),
                deepseek_model_low=third_model, deepseek_model_min=first_model,
                deepseek_model_max=second_model,
                deepseek_model_settings=dict(first_detail.get("settings") or {}),
                deepseek_responses_models=tuple(models) if item["api_style"] == "responses" else (),
                deepseek_native_tools=tuple(item.get("native_tools") or ()),
            )
        elif provider == "qwen":
            overrides.update(
                qwen_api_key=item["api_key"], qwen_base_url=item["base_url"],
                qwen_model=first_model,
                qwen_model_settings=dict(first_detail.get("settings") or {}),
            )
        elif provider == "zhipu":
            overrides.update(
                zhipu_api_key=item["api_key"], zhipu_base_url=item["base_url"],
                zhipu_model_low=third_model, zhipu_model_min=first_model,
                zhipu_model_max=second_model,
                zhipu_model_settings=dict(first_detail.get("settings") or {}),
                zhipu_responses_models=tuple(models) if item["api_style"] == "responses" else (),
                zhipu_native_tools=tuple(item.get("native_tools") or ()),
                zhipu_gateway_mode=item.get("gateway_mode", "base_url"),
            )
    if custom:
        overrides["custom_llm_configs"] = custom
    embedding = _active_embedding()
    if embedding:
        overrides.update(
            embedding_api_key=embedding["api_key"], embedding_base_url=embedding["base_url"],
            embedding_model=embedding["model_name"], embedding_dimensions=int(embedding["dimensions"]),
            embedding_pass_dimensions=bool(embedding["pass_dimensions"]),
            embedding_model_settings=embedding.get("settings") or {},
            embedding_gateway_mode=embedding.get("gateway_mode") or "base_url",
        )
    return overrides


# ────────────────────────────────────────────────────────────────
# 嵌入模型（沿用旧接口语义；全局仅允许启用一条）
# ────────────────────────────────────────────────────────────────

def _normalize_embedding(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    provider = str(payload.get("provider") or "").strip().lower() or "openai-compatible"
    api_style = str(payload.get("api_style") or "embeddings").strip().lower()
    if not 2 <= len(name) <= 80:
        raise ModelRegistryError("配置名称长度必须为 2~80 个字符")
    if not _PROVIDER_RE.fullmatch(provider):
        raise ModelRegistryError("Provider 标识必须以小写字母开头，仅含字母、数字、_ 或 -")
    if api_style != "embeddings":
        raise ModelRegistryError("嵌入模型 API 协议必须为 embeddings")
    raw = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}
    try:
        settings = {
            "temperature": float(raw.get("temperature", 0.7)),
            "top_p": float(raw.get("top_p", 0.95)),
            "max_tokens": int(raw.get("max_tokens", 0)),
            "max_retries": int(raw.get("max_retries", 3)),
            "context_size": int(raw.get("context_size", 8191)),
            "timeout_seconds": float(raw.get("timeout_seconds", 600)),
            "thinking_enabled": bool(raw.get("thinking_enabled", False)),
        }
    except (TypeError, ValueError) as exc:
        raise ModelRegistryError("模型运行参数格式无效") from exc
    checks = (
        (0 <= settings["temperature"] <= 2, "temperature 必须在 0~2 之间"),
        (0 < settings["top_p"] <= 1, "top_p 必须在 0~1 之间"),
        (0 <= settings["max_tokens"] <= 1048576, "max_tokens 必须为 0~1048576"),
        (0 <= settings["max_retries"] <= 10, "max_retries 必须在 0~10 之间"),
        (1024 <= settings["context_size"] <= 10485760, "context_size 必须在 1024~10485760 之间"),
        (1 <= settings["timeout_seconds"] <= 3600, "timeout_seconds 必须在 1~3600 之间"),
    )
    for valid, message in checks:
        if not valid:
            raise ModelRegistryError(message)
    model_name = str(payload.get("model_name") or "").strip()
    dimensions = int(payload.get("dimensions") or 0)
    if not model_name:
        raise ModelRegistryError("嵌入模型名称不能为空")
    if not 1 <= dimensions <= 65536:
        raise ModelRegistryError("嵌入向量维度必须在 1~65536 之间")
    return {
        "name": name, "category": "embedding", "provider": provider,
        "api_style": "embeddings", "base_url": _clean_url(payload.get("base_url")),
        "gateway_mode": "base_url", "native_tools": [],
        "model_name": model_name, "dimensions": dimensions,
        "pass_dimensions": bool(payload.get("pass_dimensions", True)),
        "enabled": bool(payload.get("enabled", False)),
        "settings": settings,
    }


def _embedding_row(item: dict[str, Any]) -> dict[str, Any]:
    """对外响应形状（与 Docker 版 _embedding_row 字段一致）。"""
    return {
        "id": int(item["id"]),
        "name": str(item.get("name") or ""),
        "category": "embedding",
        "provider": str(item.get("provider") or "openai-compatible"),
        "api_style": "embeddings",
        "base_url": str(item.get("base_url") or ""),
        "gateway_mode": "base_url",
        "native_tools": [],
        "model_name": str(item.get("model_name") or ""),
        "dimensions": int(item.get("dimensions") or 0),
        "pass_dimensions": bool(item.get("pass_dimensions", True)),
        "enabled": bool(item.get("enabled")),
        "api_key_ciphertext": str(item.get("api_key_ciphertext") or ""),
        "api_key_hint": str(item.get("api_key_hint") or ""),
        "settings": dict(item.get("settings") or {}),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def _public_embedding(item: dict[str, Any]) -> dict[str, Any]:
    output = dict(item)
    ciphertext = str(output.pop("api_key_ciphertext", "") or "")
    hint = str(output.pop("api_key_hint", "") or "")
    output["has_api_key"] = bool(hint)
    output["api_key_masked"] = f"••••••••{hint}" if hint else "未设置"
    output["api_key_status"] = _api_key_status(ciphertext)
    output["enabled"] = bool(output.get("enabled"))
    output["pass_dimensions"] = bool(output.get("pass_dimensions"))
    return output


def list_embedding_configs() -> list[dict[str, Any]]:
    with _LOCK:
        data = _read_unlocked()
        items = sorted(
            (_embedding_row(dict(e)) for e in data["embeddings"]),
            key=lambda e: (not e.get("enabled"), -int(e["id"])),
        )
        return [_public_embedding(item) for item in items]


def _find_embedding(data: dict[str, Any], config_id: int) -> dict[str, Any] | None:
    return next(
        (e for e in data["embeddings"] if int(e["id"]) == int(config_id)), None,
    )


def get_embedding_config(config_id: int, *, include_secret: bool = False) -> dict[str, Any] | None:
    with _LOCK:
        item = _find_embedding(_read_unlocked(), config_id)
        if item is None:
            return None
        output = _embedding_row(dict(item))
        if include_secret:
            output["api_key"] = _decrypt(output.pop("api_key_ciphertext", ""))
            return output
        return _public_embedding(output)


def _disable_embedding_peers(data: dict[str, Any], exclude_id: int = 0) -> None:
    for item in data["embeddings"]:
        if int(item["id"]) != int(exclude_id):
            item["enabled"] = False


def create_embedding_config(payload: dict[str, Any], actor_id: int) -> dict[str, Any]:
    normalized = _normalize_embedding(payload)
    secret = str(payload.get("api_key") or "").strip()
    with _LOCK:
        data = _read_unlocked()
        if any(e.get("name") == normalized["name"] for e in data["embeddings"]):
            raise ModelRegistryError("配置名称已存在")
        if normalized["enabled"]:
            _disable_embedding_peers(data)
        config_id = int(data["next_embedding_id"])
        data["next_embedding_id"] = config_id + 1
        now = _now()
        item = {
            "id": config_id,
            "name": normalized["name"], "provider": normalized["provider"],
            "base_url": normalized["base_url"], "model_name": normalized["model_name"],
            "dimensions": normalized["dimensions"],
            "pass_dimensions": normalized["pass_dimensions"],
            "enabled": normalized["enabled"],
            "api_key_ciphertext": _encrypt(secret),
            "api_key_hint": secret[-4:] if secret else "",
            "settings": normalized["settings"],
            "created_at": now, "updated_at": now,
        }
        data["embeddings"].append(item)
        _audit(data, f"embedding:{config_id}", actor_id, "created", normalized["name"])
        _write_unlocked(data)
        return _public_embedding(_embedding_row(item))


def update_embedding_config(config_id: int, payload: dict[str, Any], actor_id: int) -> dict[str, Any]:
    normalized = _normalize_embedding(payload)
    with _LOCK:
        data = _read_unlocked()
        item = _find_embedding(data, config_id)
        if item is None:
            raise ModelRegistryError("模型 API 配置不存在")
        if any(
            e.get("name") == normalized["name"] and int(e["id"]) != int(config_id)
            for e in data["embeddings"]
        ):
            raise ModelRegistryError("配置名称已存在")
        if payload.get("clear_api_key"):
            ciphertext = hint = ""
        elif str(payload.get("api_key") or "").strip():
            secret = str(payload["api_key"]).strip()
            ciphertext, hint = _encrypt(secret), secret[-4:]
        else:
            ciphertext = str(item.get("api_key_ciphertext") or "")
            hint = str(item.get("api_key_hint") or "")
        if normalized["enabled"]:
            _disable_embedding_peers(data, config_id)
        item.update(
            name=normalized["name"], provider=normalized["provider"],
            base_url=normalized["base_url"], model_name=normalized["model_name"],
            dimensions=normalized["dimensions"],
            pass_dimensions=normalized["pass_dimensions"],
            enabled=normalized["enabled"],
            api_key_ciphertext=ciphertext, api_key_hint=hint,
            settings=normalized["settings"], updated_at=_now(),
        )
        _audit(data, f"embedding:{config_id}", actor_id, "updated", normalized["name"])
        _write_unlocked(data)
        return _public_embedding(_embedding_row(item))


def delete_embedding_config(config_id: int, actor_id: int) -> None:
    with _LOCK:
        data = _read_unlocked()
        item = _find_embedding(data, config_id)
        if item is None:
            raise ModelRegistryError("模型 API 配置不存在")
        data["embeddings"] = [
            e for e in data["embeddings"] if int(e["id"]) != int(config_id)
        ]
        _audit(data, f"embedding:{config_id}", actor_id, "deleted",
               str(item.get("name") or ""))
        _write_unlocked(data)


def _active_embedding() -> dict[str, Any] | None:
    with _LOCK:
        item = next(
            (dict(e) for e in _read_unlocked()["embeddings"] if e.get("enabled")),
            None,
        )
    if not item:
        return None
    api_key = _decrypt_or_skip(item)
    if api_key is None:
        return None
    item.pop("api_key_ciphertext", None)
    item["api_key"] = api_key
    return item


init_model_registry()
