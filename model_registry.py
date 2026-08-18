"""由 Web 超级管理员维护的本地 JSON 模型注册表。

配置原子写入 ``data/model_api_configs.json``。API Key 使用 Fernet 加密，
列表/API 永不返回明文。首次升级时会从旧 ``users.db`` 模型表迁移一次。
"""
from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken


_ROOT = Path(__file__).resolve().parent
REGISTRY_PATH = _ROOT / "data" / "model_api_configs.json"
LEGACY_DB_PATH = _ROOT / "data" / "users.db"
KEY_PATH = _ROOT / "data" / "model_api.key"
_LOCK = threading.RLock()
_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_LLM_STYLES = {"chat_completions", "responses"}
_GATEWAY_MODES = {"base_url", "full_endpoint"}


class ModelRegistryError(ValueError):
    """可安全返回给超级管理员的配置错误。"""


def _empty_registry() -> dict[str, Any]:
    return {"version": 1, "next_id": 1, "configs": [], "audit": []}


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


def _write_unlocked(data: dict[str, Any]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = REGISTRY_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, REGISTRY_PATH)


def _migrate_legacy_unlocked() -> dict[str, Any] | None:
    """从旧 SQLite 表迁移；密文沿用相同 Fernet key，不接触外部服务。"""
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
    data = _empty_registry()
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
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return data


def _read_unlocked() -> dict[str, Any]:
    if not REGISTRY_PATH.is_file():
        data = _migrate_legacy_unlocked() or _empty_registry()
        _write_unlocked(data)
        return data
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelRegistryError(f"本地模型配置 JSON 无法读取: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("configs"), list):
        raise ModelRegistryError("本地模型配置 JSON 结构无效")
    data.setdefault("version", 1)
    data.setdefault("next_id", 1)
    data.setdefault("audit", [])
    return data


def init_model_registry() -> None:
    with _LOCK:
        _read_unlocked()


def _clean_url(value: object) -> str:
    url = str(value or "").strip().rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"} or not parsed.netloc
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ModelRegistryError("API 地址必须是合法 HTTP(S) 基础地址，不能包含凭据、查询或片段")
    return url


def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    category = str(payload.get("category") or "").strip().lower()
    provider = str(payload.get("provider") or "").strip().lower()
    api_style = str(payload.get("api_style") or "").strip().lower()
    if not 2 <= len(name) <= 80:
        raise ModelRegistryError("配置名称长度必须为 2~80 个字符")
    if category not in {"llm", "embedding"}:
        raise ModelRegistryError("配置类别仅支持 llm 或 embedding")
    if not _PROVIDER_RE.fullmatch(provider):
        raise ModelRegistryError("Provider 标识必须以小写字母开头，仅含字母、数字、_ 或 -")
    if category == "llm" and api_style not in _LLM_STYLES:
        raise ModelRegistryError("大模型 API 协议仅支持 chat_completions 或 responses")
    if category == "llm" and provider == "qwen" and api_style != "chat_completions":
        raise ModelRegistryError("内置 Qwen 适配器使用 Chat Completions 协议")
    if category == "embedding" and api_style != "embeddings":
        raise ModelRegistryError("嵌入模型 API 协议必须为 embeddings")
    gateway_mode = str(payload.get("gateway_mode") or "base_url").strip().lower()
    if category != "llm":
        gateway_mode = "base_url"
    if gateway_mode not in _GATEWAY_MODES:
        raise ModelRegistryError("网关端点模式仅支持 base_url 或 full_endpoint")

    raw = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}
    try:
        settings = {
            "temperature": float(raw.get("temperature", 0.7)),
            "top_p": float(raw.get("top_p", 0.95)),
            "max_tokens": int(raw.get("max_tokens", 0)),
            "max_retries": int(raw.get("max_retries", 3)),
            "context_size": int(raw.get("context_size", 8191 if category == "embedding" else 128000)),
            "timeout_seconds": float(raw.get("timeout_seconds", 600)),
            "thinking_enabled": bool(raw.get("thinking_enabled", True)),
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

    result = {
        "name": name, "category": category, "provider": provider,
        "api_style": api_style, "base_url": _clean_url(payload.get("base_url")),
        "gateway_mode": gateway_mode,
        "model_low": str(payload.get("model_low") or "").strip(),
        "model_min": str(payload.get("model_min") or "").strip(),
        "model_max": str(payload.get("model_max") or "").strip(),
        "model_name": str(payload.get("model_name") or "").strip(),
        "dimensions": int(payload.get("dimensions") or 0),
        "pass_dimensions": bool(payload.get("pass_dimensions", True)),
        "enabled": bool(payload.get("enabled", False)), "settings": settings,
    }
    if category == "llm":
        if not all(result[key] for key in ("model_low", "model_min", "model_max")):
            raise ModelRegistryError("大模型配置必须填写 Low、Min、Max 三个模型名称")
        result.update(model_name="", dimensions=0, pass_dimensions=True)
    else:
        if not result["model_name"]:
            raise ModelRegistryError("嵌入模型名称不能为空")
        if not 1 <= result["dimensions"] <= 65536:
            raise ModelRegistryError("嵌入向量维度必须在 1~65536 之间")
        result.update(model_low="", model_min="", model_max="")
    return result


def _public(item: dict[str, Any]) -> dict[str, Any]:
    output = dict(item)
    output.pop("api_key_ciphertext", None)
    hint = str(output.pop("api_key_hint", "") or "")
    output["has_api_key"] = bool(hint)
    output["api_key_masked"] = f"••••••••{hint}" if hint else "未设置"
    output["enabled"] = bool(output.get("enabled"))
    output["pass_dimensions"] = bool(output.get("pass_dimensions"))
    return output


def list_model_configs(category: str | None = None) -> list[dict[str, Any]]:
    with _LOCK:
        configs = _read_unlocked()["configs"]
        selected = [item for item in configs if not category or item.get("category") == category]
        selected.sort(key=lambda item: (item.get("category", ""), not item.get("enabled"), -int(item["id"])))
        return [_public(item) for item in selected]


def get_model_config(config_id: int, *, include_secret: bool = False) -> dict[str, Any] | None:
    with _LOCK:
        item = next((x for x in _read_unlocked()["configs"] if int(x["id"]) == config_id), None)
        if item is None:
            return None
        output = dict(item)
        if include_secret:
            output["api_key"] = _decrypt(output.pop("api_key_ciphertext", ""))
            return output
        return _public(output)


def _disable_peers(configs: list[dict[str, Any]], normalized: dict[str, Any], exclude_id: int = 0) -> None:
    if not normalized["enabled"]:
        return
    for item in configs:
        if int(item["id"]) == exclude_id:
            continue
        if normalized["category"] == "embedding":
            peer = item.get("category") == "embedding"
        else:
            peer = item.get("category") == "llm" and item.get("provider") == normalized["provider"]
        if peer:
            item["enabled"] = False


def _audit(data: dict[str, Any], config_id: int, actor_id: int, action: str, detail: str) -> None:
    data["audit"].append({
        "config_id": config_id, "actor_id": actor_id, "action": action,
        "detail": detail, "created_at": datetime.now(timezone.utc).isoformat(),
    })
    data["audit"] = data["audit"][-500:]


def create_model_config(payload: dict[str, Any], actor_id: int) -> dict[str, Any]:
    normalized = _normalize(payload)
    secret = str(payload.get("api_key") or "").strip()
    with _LOCK:
        data = _read_unlocked()
        if any(item.get("name") == normalized["name"] for item in data["configs"]):
            raise ModelRegistryError("配置名称已存在")
        config_id = int(data["next_id"])
        data["next_id"] = config_id + 1
        _disable_peers(data["configs"], normalized)
        now = datetime.now(timezone.utc).isoformat()
        item = {
            "id": config_id, **normalized, "api_key_ciphertext": _encrypt(secret),
            "api_key_hint": secret[-4:] if secret else "", "created_at": now, "updated_at": now,
        }
        data["configs"].append(item)
        _audit(data, config_id, actor_id, "created", normalized["name"])
        _write_unlocked(data)
        return _public(item)


def update_model_config(config_id: int, payload: dict[str, Any], actor_id: int) -> dict[str, Any]:
    normalized = _normalize(payload)
    with _LOCK:
        data = _read_unlocked()
        item = next((x for x in data["configs"] if int(x["id"]) == config_id), None)
        if item is None:
            raise ModelRegistryError("模型 API 配置不存在")
        if any(x.get("name") == normalized["name"] and int(x["id"]) != config_id for x in data["configs"]):
            raise ModelRegistryError("配置名称已存在")
        if payload.get("clear_api_key"):
            ciphertext = hint = ""
        elif str(payload.get("api_key") or "").strip():
            secret = str(payload["api_key"]).strip()
            ciphertext, hint = _encrypt(secret), secret[-4:]
        else:
            ciphertext, hint = item.get("api_key_ciphertext", ""), item.get("api_key_hint", "")
        _disable_peers(data["configs"], normalized, config_id)
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()
        item.clear()
        item.update(
            id=config_id, **normalized, api_key_ciphertext=ciphertext, api_key_hint=hint,
            created_at=created_at, updated_at=datetime.now(timezone.utc).isoformat(),
        )
        _audit(data, config_id, actor_id, "updated", normalized["name"])
        _write_unlocked(data)
        return _public(item)


def delete_model_config(config_id: int, actor_id: int) -> None:
    with _LOCK:
        data = _read_unlocked()
        item = next((x for x in data["configs"] if int(x["id"]) == config_id), None)
        if item is None:
            raise ModelRegistryError("模型 API 配置不存在")
        data["configs"] = [x for x in data["configs"] if int(x["id"]) != config_id]
        _audit(data, config_id, actor_id, "deleted", str(item.get("name") or ""))
        _write_unlocked(data)


def active_llm_providers(*, include_secrets: bool = False) -> list[dict[str, Any]]:
    with _LOCK:
        items = [
            dict(x) for x in _read_unlocked()["configs"]
            if x.get("category") == "llm" and x.get("enabled")
        ]
        for item in items:
            if include_secrets:
                item["api_key"] = _decrypt(item.pop("api_key_ciphertext", ""))
            else:
                public = _public(item)
                item.clear(); item.update(public)
        return items


def _active_embedding() -> dict[str, Any] | None:
    with _LOCK:
        item = next((
            dict(x) for x in _read_unlocked()["configs"]
            if x.get("category") == "embedding" and x.get("enabled")
        ), None)
        if item:
            item["api_key"] = _decrypt(item.pop("api_key_ciphertext", ""))
        return item


def load_runtime_overrides() -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    custom: dict[str, dict[str, Any]] = {}
    for item in active_llm_providers(include_secrets=True):
        provider = item["provider"]
        if provider == "deepseek":
            overrides.update(
                deepseek_api_key=item["api_key"], deepseek_base_url=item["base_url"],
                deepseek_gateway_mode=item.get("gateway_mode", "base_url"),
                deepseek_model_low=item["model_low"], deepseek_model_min=item["model_min"],
                deepseek_model_max=item["model_max"], deepseek_model_settings=item["settings"],
                deepseek_responses_models=(
                    tuple(dict.fromkeys((item["model_low"], item["model_min"], item["model_max"])))
                    if item["api_style"] == "responses" else ()
                ),
            )
        elif provider == "qwen":
            overrides.update(
                qwen_api_key=item["api_key"], qwen_base_url=item["base_url"],
                qwen_model=item["model_min"], qwen_model_settings=item["settings"],
            )
        else:
            custom[provider] = {
                key: item.get(key) for key in (
                    "name", "api_style", "base_url", "api_key", "model_low",
                    "model_min", "model_max", "gateway_mode", "settings",
                )
            }
            custom[provider]["gateway_mode"] = custom[provider].get("gateway_mode") or "base_url"
    if custom:
        overrides["custom_llm_configs"] = custom
    embedding = _active_embedding()
    if embedding:
        overrides.update(
            embedding_api_key=embedding["api_key"], embedding_base_url=embedding["base_url"],
            embedding_model=embedding["model_name"], embedding_dimensions=int(embedding["dimensions"]),
            embedding_pass_dimensions=bool(embedding["pass_dimensions"]),
            embedding_model_settings=embedding["settings"],
        )
    return overrides


init_model_registry()
