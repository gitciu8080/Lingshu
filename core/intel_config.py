"""资产测绘引擎 API Key 存储（FOFA/Hunter/Shodan/ZoomEye）。

复用模型配置的 Fernet 密钥源（data/model_api.key，或
LINGSHU_MODEL_CONFIG_KEY 环境变量），密文落盘
data/intel_api_configs.json（0600，tempfile+os.replace 原子写）。

结构与模型池同语义：owner_id 为 None 的是平台池（超管配置，全员可回退），
整数是用户私有池；查询时用户池优先，缺的平台回退平台池。
明文 key 只在调用返回值中出现，绝不写日志。
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = _PROJECT_ROOT / "data" / "intel_api_configs.json"
_KEY_SOURCE = _PROJECT_ROOT / "data" / "model_api.key"

INTEL_PLATFORMS = ("fofa", "hunter", "shodan", "zoomeye")

_LOCK = threading.RLock()


def _fernet() -> Fernet | None:
    """与 model_registry 同源的 Fernet 实例（读取失败时自动生成密钥文件）。"""
    try:
        from core.model_registry import _fernet_key, ModelRegistryError

        try:
            return Fernet(_fernet_key(create=False))
        except (ModelRegistryError, OSError):
            return Fernet(_fernet_key(create=True))
    except Exception:  # noqa: BLE001 — 密钥源不可用时存储降级为禁用
        return None


def _load_raw() -> dict[str, Any]:
    try:
        if CONFIG_PATH.is_file():
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:  # noqa: BLE001 — 损坏按空处理
        pass
    return {}


def _save_raw(data: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def _bucket(data: dict[str, Any], owner_id: int | None) -> dict[str, Any]:
    key = "platform" if owner_id is None else str(owner_id)
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def set_intel_key(
    owner_id: int | None, platform: str, *, key: str, email: str = "",
) -> dict[str, Any]:
    """写入/更新一个引擎的 key（服务端加密后落盘）。返回脱敏视图。"""
    platform = str(platform or "").strip().lower()
    if platform not in INTEL_PLATFORMS:
        raise ValueError(f"不支持的平台：{platform}（可选 {', '.join(INTEL_PLATFORMS)}）")
    key = str(key or "").strip()
    if not key:
        raise ValueError("key 不能为空")
    fernet = _fernet()
    if fernet is None:
        raise RuntimeError("Fernet 密钥源不可用（data/model_api.key 缺失且未配置环境变量）")
    with _LOCK:
        data = _load_raw()
        bucket = _bucket(data, owner_id)
        entry = bucket.get(platform) if isinstance(bucket.get(platform), dict) else {}
        entry.update({
            "email": str(email or "").strip(),
            "key_cipher": fernet.encrypt(key.encode("utf-8")).decode("utf-8"),
            "hint": ("…" + key[-4:]) if len(key) > 4 else "…",
        })
        bucket[platform] = entry
        data["platform" if owner_id is None else str(owner_id)] = bucket
        _save_raw(data)
    return intel_keys_brief(owner_id)


def delete_intel_key(owner_id: int | None, platform: str) -> dict[str, Any]:
    platform = str(platform or "").strip().lower()
    with _LOCK:
        data = _load_raw()
        bucket = _bucket(data, owner_id)
        if platform in bucket:
            bucket.pop(platform, None)
            data["platform" if owner_id is None else str(owner_id)] = bucket
            _save_raw(data)
    return intel_keys_brief(owner_id)


def _resolve_entry(
    data: dict[str, Any], owner_id: int | None, platform: str,
) -> tuple[dict[str, Any] | None, int | None]:
    """用户池优先，平台池回退。返回 (entry, 实际来源 owner_id)。"""
    for owner in (owner_id, None):
        if owner is None and owner_id is not None and owner == owner_id:
            continue  # 用户池查过才轮到平台池
        bucket = _bucket(data, owner)
        entry = bucket.get(platform)
        if isinstance(entry, dict) and entry.get("key_cipher"):
            return entry, owner
    return None, None


def get_intel_keys(owner_id: int | None, platform: str) -> dict[str, Any]:
    """返回某引擎的明文凭据（仅内存使用：HTTP 调用头），无配置返回空。"""
    platform = str(platform or "").strip().lower()
    with _LOCK:
        data = _load_raw()
    entry, source = _resolve_entry(data, owner_id, platform)
    if entry is None:
        return {}
    fernet = _fernet()
    if fernet is None:
        return {}
    try:
        key = fernet.decrypt(str(entry["key_cipher"]).encode("utf-8")).decode("utf-8")
    except (InvalidToken, KeyError):
        return {}
    return {
        "key": key, "email": str(entry.get("email") or ""),
        "source_owner": source,
    }


def intel_keys_brief(owner_id: int | None) -> dict[str, Any]:
    """给前端的脱敏视图：每个平台是否已配置 + hint，绝不回明文。"""
    with _LOCK:
        data = _load_raw()
    result: dict[str, Any] = {"platforms": {}}
    for platform in INTEL_PLATFORMS:
        entry, source = _resolve_entry(data, owner_id, platform)
        result["platforms"][platform] = {
            "configured": entry is not None,
            "email": (entry or {}).get("email") or "",
            "hint": (entry or {}).get("hint") or "",
            "source": ("mine" if source == owner_id and owner_id is not None
                       else "platform") if entry else "",
        }
    return result
