"""动态授权范围注册表。

任务启动时从 TargetSpec 初始化（含 DNS 解析结果），
之后仅允许经 ScopeAuditor 审核通过的内网 IP / 网段扩容。
每次变更自动持久化到 MissionState.authorized_scope 并推送 SSE 事件。
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any

# 始终放行的本机地址
_ALWAYS_ALLOWED = frozenset({"127.0.0.1", "::1", "0.0.0.0"})


class ScopeRegistry:
    """授权范围注册表 — scoped_shell 的语义级 IP 判定后端。"""

    def __init__(self) -> None:
        self._ips: set[str] = set(_ALWAYS_ALLOWED)
        self._networks: set[ipaddress.IPv4Network] = set()
        self._hostnames: set[str] = set()
        # 扩容记录: [{ip, evidence, approved_by, timestamp}]
        self.expansions: list[dict[str, str]] = []

    # ── 初始化 ──────────────────────────────────────────

    def add_base_target(self, host: str) -> None:
        """注册初始授权目标（IP 或主机名）。"""
        try:
            ip = str(ipaddress.ip_address(host))
            self._ips.add(ip)
            return
        except ValueError:
            pass
        # 主机名：注册 hostname，并尝试 DNS 解析把结果 IP 也纳入
        self._hostnames.add(host)
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                if family == socket.AF_INET:
                    self._ips.add(sockaddr[0])
        except socket.gaierror:
            pass  # 解析失败仅保留 hostname 匹配

    def restore(self, persisted: dict[str, Any]) -> None:
        """从持久化的 authorized_scope 恢复（崩溃恢复用）。"""
        for ip in persisted.get("ips", []):
            self._ips.add(ip)
        for cidr in persisted.get("networks", []):
            try:
                self._networks.add(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        for hn in persisted.get("hostnames", []):
            self._hostnames.add(hn)
        self.expansions = list(persisted.get("expansions", []))

    # ── 查询 ──────────────────────────────────────────

    def is_ip_allowed(self, ip_str: str) -> bool:
        """语义级判定：IP 在白名单或任一授权网段内即放行。"""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        normalized = str(addr)
        if normalized in self._ips:
            return True
        if isinstance(addr, ipaddress.IPv4Address):
            return any(addr in net for net in self._networks)
        return False

    def is_hostname_allowed(self, hostname: str) -> bool:
        return hostname in self._hostnames

    def is_target_allowed(self, target: str) -> bool:
        """判定目标字符串（IP/域名，可带端口/协议前缀）是否已进入授权范围。

        统一入口：自动剥离 ``scheme://``、路径与端口后取主机部分，
        依次做 IP 白名单与主机名匹配。供惰性范围审批与 dispatch_attack
        的 scope 检查共用，避免各调用点重复实现剥离逻辑。
        """
        host = str(target or "").strip()
        if not host:
            return False
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0].strip()
        if not host:
            return False
        return self.is_ip_allowed(host) or self.is_hostname_allowed(host)

    def is_any_target_in_command(self, command: str) -> bool:
        """检查命令中是否包含了任一已授权的 IP、网段内 IP 或主机名。"""
        import re
        _IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
        for hn in self._hostnames:
            if hn in command:
                return True
        for ip in self._ips:
            if ip in command:
                return True
        for candidate in _IP_RE.findall(command):
            if self.is_ip_allowed(candidate):
                return True
        return False

    def snapshot(self) -> dict[str, Any]:
        """当前授权范围快照（用于持久化 / SSE 推送）。"""
        return {
            "ips": sorted(self._ips - set(_ALWAYS_ALLOWED)),
            "networks": sorted(str(n) for n in self._networks),
            "hostnames": sorted(self._hostnames),
            "expansions": self.expansions,
        }

    # ── 扩容（仅由 Orchestrator 经审核后调用）──────────────

    def add_ip(self, ip_str: str, evidence: str, approved_by: str = "ScopeAuditor") -> str:
        """将单个 IP 加入授权范围。"""
        addr = ipaddress.ip_address(ip_str)  # 格式校验
        normalized = str(addr)
        if normalized in _ALWAYS_ALLOWED:
            return f"[已存在] {normalized} 为本机地址，无需授权"
        if self.is_ip_allowed(normalized):
            return f"[已存在] {normalized} 已在授权范围内"
        self._ips.add(normalized)
        self.expansions.append({
            "ip": normalized,
            "evidence": evidence[:500],
            "approved_by": approved_by,
        })
        return f"[批准] {normalized} 已加入授权范围"

    def add_network(self, cidr: str, evidence: str, approved_by: str = "ScopeAuditor") -> str:
        """将网段加入授权范围（如 10.42.0.0/16）。"""
        net = ipaddress.ip_network(cidr, strict=False)
        if net in self._networks:
            return f"[已存在] {net} 已在授权范围内"
        self._networks.add(net)
        self.expansions.append({
            "network": str(net),
            "evidence": evidence[:500],
            "approved_by": approved_by,
        })
        return f"[批准] {net} 已加入授权范围"
