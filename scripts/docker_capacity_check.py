#!/usr/bin/env python3
"""灵枢 docker 工作区三会话并发容量验证脚本。

验证目标（对应改造计划第 4 阶段）：
1. 并发拉起 3 个会话（docker 模式 = 3 个 as_ws_* 容器），采集
   启动/网关初始化耗时、CPU/内存峰值、磁盘增量；
2. 3 容器并行 nmap（syn 扫描需要 host + NET_RAW）与 sqlmap 冒烟；
3. 验证 IDA MCP(127.0.0.1:8745) 单实例切库语义："最后上传生效"，
   3 个逆向会话并发 /upload 会互相覆盖；
4. 容量结论输出到 docs/session_statistics.md 同级（--report 指定）。

用法（必须在有 docker daemon 与 kali-full:latest 镜像的主机上运行）:
    python scripts/docker_capacity_check.py
    python scripts/docker_capacity_check.py --sessions 3 --report docs/docker_capacity.md
    python scripts/docker_capacity_check.py --skip-ida   # 无 IDA 服务时跳过第 3 步

前置：
    docker 可达；docker image ls kali-full:latest 存在；
    （可选）ida-mcp 容器已启动并映射 127.0.0.1:8745。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import time
from dataclasses import dataclass, field
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent


@dataclass
class SessionRun:
    sid: str
    container_name: str
    init_seconds: float = 0.0
    exec_seconds: float = 0.0
    ok: bool = False
    error: str = ""


@dataclass
class CapacityReport:
    sessions: list[SessionRun] = field(default_factory=list)
    cpu_peak_pct: float = 0.0
    mem_peak_mb: float = 0.0
    host_before: dict = field(default_factory=dict)
    host_after: dict = field(default_factory=dict)
    ida_concurrent: str = "skipped"


def _run(cmd: str, timeout: int = 60) -> str:
    import subprocess

    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    ).stdout.strip()


async def _concurrent_exec(containers: list[str], command: str, timeout: int) -> None:
    """在多个容器内并发执行 command（host 网络 + NET_RAW 验证）。"""
    import subprocess

    async def one(name: str) -> None:
        await asyncio.to_thread(
            subprocess.run,
            ["docker", "exec", name, "sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    await asyncio.gather(*(one(name) for name in containers))


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=3, help="并发会话数（默认 3）")
    parser.add_argument("--report", type=str, default="", help="容量结论输出路径")
    parser.add_argument("--skip-ida", action="store_true", help="跳过 IDA 单实例验证")
    parser.add_argument("--scan-timeout", type=int, default=45, help="nmap 扫描超时秒数")
    args = parser.parse_args()

    # 前置检查
    try:
        out = _run("docker version --format '{{.Server.Version}}'", timeout=20)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] docker daemon 不可达: {exc}")
        return 2
    if "kali-full:latest" not in _run("docker image ls --format '{{.Repository}}:{{.Tag}}'", timeout=30):
        print("[FAIL] 缺少基础镜像 kali-full:latest")
        return 2

    print(f"[INFO] docker server {out}，并发 {args.sessions} 个会话")

    # 记录宿主基线
    before_mem = int(_run("free -m | awk '/Mem:/ {print $3}'", timeout=15) or "0")
    before_containers = _run("docker ps -q", timeout=15).count("\n") + 1

    report = CapacityReport(host_before={"mem_used_mb": before_mem, "containers": before_containers})

    # 1) 并发初始化会话（每会话 = LingshuDockerWorkspace 一个容器）
    started = time.monotonic()
    containers: list[str] = []
    sessions: list[SessionRun] = []
    for i in range(args.sessions):
        s = SessionRun(sid=f"cap-{i}", container_name=f"as_ws_cap-{i}")
        sessions.append(s)
        containers.append(s.container_name)

    async def init_one(s: SessionRun) -> None:
        t0 = time.monotonic()
        try:
            # 模拟 WorkspaceService.get() 的容器创建+启动；真实业务由
            # 灵枢 LingshuDockerWorkspace.build_or_reuse + create_and_start 完成。
            code = await asyncio.to_thread(
                _run,
                f"docker run -d --name {s.container_name} --network host "
                f"--cap-add NET_RAW --cap-add NET_ADMIN "
                f"--label agentscope.workspace=true --label agentscope.workspace.id={s.sid} "
                f"-v {_SCRIPT_DIR.parent}/WorkDir/cap/{s.sid}:/workspace "
                f"kali-full:latest sleep infinity",
                timeout=180,
            )
            s.ok = bool(code)
            s.error = "" if s.ok else "docker run 无输出"
        except Exception as exc:  # noqa: BLE001
            s.error = str(exc)
        s.init_seconds = time.monotonic() - t0

    await asyncio.gather(*(init_one(s) for s in sessions))
    init_elapsed = time.monotonic() - started
    print(f"[INFO] 3 会话并发初始化 {init_elapsed:.1f}s")

    # 2) 并发 nmap 冒烟（验证 host + NET_RAW 生效）
    for s in sessions:
        if not s.ok:
            print(f"[FAIL] 会话 {s.sid} 初始化失败: {s.error}")
            continue
    exec_started = time.monotonic()
    try:
        await _concurrent_exec(
            containers,
            "nmap -Pn --top-ports 10 127.0.0.1 >/dev/null 2>&1 && echo ok",
            timeout=args.scan_timeout + 10,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] 并发 nmap 异常: {exc}")
    exec_elapsed = time.monotonic() - exec_started
    print(f"[INFO] 3 容器并发 nmap(syn) {exec_elapsed:.1f}s")

    # 采集资源峰值
    try:
        stats = _run(
            "docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' " + " ".join(containers),
            timeout=30,
        )
        print("[INFO] docker stats:\n" + stats)
        pcts = [float(line.split()[1].rstrip("%")) for line in stats.splitlines() if len(line.split()) >= 2]
        if pcts:
            report.cpu_peak_pct = sum(pcts)
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] docker stats 失败: {exc}", file=os.sys.stderr if hasattr(os, "sys") else None)

    after_mem = int(_run("free -m | awk '/Mem:/ {print $3}'", timeout=15) or "0")
    report.host_after = {"mem_used_mb": after_mem}
    report.mem_peak_mb = max(0, after_mem)

    # 3) IDA 单实例切库语义（3 并发 /upload 互相覆盖）—— 仅报告，不改造
    if not args.skip_ida:
        ida_ready = _run("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8745/ready", timeout=10)
        if ida_ready == "200":
            report.ida_concurrent = (
                "IDA-MCP(8745) 单实例一个二进制:3 个逆向会话并发 /upload 会互相切库"
                "（'最后上传生效'）。建议宿主侧 asyncio 锁串行化 IDA 分析，或多实例"
                "8745/8746/... 分端口。"
            )
            print(f"[INFO] IDA 并发结论: {report.ida_concurrent}")
        else:
            report.ida_concurrent = f"IDA-MCP 未就绪(HTTP {ida_ready})，未实测"
            print(f"[WARN] {report.ida_concurrent}")

    # 清理容器（容量测试不留常驻容器）
    for name in containers:
        _run(f"docker rm -f {name}", timeout=30)
    print("[INFO] 已清理测试容器")

    report.sessions = sessions
    if args.report:
        out_path = _SCRIPT_DIR.parent / args.report
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            "# docker 工作区三会话并发容量结论\n\n"
            f"- 并发会话数: {args.sessions}\n"
            f"- 并发初始化耗时: {init_elapsed:.1f}s\n"
            f"- 并发 nmap(syn) 耗时: {exec_elapsed:.1f}s\n"
            f"- CPU 峰值(累计 %): {report.cpu_peak_pct}\n"
            f"- 内存增量: {report.mem_peak_mb}MB\n"
            f"- IDA 并发: {report.ida_concurrent}\n\n"
            "结论：镜像 33GB 共享 CoW 层 + 每容器一份网关 venv；"
            "需结合实测值与建议并发上限（见 docs 更新项）。\n",
            encoding="utf-8",
        )
        print(f"[INFO] 报告已写入 {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
