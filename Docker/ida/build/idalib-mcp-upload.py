#!/usr/bin/env python3
"""
idalib-mcp-upload.py
====================
基于 mrexodia/ida-pro-mcp v1.4.0 的 idalib_server.py (MIT License) 的升级分叉。

在原 MCP SSE 服务 (/sse) 之上, 于同一端口增加 HTTP 管理 API:

    POST /upload   上传二进制 (multipart 字段 file, 或裸 body + ?filename=/X-Filename)
                   -> 自动关闭旧库, 打开新库, 自动分析, 阻塞直到完成, 返回 JSON (ready)
    GET  /status   当前状态: idle | loading | ready | error, 含文件哈希/函数数/分析耗时
    GET  /ready    就绪返回 200, 否则 503 (供 Agent 轮询/健康检查)
    POST /close    关闭当前数据库, 回到 idle
    GET  /         服务信息与端点说明

Agent 工作流:
    POST /upload  ->  200 {"ok": true, "status": "ready", ...}  ->  再连接 /sse 调用 MCP 工具

用法 (与原镜像一致, 二进制路径改为可选):
    python3 idalib-mcp-upload.py [--host H] [--port P] [--unsafe] [--verbose] [input_path]
    不带 input_path 时以 idle 状态启动, 等待 /upload。

环境变量:
    IDA_MCP_UPLOAD_DIR      上传文件落盘目录 (默认 /analysis/uploads)
    IDA_MCP_MAX_UPLOAD_MB   上传大小上限 MB   (默认 512)
"""

import argparse
import hashlib
import importlib
import inspect
import logging
import os
import re
import threading
import time
import zlib
from pathlib import Path

import anyio
from mcp.server.fastmcp import FastMCP
import typing_inspection.introspection as intro

# idapro must go first to initialize idalib (必须在主线程 import, 见文件头说明)
import idapro

import ida_auto
import ida_hexrays
import ida_nalt
import idautils

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
import uvicorn

logger = logging.getLogger(__name__)

SERVER_NAME = "github.com/mrexodia/ida-pro-mcp#idalib+upload"
SERVER_VERSION = "1.4.0+upload.1"

UPLOAD_DIR = Path(os.environ.get("IDA_MCP_UPLOAD_DIR", "/analysis/uploads"))
MAX_UPLOAD_MB = int(os.environ.get("IDA_MCP_MAX_UPLOAD_MB", "512"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
# IDA 数据库伴随文件后缀 (idalib 经典布局 + 新布局)
IDB_SUFFIXES = {".i64", ".id0", ".id1", ".id2", ".id3", ".id4", ".nam", ".til", ".idw", ".idp"}

mcp = FastMCP(SERVER_NAME)

# ---------------------------------------------------------------------------
# 状态机
# ---------------------------------------------------------------------------

STATE = {
    "status": "starting",   # starting | idle | loading | ready | error
    "binary": None,         # 当前/目标二进制路径 (容器内)
    "module": None,         # IDA 模块名
    "base": None,           # 镜像基址 hex
    "size": None,
    "md5": None,
    "sha256": None,
    "crc32": None,
    "functions": None,      # 已识别函数数
    "analysis_ms": None,    # 本次打开+自动分析+hexrays 初始化耗时
    "loaded_at": None,      # epoch
    "error": None,
    "uploads": 0,
}
STATE_LOCK = threading.Lock()
SWITCH_LOCK = threading.Lock()  # 串行化上传(写文件+切换), 防止并发切换

# ---------------------------------------------------------------------------
# 线程模型 (重要, 经实测验证)
# ---------------------------------------------------------------------------
# libida 是单线程库, 两条规则:
#   1) idapro.open_database/close_database (ctypes) 必须在初始化库的线程
#      (Python 主线程) 调用, 否则挂起 (loader 报 thread-unsafe)。
#   2) MCP 工具内部的 idaapi.execute_sync 会挂起调用者 (工作线程) 并排队,
#      由主线程在事件循环中唤醒执行 —— 实测要求主线程正在运行 uvicorn 的
#      asyncio 事件循环 (queue.get() 或空 asyncio 循环都不行)。
# 结论: uvicorn 必须在主线程运行 (与原镜像一致);
#       /upload、/close 的处理协程就在主线程事件循环上, 直接内联执行阻塞的
#       IDA 库调用即可。切换期间事件循环冻结 (SSE 无心跳), 但此时 Agent 只等待
#       upload 响应, 不需要 MCP, 可接受。


def set_state(**kv):
    with STATE_LOCK:
        STATE.update(kv)


def snapshot() -> dict:
    with STATE_LOCK:
        return dict(STATE)


def file_hashes(path: Path) -> dict:
    h_md5, h_sha = hashlib.md5(), hashlib.sha256()
    crc, size = 0, 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h_md5.update(chunk)
            h_sha.update(chunk)
            crc = zlib.crc32(chunk, crc)
            size += len(chunk)
    return {
        "size": size,
        "md5": h_md5.hexdigest(),
        "sha256": h_sha.hexdigest(),
        "crc32": "0x%08x" % (crc & 0xFFFFFFFF),
    }


# ---------------------------------------------------------------------------
# 数据库切换
# ---------------------------------------------------------------------------

def _clear_idb_companions(path: Path) -> None:
    """删除该二进制的 IDA 数据库伴随文件 (保留 .sha256 侧车)。"""
    for sib in path.parent.glob(path.name + ".*"):
        if sib.suffix in IDB_SUFFIXES:
            try:
                sib.unlink()
                logger.info("removed stale idb: %s", sib.name)
            except OSError:
                pass


def _do_switch(path: Path) -> dict:
    """关闭当前库(若有)并打开新库, 阻塞直到自动分析完成。

    必须在 Python 主线程 (IDA 库初始化线程) 执行:
    启动时直接调用; 运行期由 /upload 处理协程内联调用 (协程跑在主线程事件循环上)。
    调用期间事件循环冻结。
    """
    t0 = time.time()
    try:
        idapro.close_database(save=True)
    except Exception as e:
        logger.warning("close_database: %s", e)

    rc = idapro.open_database(str(path), run_auto_analysis=True)
    if rc != 0:
        # 自愈: 可能残留损坏的旧库 (如上次异常退出), 清掉重试一次
        desc = getattr(idapro, "error_description", None) or ""
        logger.warning("open_database rc=%s %s; clearing stale IDB and retrying", rc, desc)
        _clear_idb_companions(path)
        rc = idapro.open_database(str(path), run_auto_analysis=True)
        if rc != 0:
            desc = getattr(idapro, "error_description", None) or ""
            raise RuntimeError(f"open_database failed rc={rc} {desc}".strip())

    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    meta = {"analysis_ms": int((time.time() - t0) * 1000)}
    try:
        meta["module"] = ida_nalt.get_root_filename() or path.name
    except Exception as e:
        logger.warning("collect metadata module: %s", e)
        meta["module"] = path.name
    try:
        meta["base"] = hex(ida_nalt.get_imagebase())
    except Exception as e:
        logger.warning("collect metadata base: %s", e)
        meta["base"] = None
    try:
        meta["functions"] = len(list(idautils.Functions()))
    except Exception as e:
        logger.warning("collect metadata functions: %s", e)
        meta["functions"] = None
    logger.info("database ready: %s (%d ms, %s functions)",
                path, meta["analysis_ms"], meta.get("functions"))
    return meta


def switch_to(path: Path) -> dict:
    """切换数据库。只能在主线程 (事件循环协程内联) 调用, 阻塞直到分析完成。"""
    with SWITCH_LOCK:
        return _do_switch(path)


def safe_name(name: str) -> str:
    name = Path(name).name  # 去掉任何目录成分
    name = re.sub(r"[^\w.\-]", "_", name)
    name = name.lstrip(".") or "upload"
    if len(name) > 200:
        stem, dot, ext = name.rpartition(".")
        if dot and 0 < len(ext) <= 8:
            name = stem[: 200 - len(ext) - 1] + "." + ext
        else:
            name = name[:200]
    return name


def _write_upload(dest: Path, data: bytes, cur_sha256: str, force_fresh: bool = False) -> None:
    """落盘上传文件; 内容变化(或 force_fresh)时清理旧 IDB 保证全新分析 (同内容则复用旧库, 秒级)。"""
    dest.write_bytes(data)
    sidecar = dest.parent / (dest.name + ".sha256")
    prev = sidecar.read_text().strip() if sidecar.exists() else None
    if force_fresh or prev != cur_sha256:
        _clear_idb_companions(dest)
    sidecar.write_text(cur_sha256 + "\n")


# ---------------------------------------------------------------------------
# HTTP 管理 API
# ---------------------------------------------------------------------------

async def info(request: Request):
    return JSONResponse({
        "name": "ida-pro-mcp (idalib) + upload API",
        "version": SERVER_VERSION,
        "upstream": "mrexodia/ida-pro-mcp v1.4.0",
        "mcp_sse": "/sse",
        "endpoints": {
            "POST /upload": "multipart 字段 file 或裸 body (?filename= 或 X-Filename 指定文件名); 阻塞至分析完成; ?fresh=1 强制重新分析(不复用旧 IDB)",
            "GET /status": "当前状态与元数据",
            "GET /ready": "ready 返回 200, 否则 503",
            "POST /close": "关闭当前数据库",
        },
        "upload_dir": str(UPLOAD_DIR),
        "max_upload_mb": MAX_UPLOAD_MB,
        "state": snapshot(),
    })


async def status(request: Request):
    return JSONResponse(snapshot())


async def ready(request: Request):
    s = snapshot()
    if s["status"] == "ready":
        return JSONResponse({"ok": True, **s})
    return JSONResponse({"ok": False, **s}, status_code=503)


async def upload(request: Request):
    ct = (request.headers.get("content-type") or "").lower()
    try:
        if "multipart/form-data" in ct:
            form = await request.form()
            item = None
            for v in form.values():
                if getattr(v, "filename", None):
                    item = v
                    break
            if item is None:
                return JSONResponse({"ok": False, "error": "no file field (use 'file')"}, status_code=400)
            data = await item.read()
            name = item.filename
            # 允许 ?filename= 或 X-Filename 覆盖保存名
            name = (request.query_params.get("filename")
                    or request.headers.get("x-filename")
                    or name)
        else:
            data = await request.body()
            if not data:
                return JSONResponse({"ok": False, "error": "empty body"}, status_code=400)
            name = (request.query_params.get("filename")
                    or request.headers.get("x-filename")
                    or f"upload_{int(time.time())}.bin")
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"parse request failed: {e}"}, status_code=400)

    if len(data) > MAX_UPLOAD_BYTES:
        return JSONResponse(
            {"ok": False, "error": f"file too large (max {MAX_UPLOAD_MB} MB)"}, status_code=413)

    dest = UPLOAD_DIR / safe_name(name)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    cur_sha256 = hashlib.sha256(data).hexdigest()
    # ?fresh=1 强制全量重新分析 (跳过 IDB 复用; 用于怀疑旧库损坏/分析不完整时)
    force_fresh = request.query_params.get("fresh", "").lower() in ("1", "true", "yes")

    set_state(status="loading", binary=str(dest), error=None)
    logger.info("upload: %s (%d bytes)%s -> analyzing...", dest, len(data),
                " [fresh]" if force_fresh else "")
    try:
        await anyio.to_thread.run_sync(_write_upload, dest, data, cur_sha256, force_fresh)
        # 内联执行 (主线程): 期间事件循环冻结, 直到分析完成 (可接受, 见文件头说明)
        meta = switch_to(dest)
        hashes = file_hashes(dest)
        set_state(status="ready", error=None, loaded_at=time.time(), **hashes, **meta)
        with STATE_LOCK:
            STATE["uploads"] += 1
        # 响应报告【本次请求】加载的结果 (并发上传时 live state 可能已被后续请求覆盖)
        resp = {
            "ok": True,
            "next": "connect MCP at /sse and call tools",
            "binary": str(dest),
            "module": meta.get("module"),
            "base": meta.get("base"),
            "functions": meta.get("functions"),
            "analysis_ms": meta.get("analysis_ms"),
            "size": hashes["size"],
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
            "crc32": hashes["crc32"],
            "server_status": snapshot()["status"],
        }
        return JSONResponse(resp)
    except Exception as e:  # noqa: BLE001
        logger.exception("upload/switch failed")
        set_state(status="error", error=str(e))
        return JSONResponse({"ok": False, "error": str(e), **snapshot()}, status_code=500)


async def close(request: Request):
    try:
        with SWITCH_LOCK:
            idapro.close_database(save=True)  # 内联执行 (主线程)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(e), **snapshot()}, status_code=500)
    set_state(status="idle", binary=None, module=None, base=None, size=None,
              md5=None, sha256=None, crc32=None, functions=None,
              analysis_ms=None, loaded_at=None, error=None)
    return JSONResponse(snapshot())


# ---------------------------------------------------------------------------
# MCP 工具注册 (与原版 idalib_server.py 相同)
# ---------------------------------------------------------------------------

def fixup_tool_argument_descriptions(mcp: FastMCP):
    # In our tool definitions within `mcp-plugin.py`, we use `typing.Annotated` on function
    # parameters to attach documentation. FastMCP doesn't handle these comments specially,
    # so we splice them into the tool metadata ourselves here.
    # (NOTE: https://github.com/modelcontextprotocol/python-sdk/issues/466)
    for tool in mcp._tool_manager.list_tools():
        sig = inspect.signature(tool.fn)
        for name, parameter in sig.parameters.items():
            if not parameter.annotation:
                continue
            annotation = intro.inspect_annotation(
                parameter.annotation,
                annotation_source=intro.AnnotationSource.ANY,
            )
            if annotation.type is not str:
                continue
            if len(annotation.metadata) != 1:
                continue
            description = annotation.metadata[0]
            if not isinstance(description, str):
                continue
            logger.debug("adding parameter documentation %s(%s='%s')", tool.name, name, description)
            tool.parameters["properties"][name]["description"] = description


def build_app():
    mcp_app = mcp.sse_app()
    return Starlette(routes=[
        Route("/", info, methods=["GET"]),
        Route("/status", status, methods=["GET"]),
        Route("/ready", ready, methods=["GET"]),
        Route("/upload", upload, methods=["POST"]),
        Route("/close", close, methods=["POST"]),
        Mount("/", app=mcp_app),  # /sse, /messages/...
    ])


def main():
    parser = argparse.ArgumentParser(
        description="MCP server for IDA Pro via idalib, with HTTP upload API")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8745, help="Port to listen on (default: 8745)")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("input_path", type=Path, nargs="?", default=None,
                        help="Optional binary to analyze at startup; omit to wait for POST /upload")
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    mcp.settings.log_level = logging.getLevelName(log_level)
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    logging.basicConfig(level=log_level)
    # reset logging levels that might be initialized in idapythonrc.py
    logging.getLogger().setLevel(log_level)

    if args.input_path is not None and not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    if args.input_path is not None:
        # 启动即分析 (与原镜像行为一致; 在主线程完成首次 open)
        logger.info("opening database: %s", args.input_path)
        set_state(status="loading", binary=str(args.input_path))
        try:
            meta = _do_switch(args.input_path)
            set_state(status="ready", loaded_at=time.time(), **file_hashes(args.input_path), **meta)
        except Exception:
            set_state(status="error", error="startup open failed, see logs")
            raise
    else:
        set_state(status="idle")
        logger.info("no input file given; idle, waiting for POST /upload")

    plugin = importlib.import_module("ida_pro_mcp.mcp-plugin")
    logger.debug("adding tools...")
    for name, callable in plugin.rpc_registry.methods.items():
        if args.unsafe or name not in plugin.rpc_registry.unsafe:
            logger.debug("adding tool: %s: %s", name, callable)
            mcp.add_tool(callable, name)

    fixup_tool_argument_descriptions(mcp)

    app = build_app()
    logger.info("MCP SSE:      http://%s:%d/sse", args.host, args.port)
    logger.info("Upload API:   http://%s:%d/upload", args.host, args.port)
    logger.info("Status API:   http://%s:%d/status", args.host, args.port)

    # uvicorn 必须在主线程运行 (实测: execute_sync 的唤醒机制依赖主线程事件循环)
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
