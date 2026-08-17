#!/usr/bin/env python3
"""灵枢知识库调用器（CLI）。

直接复用 ``Tools/KnowledgeBase.RAGService``（与主系统同一套实现）：
- ``build``   : 向量化知识库，从 ``.RAG`` 语料增量建立/更新向量索引（写入派生索引目录）
- ``search``  : 命中测试，对知识库做相似度检索
- ``status``  : 查看知识库可用状态 / 生效模型 / 维度 / 文档数

用法（必须在 conda agentscope 环境运行）::

    conda activate agentscope
    python knowledge_cli.py status
    python knowledge_cli.py build [--force] [--state-dir PATH]
    python knowledge_cli.py search "查询词" [--top-k N] [--full]

配置优先级与主系统一致：前端注册表（Superadmin）embedding 配置 > .env 的
LINGSHU_EMBEDDING_*。派生索引默认与主系统共享 ``.TaskMemory/rag``；当
api 服务正在运行时 Milvus Lite 单进程文件锁被占用，请用 ``--state-dir``
指定独立目录离线自测，不影响线上服务。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
# Tools 是命名空间包（无 __init__.py），其内部 `from config import ...` 需要项目根在 sys.path。
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "Tools"))


def _ensure_agentscope() -> None:
    try:
        import agentscope  # noqa: F401
    except ImportError:
        sys.exit(
            "错误：未找到 agentscope。请使用 conda 的 agentscope 环境运行：\n"
            "  conda activate agentscope\n"
            "  python knowledge_cli.py <命令>\n"
            "或直接使用该环境的解释器：\n"
            "  /home/kali/miniconda3/envs/agentscope/bin/python knowledge_cli.py <命令>",
        )


def _env_embedding_model() -> str:
    """读取 .env 中的 LINGSHU_EMBEDDING_MODEL，用于标注配置来源。"""
    try:
        for line in (PROJECT_ROOT / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("LINGSHU_EMBEDDING_MODEL="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def _milvus_locked(state_dir: Path) -> bool:
    """探测 Milvus Lite 数据库是否被其它进程占用（flock 非阻塞尝试）。"""
    import fcntl

    lock_file = state_dir / "knowledge.db" / "LOCK"
    if not lock_file.is_file():
        return False
    try:
        fd = os.open(lock_file, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False  # 能取得锁：没有其他进程占用
        except BlockingIOError:
            return True
        finally:
            os.close(fd)
    except OSError:
        return False


def _locked_hint(service) -> None:
    if _milvus_locked(service.state_dir):
        print(
            "\n提示：该派生索引目录正被运行中的服务（api.py）占用（Milvus Lite 单进程锁）。\n"
            "如需离线自测，请加 --state-dir 指定独立目录，例如：\n"
            "  python knowledge_cli.py build --state-dir .TaskMemory/rag_offline\n"
            "  python knowledge_cli.py search \"关键词\" --state-dir .TaskMemory/rag_offline",
            file=sys.stderr,
        )


def _make_progress():
    """构造 sync/start 进度回调：每 10 个文件或收尾时打印一行（含速度与 ETA）。"""
    started_at = time.monotonic()

    def callback(done: int, total_files: int, rel: str, stats: dict) -> None:
        if done % 10 != 0 and done != total_files:
            return
        elapsed = time.monotonic() - started_at
        speed = done / elapsed if elapsed > 0 else 0.0
        eta = (total_files - done) / speed if speed > 0 else 0.0
        line = (
            f"[{done}/{total_files}] 新增{stats['added']} 更新{stats['updated']} "
            f"删除{stats['removed']} | {speed:.1f} 文件/秒 | 剩余约 {eta / 60:.1f} 分钟"
        )
        if done == total_files:
            print(f"  ✓ 全部处理完成: {line}", flush=True)
        else:
            print(f"  {line} | 当前: {rel}", flush=True)

    return callback


def _print_status(service) -> None:
    status = service.status()
    print("=" * 64)
    print("灵枢知识库状态")
    print("=" * 64)
    if status["available"]:
        print("  可用性      : ✅ 可用")
    else:
        print("  可用性      : ❌ 不可用")
        if status["error"]:
            print(f"  错误原因    : {status['error']}")
    print(f"  Embedding 模型: {status['embedding_model']}")
    print(f"  配置维度    : {status['configured_dimensions']}")
    print(f"  实际维度    : {status['effective_dimensions']}")
    print(f"  Collection  : {status['collection_dimensions']}")
    env_model = _env_embedding_model()
    if env_model and env_model != status["embedding_model"]:
        print(f"  配置来源    : Web 注册表（Superadmin）优先，覆盖 .env 的 {env_model!r}")
    else:
        print(f"  配置来源    : 环境变量 .env（LINGSHU_EMBEDDING_MODEL）")
    print(f"  已入库文档  : {status['documents']} 篇")
    corpus = len(list(service.source_dir.rglob("*.md"))) if service.source_dir.is_dir() else 0
    print(f"  语料源文件  : {corpus} 篇（.RAG/*.md）")
    last = status["last_sync"] or {}
    if last:
        print(
            f"  最近同步    : 新增{last.get('added', 0)} 更新{last.get('updated', 0)} "
            f"删除{last.get('removed', 0)} 维度={last.get('dimensions')}",
        )
    if status.get("dimension_migration"):
        migration = status["dimension_migration"]
        print(
            f"  维度迁移    : {migration.get('from')} → {migration.get('to')} "
            f"（collection 已重建，源文档 {migration.get('source_documents')} 篇）",
        )
    print("=" * 64)


def _print_search(query: str, results: list[dict], full: bool) -> None:
    if not results:
        print("未命中任何结果。")
        return
    for index, hit in enumerate(results, start=1):
        snippet = hit["snippet"]
        if not full and len(snippet) > 200:
            snippet = snippet[:200] + " ……"
        print(f"── 命中 {index} ──────────────────────────────")
        print(f"  相似度 : {hit['score']:.4f}")
        print(f"  来源   : {hit['source']}")
        print(f"  片段   : {snippet.strip()}")
    print("────────────────────────────────────────────")


async def _cmd_status(args) -> int:
    from Tools.KnowledgeBase import RAGService

    service = RAGService(PROJECT_ROOT, state_dir=args.state_dir)
    try:
        if args.json:
            print(json.dumps(service.status(), ensure_ascii=False, indent=2))
        else:
            _print_status(service)
        if not service.available and service.error:
            return 1
        return 0
    finally:
        await service.close()


async def _cmd_build(args) -> int:
    from Tools.KnowledgeBase import RAGService

    service = RAGService(PROJECT_ROOT, state_dir=args.state_dir)
    try:
        if args.force:
            print("强制全量重建：删除现有向量库与清单后重新索引……")
            await service.close()
            for target in (service.state_dir / "knowledge.db", service.manifest_path):
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                elif target.is_file():
                    target.unlink(missing_ok=True)
        print(f"开始向量化知识库（语料: {service.source_dir}）……")
        print("（首次构建或全量重建耗时较长，请耐心等待；按 Ctrl+C 可中断）")
        started_at = time.monotonic()
        await service.start(progress_callback=None if args.json else _make_progress())
        elapsed = time.monotonic() - started_at
        if not service.available:
            print(f"\n❌ 知识库初始化失败: {service.error}")
            _locked_hint(service)
            return 1
        if args.json:
            print(json.dumps(service.status(), ensure_ascii=False, indent=2))
        else:
            print(f"\n✅ 向量化完成，耗时 {elapsed / 60:.1f} 分钟")
            _print_status(service)
        return 0
    finally:
        await service.close()


async def _cmd_search(args) -> int:
    from Tools.KnowledgeBase import RAGService

    service = RAGService(PROJECT_ROOT, state_dir=args.state_dir)
    try:
        await service.start()
        if not service.available:
            print(f"❌ 知识库不可用，无法检索: {service.error}")
            _locked_hint(service)
            return 1
        if not service.status()["documents"]:
            print("⚠️  知识库暂无已入库文档，请先运行 `python knowledge_cli.py build`")
            return 1
        print(f"检索: {args.query!r}（top_k={args.top_k}）\n")
        results = await service.search(args.query, top_k=args.top_k)
        if args.json:
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            _print_search(args.query, results, args.full)
        return 0
    finally:
        await service.close()


def _state_dir_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help=(
            "派生索引目录（默认 项目根/.TaskMemory/rag，与主系统共享）。"
            "当 api 服务正在运行时 Milvus Lite 文件锁被占用，可用独立目录离线自测。"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="knowledge_cli.py",
        description="灵枢知识库调用器：向量化知识库、命中测试、状态查看。",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="查看知识库状态")
    p_status.add_argument("--json", action="store_true", help="JSON 输出")
    _state_dir_arg(p_status)

    p_build = sub.add_parser("build", help="向量化知识库（增量同步 .RAG 下全部 Markdown）")
    p_build.add_argument("--force", action="store_true", help="删除现有向量库后全量重建")
    p_build.add_argument("--json", action="store_true", help="JSON 输出")
    _state_dir_arg(p_build)

    p_search = sub.add_parser("search", help="命中测试（相似度检索）")
    p_search.add_argument("query", help="查询词")
    p_search.add_argument("--top-k", type=int, default=5, help="返回命中条数（1-10，默认 5）")
    p_search.add_argument("--full", action="store_true", help="显示完整片段（默认截断 200 字符）")
    p_search.add_argument("--json", action="store_true", help="JSON 输出")
    _state_dir_arg(p_search)
    return parser


def main() -> int:
    _ensure_agentscope()
    args = build_parser().parse_args()
    try:
        if args.command == "status":
            return asyncio.run(_cmd_status(args))
        if args.command == "build":
            return asyncio.run(_cmd_build(args))
        if args.command == "search":
            return asyncio.run(_cmd_search(args))
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130
    except Exception as exc:  # noqa: BLE001 — CLI 顶层兜底
        print(f"执行失败：{exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
