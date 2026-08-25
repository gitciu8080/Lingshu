#!/usr/bin/env python3
"""灵枢 RAG 与字典查询 CLI。

所有 Markdown 索引写入 Qdrant：通用安全知识与 `long-memory` 分别使用独立
collection。`.RAG/13-字典库` 保持文件形式，可用 `dictionary` 子命令逐行精确查询。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "Tools"))


def _ensure_agentscope() -> None:
    try:
        import agentscope  # noqa: F401
    except ImportError:
        python = subprocess.list2cmdline([sys.executable])
        script = subprocess.list2cmdline([str(Path(__file__).resolve())])
        sys.exit(
            "错误：未找到 agentscope。请使用项目依赖环境运行：\n"
            f"  {python} {script} <命令>",
        )


def _make_progress():
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
        prefix = "全部处理完成" if done == total_files else f"当前: {rel}"
        print(f"  {'✓' if done == total_files else ''} {prefix}: {line}", flush=True)

    return callback


def _print_status(service) -> None:
    status = service.status()
    print("=" * 64)
    print("灵枢知识库状态")
    print("=" * 64)
    print(f"  可用性      : {'✅ 可用' if status['available'] else '❌ 不可用'}")
    if status["error"]:
        print(f"  错误原因    : {status['error']}")
    print(f"  向量后端    : Qdrant ({status['qdrant_url']})")
    print(f"  Embedding   : {status['embedding_model']} / {status['effective_dimensions']} 维")
    for key, item in status["collections"].items():
        print(f"  {key:10}: {item['name']}，{item['documents']} 篇")
    print("  字典库      : .RAG/13-字典库（文件逐行精确查询，不向量化）")
    last = status["last_sync"] or {}
    if last:
        print(
            f"  最近同步    : 新增{last.get('added', 0)} 更新{last.get('updated', 0)} "
            f"删除{last.get('removed', 0)}",
        )
    print("=" * 64)


def _print_search(results: list[dict], full: bool) -> None:
    if not results:
        print("未命中任何结果。")
        return
    for index, hit in enumerate(results, start=1):
        snippet = hit["snippet"]
        if not full and len(snippet) > 200:
            snippet = snippet[:200] + " ……"
        print(f"── 命中 {index} [{hit['corpus']}] ─────────────────────")
        print(f"  相似度 : {hit['score']:.4f}\n  来源   : {hit['source']}\n  片段   : {snippet.strip()}")


async def _service():
    from Tools.KnowledgeBase import RAGService

    service = RAGService(PROJECT_ROOT)
    await service.start()
    return service


async def _cmd_status(args) -> int:
    service = await _service()
    try:
        if args.json:
            print(json.dumps(service.status(), ensure_ascii=False, indent=2))
        else:
            _print_status(service)
        return 0 if service.available else 1
    finally:
        await service.close()


async def _cmd_build(args) -> int:
    from Tools.KnowledgeBase import RAGService

    service = RAGService(PROJECT_ROOT)
    try:
        if args.force:
            print("强制全量重建 Qdrant collection……")
            await service.rebuild(progress_callback=None if args.json else _make_progress())
        else:
            await service.start(progress_callback=None if args.json else _make_progress())
        if not service.available:
            print(f"❌ 知识库初始化失败: {service.error}")
            return 1
        if args.json:
            print(json.dumps(service.status(), ensure_ascii=False, indent=2))
        else:
            _print_status(service)
        return 0
    finally:
        await service.close()


async def _cmd_search(args) -> int:
    service = await _service()
    try:
        if not service.available:
            print(f"❌ 知识库不可用，无法检索: {service.error}")
            return 1
        results = await service.search(args.query, top_k=args.top_k)
        if args.json:
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            _print_search(results, args.full)
        return 0
    finally:
        await service.close()


async def _cmd_dictionary(args) -> int:
    from Tools.KnowledgeBase import RAGService

    service = RAGService(PROJECT_ROOT)
    results = await service.search_dictionary(args.query, args.limit)
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    elif not results:
        print("未在字典文件中精确命中。")
    else:
        for result in results:
            print(f"{result['source']}:{result['line']}: {result['value']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="灵枢 Qdrant 知识库调用器")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("status", "查看 Qdrant 索引状态"), ("build", "增量同步 Markdown")):
        item = sub.add_parser(name, help=help_text)
        item.add_argument("--json", action="store_true", help="JSON 输出")
        if name == "build":
            item.add_argument("--force", action="store_true", help="删除两个 Qdrant collection 后全量重建")
    search = sub.add_parser("search", help="跨知识/记忆 collection 相似度检索")
    search.add_argument("query")
    search.add_argument("--top-k", type=int, default=5)
    search.add_argument("--full", action="store_true")
    search.add_argument("--json", action="store_true")
    dictionary = sub.add_parser("dictionary", help="在字典 `.txt` 中逐行精确匹配")
    dictionary.add_argument("query")
    dictionary.add_argument("--limit", type=int, default=20)
    dictionary.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args()
    # 字典查询只读取 `.RAG/13-字典库` 的文本，不应要求安装向量检索依赖。
    if args.command != "dictionary":
        _ensure_agentscope()
    handlers = {
        "status": _cmd_status,
        "build": _cmd_build,
        "search": _cmd_search,
        "dictionary": _cmd_dictionary,
    }
    try:
        return asyncio.run(handlers[args.command](args))
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"执行失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
