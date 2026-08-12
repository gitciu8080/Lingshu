"""灵枢本地 Markdown 知识库。

`.RAG` 是只读语料源；向量库、哈希清单均写入 `.TaskMemory/rag`。
服务配置或可选依赖缺失时安全降级，主任务链不受影响。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from config import RuntimeConfig


class RAGService:
    """Own the KnowledgeBase runtime and incremental Markdown indexing."""

    def __init__(self, project_root: Path, runtime: RuntimeConfig | None = None) -> None:
        self.project_root = project_root
        self.source_dir = project_root / ".RAG"
        self.state_dir = project_root / ".TaskMemory" / "rag"
        self.manifest_path = self.state_dir / "manifest.json"
        self.runtime = runtime or RuntimeConfig.from_env()
        self.knowledge: Any | None = None
        self.store: Any | None = None
        self.available = False
        self.started = False
        self.error: str | None = None
        self.last_sync: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Initialize the optional RAG runtime, then synchronize the corpus."""
        if self.started:
            return
        self.started = True
        config_error = self.runtime.embedding_error()
        if config_error:
            self.error = config_error
            return
        try:
            from agentscope.credential import OpenAICredential
            from agentscope.embedding import OpenAIEmbeddingModel
            from agentscope.rag import KnowledgeBase, MilvusLiteStore
            from pydantic import SecretStr

            self.state_dir.mkdir(parents=True, exist_ok=True)
            self.store = MilvusLiteStore(uri=str(self.state_dir / "knowledge.db"))
            await self.store.__aenter__()
            embedding = OpenAIEmbeddingModel(
                credential=OpenAICredential(
                    api_key=SecretStr(self.runtime.embedding_api_key),
                    base_url=self.runtime.embedding_base_url,
                ),
                model=self.runtime.embedding_model,
                dimensions=self.runtime.embedding_dimensions,
                pass_dimensions=self.runtime.embedding_pass_dimensions,
            )
            self.knowledge = KnowledgeBase(
                name="lingshu-rag",
                description="灵枢本地安全测试与 CTF Writeup 知识库",
                embedding_model=embedding,
                vector_store=self.store,
                collection="lingshu_rag",
            )
            self.available = True
            await self.sync()
        except Exception as exc:  # optional subsystem must never block mission startup
            self.error = f"知识库初始化失败: {exc}"
            self.available = False
            if self.store is not None:
                await self.store.__aexit__(None, None, None)
                self.store = None

    async def close(self) -> None:
        if self.store is not None:
            await self.store.__aexit__(None, None, None)
        self.store = self.knowledge = None
        self.available = False
        self.started = False

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "error": self.error,
            "source_dir": ".RAG",
            "documents": len(self._load_manifest()),
            "last_sync": self.last_sync,
        }

    def middleware(self):
        """Return agentic middleware, or None when RAG is unavailable."""
        if not self.available or self.knowledge is None:
            return None
        from agentscope.middleware import RAGMiddleware

        return RAGMiddleware(
            knowledge_bases=[self.knowledge],
            parameters=RAGMiddleware.Parameters(mode="agentic", top_k=3),
        )

    def _load_manifest(self) -> dict[str, dict[str, str]]:
        try:
            raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _write_manifest(self, manifest: dict[str, dict[str, str]]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.manifest_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.manifest_path)

    def _sources(self) -> dict[str, tuple[Path, str]]:
        if not self.source_dir.is_dir():
            return {}
        result: dict[str, tuple[Path, str]] = {}
        for path in self.source_dir.rglob("*.md"):
            if path.is_file():
                content = path.read_bytes()
                result[path.relative_to(self.source_dir).as_posix()] = (
                    path,
                    hashlib.sha256(content).hexdigest(),
                )
        return result

    async def sync(self) -> dict[str, Any]:
        """Incrementally synchronize Markdown sources and remove stale documents."""
        if not self.available or self.knowledge is None:
            return self.status()
        async with self._lock:
            from agentscope.rag import ApproxTokenChunker, TextParser

            old = self._load_manifest()
            sources = self._sources()
            parser, chunker = TextParser(), ApproxTokenChunker(chunk_size=512, overlap=64)
            added = updated = removed = 0
            for rel, entry in old.items():
                if rel not in sources or sources[rel][1] != entry.get("sha256"):
                    await self.knowledge.delete_document(entry["document_id"])
                    removed += int(rel not in sources)
            new_manifest: dict[str, dict[str, str]] = {}
            for rel, (path, digest) in sources.items():
                old_entry = old.get(rel)
                if old_entry and old_entry.get("sha256") == digest:
                    new_manifest[rel] = old_entry
                    continue
                sections = await parser.parse(file=path.read_bytes(), filename=rel)
                chunks = await chunker.chunk(sections)
                document_id = await self.knowledge.insert_document(
                    chunks, document_metadata={"source": rel, "sha256": digest},
                )
                new_manifest[rel] = {"sha256": digest, "document_id": document_id}
                if old_entry:
                    updated += 1
                else:
                    added += 1
            self._write_manifest(new_manifest)
            self.last_sync = {"added": added, "updated": updated, "removed": removed}
            return self.status()

    async def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        if not self.available or self.knowledge is None:
            raise RuntimeError(self.error or "知识库不可用")
        from agentscope.message import TextBlock

        results = await self.knowledge.search(queries=[query], top_k=max(1, min(top_k, 10)))
        output = []
        for result in results:
            text = result.chunk.content.text if isinstance(result.chunk.content, TextBlock) else ""
            output.append({
                "score": result.score,
                "source": result.chunk.metadata.get("source", "未知来源"),
                "snippet": text[:1200],
            })
        return output


_service: RAGService | None = None


def get_rag_service(project_root: Path | None = None) -> RAGService:
    global _service
    if _service is None:
        _service = RAGService(project_root or Path(__file__).resolve().parents[1])
    return _service
