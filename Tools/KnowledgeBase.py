"""灵枢的容器化 RAG 与文件型字典查询。

`.RAG` 始终是只读语料源：通用安全知识和脱敏长期记忆分别写入 Qdrant
collection；`.RAG/13-字典库` 不参与向量化，只提供精确匹配查询。增量同步
清单是可重建的派生状态，保存在 `.TaskMemory/rag`。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from core.config import RuntimeConfig


_COLLECTIONS = {
    "knowledge": {
        "collection": "lingshu_security_knowledge",
        "name": "lingshu-security-knowledge",
        "description": "灵枢安全测试、漏洞与 CTF Writeup 知识库",
    },
    "memory": {
        "collection": "lingshu_agent_memory",
        "name": "lingshu-agent-memory",
        "description": "灵枢脱敏的历史任务经验，仅供当前授权任务参考",
    },
}
_MEMORY_PREFIX = "long-memory/"
_DICTIONARY_DIR = "13-字典库"


class RAGService:
    """管理 Qdrant collection、Markdown 增量索引与字典精确查询。"""

    def __init__(
        self,
        project_root: Path,
        runtime: RuntimeConfig | None = None,
        state_dir: Path | None = None,
    ) -> None:
        self.project_root = project_root
        self.source_dir = project_root / ".RAG"
        self.dictionary_dir = self.source_dir / _DICTIONARY_DIR
        self.state_dir = state_dir or (project_root / ".TaskMemory" / "rag")
        self.manifest_paths = {
            key: self.state_dir / f"{key}_manifest.json"
            for key in _COLLECTIONS
        }
        self.runtime = runtime or RuntimeConfig.from_env()
        # ``knowledge`` 和 ``store`` 保留为兼容属性，指向通用知识 collection。
        self.knowledge: Any | None = None
        self.store: Any | None = None
        self.knowledge_bases: dict[str, Any] = {}
        self.stores: dict[str, Any] = {}
        self._qdrant_admin: Any | None = None
        self.available = False
        self.started = False
        self.error: str | None = None
        self.last_sync: dict[str, Any] = {}
        self.configured_dimensions = self.runtime.embedding_dimensions
        self.effective_dimensions: int | None = None
        self.collection_dimensions: dict[str, int | None] = {
            key: None for key in _COLLECTIONS
        }
        self.dimension_migration: dict[str, dict[str, int]] = {}
        self._lock = asyncio.Lock()

    async def start(self, progress_callback=None) -> None:
        """连接 Qdrant、建立知识库句柄并同步 `.RAG` 的 Markdown。"""
        if self.started:
            return
        self.started = True
        self.error = None
        self.dimension_migration = {}
        config_error = self.runtime.embedding_error()
        if config_error:
            self.error = config_error
            return
        try:
            from agentscope.credential import OpenAICredential
            from agentscope.embedding import OpenAIEmbeddingModel
            from agentscope.rag import KnowledgeBase, QdrantStore
            from pydantic import SecretStr
            from qdrant_client import AsyncQdrantClient

            self.state_dir.mkdir(parents=True, exist_ok=True)
            embedding = OpenAIEmbeddingModel(
                credential=OpenAICredential(
                    api_key=SecretStr(self.runtime.embedding_api_key),
                    base_url=self.runtime.embedding_base_url,
                ),
                model=self.runtime.embedding_model,
                dimensions=self.runtime.embedding_dimensions,
                pass_dimensions=self.runtime.embedding_pass_dimensions,
                max_retries=int(self.runtime.embedding_model_settings.get("max_retries", 3)),
                context_size=int(self.runtime.embedding_model_settings.get("context_size", 8191)),
            )
            # 兼容端点可能忽略 dimensions；以实际探测到的长度作为 collection 约束。
            self.effective_dimensions = await self._probe_embedding_dimensions(embedding)
            embedding.dimensions = self.effective_dimensions
            self._qdrant_admin = AsyncQdrantClient(url=self.runtime.qdrant_url)

            for key, spec in _COLLECTIONS.items():
                await self._ensure_collection_dimensions(key, self.effective_dimensions)
                store = QdrantStore(url=self.runtime.qdrant_url)
                await store.__aenter__()
                self.stores[key] = store
                self.knowledge_bases[key] = KnowledgeBase(
                    name=spec["name"],
                    description=spec["description"],
                    embedding_model=embedding,
                    vector_store=store,
                    collection=spec["collection"],
                )

            self.store = self.stores["knowledge"]
            self.knowledge = self.knowledge_bases["knowledge"]
            self.available = True
            await self.sync(progress_callback=progress_callback)
        except Exception as exc:  # 可选子系统不得阻断主任务启动
            self.error = f"知识库初始化失败: {exc}"
            self.available = False
            await self._close_resources()

    async def _close_resources(self) -> None:
        for store in self.stores.values():
            try:
                await store.__aexit__(None, None, None)
            except Exception:
                pass
        self.stores = {}
        self.knowledge_bases = {}
        self.store = self.knowledge = None
        if self._qdrant_admin is not None:
            try:
                await self._qdrant_admin.close()
            except Exception:
                pass
        self._qdrant_admin = None

    async def close(self) -> None:
        await self._close_resources()
        self.available = False
        self.started = False

    async def restart(self) -> None:
        """重新连接 Qdrant 并重试初始化，供重建接口恢复可选 RAG 服务。"""
        await self.close()
        await self.start()

    async def reload_runtime(self) -> None:
        """重新读取嵌入与 Qdrant 配置。"""
        await self.close()
        self.runtime = RuntimeConfig.from_env()
        self.configured_dimensions = self.runtime.embedding_dimensions
        self.effective_dimensions = None
        self.collection_dimensions = {key: None for key in _COLLECTIONS}
        self.dimension_migration = {}
        await self.start()

    def status(self) -> dict[str, Any]:
        documents = {key: len(self._load_manifest(key)) for key in _COLLECTIONS}
        return {
            "available": self.available,
            "error": self.error,
            "source_dir": ".RAG",
            "vector_store": "qdrant",
            "qdrant_url": self.runtime.qdrant_url,
            "documents": sum(documents.values()),
            "collections": {
                key: {
                    "name": spec["collection"],
                    "documents": documents[key],
                    "dimensions": self.collection_dimensions[key],
                }
                for key, spec in _COLLECTIONS.items()
            },
            "dictionary": {
                "source_dir": f".RAG/{_DICTIONARY_DIR}",
                "indexed": False,
                "query_mode": "exact_file_match",
            },
            "last_sync": self.last_sync,
            "embedding_model": self.runtime.embedding_model,
            "configured_dimensions": self.configured_dimensions,
            "effective_dimensions": self.effective_dimensions,
            "dimension_migration": self.dimension_migration or None,
        }

    async def _probe_embedding_dimensions(self, embedding: Any) -> int:
        response = await embedding(["灵枢知识库向量维度探测"])
        vectors = getattr(response, "embeddings", None)
        if not vectors or not vectors[0]:
            raise RuntimeError("Embedding API 未返回可用向量，无法确定知识库维度")
        actual = len(vectors[0])
        if actual <= 0:
            raise RuntimeError("Embedding API 返回了空向量")
        return actual

    @staticmethod
    def _qdrant_vector_dimension(info: Any) -> int | None:
        """从 qdrant-client 的 collection 信息中读取单向量字段维度。"""
        vectors = getattr(getattr(getattr(info, "config", None), "params", None), "vectors", None)
        if isinstance(vectors, dict):
            vectors = next(iter(vectors.values()), None)
        size = getattr(vectors, "size", None)
        try:
            return int(size) if size is not None and int(size) > 0 else None
        except (TypeError, ValueError):
            return None

    async def _ensure_collection_dimensions(self, key: str, actual_dimensions: int) -> None:
        """维度改变时删除对应的派生 Qdrant collection 后全量重建。"""
        if self._qdrant_admin is None:
            raise RuntimeError("Qdrant 管理客户端尚未初始化")
        collection = str(_COLLECTIONS[key]["collection"])
        exists = await self._qdrant_admin.collection_exists(collection)
        if not exists:
            if self._load_manifest(key):
                self._write_manifest(key, {})
            self.collection_dimensions[key] = actual_dimensions
            return

        current_dimensions = self._qdrant_vector_dimension(
            await self._qdrant_admin.get_collection(collection),
        )
        if current_dimensions is None:
            raise RuntimeError(f"无法读取 Qdrant collection {collection!r} 的向量维度")
        self.collection_dimensions[key] = current_dimensions
        if current_dimensions == actual_dimensions:
            return

        await self._qdrant_admin.delete_collection(collection)
        self._write_manifest(key, {})
        self.collection_dimensions[key] = actual_dimensions
        self.dimension_migration[key] = {
            "from": current_dimensions,
            "to": actual_dimensions,
            "source_documents": len(self._sources_by_collection()[key]),
        }

    def middleware(self):
        """将通用知识与长期经验作为独立知识库挂载到 AgentScope。"""
        if not self.available or not self.knowledge_bases:
            return None
        from agentscope.middleware import RAGMiddleware

        return RAGMiddleware(
            knowledge_bases=list(self.knowledge_bases.values()),
            parameters=RAGMiddleware.Parameters(mode="agentic", top_k=3),
        )

    def _manifest_path(self, key: str) -> Path:
        return self.manifest_paths[key]

    def _load_manifest(self, key: str) -> dict[str, dict[str, str]]:
        try:
            raw = json.loads(self._manifest_path(key).read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _write_manifest(self, key: str, manifest: dict[str, dict[str, str]]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        path = self._manifest_path(key)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    def _sources_by_collection(self) -> dict[str, dict[str, tuple[Path, str]]]:
        """将 `long-memory` 与其余 Markdown 拆分，字典 `.txt` 永不向量化。"""
        result: dict[str, dict[str, tuple[Path, str]]] = {key: {} for key in _COLLECTIONS}
        if not self.source_dir.is_dir():
            return result
        for path in self.source_dir.rglob("*.md"):
            if not path.is_file():
                continue
            rel = path.relative_to(self.source_dir).as_posix()
            key = "memory" if rel.startswith(_MEMORY_PREFIX) else "knowledge"
            content = path.read_bytes()
            result[key][rel] = (path, hashlib.sha256(content).hexdigest())
        return result

    async def sync(self, progress_callback=None) -> dict[str, Any]:
        """按 collection 增量同步 Markdown，删除已移除的派生向量。"""
        if not self.available or not self.knowledge_bases:
            return self.status()
        async with self._lock:
            from agentscope.rag import ApproxTokenChunker, TextParser

            sources_by_collection = self._sources_by_collection()
            parser, chunker = TextParser(), ApproxTokenChunker(chunk_size=512, overlap=64)
            per_collection: dict[str, dict[str, int]] = {}
            total = sum(len(sources) for sources in sources_by_collection.values())
            done = 0
            for key, sources in sources_by_collection.items():
                old = self._load_manifest(key)
                knowledge = self.knowledge_bases[key]
                added = updated = removed = 0
                for rel, entry in old.items():
                    if rel not in sources or sources[rel][1] != entry.get("sha256"):
                        await knowledge.delete_document(entry["document_id"])
                        removed += int(rel not in sources)

                new_manifest: dict[str, dict[str, str]] = {}
                for rel, (path, digest) in sources.items():
                    old_entry = old.get(rel)
                    if old_entry and old_entry.get("sha256") == digest:
                        new_manifest[rel] = old_entry
                    else:
                        sections = await parser.parse(file=path.read_bytes(), filename=rel)
                        chunks = await chunker.chunk(sections)
                        document_id = await knowledge.insert_document(
                            chunks,
                            document_metadata={"source": rel, "sha256": digest, "corpus": key},
                        )
                        new_manifest[rel] = {"sha256": digest, "document_id": document_id}
                        if old_entry:
                            updated += 1
                        else:
                            added += 1
                    done += 1
                    if progress_callback is not None:
                        progress_callback(done, total, rel, {
                            "added": added,
                            "updated": updated,
                            "removed": removed,
                            "collection": key,
                        })
                self._write_manifest(key, new_manifest)
                per_collection[key] = {"added": added, "updated": updated, "removed": removed}

            self.last_sync = {
                "added": sum(item["added"] for item in per_collection.values()),
                "updated": sum(item["updated"] for item in per_collection.values()),
                "removed": sum(item["removed"] for item in per_collection.values()),
                "collections": per_collection,
                "dimensions": self.effective_dimensions,
                "collection_recreated": bool(self.dimension_migration),
            }
            return self.status()

    async def rebuild(self, progress_callback=None) -> dict[str, Any]:
        """删除两个派生 Qdrant collection 后，从 `.RAG` 全量重建。"""
        await self.close()
        from qdrant_client import AsyncQdrantClient

        client = AsyncQdrantClient(url=self.runtime.qdrant_url)
        try:
            for key, spec in _COLLECTIONS.items():
                collection = str(spec["collection"])
                if await client.collection_exists(collection):
                    await client.delete_collection(collection)
                self._write_manifest(key, {})
        finally:
            await client.close()
        await self.start(progress_callback=progress_callback)
        return self.status()

    async def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """跨两个 collection 检索后按相似度统一排序。"""
        if not self.available or not self.knowledge_bases:
            raise RuntimeError(self.error or "知识库不可用")
        from agentscope.message import TextBlock

        normalized_query = query.strip()
        if not normalized_query:
            return []
        limit = max(1, min(top_k, 10))
        ranked: list[tuple[str, Any]] = []
        async with self._lock:
            for key, knowledge in self.knowledge_bases.items():
                results = await knowledge.search(queries=[normalized_query], top_k=limit)
                ranked.extend((key, result) for result in results)

        ranked.sort(key=lambda item: float(getattr(item[1], "score", 0.0) or 0.0), reverse=True)
        output = []
        for corpus, result in ranked[:limit]:
            chunk = getattr(result, "chunk", None)
            content = getattr(chunk, "content", None)
            text = content.text if isinstance(content, TextBlock) else str(getattr(content, "text", "") or "")
            metadata = getattr(chunk, "metadata", None)
            metadata = metadata if isinstance(metadata, dict) else {}
            source = metadata.get("source") or getattr(chunk, "source", None) or getattr(result, "document_id", None) or "未知来源"
            output.append({
                "score": float(getattr(result, "score", 0.0) or 0.0),
                "source": str(source),
                "corpus": corpus,
                "snippet": text[:1200],
            })
        return output

    async def search_dictionary(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """在 `.RAG/13-字典库` 的文本文件中作逐行、大小写无关的精确匹配。"""
        normalized_query = query.strip()
        if not normalized_query or not self.dictionary_dir.is_dir():
            return []
        return await asyncio.to_thread(
            self._search_dictionary_sync,
            normalized_query.casefold(),
            max(1, min(limit, 100)),
        )

    def _search_dictionary_sync(self, needle: str, limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for path in sorted(self.dictionary_dir.rglob("*.txt")):
            if not path.is_file():
                continue
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    for line_number, line in enumerate(handle, start=1):
                        value = line.strip()
                        if value and value.casefold() == needle:
                            results.append({
                                "source": path.relative_to(self.source_dir).as_posix(),
                                "line": line_number,
                                "value": value[:1000],
                            })
                            if len(results) >= limit:
                                return results
            except OSError:
                continue
        return results


_service: RAGService | None = None


def get_rag_service(project_root: Path | None = None) -> RAGService:
    global _service
    if _service is None:
        _service = RAGService(project_root or Path(__file__).resolve().parents[1])
    return _service
