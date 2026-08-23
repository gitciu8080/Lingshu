"""灵枢本地 Markdown 知识库。

`.RAG` 是只读语料源；向量库、哈希清单均写入 `.TaskMemory/rag`。
服务配置或可选依赖缺失时安全降级，主任务链不受影响。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from core.config import RuntimeConfig


logger = logging.getLogger(__name__)

_DEFAULT_FETCH_K = 8
_DEFAULT_CONTEXT_K = 4
_DEFAULT_SCORE_THRESHOLD = 0.25
_DEFAULT_ITEM_CHARS = 800
_DEFAULT_CONTEXT_CHARS = 3600


def build_retrieval_request(
    mission: Any,
    *,
    consumer: str,
    focus: str = "",
) -> dict[str, Any]:
    """基于当前知识缺口构造确定性的检索请求，不额外调用 LLM。

    返回 ``needed/reason/query/cache_key``。Query 只包含当前任务、阶段、题型、
    有界 Facts/Hypotheses 和本轮问题，不携带完整对话或工具历史。
    """
    category = dict(getattr(mission, "category_decision", None) or {})
    primary = str(category.get("primary") or "unknown")
    secondary = [str(item) for item in category.get("secondary") or []][:3]
    confidence = float(category.get("confidence") or 0.0)
    complexity = str(getattr(mission, "complexity", "complex") or "complex")
    phase_obj = getattr(mission, "phase", "planning")
    phase = str(getattr(phase_obj, "value", phase_obj))
    facts = [str(getattr(item, "content", ""))[:300] for item in getattr(mission, "facts", [])[-5:]]
    hypotheses = [
        str(getattr(item, "statement", ""))[:300]
        for item in getattr(mission, "hypotheses", [])[-3:]
        if str(getattr(item, "status", "")) not in {"rejected", "confirmed"}
    ]
    bounded_focus = " ".join(str(focus).split())[:600]

    reasons: list[str] = []
    if primary == "unknown" or confidence < 0.70:
        reasons.append("题型或技术路线仍不确定")
    if secondary:
        reasons.append("存在多个候选题型")
    if complexity == "complex" and len(facts) < 2:
        reasons.append("复杂任务的已验证 Facts 仍稀疏")
    if hypotheses:
        reasons.append("存在待验证 Hypothesis 的方法知识缺口")
    if bounded_focus and re.search(
        r"CVE-\d{4}-\d+|SQLi?|SSTI|SSRF|XXE|JWT|RCE|ROP|ret2\w+|"
        r"反序列化|目录穿越|文件包含|缓冲区溢出|格式化字符串|栈迁移|"
        r"特定协议|特定算法|认证绕过|权限绕过|payload",
        bounded_focus,
        re.IGNORECASE,
    ):
        reasons.append("当前问题需要具体方法或机制参考")

    # 清晰、简单且已有足够证据的任务不启动 RAG。
    needed = bool(reasons)
    gap = "；".join(dict.fromkeys(reasons))
    parts = [
        f"任务目标：{str(getattr(mission, 'goal', ''))[:700]}",
        f"当前阶段：{phase}",
        f"当前题型：{primary}",
    ]
    if secondary:
        parts.append(f"候选题型：{', '.join(secondary)}")
    if facts:
        parts.append("当前已验证 Facts：" + "；".join(facts))
    if hypotheses:
        parts.append("待验证 Hypothesis：" + "；".join(hypotheses))
    if bounded_focus:
        parts.append(f"当前问题：{bounded_focus}")
    if gap:
        parts.append(f"知识缺口：{gap}")
    query = "\n".join(parts)
    fingerprint_payload = {
        "phase": phase,
        "primary": primary,
        "secondary": secondary,
        "facts": facts,
        "hypotheses": hypotheses,
        "focus": bounded_focus,
        "goal": str(getattr(mission, "goal", ""))[:700],
    }
    cache_key = hashlib.sha256(
        json.dumps(fingerprint_payload, ensure_ascii=False, sort_keys=True).encode("utf-8"),
    ).hexdigest()
    return {
        "needed": needed,
        "reason": gap or "当前信息足够，无需知识检索",
        "query": query,
        "cache_key": cache_key,
        "phase": phase,
        "consumer": consumer.lower(),
    }


class RAGService:
    """Own the KnowledgeBase runtime and incremental Markdown indexing."""

    def __init__(
        self,
        project_root: Path,
        runtime: RuntimeConfig | None = None,
        state_dir: Path | None = None,
    ) -> None:
        self.project_root = project_root
        self.source_dir = project_root / ".RAG"
        # 默认与主系统共享派生索引；CLI 等离线调用方可通过 state_dir 指定独立目录，
        # 避免与运行中的服务争用 Milvus Lite 的单进程文件锁。
        self.state_dir = state_dir or (project_root / ".TaskMemory" / "rag")
        self.manifest_path = self.state_dir / "manifest.json"
        self.runtime = runtime or RuntimeConfig.from_env()
        self.knowledge: Any | None = None
        self.store: Any | None = None
        self.available = False
        self.started = False
        self.error: str | None = None
        self.last_sync: dict[str, Any] = {}
        self.configured_dimensions = self.runtime.embedding_dimensions
        self.effective_dimensions: int | None = None
        self.collection_dimensions: int | None = None
        self.dimension_migration: dict[str, Any] | None = None
        self._lock = asyncio.Lock()

    async def start(self, progress_callback=None) -> None:
        """Initialize the optional RAG runtime, then synchronize the corpus.

        ``progress_callback`` is forwarded to :meth:`sync` when provided.
        """
        if self.started:
            return
        self.started = True
        self.error = None
        self.dimension_migration = None
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
                max_retries=int(self.runtime.embedding_model_settings.get("max_retries", 3)),
                context_size=int(self.runtime.embedding_model_settings.get("context_size", 8191)),
            )
            # 兼容端点可能忽略 dimensions 参数，不能直接把配置值当成真实维度。
            # 先用单条探测文本取得实际向量长度，再以真实维度创建/校验 collection。
            actual_dimensions = await self._probe_embedding_dimensions(embedding)
            self.effective_dimensions = actual_dimensions
            embedding.dimensions = actual_dimensions
            await self._ensure_collection_dimensions(actual_dimensions)
            await self._load_collection()
            self.knowledge = KnowledgeBase(
                name="lingshu-rag",
                description="灵枢本地安全测试与 CTF Writeup 知识库",
                embedding_model=embedding,
                vector_store=self.store,
                collection="lingshu_rag",
            )
            self.available = True
            await self.sync(progress_callback=progress_callback)
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

    async def restart(self) -> None:
        """关闭并重新初始化失败的 RAG 服务，供重建接口进行运行时恢复。"""
        await self.close()
        await self.start()

    async def reload_runtime(self) -> None:
        """重新读取管理员/环境配置，并用新的嵌入端点重建运行时。"""
        await self.close()
        self.runtime = RuntimeConfig.from_env()
        self.configured_dimensions = self.runtime.embedding_dimensions
        self.effective_dimensions = None
        self.collection_dimensions = None
        self.dimension_migration = None
        await self.start()

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "error": self.error,
            "source_dir": ".RAG",
            "documents": len(self._load_manifest()),
            "last_sync": self.last_sync,
            "embedding_model": self.runtime.embedding_model,
            "configured_dimensions": self.configured_dimensions,
            "effective_dimensions": self.effective_dimensions,
            "collection_dimensions": self.collection_dimensions,
            "dimension_migration": self.dimension_migration,
        }

    async def _probe_embedding_dimensions(self, embedding: Any) -> int:
        """调用一次 Embedding API，返回供应商实际输出的向量维度。"""
        response = await embedding(["灵枢知识库向量维度探测"])
        vectors = getattr(response, "embeddings", None)
        if not vectors or not vectors[0]:
            raise RuntimeError("Embedding API 未返回可用向量，无法确定知识库维度")
        actual = len(vectors[0])
        if actual <= 0:
            raise RuntimeError("Embedding API 返回了空向量")
        return actual

    @staticmethod
    def _extract_vector_dimension(description: Any) -> int | None:
        """兼容不同 pymilvus 版本的 describe_collection 返回结构。"""
        if not isinstance(description, dict):
            return None
        schema = description.get("schema")
        candidates = [description.get("fields")]
        if isinstance(schema, dict):
            candidates.append(schema.get("fields"))
        for fields in candidates:
            if not isinstance(fields, list):
                continue
            for field in fields:
                if not isinstance(field, dict) or field.get("name") != "vector":
                    continue
                values = [
                    field.get("dim"),
                    (field.get("params") or {}).get("dim") if isinstance(field.get("params"), dict) else None,
                    (field.get("type_params") or {}).get("dim") if isinstance(field.get("type_params"), dict) else None,
                ]
                for value in values:
                    try:
                        if value is not None and int(value) > 0:
                            return int(value)
                    except (TypeError, ValueError):
                        continue
        return None

    async def _ensure_collection_dimensions(self, actual_dimensions: int) -> None:
        """校验 collection；维度变化时删除派生索引并从 `.RAG` 自动重建。"""
        if self.store is None:
            raise RuntimeError("Milvus 向量存储尚未初始化")
        collection = "lingshu_rag"
        exists = await self.store.has_collection(collection)
        if not exists:
            # collection 被手工删除后旧 manifest 也必须清空，否则增量同步会误判无需写入。
            if self._load_manifest():
                self._write_manifest({})
            self.collection_dimensions = actual_dimensions
            return

        description = await asyncio.to_thread(
            self.store.get_client().describe_collection,
            collection_name=collection,
        )
        current_dimensions = self._extract_vector_dimension(description)
        if current_dimensions is None:
            raise RuntimeError("无法读取 Milvus collection 的 vector 维度")
        self.collection_dimensions = current_dimensions
        if current_dimensions == actual_dimensions:
            return

        # Milvus 的向量字段维度不可原地修改；该数据库只是 `.RAG` 的派生缓存，
        # 因而删除 collection 并清空 manifest，随后 sync 会从 Markdown 完整重建。
        source_documents = len(self._sources())
        await self.store.delete_collection(collection)
        self._write_manifest({})
        self.dimension_migration = {
            "recreated": True,
            "from": current_dimensions,
            "to": actual_dimensions,
            "source_documents": source_documents,
        }
        self.collection_dimensions = actual_dimensions

    async def _load_collection(self) -> None:
        """确保 Milvus Lite collection 处于可检索的 loaded 状态。

        Milvus Lite 在同一数据库被其它 client 关闭或释放后，collection 仍然
        存在但会变为 ``released``。这种状态下 status/sync 看起来正常，search
        却会报 code=101，因此加载操作必须在搜索前重复执行且保持幂等。
        """
        if self.store is None:
            raise RuntimeError("Milvus 向量存储尚未初始化")
        collection = "lingshu_rag"
        if not await self.store.has_collection(collection):
            return
        await asyncio.to_thread(
            self.store.get_client().load_collection,
            collection_name=collection,
        )

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

    async def sync(self, progress_callback=None) -> dict[str, Any]:
        """Incrementally synchronize Markdown sources and remove stale documents.

        ``progress_callback(done, total, rel, stats)`` is invoked after each
        source file is processed (inserted, updated, or skipped); ``stats`` is
        a dict with the running ``added``/``updated``/``removed`` counters.
        """
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
            total = len(sources)
            done = 0
            for rel, (path, digest) in sources.items():
                old_entry = old.get(rel)
                if old_entry and old_entry.get("sha256") == digest:
                    new_manifest[rel] = old_entry
                else:
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
                done += 1
                if progress_callback is not None:
                    progress_callback(done, total, rel, {
                        "added": added, "updated": updated, "removed": removed,
                    })
            self._write_manifest(new_manifest)
            self.last_sync = {
                "added": added,
                "updated": updated,
                "removed": removed,
                "dimensions": self.effective_dimensions,
                "collection_recreated": bool(self.dimension_migration),
            }
            return self.status()

    async def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        if not self.available or self.knowledge is None:
            raise RuntimeError(self.error or "知识库不可用")
        from agentscope.message import TextBlock

        normalized_query = query.strip()
        if not normalized_query:
            return []

        # KnowledgeBase 和 Milvus Lite 都会复用同一个 client；与同步索引并发时
        # 某些 pymilvus 版本会返回不完整的记录。因此检索也使用同一把锁。
        async with self._lock:
            await self._load_collection()
            try:
                results = await self.knowledge.search(
                    queries=[normalized_query],
                    top_k=max(1, min(top_k, 10)),
                )
            except Exception as exc:
                # 另一个 Lite client 恰好释放 collection 时，重载并仅重试一次。
                # 其它错误（如 Embedding API 或维度异常）原样交给 API 层处理。
                if "released" not in str(exc).lower():
                    raise
                await self._load_collection()
                results = await self.knowledge.search(
                    queries=[normalized_query],
                    top_k=max(1, min(top_k, 10)),
                )

        output = []
        for result in results:
            chunk = getattr(result, "chunk", None)
            content = getattr(chunk, "content", None)
            if isinstance(content, TextBlock):
                text = content.text
            else:
                # 仅 Markdown 入库时通常均为 TextBlock；保留降级逻辑，防止单条
                # 异常/非文本 chunk 让整个搜索接口变成 500。
                text = str(getattr(content, "text", "") or "")
            metadata = getattr(chunk, "metadata", None)
            if not isinstance(metadata, dict):
                metadata = {}
            source = (
                metadata.get("source")
                or getattr(chunk, "source", None)
                or getattr(result, "document_id", None)
                or "未知来源"
            )
            output.append({
                "score": float(getattr(result, "score", 0.0) or 0.0),
                "source": str(source),
                "snippet": text[:1200],
            })
        return output

    async def retrieve_context(
        self,
        query: str,
        *,
        fetch_k: int = _DEFAULT_FETCH_K,
        context_k: int = _DEFAULT_CONTEXT_K,
        score_threshold: float = _DEFAULT_SCORE_THRESHOLD,
        max_item_chars: int = _DEFAULT_ITEM_CHARS,
        max_context_chars: int = _DEFAULT_CONTEXT_CHARS,
    ) -> dict[str, Any]:
        """检索并生成有界 Knowledge Context。

        处理顺序为 Top-K 获取、相似度过滤、内容去重、单条截断、总量截断。
        返回内容始终标记为参考知识，调用方不得将其写成 Facts/Evidence。
        """
        raw = await self.search(query, top_k=max(1, min(fetch_k, 10)))
        filtered: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw:
            snippet = " ".join(str(item.get("snippet") or "").split())
            score = float(item.get("score") or 0.0)
            if not snippet or score < score_threshold:
                continue
            dedup_key = hashlib.sha256(snippet.lower().encode("utf-8")).hexdigest()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            filtered.append({
                "score": score,
                "source": str(item.get("source") or "未知来源")[:300],
                "snippet": snippet[:max_item_chars],
            })
            if len(filtered) >= max(1, context_k):
                break

        blocks: list[str] = []
        used = 0
        kept: list[dict[str, Any]] = []
        for index, item in enumerate(filtered, 1):
            block = (
                f"[K{index}] 来源：{item['source']}；相关度：{item['score']:.3f}\n"
                f"{item['snippet']}"
            )
            remaining = max_context_chars - used
            if remaining <= 0:
                break
            if len(block) > remaining:
                block = block[:remaining].rstrip()
            if not block:
                break
            blocks.append(block)
            kept.append(item)
            used += len(block) + 2

        context = "\n\n".join(blocks)
        logger.info(
            "[RAG] 检索结果数量=%d，过滤后数量=%d，Context字符数=%d",
            len(raw), len(kept), len(context),
        )
        return {
            "context": context,
            "result_count": len(raw),
            "filtered_count": len(kept),
            "sources": [item["source"] for item in kept],
            "score_threshold": score_threshold,
            "fetch_k": max(1, min(fetch_k, 10)),
            "context_k": max(1, context_k),
        }


_service: RAGService | None = None


def get_rag_service(project_root: Path | None = None) -> RAGService:
    global _service
    if _service is None:
        _service = RAGService(project_root or Path(__file__).resolve().parents[1])
    return _service
