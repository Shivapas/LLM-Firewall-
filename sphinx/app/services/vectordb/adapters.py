"""Vector DB adapters — transparent proxy adapters for ChromaDB, Pinecone, and Milvus.

Each adapter translates the unified ProxyRequest into provider-specific operations
and returns normalized document results.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

from app.services.vectordb.proxy import (
    ProxyRequest,
    VectorDBProvider,
    VectorOperation,
)

logger = logging.getLogger("sphinx.vectordb.adapters")


class BaseVectorAdapter(ABC):
    """Abstract base class for vector DB adapters."""

    provider: VectorDBProvider

    @abstractmethod
    def execute(self, request: ProxyRequest) -> list[dict[str, Any]]:
        """Execute a vector DB operation and return normalized documents."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Check if the vector DB connection is healthy."""
        ...


class ChromaDBAdapter(BaseVectorAdapter):
    """Adapter for ChromaDB — supports HTTP and in-process clients."""

    provider = VectorDBProvider.CHROMADB

    def __init__(self, client: Any = None, host: str = "localhost", port: int = 8000):
        self._client = client
        self._host = host
        self._port = port

    def execute(self, request: ProxyRequest) -> list[dict[str, Any]]:
        if self._client is None:
            logger.warning("ChromaDB client not configured; returning empty results")
            return []

        collection = self._client.get_collection(request.collection_name)

        if request.operation == VectorOperation.QUERY:
            where_filter = request.filters if request.filters else None
            kwargs: dict[str, Any] = {
                "n_results": request.top_k,
            }
            if where_filter:
                kwargs["where"] = where_filter
            if request.query_vector:
                kwargs["query_embeddings"] = [request.query_vector]
            elif request.query_text:
                kwargs["query_texts"] = [request.query_text]

            raw = collection.query(**kwargs)
            return self._normalize_chroma_results(raw)

        elif request.operation == VectorOperation.INSERT:
            if request.documents:
                ids = [d.get("id", f"doc_{i}") for i, d in enumerate(request.documents)]
                docs = [d.get("content", "") for d in request.documents]
                metadatas = [d.get("metadata", {}) for d in request.documents]
                collection.add(ids=ids, documents=docs, metadatas=metadatas)
            return []

        elif request.operation == VectorOperation.DELETE:
            if request.document_ids:
                collection.delete(ids=request.document_ids)
            return []

        return []

    def _normalize_chroma_results(self, raw: dict) -> list[dict[str, Any]]:
        docs = []
        if not raw or "ids" not in raw:
            return docs
        ids_list = raw["ids"][0] if raw["ids"] else []
        docs_list = raw.get("documents", [[]])[0] if raw.get("documents") else []
        meta_list = raw.get("metadatas", [[]])[0] if raw.get("metadatas") else []
        dist_list = raw.get("distances", [[]])[0] if raw.get("distances") else []

        for i, doc_id in enumerate(ids_list):
            doc = {
                "id": doc_id,
                "content": docs_list[i] if i < len(docs_list) else "",
                "metadata": meta_list[i] if i < len(meta_list) else {},
                "score": dist_list[i] if i < len(dist_list) else 0.0,
            }
            docs.append(doc)
        return docs

    def health_check(self) -> bool:
        try:
            if self._client:
                self._client.heartbeat()
                return True
        except Exception:
            pass
        return False


class PineconeAdapter(BaseVectorAdapter):
    """Adapter for Pinecone — supports gRPC and REST clients."""

    provider = VectorDBProvider.PINECONE

    def __init__(self, index: Any = None, api_key: str = "", environment: str = ""):
        self._index = index
        self._api_key = api_key
        self._environment = environment

    def execute(self, request: ProxyRequest) -> list[dict[str, Any]]:
        if self._index is None:
            logger.warning("Pinecone index not configured; returning empty results")
            return []

        if request.operation == VectorOperation.QUERY:
            kwargs: dict[str, Any] = {
                "top_k": request.top_k,
                "include_metadata": True,
            }
            if request.query_vector:
                kwargs["vector"] = request.query_vector
            if request.filters:
                kwargs["filter"] = self._translate_pinecone_filter(request.filters)
            if request.metadata.get("namespace"):
                kwargs["namespace"] = request.metadata["namespace"]

            raw = self._index.query(**kwargs)
            return self._normalize_pinecone_results(raw)

        elif request.operation == VectorOperation.INSERT:
            if request.documents:
                vectors = []
                for doc in request.documents:
                    vectors.append({
                        "id": doc.get("id", ""),
                        "values": doc.get("vector", []),
                        "metadata": doc.get("metadata", {}),
                    })
                self._index.upsert(vectors=vectors)
            return []

        elif request.operation == VectorOperation.DELETE:
            if request.document_ids:
                self._index.delete(ids=request.document_ids)
            return []

        return []

    def _translate_pinecone_filter(self, filters: dict) -> dict:
        """Translate flat key=value filters to Pinecone filter format."""
        pinecone_filter = {}
        for key, value in filters.items():
            pinecone_filter[key] = {"$eq": value}
        return pinecone_filter

    def _normalize_pinecone_results(self, raw: Any) -> list[dict[str, Any]]:
        docs = []
        matches = getattr(raw, "matches", []) if raw else []
        for match in matches:
            doc = {
                "id": getattr(match, "id", ""),
                "content": getattr(match, "metadata", {}).get("content", ""),
                "metadata": dict(getattr(match, "metadata", {})),
                "score": getattr(match, "score", 0.0),
            }
            docs.append(doc)
        return docs

    def health_check(self) -> bool:
        try:
            if self._index:
                self._index.describe_index_stats()
                return True
        except Exception:
            pass
        return False


class MilvusAdapter(BaseVectorAdapter):
    """Adapter for Milvus — supports PyMilvus client library."""

    provider = VectorDBProvider.MILVUS

    def __init__(self, connection: Any = None, host: str = "localhost", port: int = 19530):
        self._connection = connection
        self._host = host
        self._port = port

    def execute(self, request: ProxyRequest) -> list[dict[str, Any]]:
        if self._connection is None:
            logger.warning("Milvus connection not configured; returning empty results")
            return []

        if request.operation == VectorOperation.QUERY:
            # Build boolean expression for filter
            expr = self._build_milvus_expr(request.filters)
            search_params = {"metric_type": "L2", "params": {"nprobe": 10}}
            kwargs: dict[str, Any] = {
                "collection_name": request.collection_name,
                "data": [request.query_vector] if request.query_vector else [],
                "limit": request.top_k,
                "output_fields": ["*"],
                "search_params": search_params,
            }
            if expr:
                kwargs["filter"] = expr

            raw = self._connection.search(**kwargs)
            return self._normalize_milvus_results(raw)

        elif request.operation == VectorOperation.INSERT:
            if request.documents:
                self._connection.insert(
                    collection_name=request.collection_name,
                    data=request.documents,
                )
            return []

        elif request.operation == VectorOperation.DELETE:
            if request.document_ids:
                expr = f"id in {request.document_ids}"
                self._connection.delete(
                    collection_name=request.collection_name,
                    filter=expr,
                )
            return []

        return []

    def _build_milvus_expr(self, filters: dict) -> str:
        """Build Milvus boolean expression from flat filters."""
        parts = []
        for key, value in filters.items():
            if isinstance(value, str):
                parts.append(f'{key} == "{value}"')
            else:
                parts.append(f"{key} == {value}")
        return " and ".join(parts) if parts else ""

    def _normalize_milvus_results(self, raw: Any) -> list[dict[str, Any]]:
        docs = []
        if not raw:
            return docs
        # Milvus returns list of lists of hits
        hits = raw[0] if raw else []
        for hit in hits:
            entity = getattr(hit, "entity", {})
            doc = {
                "id": getattr(hit, "id", ""),
                "content": entity.get("content", "") if isinstance(entity, dict) else "",
                "metadata": dict(entity) if isinstance(entity, dict) else {},
                "score": getattr(hit, "distance", 0.0),
            }
            docs.append(doc)
        return docs

    def health_check(self) -> bool:
        try:
            if self._connection:
                self._connection.list_collections()
                return True
        except Exception:
            pass
        return False
