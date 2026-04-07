"""Semantic Cache Layer — Sprint 30.

Tenant-scoped semantic cache using embedding similarity.
Cache hit threshold configurable (default cosine similarity > 0.95).
Cache responses per policy-version + model combination.
"""

from __future__ import annotations

import hashlib
import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.semantic_cache.layer")


@dataclass
class CacheEntry:
    """A cached query-response pair."""
    entry_id: str = ""
    tenant_id: str = ""
    query_hash: str = ""
    query_text: str = ""
    response_text: str = ""
    model: str = ""
    policy_version: str = ""
    embedding: list[float] = field(default_factory=list)
    similarity_threshold: float = 0.95
    hit_count: int = 0
    created_at: str = ""
    last_hit_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "tenant_id": self.tenant_id,
            "query_hash": self.query_hash,
            "model": self.model,
            "policy_version": self.policy_version,
            "hit_count": self.hit_count,
            "created_at": self.created_at,
            "last_hit_at": self.last_hit_at,
            "metadata": self.metadata,
        }


@dataclass
class CacheLookupResult:
    """Result of a cache lookup."""
    is_hit: bool = False
    entry: CacheEntry | None = None
    similarity_score: float = 0.0
    cache_key: str = ""
    lookup_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "is_hit": self.is_hit,
            "entry": self.entry.to_dict() if self.entry else None,
            "similarity_score": self.similarity_score,
            "cache_key": self.cache_key,
            "lookup_time_ms": self.lookup_time_ms,
        }


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def simple_embedding(text: str, dim: int = 64) -> list[float]:
    """Simple deterministic embedding for demonstration.

    In production, this would use a real embedding model (e.g. text-embedding-ada-002).
    This uses character n-gram hashing to produce a stable vector.
    """
    vec = [0.0] * dim
    text_lower = text.lower().strip()
    for i in range(len(text_lower)):
        for n in range(1, 4):  # 1-gram, 2-gram, 3-gram
            if i + n <= len(text_lower):
                ngram = text_lower[i:i + n]
                h = int(hashlib.md5(ngram.encode()).hexdigest(), 16)
                idx = h % dim
                vec[idx] += 1.0

    # L2 normalize
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


class SemanticCacheLayer:
    """Tenant-scoped semantic cache with embedding-based similarity matching.

    Features:
    - Per-tenant namespace isolation
    - Configurable similarity threshold (default 0.95)
    - Cache keyed by policy_version + model combination
    - Automatic invalidation on policy change
    """

    def __init__(
        self,
        similarity_threshold: float = 0.95,
        max_entries_per_tenant: int = 10000,
        embedding_dim: int = 64,
    ) -> None:
        self.similarity_threshold = similarity_threshold
        self.max_entries_per_tenant = max_entries_per_tenant
        self.embedding_dim = embedding_dim
        # tenant_id -> list[CacheEntry]
        self._cache: dict[str, list[CacheEntry]] = {}
        self._stats: dict[str, int] = {
            "total_entries": 0,
            "total_lookups": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "evictions": 0,
        }

    def store(
        self,
        tenant_id: str,
        query_text: str,
        response_text: str,
        model: str = "",
        policy_version: str = "",
        embedding: list[float] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CacheEntry:
        """Store a query-response pair in the cache."""
        if embedding is None:
            embedding = simple_embedding(query_text, self.embedding_dim)

        query_hash = hashlib.sha256(query_text.encode()).hexdigest()[:16]
        now = datetime.now(timezone.utc).isoformat()

        entry = CacheEntry(
            entry_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            query_hash=query_hash,
            query_text=query_text,
            response_text=response_text,
            model=model,
            policy_version=policy_version,
            embedding=embedding,
            similarity_threshold=self.similarity_threshold,
            created_at=now,
            last_hit_at=now,
            metadata=metadata or {},
        )

        if tenant_id not in self._cache:
            self._cache[tenant_id] = []

        entries = self._cache[tenant_id]

        # Evict if at capacity
        if len(entries) >= self.max_entries_per_tenant:
            entries.pop(0)  # FIFO eviction
            self._stats["evictions"] += 1

        entries.append(entry)
        self._stats["total_entries"] += 1

        logger.debug(
            "Cache store: tenant=%s model=%s policy=%s hash=%s",
            tenant_id, model, policy_version, query_hash,
        )
        return entry

    def lookup(
        self,
        tenant_id: str,
        query_text: str,
        model: str = "",
        policy_version: str = "",
        embedding: list[float] | None = None,
    ) -> CacheLookupResult:
        """Look up a query in the tenant-scoped cache.

        Returns the best matching cached response if similarity >= threshold.
        Only matches entries with the same model + policy_version.
        """
        import time
        start = time.monotonic()

        self._stats["total_lookups"] += 1

        if embedding is None:
            embedding = simple_embedding(query_text, self.embedding_dim)

        entries = self._cache.get(tenant_id, [])
        query_hash = hashlib.sha256(query_text.encode()).hexdigest()[:16]

        best_entry: CacheEntry | None = None
        best_score = 0.0

        for entry in entries:
            # Must match model + policy version
            if model and entry.model != model:
                continue
            if policy_version and entry.policy_version != policy_version:
                continue

            score = cosine_similarity(embedding, entry.embedding)
            if score > best_score:
                best_score = score
                best_entry = entry

        elapsed = (time.monotonic() - start) * 1000

        if best_entry and best_score >= self.similarity_threshold:
            best_entry.hit_count += 1
            best_entry.last_hit_at = datetime.now(timezone.utc).isoformat()
            self._stats["cache_hits"] += 1

            logger.debug(
                "Cache HIT: tenant=%s score=%.4f hash=%s",
                tenant_id, best_score, query_hash,
            )
            return CacheLookupResult(
                is_hit=True,
                entry=best_entry,
                similarity_score=best_score,
                cache_key=best_entry.entry_id,
                lookup_time_ms=elapsed,
            )

        self._stats["cache_misses"] += 1
        return CacheLookupResult(
            is_hit=False,
            similarity_score=best_score,
            cache_key="",
            lookup_time_ms=elapsed,
        )

    def invalidate_tenant(self, tenant_id: str) -> int:
        """Invalidate all cache entries for a tenant."""
        entries = self._cache.pop(tenant_id, [])
        count = len(entries)
        self._stats["total_entries"] -= count
        logger.info("Cache invalidated: tenant=%s entries=%d", tenant_id, count)
        return count

    def invalidate_policy_version(self, tenant_id: str, policy_version: str) -> int:
        """Invalidate cache entries for a specific policy version."""
        entries = self._cache.get(tenant_id, [])
        before = len(entries)
        self._cache[tenant_id] = [
            e for e in entries if e.policy_version != policy_version
        ]
        removed = before - len(self._cache[tenant_id])
        self._stats["total_entries"] -= removed
        if removed:
            logger.info(
                "Cache invalidated for policy: tenant=%s policy=%s entries=%d",
                tenant_id, policy_version, removed,
            )
        return removed

    def get_tenant_entries(self, tenant_id: str) -> list[CacheEntry]:
        return self._cache.get(tenant_id, [])

    def get_cache_hit_rate(self) -> float:
        total = self._stats["cache_hits"] + self._stats["cache_misses"]
        return self._stats["cache_hits"] / total if total > 0 else 0.0

    def get_stats(self) -> dict[str, Any]:
        stats = dict(self._stats)
        stats["hit_rate"] = self.get_cache_hit_rate()
        stats["tenant_count"] = len(self._cache)
        return stats

    def entry_count(self, tenant_id: str = "") -> int:
        if tenant_id:
            return len(self._cache.get(tenant_id, []))
        return sum(len(v) for v in self._cache.values())


# ── Singleton ────────────────────────────────────────────────────────────

_cache: SemanticCacheLayer | None = None


def get_semantic_cache_layer(
    similarity_threshold: float = 0.95,
    max_entries_per_tenant: int = 10000,
) -> SemanticCacheLayer:
    global _cache
    if _cache is None:
        _cache = SemanticCacheLayer(similarity_threshold, max_entries_per_tenant)
    return _cache


def reset_semantic_cache_layer() -> None:
    global _cache
    _cache = None
