"""Cache-Hit Audit Logging — Sprint 30.

Log cache hits: original query hash, matched cache key, similarity score,
policy version at cache time.  Distinguish cache-served vs. model-served
responses in the audit trail.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.semantic_cache.audit")


class ResponseSource:
    CACHE = "cache"
    MODEL = "model"


@dataclass
class CacheAuditEntry:
    """Audit log entry for a cache event (hit or miss)."""
    audit_id: str = ""
    tenant_id: str = ""
    query_hash: str = ""
    response_source: str = "model"   # "cache" or "model"
    cache_key: str = ""              # matched entry_id if cache hit
    similarity_score: float = 0.0
    policy_version: str = ""
    model: str = ""
    lookup_time_ms: float = 0.0
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "tenant_id": self.tenant_id,
            "query_hash": self.query_hash,
            "response_source": self.response_source,
            "cache_key": self.cache_key,
            "similarity_score": self.similarity_score,
            "policy_version": self.policy_version,
            "model": self.model,
            "lookup_time_ms": self.lookup_time_ms,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class CacheAuditLogger:
    """Logs all cache lookup events for audit trail compliance.

    Every request gets an audit entry indicating whether the response
    was served from cache or from the upstream model.
    """

    def __init__(self) -> None:
        self._entries: list[CacheAuditEntry] = []
        self._stats: dict[str, int] = {
            "total_entries": 0,
            "cache_served": 0,
            "model_served": 0,
        }

    def log_cache_hit(
        self,
        tenant_id: str,
        query_hash: str,
        cache_key: str,
        similarity_score: float,
        policy_version: str = "",
        model: str = "",
        lookup_time_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> CacheAuditEntry:
        """Log a cache hit event."""
        entry = CacheAuditEntry(
            audit_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            query_hash=query_hash,
            response_source=ResponseSource.CACHE,
            cache_key=cache_key,
            similarity_score=similarity_score,
            policy_version=policy_version,
            model=model,
            lookup_time_ms=lookup_time_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        self._entries.append(entry)
        self._stats["total_entries"] += 1
        self._stats["cache_served"] += 1

        logger.info(
            "Cache HIT audit: tenant=%s hash=%s key=%s score=%.4f policy=%s",
            tenant_id, query_hash, cache_key, similarity_score, policy_version,
        )
        return entry

    def log_cache_miss(
        self,
        tenant_id: str,
        query_hash: str,
        best_similarity: float = 0.0,
        policy_version: str = "",
        model: str = "",
        lookup_time_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> CacheAuditEntry:
        """Log a cache miss event (response served from model)."""
        entry = CacheAuditEntry(
            audit_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            query_hash=query_hash,
            response_source=ResponseSource.MODEL,
            cache_key="",
            similarity_score=best_similarity,
            policy_version=policy_version,
            model=model,
            lookup_time_ms=lookup_time_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        self._entries.append(entry)
        self._stats["total_entries"] += 1
        self._stats["model_served"] += 1
        return entry

    def get_entries(
        self,
        tenant_id: str = "",
        response_source: str = "",
        limit: int = 100,
    ) -> list[CacheAuditEntry]:
        entries = self._entries
        if tenant_id:
            entries = [e for e in entries if e.tenant_id == tenant_id]
        if response_source:
            entries = [e for e in entries if e.response_source == response_source]
        return entries[-limit:]

    def get_stats(self) -> dict[str, Any]:
        stats = dict(self._stats)
        total = stats["cache_served"] + stats["model_served"]
        stats["cache_serve_rate"] = stats["cache_served"] / total if total > 0 else 0.0
        return stats

    def entry_count(self) -> int:
        return len(self._entries)


# ── Singleton ────────────────────────────────────────────────────────────

_logger: CacheAuditLogger | None = None


def get_cache_audit_logger() -> CacheAuditLogger:
    global _logger
    if _logger is None:
        _logger = CacheAuditLogger()
    return _logger


def reset_cache_audit_logger() -> None:
    global _logger
    _logger = None
