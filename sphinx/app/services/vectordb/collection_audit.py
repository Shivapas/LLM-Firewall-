"""Collection-Level Audit Log — per-collection query audit with full traceability.

Sprint 10: Vector DB Firewall Hardening & Observability.

Records for every governed query:
- Query hash (deterministic, for dedup)
- Namespace filter applied
- Chunks returned vs chunks blocked
- Anomaly score
- Compliance tags applied
- Latency
"""

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("sphinx.vectordb.collection_audit")


@dataclass
class CollectionAuditEntry:
    """A single audit log entry for a governed vector DB query."""
    audit_id: str = ""
    timestamp: float = 0.0
    collection_name: str = ""
    tenant_id: str = ""
    operation: str = ""
    query_hash: str = ""
    # Namespace enforcement
    namespace_field: str = ""
    namespace_value: str = ""
    namespace_injected: bool = False
    # Results
    chunks_returned: int = 0
    chunks_blocked: int = 0
    results_capped: bool = False
    original_top_k: int = 0
    enforced_top_k: int = 0
    # Scanning
    injection_blocks: int = 0
    sensitive_field_blocks: int = 0
    # Anomaly
    anomaly_score: float = 0.0
    anomaly_detected: bool = False
    # Compliance
    compliance_tags: dict[str, int] = field(default_factory=dict)
    requires_private_model: bool = False
    # Performance
    latency_ms: float = 0.0
    # Provider
    provider: str = ""
    # Action taken
    action: str = "allowed"  # allowed, blocked, monitored

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "collection_name": self.collection_name,
            "tenant_id": self.tenant_id,
            "operation": self.operation,
            "query_hash": self.query_hash,
            "namespace_field": self.namespace_field,
            "namespace_value": self.namespace_value,
            "namespace_injected": self.namespace_injected,
            "chunks_returned": self.chunks_returned,
            "chunks_blocked": self.chunks_blocked,
            "results_capped": self.results_capped,
            "original_top_k": self.original_top_k,
            "enforced_top_k": self.enforced_top_k,
            "injection_blocks": self.injection_blocks,
            "sensitive_field_blocks": self.sensitive_field_blocks,
            "anomaly_score": round(self.anomaly_score, 6),
            "anomaly_detected": self.anomaly_detected,
            "compliance_tags": self.compliance_tags,
            "requires_private_model": self.requires_private_model,
            "latency_ms": round(self.latency_ms, 2),
            "provider": self.provider,
            "action": self.action,
        }


def compute_query_hash(
    collection_name: str,
    tenant_id: str,
    operation: str,
    filters: dict,
    query_text: Optional[str] = None,
) -> str:
    """Compute deterministic hash for a vector DB query."""
    data = json.dumps({
        "collection": collection_name,
        "tenant": tenant_id,
        "op": operation,
        "filters": filters,
        "query": query_text or "",
    }, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()[:32]


class CollectionAuditLog:
    """Per-collection audit log that records every governed query.

    Stores entries in memory with periodic flush to persistent storage.
    Provides query interface for the admin dashboard.
    """

    def __init__(self, max_buffer_size: int = 10000):
        self._buffer: list[CollectionAuditEntry] = []
        self._max_buffer_size = max_buffer_size
        self._total_entries = 0
        # Per-collection stats
        self._collection_stats: dict[str, dict[str, Any]] = {}

    def record(self, entry: CollectionAuditEntry) -> None:
        """Record a new audit entry."""
        if not entry.audit_id:
            entry.audit_id = str(uuid.uuid4())
        if entry.timestamp == 0.0:
            entry.timestamp = time.time()

        self._buffer.append(entry)
        self._total_entries += 1

        # Update per-collection stats
        cname = entry.collection_name
        if cname not in self._collection_stats:
            self._collection_stats[cname] = {
                "total_queries": 0,
                "total_blocked": 0,
                "total_chunks_returned": 0,
                "total_chunks_blocked": 0,
                "total_anomalies": 0,
                "total_injection_blocks": 0,
                "avg_latency_ms": 0.0,
                "last_query_at": 0.0,
                "tenants": set(),
            }
        stats = self._collection_stats[cname]
        stats["total_queries"] += 1
        if entry.action == "blocked":
            stats["total_blocked"] += 1
        stats["total_chunks_returned"] += entry.chunks_returned
        stats["total_chunks_blocked"] += entry.chunks_blocked
        if entry.anomaly_detected:
            stats["total_anomalies"] += 1
        stats["total_injection_blocks"] += entry.injection_blocks
        # Running average latency
        n = stats["total_queries"]
        stats["avg_latency_ms"] = (
            stats["avg_latency_ms"] * (n - 1) + entry.latency_ms
        ) / n
        stats["last_query_at"] = entry.timestamp
        stats["tenants"].add(entry.tenant_id)

        # Trim buffer if too large
        if len(self._buffer) > self._max_buffer_size:
            self._buffer = self._buffer[-self._max_buffer_size:]

        logger.debug(
            "Audit entry: collection=%s tenant=%s op=%s action=%s chunks=%d blocked=%d",
            entry.collection_name, entry.tenant_id, entry.operation,
            entry.action, entry.chunks_returned, entry.chunks_blocked,
        )

    def get_entries(
        self,
        collection_name: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CollectionAuditEntry]:
        """Query audit entries with optional filters."""
        filtered = self._buffer
        if collection_name:
            filtered = [e for e in filtered if e.collection_name == collection_name]
        if tenant_id:
            filtered = [e for e in filtered if e.tenant_id == tenant_id]

        # Most recent first
        filtered = list(reversed(filtered))
        return filtered[offset: offset + limit]

    def get_collection_stats(self, collection_name: Optional[str] = None) -> dict[str, Any]:
        """Get aggregated stats per collection."""
        if collection_name:
            stats = self._collection_stats.get(collection_name, {})
            if stats:
                return {
                    collection_name: {
                        **{k: v for k, v in stats.items() if k != "tenants"},
                        "unique_tenants": len(stats.get("tenants", set())),
                    }
                }
            return {}

        result = {}
        for cname, stats in self._collection_stats.items():
            result[cname] = {
                **{k: v for k, v in stats.items() if k != "tenants"},
                "unique_tenants": len(stats.get("tenants", set())),
            }
        return result

    def get_tenant_stats(self, collection_name: str) -> dict[str, Any]:
        """Get per-tenant query volume for a collection."""
        tenant_counts: dict[str, int] = {}
        tenant_blocked: dict[str, int] = {}
        for entry in self._buffer:
            if entry.collection_name == collection_name:
                tenant_counts[entry.tenant_id] = tenant_counts.get(entry.tenant_id, 0) + 1
                if entry.action == "blocked":
                    tenant_blocked[entry.tenant_id] = tenant_blocked.get(entry.tenant_id, 0) + 1

        return {
            tid: {"query_count": count, "blocked_count": tenant_blocked.get(tid, 0)}
            for tid, count in tenant_counts.items()
        }

    def get_anomaly_timeline(
        self,
        collection_name: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get timeline of anomaly events."""
        anomalies = [
            e for e in self._buffer
            if e.anomaly_detected
            and (collection_name is None or e.collection_name == collection_name)
        ]
        anomalies = list(reversed(anomalies))[:limit]
        return [
            {
                "audit_id": a.audit_id,
                "timestamp": a.timestamp,
                "collection_name": a.collection_name,
                "tenant_id": a.tenant_id,
                "anomaly_score": a.anomaly_score,
            }
            for a in anomalies
        ]

    def flush(self) -> list[CollectionAuditEntry]:
        """Flush buffer and return all entries for persistence."""
        entries = list(self._buffer)
        self._buffer.clear()
        return entries

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    @property
    def total_entries(self) -> int:
        return self._total_entries


# ── Singleton ──────────────────────────────────────────────────────────

_audit_log: Optional[CollectionAuditLog] = None


def get_collection_audit_log() -> CollectionAuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = CollectionAuditLog()
    return _audit_log


def reset_collection_audit_log() -> None:
    global _audit_log
    _audit_log = None
