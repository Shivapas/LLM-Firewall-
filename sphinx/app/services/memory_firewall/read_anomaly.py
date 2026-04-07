"""Memory Read Anomaly Detection — Sprint 26.

Monitors agent memory read patterns and flags anomalies:
- Cross-agent memory access: reads of content written by a different agent.
- High-age stale reads: reads of memory chunks not accessed in
  anomaly-threshold days.

Each flagged read produces an anomaly alert record for dashboarding and
automated response.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.read_anomaly")


# ── Data Structures ─────────────────────────────────────────────────────


@dataclass
class MemoryReadRequest:
    """Represents an agent memory read operation."""
    reader_agent_id: str
    content_key: str
    namespace: str = ""
    backend: str = "redis"
    framework: str = "langchain"
    session_id: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class MemoryChunkMetadata:
    """Metadata about a stored memory chunk."""
    content_key: str
    writer_agent_id: str
    namespace: str = ""
    written_at: str = ""
    last_accessed_at: str = ""
    token_count: int = 0
    content_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "content_key": self.content_key,
            "writer_agent_id": self.writer_agent_id,
            "namespace": self.namespace,
            "written_at": self.written_at,
            "last_accessed_at": self.last_accessed_at,
            "token_count": self.token_count,
            "content_hash": self.content_hash,
        }


@dataclass
class ReadAnomalyAlert:
    """Alert record for an anomalous memory read."""
    alert_id: str = ""
    timestamp: str = ""
    reader_agent_id: str = ""
    content_key: str = ""
    anomaly_type: str = ""  # "cross_agent_read" | "stale_read"
    severity: str = "medium"  # "low" | "medium" | "high" | "critical"
    details: str = ""
    writer_agent_id: str = ""
    namespace: str = ""
    chunk_age_days: float = 0.0
    days_since_last_access: float = 0.0
    blocked: bool = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "reader_agent_id": self.reader_agent_id,
            "content_key": self.content_key,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "details": self.details,
            "writer_agent_id": self.writer_agent_id,
            "namespace": self.namespace,
            "chunk_age_days": self.chunk_age_days,
            "days_since_last_access": self.days_since_last_access,
            "blocked": self.blocked,
        }


# ── Read Anomaly Detector ──────────────────────────────────────────────


class ReadAnomalyDetector:
    """Detects anomalous agent memory read patterns.

    Maintains an in-memory registry of memory chunks and their ownership.
    On each read request, checks for:
    1. Cross-agent access (reader != writer and not explicitly permitted).
    2. Stale reads (content not accessed in more than ``stale_threshold_days``).
    """

    DEFAULT_STALE_THRESHOLD_DAYS = 30

    def __init__(self, stale_threshold_days: int = DEFAULT_STALE_THRESHOLD_DAYS):
        self._stale_threshold_days = stale_threshold_days
        # content_key -> MemoryChunkMetadata
        self._chunk_registry: dict[str, MemoryChunkMetadata] = {}
        self._alerts: list[ReadAnomalyAlert] = []
        self._stats: dict[str, int] = {
            "total_reads": 0,
            "cross_agent_reads": 0,
            "stale_reads": 0,
            "clean_reads": 0,
        }

    @property
    def stale_threshold_days(self) -> int:
        return self._stale_threshold_days

    @stale_threshold_days.setter
    def stale_threshold_days(self, value: int) -> None:
        self._stale_threshold_days = value

    # ── Chunk Registration ──────────────────────────────────────────────

    def register_chunk(
        self,
        content_key: str,
        writer_agent_id: str,
        namespace: str = "",
        token_count: int = 0,
        content_hash: str = "",
        written_at: str | None = None,
    ) -> MemoryChunkMetadata:
        """Register a memory chunk in the read-anomaly registry."""
        now = written_at or datetime.now(timezone.utc).isoformat()
        chunk = MemoryChunkMetadata(
            content_key=content_key,
            writer_agent_id=writer_agent_id,
            namespace=namespace,
            written_at=now,
            last_accessed_at=now,
            token_count=token_count,
            content_hash=content_hash,
        )
        self._chunk_registry[content_key] = chunk
        return chunk

    def get_chunk(self, content_key: str) -> MemoryChunkMetadata | None:
        return self._chunk_registry.get(content_key)

    def list_chunks(self, agent_id: str | None = None) -> list[MemoryChunkMetadata]:
        chunks = list(self._chunk_registry.values())
        if agent_id:
            chunks = [c for c in chunks if c.writer_agent_id == agent_id]
        return chunks

    def remove_chunk(self, content_key: str) -> bool:
        if content_key in self._chunk_registry:
            del self._chunk_registry[content_key]
            return True
        return False

    def chunk_count(self) -> int:
        return len(self._chunk_registry)

    # ── Read Interception ───────────────────────────────────────────────

    def check_read(
        self,
        request: MemoryReadRequest,
        permitted_cross_agents: set[str] | None = None,
    ) -> list[ReadAnomalyAlert]:
        """Check a memory read for anomalies.

        Returns a list of anomaly alerts (empty if read is clean).
        Updates chunk last_accessed_at on access.
        """
        self._stats["total_reads"] += 1
        alerts: list[ReadAnomalyAlert] = []

        chunk = self._chunk_registry.get(request.content_key)
        if chunk is None:
            # Unknown chunk — cannot evaluate anomalies
            self._stats["clean_reads"] += 1
            return alerts

        now = datetime.now(timezone.utc)
        permitted = permitted_cross_agents or set()

        # Check 1: Cross-agent read
        if (
            chunk.writer_agent_id != request.reader_agent_id
            and chunk.writer_agent_id not in permitted
        ):
            alert = ReadAnomalyAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=now.isoformat(),
                reader_agent_id=request.reader_agent_id,
                content_key=request.content_key,
                anomaly_type="cross_agent_read",
                severity="high",
                details=(
                    f"Agent '{request.reader_agent_id}' attempted to read memory "
                    f"written by agent '{chunk.writer_agent_id}'"
                ),
                writer_agent_id=chunk.writer_agent_id,
                namespace=chunk.namespace,
                blocked=False,
            )
            alerts.append(alert)
            self._alerts.append(alert)
            self._stats["cross_agent_reads"] += 1
            logger.warning(
                "Cross-agent memory read detected: reader=%s writer=%s key=%s",
                request.reader_agent_id,
                chunk.writer_agent_id,
                request.content_key,
            )

        # Check 2: Stale read
        last_accessed = datetime.fromisoformat(chunk.last_accessed_at)
        days_since_access = (now - last_accessed).total_seconds() / 86400
        if days_since_access > self._stale_threshold_days:
            written_at = datetime.fromisoformat(chunk.written_at)
            chunk_age_days = (now - written_at).total_seconds() / 86400
            alert = ReadAnomalyAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=now.isoformat(),
                reader_agent_id=request.reader_agent_id,
                content_key=request.content_key,
                anomaly_type="stale_read",
                severity="medium",
                details=(
                    f"Memory chunk '{request.content_key}' not accessed in "
                    f"{days_since_access:.1f} days (threshold: {self._stale_threshold_days})"
                ),
                writer_agent_id=chunk.writer_agent_id,
                namespace=chunk.namespace,
                chunk_age_days=chunk_age_days,
                days_since_last_access=days_since_access,
                blocked=False,
            )
            alerts.append(alert)
            self._alerts.append(alert)
            self._stats["stale_reads"] += 1
            logger.warning(
                "Stale memory read detected: key=%s days_since_access=%.1f threshold=%d",
                request.content_key,
                days_since_access,
                self._stale_threshold_days,
            )

        # Update last_accessed_at
        chunk.last_accessed_at = now.isoformat()

        if not alerts:
            self._stats["clean_reads"] += 1

        return alerts

    # ── Query ───────────────────────────────────────────────────────────

    def get_alerts(
        self,
        anomaly_type: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[ReadAnomalyAlert]:
        results = self._alerts
        if anomaly_type:
            results = [a for a in results if a.anomaly_type == anomaly_type]
        if agent_id:
            results = [a for a in results if a.reader_agent_id == agent_id]
        return results[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def alert_count(self) -> int:
        return len(self._alerts)

    def clear_alerts(self) -> int:
        count = len(self._alerts)
        self._alerts.clear()
        return count


# ── Singleton ────────────────────────────────────────────────────────────

_detector: ReadAnomalyDetector | None = None


def get_read_anomaly_detector() -> ReadAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = ReadAnomalyDetector()
    return _detector


def reset_read_anomaly_detector() -> None:
    global _detector
    _detector = None
