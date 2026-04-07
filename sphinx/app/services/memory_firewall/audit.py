"""Memory Write Audit Log — Sprint 25.

Immutable per-write audit record:
- agent_id, session_id
- content_hash (SHA-256 of content, never the raw content)
- scanner verdict and matched patterns
- action taken (allowed / blocked / quarantined / pending_approval)
- enforcement duration

Records form a tamper-evident chain via previous_hash / record_hash,
consistent with the Sprint 18 audit pattern.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.audit")


@dataclass
class MemoryWriteAuditRecord:
    """Single immutable audit record for a memory write operation."""
    record_id: str = ""
    timestamp: str = ""
    request_id: str = ""
    agent_id: str = ""
    session_id: str = ""
    content_hash: str = ""
    content_key: str = ""
    backend: str = ""
    framework: str = ""
    namespace: str = ""
    scanner_verdict: str = ""  # "clean" | "suspicious"
    scanner_score: float = 0.0
    matched_patterns: list[str] = field(default_factory=list)
    action_taken: str = ""  # allowed | blocked | quarantined | pending_approval
    reason: str = ""
    enforcement_duration_ms: float = 0.0
    previous_hash: str = ""
    record_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "content_hash": self.content_hash,
            "content_key": self.content_key,
            "backend": self.backend,
            "framework": self.framework,
            "namespace": self.namespace,
            "scanner_verdict": self.scanner_verdict,
            "scanner_score": self.scanner_score,
            "matched_patterns": self.matched_patterns,
            "action_taken": self.action_taken,
            "reason": self.reason,
            "enforcement_duration_ms": self.enforcement_duration_ms,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }

    def compute_hash(self) -> str:
        """Compute a tamper-evident hash over all fields except record_hash."""
        data = (
            f"{self.record_id}:{self.timestamp}:{self.request_id}:"
            f"{self.agent_id}:{self.session_id}:{self.content_hash}:"
            f"{self.scanner_verdict}:{self.scanner_score}:"
            f"{self.action_taken}:{self.previous_hash}"
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:32]


class MemoryWriteAuditLog:
    """In-memory tamper-evident audit log for memory write operations.

    Maintains a hash chain: each record's ``previous_hash`` references the
    ``record_hash`` of the preceding entry, enabling integrity verification.
    """

    def __init__(self) -> None:
        self._records: list[MemoryWriteAuditRecord] = []
        self._last_hash: str = "genesis"

    def record_write(
        self,
        request_id: str,
        agent_id: str,
        session_id: str = "",
        content_hash: str = "",
        content_key: str = "",
        backend: str = "",
        framework: str = "",
        namespace: str = "",
        scanner_verdict: str = "clean",
        scanner_score: float = 0.0,
        matched_patterns: list[str] | None = None,
        action_taken: str = "allowed",
        reason: str = "",
        enforcement_duration_ms: float = 0.0,
    ) -> MemoryWriteAuditRecord:
        """Create and append an immutable audit record."""
        record = MemoryWriteAuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            agent_id=agent_id,
            session_id=session_id,
            content_hash=content_hash,
            content_key=content_key,
            backend=backend,
            framework=framework,
            namespace=namespace,
            scanner_verdict=scanner_verdict,
            scanner_score=scanner_score,
            matched_patterns=matched_patterns or [],
            action_taken=action_taken,
            reason=reason,
            enforcement_duration_ms=enforcement_duration_ms,
            previous_hash=self._last_hash,
        )
        record.record_hash = record.compute_hash()
        self._last_hash = record.record_hash

        self._records.append(record)
        logger.info(
            "Memory write audit: agent=%s action=%s verdict=%s hash=%s",
            agent_id,
            action_taken,
            scanner_verdict,
            record.record_hash,
        )
        return record

    def get_records(
        self,
        agent_id: str | None = None,
        action_taken: str | None = None,
        limit: int = 100,
    ) -> list[MemoryWriteAuditRecord]:
        """Query audit records with optional filters."""
        results = self._records
        if agent_id:
            results = [r for r in results if r.agent_id == agent_id]
        if action_taken:
            results = [r for r in results if r.action_taken == action_taken]
        return results[-limit:]

    def get_record_by_id(self, record_id: str) -> MemoryWriteAuditRecord | None:
        """Look up a single audit record by its ID."""
        for r in self._records:
            if r.record_id == record_id:
                return r
        return None

    def verify_chain_integrity(self) -> tuple[bool, str]:
        """Verify the hash chain integrity of all records.

        Returns (is_valid, message).
        """
        if not self._records:
            return True, "No records to verify"

        expected_prev = "genesis"
        for i, record in enumerate(self._records):
            if record.previous_hash != expected_prev:
                return False, (
                    f"Chain broken at record {i} ({record.record_id}): "
                    f"expected previous_hash={expected_prev}, got {record.previous_hash}"
                )
            computed = record.compute_hash()
            if record.record_hash != computed:
                return False, (
                    f"Tampered record at index {i} ({record.record_id}): "
                    f"stored hash={record.record_hash}, computed={computed}"
                )
            expected_prev = record.record_hash

        return True, f"Chain valid: {len(self._records)} records verified"

    def count(self) -> int:
        return len(self._records)

    def count_by_action(self) -> dict[str, int]:
        """Return record counts grouped by action_taken."""
        counts: dict[str, int] = {}
        for r in self._records:
            counts[r.action_taken] = counts.get(r.action_taken, 0) + 1
        return counts

    def count_by_agent(self) -> dict[str, int]:
        """Return record counts grouped by agent_id."""
        counts: dict[str, int] = {}
        for r in self._records:
            counts[r.agent_id] = counts.get(r.agent_id, 0) + 1
        return counts


# ── Singleton ────────────────────────────────────────────────────────────

_audit_log: MemoryWriteAuditLog | None = None


def get_memory_write_audit_log() -> MemoryWriteAuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = MemoryWriteAuditLog()
    return _audit_log


def reset_memory_write_audit_log() -> None:
    global _audit_log
    _audit_log = None
