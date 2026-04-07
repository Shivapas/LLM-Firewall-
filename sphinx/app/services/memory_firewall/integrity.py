"""Memory Integrity Verification — Sprint 26.

Periodic hash-chain verification on stored memory records.  Detects
post-write tampering.  Alerts on integrity failure.

Works alongside the Sprint 25 audit hash-chain but focuses specifically
on the stored memory *content* records rather than the audit trail.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.integrity")


# ── Data Structures ─────────────────────────────────────────────────────


@dataclass
class MemoryRecord:
    """A stored memory record subject to integrity verification."""
    record_id: str = ""
    agent_id: str = ""
    content_key: str = ""
    namespace: str = ""
    content_hash: str = ""  # SHA-256 of content at write time
    created_at: str = ""
    previous_hash: str = ""
    record_hash: str = ""

    def compute_hash(self) -> str:
        """Compute integrity hash over immutable fields."""
        data = (
            f"{self.record_id}:{self.agent_id}:{self.content_key}:"
            f"{self.namespace}:{self.content_hash}:{self.created_at}:"
            f"{self.previous_hash}"
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "agent_id": self.agent_id,
            "content_key": self.content_key,
            "namespace": self.namespace,
            "content_hash": self.content_hash,
            "created_at": self.created_at,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


@dataclass
class IntegrityAlert:
    """Alert produced when integrity verification fails."""
    alert_id: str = ""
    timestamp: str = ""
    record_id: str = ""
    agent_id: str = ""
    content_key: str = ""
    failure_type: str = ""  # "hash_mismatch" | "chain_break" | "missing_record"
    expected_hash: str = ""
    actual_hash: str = ""
    details: str = ""
    severity: str = "critical"

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "record_id": self.record_id,
            "agent_id": self.agent_id,
            "content_key": self.content_key,
            "failure_type": self.failure_type,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "details": self.details,
            "severity": self.severity,
        }


@dataclass
class VerificationResult:
    """Result of an integrity verification run."""
    run_id: str = ""
    timestamp: str = ""
    records_checked: int = 0
    records_valid: int = 0
    records_tampered: int = 0
    chain_valid: bool = True
    alerts: list[IntegrityAlert] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "records_checked": self.records_checked,
            "records_valid": self.records_valid,
            "records_tampered": self.records_tampered,
            "chain_valid": self.chain_valid,
            "alerts": [a.to_dict() for a in self.alerts],
        }


# ── Memory Integrity Verifier ──────────────────────────────────────────


class MemoryIntegrityVerifier:
    """Maintains and verifies a hash-chain over stored memory records.

    Each record's ``previous_hash`` references the ``record_hash`` of the
    preceding entry.  Periodic verification detects:
    - Hash mismatch (post-write tampering of individual records).
    - Chain break (insertion, deletion, or reordering of records).
    """

    def __init__(self) -> None:
        self._records: list[MemoryRecord] = []
        self._last_hash: str = "genesis"
        self._alerts: list[IntegrityAlert] = []
        self._verification_history: list[VerificationResult] = []
        self._stats: dict[str, int] = {
            "total_records": 0,
            "verification_runs": 0,
            "tampering_detected": 0,
        }

    # ── Record Management ───────────────────────────────────────────────

    def add_record(
        self,
        agent_id: str,
        content_key: str,
        content_hash: str,
        namespace: str = "",
    ) -> MemoryRecord:
        """Add a new memory record to the integrity chain."""
        record = MemoryRecord(
            record_id=str(uuid.uuid4()),
            agent_id=agent_id,
            content_key=content_key,
            namespace=namespace,
            content_hash=content_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
            previous_hash=self._last_hash,
        )
        record.record_hash = record.compute_hash()
        self._last_hash = record.record_hash
        self._records.append(record)
        self._stats["total_records"] += 1

        logger.info(
            "Memory integrity record added: agent=%s key=%s hash=%s",
            agent_id,
            content_key,
            record.record_hash,
        )
        return record

    def get_records(
        self,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[MemoryRecord]:
        results = self._records
        if agent_id:
            results = [r for r in results if r.agent_id == agent_id]
        return results[-limit:]

    def record_count(self) -> int:
        return len(self._records)

    # ── Verification ────────────────────────────────────────────────────

    def verify_integrity(self) -> VerificationResult:
        """Run a full integrity verification over all records.

        Checks:
        1. Each record's hash matches its computed hash (tamper detection).
        2. Each record's previous_hash matches the preceding record's
           record_hash (chain integrity).
        """
        run_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        alerts: list[IntegrityAlert] = []

        self._stats["verification_runs"] += 1

        if not self._records:
            result = VerificationResult(
                run_id=run_id,
                timestamp=now,
                records_checked=0,
                records_valid=0,
                chain_valid=True,
            )
            self._verification_history.append(result)
            return result

        expected_prev = "genesis"
        records_valid = 0

        for i, record in enumerate(self._records):
            # Check chain link
            if record.previous_hash != expected_prev:
                alert = IntegrityAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=now,
                    record_id=record.record_id,
                    agent_id=record.agent_id,
                    content_key=record.content_key,
                    failure_type="chain_break",
                    expected_hash=expected_prev,
                    actual_hash=record.previous_hash,
                    details=(
                        f"Chain broken at record index {i}: "
                        f"expected previous_hash={expected_prev}, "
                        f"got {record.previous_hash}"
                    ),
                )
                alerts.append(alert)
                self._alerts.append(alert)
                self._stats["tampering_detected"] += 1
                logger.critical(
                    "Memory integrity chain break: index=%d record=%s",
                    i,
                    record.record_id,
                )

            # Check record hash
            computed = record.compute_hash()
            if record.record_hash != computed:
                alert = IntegrityAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=now,
                    record_id=record.record_id,
                    agent_id=record.agent_id,
                    content_key=record.content_key,
                    failure_type="hash_mismatch",
                    expected_hash=computed,
                    actual_hash=record.record_hash,
                    details=(
                        f"Record tampered at index {i}: "
                        f"stored hash={record.record_hash}, "
                        f"computed={computed}"
                    ),
                )
                alerts.append(alert)
                self._alerts.append(alert)
                self._stats["tampering_detected"] += 1
                logger.critical(
                    "Memory integrity hash mismatch: index=%d record=%s",
                    i,
                    record.record_id,
                )
            else:
                records_valid += 1

            expected_prev = record.record_hash

        result = VerificationResult(
            run_id=run_id,
            timestamp=now,
            records_checked=len(self._records),
            records_valid=records_valid,
            records_tampered=len(alerts),
            chain_valid=len(alerts) == 0,
            alerts=alerts,
        )
        self._verification_history.append(result)

        logger.info(
            "Memory integrity verification: checked=%d valid=%d tampered=%d chain_valid=%s",
            result.records_checked,
            result.records_valid,
            result.records_tampered,
            result.chain_valid,
        )
        return result

    # ── Simulate Tampering (for testing) ────────────────────────────────

    def simulate_tamper(self, record_index: int, new_content_hash: str) -> bool:
        """Simulate post-write tampering by modifying a record's content_hash.

        FOR TESTING ONLY.  Does not recompute the record_hash, so the next
        verification will detect the tampering.
        """
        if 0 <= record_index < len(self._records):
            self._records[record_index].content_hash = new_content_hash
            logger.warning("Simulated tampering on record index %d", record_index)
            return True
        return False

    # ── Query ───────────────────────────────────────────────────────────

    def get_alerts(self, limit: int = 100) -> list[IntegrityAlert]:
        return self._alerts[-limit:]

    def get_verification_history(self, limit: int = 20) -> list[VerificationResult]:
        return self._verification_history[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def alert_count(self) -> int:
        return len(self._alerts)


# ── Singleton ────────────────────────────────────────────────────────────

_verifier: MemoryIntegrityVerifier | None = None


def get_memory_integrity_verifier() -> MemoryIntegrityVerifier:
    global _verifier
    if _verifier is None:
        _verifier = MemoryIntegrityVerifier()
    return _verifier


def reset_memory_integrity_verifier() -> None:
    global _verifier
    _verifier = None
