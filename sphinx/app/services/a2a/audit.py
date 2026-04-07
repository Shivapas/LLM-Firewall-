"""A2A Audit Log — Sprint 27.

Per-message audit record for agent-to-agent communication:
- sender agent, receiver agent
- message content hash (never raw content)
- signature verified (bool)
- action taken (allowed / rejected_*)
- enforcement duration
- framework and session context

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
from typing import Any, Optional

logger = logging.getLogger("sphinx.a2a.audit")


@dataclass
class A2AAuditRecord:
    """Single immutable audit record for an A2A message."""
    record_id: str = ""
    timestamp: str = ""
    message_id: str = ""
    sender_agent_id: str = ""
    receiver_agent_id: str = ""
    content_hash: str = ""
    message_type: str = ""
    framework: str = ""
    session_id: str = ""
    correlation_id: str = ""
    signature_verified: bool = False
    token_valid: bool = False
    nonce_valid: bool = True
    mtls_verified: bool = False
    action_taken: str = ""
    reason: str = ""
    enforcement_duration_ms: float = 0.0
    previous_hash: str = ""
    record_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "sender_agent_id": self.sender_agent_id,
            "receiver_agent_id": self.receiver_agent_id,
            "content_hash": self.content_hash,
            "message_type": self.message_type,
            "framework": self.framework,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "signature_verified": self.signature_verified,
            "token_valid": self.token_valid,
            "nonce_valid": self.nonce_valid,
            "mtls_verified": self.mtls_verified,
            "action_taken": self.action_taken,
            "reason": self.reason,
            "enforcement_duration_ms": self.enforcement_duration_ms,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }

    def compute_hash(self) -> str:
        """Compute a tamper-evident hash over all fields except record_hash."""
        data = (
            f"{self.record_id}:{self.timestamp}:{self.message_id}:"
            f"{self.sender_agent_id}:{self.receiver_agent_id}:"
            f"{self.content_hash}:{self.signature_verified}:"
            f"{self.token_valid}:{self.nonce_valid}:{self.mtls_verified}:"
            f"{self.action_taken}:{self.previous_hash}"
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:32]


class A2AAuditLog:
    """Immutable audit log for A2A messages.

    Every intercepted message generates an audit record regardless of
    the enforcement action. Records are chained for tamper evidence.
    """

    def __init__(self):
        self._records: list[A2AAuditRecord] = []
        self._previous_hash: str = "0" * 32

    def record(self, message, result) -> A2AAuditRecord:
        """Create an audit record for an intercepted A2A message."""
        record = A2AAuditRecord(
            record_id=uuid.uuid4().hex[:16],
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_id=result.message_id,
            sender_agent_id=message.sender_agent_id,
            receiver_agent_id=message.receiver_agent_id,
            content_hash=message.content_hash(),
            message_type=message.message_type,
            framework=message.framework,
            session_id=message.session_id,
            correlation_id=message.correlation_id,
            signature_verified=result.signature_valid,
            token_valid=result.token_valid,
            nonce_valid=result.nonce_valid,
            mtls_verified=result.mtls_verified,
            action_taken=result.action.value if hasattr(result.action, "value") else str(result.action),
            reason=result.reason,
            enforcement_duration_ms=result.enforcement_duration_ms,
            previous_hash=self._previous_hash,
        )

        record.record_hash = record.compute_hash()
        self._previous_hash = record.record_hash
        self._records.append(record)

        logger.info(
            "A2A audit: %s -> %s action=%s sig=%s nonce=%s mtls=%s",
            record.sender_agent_id,
            record.receiver_agent_id,
            record.action_taken,
            record.signature_verified,
            record.nonce_valid,
            record.mtls_verified,
        )

        return record

    def get_records(
        self,
        sender_agent_id: str = "",
        receiver_agent_id: str = "",
        action: str = "",
        limit: int = 100,
    ) -> list[A2AAuditRecord]:
        """Query audit records with optional filters."""
        results = self._records
        if sender_agent_id:
            results = [r for r in results if r.sender_agent_id == sender_agent_id]
        if receiver_agent_id:
            results = [r for r in results if r.receiver_agent_id == receiver_agent_id]
        if action:
            results = [r for r in results if r.action_taken == action]
        return results[-limit:]

    def get_record_by_id(self, record_id: str) -> Optional[A2AAuditRecord]:
        for r in self._records:
            if r.record_id == record_id:
                return r
        return None

    def verify_chain_integrity(self) -> dict:
        """Verify the tamper-evident hash chain."""
        if not self._records:
            return {"valid": True, "checked": 0}

        expected_prev = "0" * 32
        for i, rec in enumerate(self._records):
            if rec.previous_hash != expected_prev:
                return {
                    "valid": False,
                    "broken_at": i,
                    "record_id": rec.record_id,
                    "reason": "Previous hash mismatch",
                }
            recomputed = rec.compute_hash()
            if rec.record_hash != recomputed:
                return {
                    "valid": False,
                    "broken_at": i,
                    "record_id": rec.record_id,
                    "reason": "Record hash tampered",
                }
            expected_prev = rec.record_hash

        return {"valid": True, "checked": len(self._records)}

    def count(self) -> int:
        return len(self._records)

    def get_stats(self) -> dict:
        actions = {}
        for r in self._records:
            actions[r.action_taken] = actions.get(r.action_taken, 0) + 1
        return {
            "total_records": len(self._records),
            "actions": actions,
        }

    def reset(self):
        self._records.clear()
        self._previous_hash = "0" * 32


# ── Singleton ────────────────────────────────────────────────────────────

_audit_log: Optional[A2AAuditLog] = None


def get_a2a_audit_log() -> A2AAuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = A2AAuditLog()
    return _audit_log


def reset_a2a_audit_log():
    global _audit_log
    _audit_log = None
