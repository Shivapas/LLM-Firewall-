"""Sprint 18: Tamper-evident hash chaining for audit records.

Each audit record includes a SHA-256 hash of its own content concatenated
with the hash of the previous record.  A verification API walks the chain
and detects any gaps, mutations, or deletions.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

logger = logging.getLogger("sphinx.audit.hashchain")

# Genesis hash — the "previous_hash" for the very first record in the chain.
GENESIS_HASH = "0" * 64


def compute_record_hash(
    event_id: str,
    timestamp: float,
    request_hash: str,
    tenant_id: str,
    model: str,
    policy_version: str,
    risk_score: float,
    action_taken: str,
    enforcement_duration_ms: float,
    previous_hash: str,
) -> str:
    """Compute a deterministic SHA-256 hash for one audit record.

    The hash covers the immutable audit fields plus the previous record's hash,
    forming a linked chain.
    """
    payload = json.dumps(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "request_hash": request_hash,
            "tenant_id": tenant_id,
            "model": model,
            "policy_version": policy_version,
            "risk_score": risk_score,
            "action_taken": action_taken,
            "enforcement_duration_ms": enforcement_duration_ms,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditHashChainService:
    """Manages the tamper-evident hash chain for audit records."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._last_hash: str = GENESIS_HASH
        self._sequence: int = 0

    async def initialize(self) -> None:
        """Load the latest hash from the database to resume the chain."""
        if not self._session_factory:
            return
        try:
            from app.models.api_key import AuditLog
            from sqlalchemy import select

            async with self._session_factory() as db:
                result = await db.execute(
                    select(AuditLog)
                    .where(AuditLog.record_hash != "")
                    .order_by(AuditLog.chain_sequence.desc())
                    .limit(1)
                )
                last_record = result.scalar_one_or_none()
                if last_record:
                    self._last_hash = last_record.record_hash
                    self._sequence = last_record.chain_sequence
                    logger.info(
                        "Hash chain resumed at sequence=%d hash=%s",
                        self._sequence,
                        self._last_hash[:16],
                    )
                else:
                    logger.info("Hash chain starting from genesis")
        except Exception:
            logger.warning("Failed to load hash chain state from DB", exc_info=True)

    def chain_event(self, event_dict: dict) -> dict:
        """Attach hash chain fields to an audit event dict.

        Mutates and returns the dict with previous_hash, record_hash,
        and chain_sequence set.
        """
        previous_hash = self._last_hash
        record_hash = compute_record_hash(
            event_id=event_dict.get("event_id", ""),
            timestamp=event_dict.get("timestamp", 0.0),
            request_hash=event_dict.get("request_hash", ""),
            tenant_id=event_dict.get("tenant_id", ""),
            model=event_dict.get("model", ""),
            policy_version=event_dict.get("policy_version", ""),
            risk_score=event_dict.get("risk_score", 0.0),
            action_taken=event_dict.get("action_taken", ""),
            enforcement_duration_ms=event_dict.get("enforcement_duration_ms", 0.0),
            previous_hash=previous_hash,
        )
        self._sequence += 1
        event_dict["previous_hash"] = previous_hash
        event_dict["record_hash"] = record_hash
        event_dict["chain_sequence"] = self._sequence

        self._last_hash = record_hash
        return event_dict

    async def verify_chain(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 10000,
    ) -> dict:
        """Verify the integrity of the audit hash chain.

        Returns a dict with:
        - valid: bool
        - records_checked: int
        - first_invalid_sequence: int | None
        - tamper_details: str
        """
        if not self._session_factory:
            return {"valid": False, "records_checked": 0, "first_invalid_sequence": None, "tamper_details": "No DB session"}

        from app.models.api_key import AuditLog
        from sqlalchemy import select

        async with self._session_factory() as db:
            query = (
                select(AuditLog)
                .where(AuditLog.record_hash != "")
                .order_by(AuditLog.chain_sequence.asc())
                .limit(limit)
            )
            if tenant_id:
                query = query.where(AuditLog.tenant_id == tenant_id)

            result = await db.execute(query)
            records = result.scalars().all()

        if not records:
            return {"valid": True, "records_checked": 0, "first_invalid_sequence": None, "tamper_details": ""}

        expected_prev = GENESIS_HASH
        for i, rec in enumerate(records):
            # Check chain linkage
            if rec.previous_hash != expected_prev:
                return {
                    "valid": False,
                    "records_checked": i + 1,
                    "first_invalid_sequence": rec.chain_sequence,
                    "tamper_details": f"Chain break at sequence {rec.chain_sequence}: expected previous_hash={expected_prev[:16]}... got {rec.previous_hash[:16]}...",
                }

            # Recompute and verify record hash
            expected_hash = compute_record_hash(
                event_id=str(rec.id),
                timestamp=rec.event_timestamp,
                request_hash=rec.request_hash,
                tenant_id=rec.tenant_id,
                model=rec.model,
                policy_version=rec.policy_version,
                risk_score=rec.risk_score,
                action_taken=rec.action_taken,
                enforcement_duration_ms=rec.enforcement_duration_ms,
                previous_hash=rec.previous_hash,
            )
            if rec.record_hash != expected_hash:
                return {
                    "valid": False,
                    "records_checked": i + 1,
                    "first_invalid_sequence": rec.chain_sequence,
                    "tamper_details": f"Record tampered at sequence {rec.chain_sequence}: hash mismatch",
                }

            expected_prev = rec.record_hash

        return {
            "valid": True,
            "records_checked": len(records),
            "first_invalid_sequence": None,
            "tamper_details": "",
        }


# Module-level singleton
_hash_chain_service: Optional[AuditHashChainService] = None


def get_hash_chain_service(session_factory=None) -> AuditHashChainService:
    global _hash_chain_service
    if _hash_chain_service is None:
        _hash_chain_service = AuditHashChainService(session_factory=session_factory)
    return _hash_chain_service
