"""HITL Approval Workflow Service.

Manages the lifecycle of human-in-the-loop approval requests:
- Create approval request when policy triggers 'require_approval'
- List pending approvals
- Approve / reject with reason
- Auto-expire on timeout with configurable fallback (block or auto-approve)
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.hitl.approval_workflow")


@dataclass
class ApprovalRequestDTO:
    """In-memory representation of an approval request."""
    id: str
    agent_id: str
    tenant_id: str
    action_description: str
    risk_context: dict
    risk_level: str
    risk_score: float
    matched_patterns: list[str]
    status: str  # pending, approved, rejected, expired
    fallback_action: str  # block, auto-approve
    timeout_seconds: int
    notification_channels: list[str]
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    decided_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class ApprovalWorkflowService:
    """Manages HITL approval request lifecycle."""

    def __init__(self, notification_service=None):
        self._pending: dict[str, ApprovalRequestDTO] = {}
        self._history: list[ApprovalRequestDTO] = []
        self._notification_service = notification_service
        self._expiry_task: Optional[asyncio.Task] = None
        self._running = False

    async def start_expiry_monitor(self, interval_seconds: int = 10) -> None:
        """Start background task to expire timed-out approvals."""
        self._running = True
        self._expiry_task = asyncio.create_task(
            self._expiry_loop(interval_seconds)
        )
        logger.info("Approval expiry monitor started (interval=%ds)", interval_seconds)

    async def stop_expiry_monitor(self) -> None:
        """Stop the background expiry monitor."""
        self._running = False
        if self._expiry_task:
            self._expiry_task.cancel()
            try:
                await self._expiry_task
            except asyncio.CancelledError:
                pass
        logger.info("Approval expiry monitor stopped")

    async def _expiry_loop(self, interval: int) -> None:
        while self._running:
            try:
                await self._expire_timed_out()
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in approval expiry loop")
                await asyncio.sleep(interval)

    async def _expire_timed_out(self) -> None:
        """Check pending approvals and expire those past timeout."""
        now = datetime.now(timezone.utc)
        expired_ids = []
        for req_id, req in self._pending.items():
            if req.expires_at and now >= req.expires_at:
                expired_ids.append(req_id)

        for req_id in expired_ids:
            req = self._pending.pop(req_id)
            req.status = "expired"
            req.decided_at = now
            # Apply fallback action
            if req.fallback_action == "auto-approve":
                req.status = "approved"
                req.decided_by = "system:auto-approve"
                req.decision_reason = "Approval timeout expired; auto-approved per fallback policy"
                logger.info("Approval %s auto-approved on timeout", req_id)
            else:
                req.decided_by = "system:auto-block"
                req.decision_reason = "Approval timeout expired; blocked per fallback policy"
                logger.info("Approval %s expired and blocked", req_id)
            self._history.append(req)

    async def create_approval(
        self,
        agent_id: str,
        tenant_id: str,
        action_description: str,
        risk_context: dict,
        risk_level: str,
        risk_score: float,
        matched_patterns: list[str],
        fallback_action: str = "block",
        timeout_seconds: int = 300,
        notification_channels: list[str] | None = None,
    ) -> ApprovalRequestDTO:
        """Create a new approval request and notify approvers."""
        now = datetime.now(timezone.utc)
        req = ApprovalRequestDTO(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_description=action_description,
            risk_context=risk_context,
            risk_level=risk_level,
            risk_score=risk_score,
            matched_patterns=matched_patterns,
            status="pending",
            fallback_action=fallback_action,
            timeout_seconds=timeout_seconds,
            notification_channels=notification_channels or ["slack"],
            created_at=now,
            expires_at=now + timedelta(seconds=timeout_seconds),
        )
        self._pending[req.id] = req
        logger.info(
            "Approval request %s created for agent=%s tenant=%s risk=%s",
            req.id, agent_id, tenant_id, risk_level,
        )

        # Send notifications via configured channels
        if self._notification_service:
            await self._notification_service.send_approval_notification(req)

        return req

    async def list_pending(
        self, tenant_id: str | None = None
    ) -> list[ApprovalRequestDTO]:
        """List all pending approval requests, optionally filtered by tenant."""
        results = list(self._pending.values())
        if tenant_id:
            results = [r for r in results if r.tenant_id == tenant_id]
        return sorted(results, key=lambda r: r.created_at or datetime.min)

    async def get_approval(self, approval_id: str) -> Optional[ApprovalRequestDTO]:
        """Get a specific approval request by ID."""
        req = self._pending.get(approval_id)
        if req:
            return req
        # Check history
        for h in self._history:
            if h.id == approval_id:
                return h
        return None

    async def approve(
        self,
        approval_id: str,
        decided_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequestDTO]:
        """Approve a pending request."""
        req = self._pending.pop(approval_id, None)
        if not req:
            return None
        req.status = "approved"
        req.decided_by = decided_by
        req.decision_reason = reason
        req.decided_at = datetime.now(timezone.utc)
        self._history.append(req)
        logger.info("Approval %s approved by %s", approval_id, decided_by)
        return req

    async def reject(
        self,
        approval_id: str,
        decided_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequestDTO]:
        """Reject a pending request."""
        req = self._pending.pop(approval_id, None)
        if not req:
            return None
        req.status = "rejected"
        req.decided_by = decided_by
        req.decision_reason = reason
        req.decided_at = datetime.now(timezone.utc)
        self._history.append(req)
        logger.info("Approval %s rejected by %s", approval_id, decided_by)
        return req

    def pending_count(self) -> int:
        return len(self._pending)

    def history_count(self) -> int:
        return len(self._history)

    def to_dict(self, req: ApprovalRequestDTO) -> dict:
        """Serialize an approval request to a JSON-safe dict."""
        return {
            "id": req.id,
            "agent_id": req.agent_id,
            "tenant_id": req.tenant_id,
            "action_description": req.action_description,
            "risk_context": req.risk_context,
            "risk_level": req.risk_level,
            "risk_score": round(req.risk_score, 4),
            "matched_patterns": req.matched_patterns,
            "status": req.status,
            "fallback_action": req.fallback_action,
            "timeout_seconds": req.timeout_seconds,
            "notification_channels": req.notification_channels,
            "decided_by": req.decided_by,
            "decision_reason": req.decision_reason,
            "created_at": req.created_at.isoformat() if req.created_at else None,
            "decided_at": req.decided_at.isoformat() if req.decided_at else None,
            "expires_at": req.expires_at.isoformat() if req.expires_at else None,
        }


# ── Singleton ─────────────────────────────────────────────────────────

_approval_service: Optional[ApprovalWorkflowService] = None


def get_approval_workflow_service(
    notification_service=None,
) -> ApprovalWorkflowService:
    global _approval_service
    if _approval_service is None:
        _approval_service = ApprovalWorkflowService(
            notification_service=notification_service,
        )
    return _approval_service
