"""A2A Message Interception Layer — Sprint 27.

Intercepts agent-to-agent messages using the Agent2Agent (A2A) protocol.
Supports LangGraph, AutoGen multi-agent, and CrewAI orchestration frameworks.

Each intercepted message passes through:
1. Agent identity verification (JWT token validation)
2. Message signature verification (HMAC + nonce replay check)
3. mTLS channel enforcement
4. Audit logging

Messages from unregistered agents or with invalid credentials are rejected.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("sphinx.a2a.interceptor")


# ── Enums & Data Structures ──────────────────────────────────────────────


class FrameworkType(str, Enum):
    LANGGRAPH = "langgraph"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    CUSTOM = "custom"


class MessageAction(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REJECTED_UNREGISTERED = "rejected_unregistered"
    REJECTED_INVALID_SIGNATURE = "rejected_invalid_signature"
    REJECTED_REPLAY = "rejected_replay"
    REJECTED_EXPIRED_TOKEN = "rejected_expired_token"
    REJECTED_SCOPE_VIOLATION = "rejected_scope_violation"
    REJECTED_MTLS_REQUIRED = "rejected_mtls_required"


class MessageType(str, Enum):
    TASK = "task"
    RESULT = "result"
    STATUS = "status"
    ERROR = "error"
    CONTROL = "control"


@dataclass
class A2AMessage:
    """Represents an agent-to-agent message to be intercepted."""
    sender_agent_id: str
    receiver_agent_id: str
    content: str = ""
    message_type: str = "task"
    framework: str = "langgraph"
    session_id: str = ""
    correlation_id: str = ""
    jwt_token: str = ""
    signature: str = ""
    nonce: str = ""
    timestamp: float = 0.0
    metadata: dict = field(default_factory=dict)
    mtls_verified: bool = False
    sender_cert_fingerprint: str = ""

    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()[:32]

    def message_id(self) -> str:
        data = f"{self.sender_agent_id}:{self.receiver_agent_id}:{self.nonce}:{self.timestamp}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


@dataclass
class InterceptionResult:
    """Result of an A2A message interception."""
    message_id: str
    sender_agent_id: str
    receiver_agent_id: str
    action: MessageAction
    reason: str = ""
    token_valid: bool = False
    signature_valid: bool = False
    nonce_valid: bool = False
    mtls_verified: bool = False
    enforcement_duration_ms: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "sender_agent_id": self.sender_agent_id,
            "receiver_agent_id": self.receiver_agent_id,
            "action": self.action.value if isinstance(self.action, MessageAction) else self.action,
            "reason": self.reason,
            "token_valid": self.token_valid,
            "signature_valid": self.signature_valid,
            "nonce_valid": self.nonce_valid,
            "mtls_verified": self.mtls_verified,
            "enforcement_duration_ms": self.enforcement_duration_ms,
            "timestamp": self.timestamp,
        }


class A2AInterceptor:
    """Central A2A message interception layer.

    Orchestrates token validation, signature verification, nonce tracking,
    mTLS enforcement, and audit logging for every agent-to-agent message.
    """

    def __init__(
        self,
        token_issuer=None,
        signature_verifier=None,
        mtls_enforcer=None,
        audit_log=None,
    ):
        self._token_issuer = token_issuer
        self._signature_verifier = signature_verifier
        self._mtls_enforcer = mtls_enforcer
        self._audit_log = audit_log
        self._stats = {
            "total_intercepted": 0,
            "allowed": 0,
            "rejected": 0,
        }

    def set_token_issuer(self, token_issuer):
        self._token_issuer = token_issuer

    def set_signature_verifier(self, signature_verifier):
        self._signature_verifier = signature_verifier

    def set_mtls_enforcer(self, mtls_enforcer):
        self._mtls_enforcer = mtls_enforcer

    def set_audit_log(self, audit_log):
        self._audit_log = audit_log

    def intercept(self, message: A2AMessage) -> InterceptionResult:
        """Intercept and validate an A2A message through all security checks."""
        start = time.monotonic()
        self._stats["total_intercepted"] += 1

        msg_id = message.message_id()
        ts = datetime.now(timezone.utc).isoformat()

        # 1. Validate sender agent identity (JWT token)
        # Fail-closed: if security dependencies are not configured, reject all messages
        if not self._token_issuer:
            result = self._build_result(
                msg_id, message, MessageAction.REJECTED_UNREGISTERED,
                reason="A2A interceptor not configured: token issuer not available (fail-closed)",
                token_valid=False, start=start, ts=ts,
            )
            self._stats["rejected"] += 1
            self._record_audit(message, result)
            return result

        token_valid = False
        if self._token_issuer:
            token_result = self._token_issuer.validate_token(
                message.jwt_token, message.sender_agent_id
            )
            token_valid = token_result.get("valid", False)

            if not token_valid:
                # Distinguish expired tokens from unregistered agents
                if token_result.get("expired", False):
                    result = self._build_result(
                        msg_id, message, MessageAction.REJECTED_EXPIRED_TOKEN,
                        reason="Agent token has expired",
                        token_valid=False, start=start, ts=ts,
                    )
                else:
                    result = self._build_result(
                        msg_id, message, MessageAction.REJECTED_UNREGISTERED,
                        reason=token_result.get("reason", "Invalid or missing agent token"),
                        token_valid=False, start=start, ts=ts,
                    )
                self._record_audit(message, result)
                return result

            # Check scope: sender allowed to message receiver
            allowed_downstream = token_result.get("allowed_downstream", [])
            if allowed_downstream and message.receiver_agent_id not in allowed_downstream:
                if "*" not in allowed_downstream:
                    result = self._build_result(
                        msg_id, message, MessageAction.REJECTED_SCOPE_VIOLATION,
                        reason=f"Agent {message.sender_agent_id} not allowed to message {message.receiver_agent_id}",
                        token_valid=True, start=start, ts=ts,
                    )
                    self._record_audit(message, result)
                    return result

        # 2. Verify message signature
        signature_valid = False
        if self._signature_verifier:
            sig_result = self._signature_verifier.verify(message)
            signature_valid = sig_result.get("valid", False)

            if not signature_valid:
                # Distinguish replay attacks from signature failures
                nonce_valid = sig_result.get("nonce_valid", True)
                if not nonce_valid:
                    result = self._build_result(
                        msg_id, message, MessageAction.REJECTED_REPLAY,
                        reason="Replay attack detected: nonce already used",
                        token_valid=token_valid, signature_valid=False,
                        nonce_valid=False, start=start, ts=ts,
                    )
                else:
                    result = self._build_result(
                        msg_id, message, MessageAction.REJECTED_INVALID_SIGNATURE,
                        reason=sig_result.get("reason", "Invalid message signature"),
                        token_valid=token_valid, signature_valid=False,
                        start=start, ts=ts,
                    )
                self._record_audit(message, result)
                return result

        # 3. Enforce mTLS
        mtls_verified = message.mtls_verified
        if self._mtls_enforcer:
            mtls_result = self._mtls_enforcer.verify_channel(message)
            mtls_verified = mtls_result.get("verified", False)

            if not mtls_verified and self._mtls_enforcer.is_required(
                message.sender_agent_id, message.receiver_agent_id
            ):
                result = self._build_result(
                    msg_id, message, MessageAction.REJECTED_MTLS_REQUIRED,
                    reason="mTLS required but not established between agents",
                    token_valid=token_valid, signature_valid=signature_valid,
                    nonce_valid=True, mtls_verified=False,
                    start=start, ts=ts,
                )
                self._record_audit(message, result)
                return result

        # All checks passed
        self._stats["allowed"] += 1
        result = self._build_result(
            msg_id, message, MessageAction.ALLOWED,
            reason="All security checks passed",
            token_valid=token_valid, signature_valid=signature_valid,
            nonce_valid=True, mtls_verified=mtls_verified,
            start=start, ts=ts,
        )
        self._record_audit(message, result)
        return result

    def _build_result(
        self, msg_id, message, action, reason="",
        token_valid=False, signature_valid=False,
        nonce_valid=True, mtls_verified=False,
        start=0.0, ts="",
    ) -> InterceptionResult:
        if action != MessageAction.ALLOWED:
            self._stats["rejected"] += 1
        elapsed = (time.monotonic() - start) * 1000
        return InterceptionResult(
            message_id=msg_id,
            sender_agent_id=message.sender_agent_id,
            receiver_agent_id=message.receiver_agent_id,
            action=action,
            reason=reason,
            token_valid=token_valid,
            signature_valid=signature_valid,
            nonce_valid=nonce_valid,
            mtls_verified=mtls_verified,
            enforcement_duration_ms=round(elapsed, 3),
            timestamp=ts,
        )

    def _record_audit(self, message: A2AMessage, result: InterceptionResult):
        if self._audit_log:
            self._audit_log.record(message, result)

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset(self):
        self._stats = {"total_intercepted": 0, "allowed": 0, "rejected": 0}


# ── Singleton ────────────────────────────────────────────────────────────

_interceptor: Optional[A2AInterceptor] = None


def get_a2a_interceptor() -> A2AInterceptor:
    global _interceptor
    if _interceptor is None:
        _interceptor = A2AInterceptor()
    return _interceptor


def reset_a2a_interceptor():
    global _interceptor
    _interceptor = None
