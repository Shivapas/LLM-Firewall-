"""Session Context Store for Multi-Turn Security — Sprint 29.

Maintain session context (last N turns, cumulative risk score) per
conversation.  Expire sessions on inactivity.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger("sphinx.session_security.context_store")


@dataclass
class TurnRecord:
    """A single turn in a conversation session."""
    turn_id: str = ""
    turn_number: int = 0
    risk_score: float = 0.0
    risk_level: str = "none"        # none, low, medium, high, critical
    matched_patterns: list[str] = field(default_factory=list)
    action_taken: str = "allowed"   # allowed, flagged, blocked
    input_preview: str = ""         # first 200 chars of user input (redacted)
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "turn_id": self.turn_id,
            "turn_number": self.turn_number,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_patterns": self.matched_patterns,
            "action_taken": self.action_taken,
            "input_preview": self.input_preview,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class SessionContext:
    """Context for a multi-turn conversation session."""
    session_id: str = ""
    tenant_id: str = ""
    agent_id: str = ""
    turns: list[TurnRecord] = field(default_factory=list)
    cumulative_risk_score: float = 0.0
    max_risk_level: str = "none"
    turn_count: int = 0
    is_escalated: bool = False
    escalation_reason: str = ""
    created_at: str = ""
    last_activity_at: str = ""
    expired: bool = False

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "turn_count": self.turn_count,
            "cumulative_risk_score": self.cumulative_risk_score,
            "max_risk_level": self.max_risk_level,
            "is_escalated": self.is_escalated,
            "escalation_reason": self.escalation_reason,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
            "expired": self.expired,
            "turns": [t.to_dict() for t in self.turns],
        }


class SessionContextStore:
    """Maintains per-session context for multi-turn security analysis.

    Features:
    - Track last N turns per session
    - Accumulate risk scores across turns
    - Expire sessions on inactivity
    - Support session enumeration for monitoring
    """

    def __init__(
        self,
        max_turns: int = 50,
        inactivity_timeout_seconds: int = 1800,  # 30 minutes
    ) -> None:
        self.max_turns = max_turns
        self.inactivity_timeout = timedelta(seconds=inactivity_timeout_seconds)
        self._sessions: dict[str, SessionContext] = {}
        self._stats: dict[str, int] = {
            "total_sessions": 0,
            "active_sessions": 0,
            "expired_sessions": 0,
            "total_turns": 0,
        }

    def get_or_create_session(
        self,
        session_id: str,
        tenant_id: str = "",
        agent_id: str = "",
    ) -> SessionContext:
        """Get existing session or create a new one."""
        if session_id in self._sessions:
            session = self._sessions[session_id]
            if not session.expired:
                # Check inactivity timeout
                last_activity = datetime.fromisoformat(session.last_activity_at)
                if datetime.now(timezone.utc) - last_activity > self.inactivity_timeout:
                    session.expired = True
                    self._stats["expired_sessions"] += 1
                    self._stats["active_sessions"] = max(0, self._stats["active_sessions"] - 1)
                    logger.info("Session expired due to inactivity: %s", session_id)
                    # Create new session with same ID
                    return self._create_session(session_id, tenant_id, agent_id)
                return session
            # Expired — create new
            return self._create_session(session_id, tenant_id, agent_id)

        return self._create_session(session_id, tenant_id, agent_id)

    def _create_session(self, session_id: str, tenant_id: str, agent_id: str) -> SessionContext:
        now = datetime.now(timezone.utc).isoformat()
        session = SessionContext(
            session_id=session_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            created_at=now,
            last_activity_at=now,
        )
        self._sessions[session_id] = session
        self._stats["total_sessions"] += 1
        self._stats["active_sessions"] += 1
        logger.info("New session created: %s tenant=%s agent=%s", session_id, tenant_id, agent_id)
        return session

    def record_turn(
        self,
        session_id: str,
        risk_score: float = 0.0,
        risk_level: str = "none",
        matched_patterns: list[str] | None = None,
        action_taken: str = "allowed",
        input_preview: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> TurnRecord:
        """Record a new turn in a session."""
        session = self._sessions.get(session_id)
        if session is None:
            session = self.get_or_create_session(session_id)

        now = datetime.now(timezone.utc).isoformat()
        session.turn_count += 1
        self._stats["total_turns"] += 1

        turn = TurnRecord(
            turn_id=str(uuid.uuid4()),
            turn_number=session.turn_count,
            risk_score=risk_score,
            risk_level=risk_level,
            matched_patterns=matched_patterns or [],
            action_taken=action_taken,
            input_preview=input_preview[:200] if input_preview else "",
            timestamp=now,
            metadata=metadata or {},
        )

        session.turns.append(turn)
        # Trim to max turns
        if len(session.turns) > self.max_turns:
            session.turns = session.turns[-self.max_turns:]

        # Update cumulative risk
        session.cumulative_risk_score += risk_score

        # Track max risk level
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if risk_order.get(risk_level, 0) > risk_order.get(session.max_risk_level, 0):
            session.max_risk_level = risk_level

        session.last_activity_at = now

        logger.debug(
            "Turn recorded: session=%s turn=%d risk=%.2f cumulative=%.2f",
            session_id, session.turn_count, risk_score, session.cumulative_risk_score,
        )
        return turn

    def get_session(self, session_id: str) -> SessionContext | None:
        return self._sessions.get(session_id)

    def expire_session(self, session_id: str) -> bool:
        """Manually expire a session."""
        session = self._sessions.get(session_id)
        if session and not session.expired:
            session.expired = True
            self._stats["expired_sessions"] += 1
            self._stats["active_sessions"] = max(0, self._stats["active_sessions"] - 1)
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired sessions from memory."""
        now = datetime.now(timezone.utc)
        expired_ids = []
        for sid, session in self._sessions.items():
            if session.expired:
                expired_ids.append(sid)
                continue
            last_activity = datetime.fromisoformat(session.last_activity_at)
            if now - last_activity > self.inactivity_timeout:
                session.expired = True
                self._stats["expired_sessions"] += 1
                self._stats["active_sessions"] = max(0, self._stats["active_sessions"] - 1)
                expired_ids.append(sid)

        for sid in expired_ids:
            del self._sessions[sid]

        if expired_ids:
            logger.info("Cleaned up %d expired sessions", len(expired_ids))
        return len(expired_ids)

    def list_sessions(self, tenant_id: str = "", active_only: bool = True) -> list[SessionContext]:
        """List sessions, optionally filtered by tenant."""
        sessions = list(self._sessions.values())
        if tenant_id:
            sessions = [s for s in sessions if s.tenant_id == tenant_id]
        if active_only:
            sessions = [s for s in sessions if not s.expired]
        return sessions

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def session_count(self) -> int:
        return len(self._sessions)


# ── Singleton ────────────────────────────────────────────────────────────

_store: SessionContextStore | None = None


def get_session_context_store(
    max_turns: int = 50,
    inactivity_timeout_seconds: int = 1800,
) -> SessionContextStore:
    global _store
    if _store is None:
        _store = SessionContextStore(max_turns, inactivity_timeout_seconds)
    return _store


def reset_session_context_store() -> None:
    global _store
    _store = None
