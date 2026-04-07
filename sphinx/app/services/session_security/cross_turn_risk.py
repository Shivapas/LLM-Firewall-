"""Cross-Turn Risk Accumulation — Sprint 29.

Accumulate risk score across turns in a session.  Trigger escalated
action (block or HITL) when session-level cumulative score exceeds
threshold.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.session_security.context_store import (
    SessionContext,
    SessionContextStore,
    get_session_context_store,
)

logger = logging.getLogger("sphinx.session_security.cross_turn_risk")


@dataclass
class EscalationEvent:
    """Event produced when cumulative risk triggers escalation."""
    event_id: str = ""
    session_id: str = ""
    tenant_id: str = ""
    agent_id: str = ""
    cumulative_risk_score: float = 0.0
    threshold: float = 0.0
    turn_count: int = 0
    escalation_action: str = "block"  # block, require_approval
    trigger_turn_number: int = 0
    risk_trajectory: list[float] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "cumulative_risk_score": self.cumulative_risk_score,
            "threshold": self.threshold,
            "turn_count": self.turn_count,
            "escalation_action": self.escalation_action,
            "trigger_turn_number": self.trigger_turn_number,
            "risk_trajectory": self.risk_trajectory,
            "timestamp": self.timestamp,
        }


class CrossTurnRiskAccumulator:
    """Monitors session-level cumulative risk and triggers escalation.

    Escalation rules:
    - cumulative_risk_score >= escalation_threshold -> block or HITL
    - consecutive high-risk turns >= consecutive_high_threshold -> immediate block
    - Risk decay: older turns contribute less to the cumulative score
    """

    def __init__(
        self,
        escalation_threshold: float = 3.0,
        consecutive_high_threshold: int = 3,
        decay_factor: float = 0.95,
        escalation_action: str = "block",
    ) -> None:
        self.escalation_threshold = escalation_threshold
        self.consecutive_high_threshold = consecutive_high_threshold
        self.decay_factor = decay_factor
        self.escalation_action = escalation_action
        self._escalation_events: list[EscalationEvent] = []
        self._stats: dict[str, int] = {
            "total_evaluations": 0,
            "escalations_triggered": 0,
            "cumulative_escalations": 0,
            "consecutive_escalations": 0,
        }

    def evaluate_turn(
        self,
        session_id: str,
        risk_score: float,
        risk_level: str = "none",
        matched_patterns: list[str] | None = None,
        input_preview: str = "",
        tenant_id: str = "",
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Evaluate a new turn and check for escalation conditions.

        Records the turn in the session context store and checks whether
        the cumulative risk exceeds the escalation threshold.

        Returns:
            Dict with keys: action, escalated, escalation_event, session
        """
        self._stats["total_evaluations"] += 1

        store = get_session_context_store()
        session = store.get_or_create_session(session_id, tenant_id, agent_id)

        # Record the turn
        store.record_turn(
            session_id=session_id,
            risk_score=risk_score,
            risk_level=risk_level,
            matched_patterns=matched_patterns,
            input_preview=input_preview,
        )

        # Compute weighted cumulative risk with decay
        weighted_risk = self._compute_weighted_risk(session)

        # Check escalation conditions
        escalated = False
        escalation_event = None

        # Condition 1: Cumulative risk exceeds threshold
        if weighted_risk >= self.escalation_threshold and not session.is_escalated:
            escalated = True
            self._stats["cumulative_escalations"] += 1
            reason = (
                f"Cumulative risk score {weighted_risk:.2f} exceeds "
                f"threshold {self.escalation_threshold:.2f}"
            )
            escalation_event = self._create_escalation(
                session, weighted_risk, reason,
            )

        # Condition 2: Consecutive high-risk turns
        if not escalated and not session.is_escalated:
            consecutive = self._count_consecutive_high(session)
            if consecutive >= self.consecutive_high_threshold:
                escalated = True
                self._stats["consecutive_escalations"] += 1
                reason = (
                    f"{consecutive} consecutive high-risk turns "
                    f"(threshold: {self.consecutive_high_threshold})"
                )
                escalation_event = self._create_escalation(
                    session, weighted_risk, reason,
                )

        action = self.escalation_action if escalated else "allowed"

        return {
            "action": action,
            "escalated": escalated,
            "escalation_event": escalation_event.to_dict() if escalation_event else None,
            "session": {
                "session_id": session.session_id,
                "cumulative_risk_score": session.cumulative_risk_score,
                "weighted_risk_score": weighted_risk,
                "turn_count": session.turn_count,
                "is_escalated": session.is_escalated,
            },
        }

    def _compute_weighted_risk(self, session: SessionContext) -> float:
        """Compute decay-weighted cumulative risk for a session."""
        if not session.turns:
            return 0.0
        total = 0.0
        n = len(session.turns)
        for i, turn in enumerate(session.turns):
            # More recent turns have higher weight
            age = n - 1 - i
            weight = self.decay_factor ** age
            total += turn.risk_score * weight
        return total

    def _count_consecutive_high(self, session: SessionContext) -> int:
        """Count consecutive high/critical risk turns from the most recent."""
        count = 0
        for turn in reversed(session.turns):
            if turn.risk_level in ("high", "critical"):
                count += 1
            else:
                break
        return count

    def _create_escalation(
        self,
        session: SessionContext,
        weighted_risk: float,
        reason: str,
    ) -> EscalationEvent:
        """Create an escalation event and mark the session."""
        session.is_escalated = True
        session.escalation_reason = reason
        self._stats["escalations_triggered"] += 1

        trajectory = [t.risk_score for t in session.turns]
        event = EscalationEvent(
            event_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            agent_id=session.agent_id,
            cumulative_risk_score=weighted_risk,
            threshold=self.escalation_threshold,
            turn_count=session.turn_count,
            escalation_action=self.escalation_action,
            trigger_turn_number=session.turn_count,
            risk_trajectory=trajectory,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._escalation_events.append(event)

        logger.warning(
            "Cross-turn escalation: session=%s risk=%.2f reason=%s action=%s",
            session.session_id, weighted_risk, reason, self.escalation_action,
        )
        return event

    def reset_session_escalation(self, session_id: str) -> bool:
        """Reset escalation for a session (e.g. after HITL approval)."""
        store = get_session_context_store()
        session = store.get_session(session_id)
        if session and session.is_escalated:
            session.is_escalated = False
            session.escalation_reason = ""
            return True
        return False

    def get_escalation_events(self, limit: int = 50) -> list[EscalationEvent]:
        return self._escalation_events[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)


# ── Singleton ────────────────────────────────────────────────────────────

_accumulator: CrossTurnRiskAccumulator | None = None


def get_cross_turn_risk_accumulator(
    escalation_threshold: float = 3.0,
    consecutive_high_threshold: int = 3,
    escalation_action: str = "block",
) -> CrossTurnRiskAccumulator:
    global _accumulator
    if _accumulator is None:
        _accumulator = CrossTurnRiskAccumulator(
            escalation_threshold=escalation_threshold,
            consecutive_high_threshold=consecutive_high_threshold,
            escalation_action=escalation_action,
        )
    return _accumulator


def reset_cross_turn_risk_accumulator() -> None:
    global _accumulator
    _accumulator = None
