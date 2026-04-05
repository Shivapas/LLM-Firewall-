"""Escalation gate — decides whether to escalate Tier 1 results to Tier 2 ML scanning.

Logic:
- Tier 1 returns High/Critical → act immediately, NO Tier 2 delay
- Tier 1 returns Medium with no pattern match → escalate to Tier 2
- Tier 1 returns Low → allow, no escalation
"""

import logging
from dataclasses import dataclass
from typing import Optional

from app.services.threat_detection.scorer import ThreatScore
from app.services.threat_detection.action_engine import ActionResult
from app.services.threat_detection.tier2_scanner import (
    Tier2Result,
    Tier2SemanticScanner,
    get_tier2_scanner,
)

logger = logging.getLogger("sphinx.threat_detection.escalation")


@dataclass
class EscalationDecision:
    """Result of the escalation gate evaluation."""
    escalated_to_tier2: bool
    reason: str
    tier1_risk_level: str
    tier1_score: float
    tier1_match_count: int
    tier2_result: Optional[Tier2Result] = None
    final_action: str = "allow"
    final_risk_level: str = "low"
    final_score: float = 0.0

    def to_dict(self) -> dict:
        result = {
            "escalated_to_tier2": self.escalated_to_tier2,
            "reason": self.reason,
            "tier1_risk_level": self.tier1_risk_level,
            "tier1_score": round(self.tier1_score, 4),
            "tier1_match_count": self.tier1_match_count,
            "final_action": self.final_action,
            "final_risk_level": self.final_risk_level,
            "final_score": round(self.final_score, 4),
        }
        if self.tier2_result:
            result["tier2"] = self.tier2_result.to_dict()
        return result


class EscalationGate:
    """Evaluates Tier 1 results and decides whether Tier 2 scanning is needed.

    Rules:
    1. High/Critical risk → immediate action (block/rewrite/downgrade), skip Tier 2
    2. Medium risk with NO pattern matches → escalate to Tier 2 for semantic analysis
    3. Medium risk WITH pattern matches → use Tier 1 action (patterns were detected)
    4. Low risk → allow, no escalation
    """

    def __init__(self, tier2_scanner: Optional[Tier2SemanticScanner] = None):
        self._tier2 = tier2_scanner

    @property
    def tier2_scanner(self) -> Tier2SemanticScanner:
        if self._tier2 is None:
            self._tier2 = get_tier2_scanner()
        return self._tier2

    def evaluate(
        self,
        text: str,
        tier1_score: ThreatScore,
        tier1_action: ActionResult,
    ) -> EscalationDecision:
        """Evaluate whether to escalate to Tier 2 and return final decision.

        Args:
            text: The original prompt text
            tier1_score: The Tier 1 threat score result
            tier1_action: The Tier 1 action result

        Returns:
            EscalationDecision with final action to take
        """
        risk_level = tier1_score.risk_level
        match_count = len(tier1_score.matches)

        # Rule 1: High/Critical → immediate action, no Tier 2
        if risk_level in ("high", "critical"):
            logger.info(
                "Escalation gate: %s risk, applying Tier 1 action=%s immediately (no Tier 2 delay)",
                risk_level, tier1_action.action,
            )
            return EscalationDecision(
                escalated_to_tier2=False,
                reason=f"Tier 1 detected {risk_level} risk — immediate action applied",
                tier1_risk_level=risk_level,
                tier1_score=tier1_score.score,
                tier1_match_count=match_count,
                final_action=tier1_action.action,
                final_risk_level=risk_level,
                final_score=tier1_score.score,
            )

        # Rule 2: Medium risk with no pattern matches → escalate to Tier 2
        if risk_level == "medium" and match_count == 0:
            logger.info(
                "Escalation gate: medium risk with no pattern matches — escalating to Tier 2",
            )
            tier2_result = self.tier2_scanner.scan(text)

            # Use the higher of Tier 1 and Tier 2 scores
            final_score = max(tier1_score.score, tier2_result.score)
            final_risk = tier2_result.risk_level
            final_action = self._risk_to_action(final_risk)

            return EscalationDecision(
                escalated_to_tier2=True,
                reason="Tier 1 medium risk with no pattern matches — Tier 2 semantic analysis applied",
                tier1_risk_level=risk_level,
                tier1_score=tier1_score.score,
                tier1_match_count=match_count,
                tier2_result=tier2_result,
                final_action=final_action,
                final_risk_level=final_risk,
                final_score=final_score,
            )

        # Rule 3: Medium risk WITH pattern matches → use Tier 1 action
        if risk_level == "medium" and match_count > 0:
            logger.info(
                "Escalation gate: medium risk with %d pattern matches — using Tier 1 action=%s",
                match_count, tier1_action.action,
            )
            return EscalationDecision(
                escalated_to_tier2=False,
                reason=f"Tier 1 detected {match_count} pattern(s) at medium risk",
                tier1_risk_level=risk_level,
                tier1_score=tier1_score.score,
                tier1_match_count=match_count,
                final_action=tier1_action.action,
                final_risk_level=risk_level,
                final_score=tier1_score.score,
            )

        # Rule 4: Low risk → allow
        logger.debug("Escalation gate: low risk — allowing")
        return EscalationDecision(
            escalated_to_tier2=False,
            reason="Tier 1 detected low risk — allowed",
            tier1_risk_level=risk_level,
            tier1_score=tier1_score.score,
            tier1_match_count=match_count,
            final_action="allow",
            final_risk_level="low",
            final_score=tier1_score.score,
        )

    def _risk_to_action(self, risk_level: str) -> str:
        """Map risk level to default action."""
        return {
            "critical": "block",
            "high": "block",
            "medium": "allow",
            "low": "allow",
        }.get(risk_level, "allow")


# Singleton
_gate: Optional[EscalationGate] = None


def get_escalation_gate() -> EscalationGate:
    """Get or create the singleton escalation gate."""
    global _gate
    if _gate is None:
        _gate = EscalationGate()
    return _gate


def reset_escalation_gate() -> None:
    """Reset the singleton gate (for testing)."""
    global _gate
    _gate = None
