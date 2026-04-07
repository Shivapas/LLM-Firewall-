"""Policy action engine — maps risk levels and policy rules to enforcement actions."""

import logging
import re
from dataclasses import dataclass
from typing import Optional

from app.services.threat_detection.scorer import ThreatScore

logger = logging.getLogger("sphinx.threat_detection.action_engine")


@dataclass
class ActionResult:
    """Result of applying the policy action engine to a threat score."""
    action: str  # allow, block, rewrite, downgrade, require_approval
    risk_level: str
    score: float
    reason: str
    rewritten_text: Optional[str] = None
    matched_patterns: list[str] | None = None
    downgrade_model: Optional[str] = None
    approval_id: Optional[str] = None  # Sprint 28: populated when action=require_approval

    def to_dict(self) -> dict:
        result = {
            "action": self.action,
            "risk_level": self.risk_level,
            "score": round(self.score, 4),
            "reason": self.reason,
        }
        if self.rewritten_text is not None:
            result["rewritten"] = True
        if self.matched_patterns:
            result["matched_patterns"] = self.matched_patterns
        if self.downgrade_model:
            result["downgrade_model"] = self.downgrade_model
        if self.approval_id:
            result["approval_id"] = self.approval_id
        return result


class PolicyActionEngine:
    """Maps risk levels to configured actions: Allow / Block / Rewrite / Downgrade / Require Approval.

    Actions are configurable per severity level and per individual policy rule.
    Sprint 28: Added 'require_approval' action for HITL enforcement checkpoints.
    """

    # Default action mapping (overridable by policy rules)
    DEFAULT_ACTIONS = {
        "critical": "block",
        "high": "block",
        "medium": "allow",
        "low": "allow",
    }

    # Default rewrite substitution templates
    DEFAULT_REWRITE_TEMPLATES = {
        "prompt_injection": "[Content removed: potential prompt injection detected]",
        "jailbreak": "[Content removed: jailbreak attempt detected]",
        "data_extraction": "[Content removed: data extraction attempt detected]",
        "privilege_escalation": "[Content removed: privilege escalation attempt detected]",
        "model_manipulation": "[Content removed: model manipulation detected]",
        "insecure_output": "[Content removed: insecure output request detected]",
        "sensitive_disclosure": "[Content removed: sensitive information request detected]",
        "denial_of_service": "[Content removed: resource exhaustion attempt detected]",
    }

    # Default downgrade model
    DEFAULT_DOWNGRADE_MODEL = "gpt-3.5-turbo"

    def __init__(
        self,
        action_overrides: dict[str, str] | None = None,
        rewrite_templates: dict[str, str] | None = None,
        downgrade_model: str | None = None,
    ):
        self._actions = dict(self.DEFAULT_ACTIONS)
        if action_overrides:
            self._actions.update(action_overrides)

        self._rewrite_templates = dict(self.DEFAULT_REWRITE_TEMPLATES)
        if rewrite_templates:
            self._rewrite_templates.update(rewrite_templates)

        self._downgrade_model = downgrade_model or self.DEFAULT_DOWNGRADE_MODEL

    def evaluate(self, text: str, threat_score: ThreatScore) -> ActionResult:
        """Evaluate threat score and return the appropriate action."""
        if not threat_score.matches:
            return ActionResult(
                action="allow",
                risk_level="low",
                score=0.0,
                reason="No threats detected",
            )

        risk_level = threat_score.risk_level
        action = self._actions.get(risk_level, "allow")
        matched_pattern_ids = [m.pattern_id for m in threat_score.matches]

        reason = (
            f"Detected {len(threat_score.matches)} threat pattern(s) "
            f"across {len(threat_score.categories_hit)} category(ies): "
            f"{', '.join(sorted(threat_score.categories_hit))}"
        )

        result = ActionResult(
            action=action,
            risk_level=risk_level,
            score=threat_score.score,
            reason=reason,
            matched_patterns=matched_pattern_ids,
        )

        if action == "rewrite":
            result.rewritten_text = self._apply_rewrite(text, threat_score)
        elif action == "downgrade":
            result.downgrade_model = self._downgrade_model
        elif action == "require_approval":
            # HITL: caller is responsible for creating the approval request
            # and populating approval_id before returning to the agent
            pass

        return result

    def _apply_rewrite(self, text: str, threat_score: ThreatScore) -> str:
        """Apply rewrite substitution to remove detected threat patterns from text.

        Replaces matched regions with configured placeholder text,
        preserving sentence structure for model coherence.
        """
        if not threat_score.matches:
            return text

        # Sort matches by position (descending) so we can replace from end to start
        sorted_matches = sorted(threat_score.matches, key=lambda m: m.position[0], reverse=True)

        rewritten = text
        seen_ranges: list[tuple[int, int]] = []

        for match in sorted_matches:
            start, end = match.position
            # Skip overlapping ranges
            if any(s <= start < e or s < end <= e for s, e in seen_ranges):
                continue

            template = self._rewrite_templates.get(
                match.category,
                "[Content removed: security policy violation]",
            )
            rewritten = rewritten[:start] + template + rewritten[end:]
            seen_ranges.append((start, end))

        return rewritten

    def update_action(self, severity: str, action: str) -> None:
        """Update the action for a severity level."""
        valid_actions = {"allow", "block", "rewrite", "downgrade", "require_approval"}
        if action not in valid_actions:
            raise ValueError(f"Invalid action: {action}. Must be one of {valid_actions}")
        self._actions[severity] = action

    def update_rewrite_template(self, category: str, template: str) -> None:
        """Update the rewrite template for a category."""
        self._rewrite_templates[category] = template

    def get_actions(self) -> dict[str, str]:
        """Return current action mapping."""
        return dict(self._actions)
