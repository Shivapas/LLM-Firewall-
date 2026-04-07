"""Output Policy Evaluator — evaluates compiled policy rules against output content.

Supports actions: Stream (pass-through), Redact, Block, Rewrite, Incident Log.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.output_scanner.output_policy")


class OutputAction(str, Enum):
    """Actions that can be taken on output content."""
    STREAM = "stream"        # Pass through unchanged
    REDACT = "redact"        # Replace sensitive content with [REDACTED] markers
    BLOCK = "block"          # Block the chunk entirely
    REWRITE = "rewrite"      # Rewrite the content (placeholder for future)
    INCIDENT_LOG = "incident_log"  # Log incident and stream (for monitoring)


@dataclass
class OutputPolicyRule:
    """A single output policy rule."""
    rule_id: str
    name: str
    description: str = ""
    # What triggers this rule
    entity_types: list[str] = field(default_factory=list)  # PII types to match
    min_confidence: float = 0.8
    # What action to take
    action: OutputAction = OutputAction.REDACT
    # Priority (lower = higher priority)
    priority: int = 100
    enabled: bool = True


@dataclass
class OutputPolicyResult:
    """Result of output policy evaluation."""
    action: OutputAction
    matched_rules: list[OutputPolicyRule]
    entity_count: int = 0
    incident_logged: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "matched_rules": [r.rule_id for r in self.matched_rules],
            "entity_count": self.entity_count,
            "incident_logged": self.incident_logged,
            "reason": self.reason,
        }


# Default output policy rules
_DEFAULT_RULES: list[OutputPolicyRule] = [
    # Block private keys in output (highest priority)
    OutputPolicyRule(
        rule_id="OUT-001",
        name="Block private keys",
        entity_types=["PRIVATE_KEY"],
        action=OutputAction.BLOCK,
        priority=10,
    ),
    # Redact all credential types
    OutputPolicyRule(
        rule_id="OUT-002",
        name="Redact API keys and tokens",
        entity_types=[
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY", "GITHUB_TOKEN", "GITHUB_PAT", "SLACK_TOKEN",
            "STRIPE_KEY", "GOOGLE_API_KEY", "AZURE_KEY", "GENERIC_API_KEY",
            "JWT_TOKEN", "BEARER_TOKEN",
        ],
        action=OutputAction.REDACT,
        priority=20,
    ),
    # Redact connection strings
    OutputPolicyRule(
        rule_id="OUT-003",
        name="Redact connection strings",
        entity_types=["CONNECTION_STRING"],
        action=OutputAction.REDACT,
        priority=20,
    ),
    # Redact credit cards
    OutputPolicyRule(
        rule_id="OUT-004",
        name="Redact credit cards",
        entity_types=["CREDIT_CARD"],
        action=OutputAction.REDACT,
        priority=25,
    ),
    # Redact PII - SSN
    OutputPolicyRule(
        rule_id="OUT-005",
        name="Redact SSN",
        entity_types=["SSN"],
        action=OutputAction.REDACT,
        priority=30,
    ),
    # Redact PII - other
    OutputPolicyRule(
        rule_id="OUT-006",
        name="Redact PII entities",
        entity_types=["EMAIL", "PHONE", "DATE_OF_BIRTH", "ADDRESS", "NAME"],
        action=OutputAction.REDACT,
        priority=40,
    ),
    # Redact PHI entities
    OutputPolicyRule(
        rule_id="OUT-007",
        name="Redact PHI entities",
        entity_types=["PATIENT_ID", "DIAGNOSIS_CODE", "MEDICATION", "PROVIDER_NAME", "MRN"],
        action=OutputAction.REDACT,
        priority=35,
    ),
]


class OutputPolicyEvaluator:
    """Evaluates output content against policy rules to determine action."""

    def __init__(self, rules: list[OutputPolicyRule] | None = None):
        self._rules = sorted(rules or _DEFAULT_RULES, key=lambda r: r.priority)

    def evaluate(
        self,
        detected_entity_types: list[str],
        entity_count: int = 0,
        compliance_tags: list[str] | None = None,
    ) -> OutputPolicyResult:
        """Evaluate detected entities against policy rules.

        Args:
            detected_entity_types: List of entity type strings found in the output.
            entity_count: Total number of entities detected.
            compliance_tags: Compliance tags from the input pipeline (for leakage detection).

        Returns:
            OutputPolicyResult with the determined action.
        """
        if not detected_entity_types:
            return OutputPolicyResult(
                action=OutputAction.STREAM,
                matched_rules=[],
                entity_count=0,
                reason="No entities detected",
            )

        matched_rules: list[OutputPolicyRule] = []
        highest_action = OutputAction.STREAM

        # Action priority: BLOCK > REDACT > INCIDENT_LOG > REWRITE > STREAM
        action_priority = {
            OutputAction.BLOCK: 5,
            OutputAction.REDACT: 4,
            OutputAction.INCIDENT_LOG: 3,
            OutputAction.REWRITE: 2,
            OutputAction.STREAM: 1,
        }

        entity_set = set(detected_entity_types)

        for rule in self._rules:
            if not rule.enabled:
                continue
            rule_types = set(rule.entity_types)
            if rule_types & entity_set:
                matched_rules.append(rule)
                if action_priority[rule.action] > action_priority[highest_action]:
                    highest_action = rule.action

        # If compliance tags indicate regulated data, escalate to incident log
        incident_logged = False
        if compliance_tags and action_priority.get(highest_action, 0) >= action_priority[OutputAction.REDACT]:
            incident_logged = True

        reason_parts = []
        if matched_rules:
            reason_parts.append(f"Matched {len(matched_rules)} output policy rule(s)")
        if incident_logged:
            reason_parts.append(f"Regulated data leakage (tags: {', '.join(compliance_tags)})")

        return OutputPolicyResult(
            action=highest_action,
            matched_rules=matched_rules,
            entity_count=entity_count,
            incident_logged=incident_logged,
            reason="; ".join(reason_parts) if reason_parts else "No action required",
        )


# Singleton
_evaluator: Optional[OutputPolicyEvaluator] = None


def get_output_policy_evaluator() -> OutputPolicyEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = OutputPolicyEvaluator()
    return _evaluator


def reset_output_policy_evaluator() -> None:
    global _evaluator
    _evaluator = None
