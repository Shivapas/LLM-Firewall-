"""Main threat detection engine — orchestrates pattern matching, scoring, and action enforcement."""

import json
import logging
from typing import Optional

from app.services.threat_detection.pattern_library import PatternLibrary, ThreatPattern
from app.services.threat_detection.scorer import ThreatScorer, ThreatScore
from app.services.threat_detection.action_engine import PolicyActionEngine, ActionResult
from app.services.threat_detection.escalation_gate import EscalationGate, EscalationDecision
from app.services.threat_detection.tier2_scanner import get_tier2_scanner

logger = logging.getLogger("sphinx.threat_detection.engine")

# Singleton engine instance
_engine: Optional["ThreatDetectionEngine"] = None


class ThreatDetectionEngine:
    """Tier 1 + Tier 2 Threat Detection Engine.

    Orchestrates the pattern library, scorer, action engine, and escalation
    gate to scan incoming prompts and enforce security policies.
    Tier 2 ML semantic analysis is invoked only on Tier 1 escalations.
    """

    def __init__(
        self,
        patterns_path: str | None = None,
        action_overrides: dict[str, str] | None = None,
        rewrite_templates: dict[str, str] | None = None,
        enable_tier2: bool = True,
    ):
        self._library = PatternLibrary()
        self._library.load_from_yaml(patterns_path)
        self._scorer = ThreatScorer(self._library)
        self._action_engine = PolicyActionEngine(
            action_overrides=action_overrides,
            rewrite_templates=rewrite_templates,
        )
        self._enable_tier2 = enable_tier2
        self._escalation_gate = EscalationGate() if enable_tier2 else None

    @property
    def library(self) -> PatternLibrary:
        return self._library

    @property
    def scorer(self) -> ThreatScorer:
        return self._scorer

    @property
    def action_engine(self) -> PolicyActionEngine:
        return self._action_engine

    @property
    def escalation_gate(self) -> Optional[EscalationGate]:
        return self._escalation_gate

    @property
    def tier2_enabled(self) -> bool:
        return self._enable_tier2

    def scan(self, text: str) -> ThreatScore:
        """Scan text for threats and return threat score (no enforcement)."""
        return self._scorer.scan(text)

    def evaluate(self, text: str) -> ActionResult:
        """Scan text and evaluate the policy action to take (Tier 1 only)."""
        threat_score = self._scorer.scan(text)
        return self._action_engine.evaluate(text, threat_score)

    def evaluate_with_escalation(self, text: str) -> tuple[ActionResult, Optional[EscalationDecision]]:
        """Scan text with Tier 1 + Tier 2 escalation gate.

        Returns (ActionResult, EscalationDecision or None).
        If Tier 2 is disabled, returns (Tier 1 result, None).
        """
        threat_score = self._scorer.scan(text)
        tier1_action = self._action_engine.evaluate(text, threat_score)

        if not self._enable_tier2 or not self._escalation_gate:
            return tier1_action, None

        escalation = self._escalation_gate.evaluate(text, threat_score, tier1_action)

        # Build final ActionResult from escalation decision
        if escalation.escalated_to_tier2:
            final_action = ActionResult(
                action=escalation.final_action,
                risk_level=escalation.final_risk_level,
                score=escalation.final_score,
                reason=escalation.reason,
                matched_patterns=tier1_action.matched_patterns,
            )
            return final_action, escalation

        return tier1_action, escalation

    def scan_request_body(self, body: bytes) -> ActionResult:
        """Scan a request body (JSON) and evaluate policy actions.

        Extracts prompt text from common LLM API request formats:
        - OpenAI: messages[].content
        - Anthropic: messages[].content, system
        - Simple: prompt field
        """
        if not body:
            return ActionResult(
                action="allow", risk_level="low", score=0.0, reason="Empty request body"
            )

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return ActionResult(
                action="allow", risk_level="low", score=0.0, reason="Non-JSON request body"
            )

        text = self._extract_prompt_text(payload)
        if not text:
            return ActionResult(
                action="allow", risk_level="low", score=0.0, reason="No prompt text found"
            )

        return self.evaluate(text)

    def scan_request_body_with_escalation(
        self, body: bytes
    ) -> tuple[ActionResult, Optional[EscalationDecision]]:
        """Scan a request body with Tier 1 + Tier 2 escalation gate.

        Returns (ActionResult, EscalationDecision or None).
        """
        if not body:
            return (
                ActionResult(action="allow", risk_level="low", score=0.0, reason="Empty request body"),
                None,
            )

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return (
                ActionResult(action="allow", risk_level="low", score=0.0, reason="Non-JSON request body"),
                None,
            )

        text = self._extract_prompt_text(payload)
        if not text:
            return (
                ActionResult(action="allow", risk_level="low", score=0.0, reason="No prompt text found"),
                None,
            )

        return self.evaluate_with_escalation(text)

    def apply_rewrite_to_body(self, body: bytes, action_result: ActionResult) -> bytes:
        """If action is rewrite, apply the rewrite to the request body and return modified body."""
        if action_result.action != "rewrite" or action_result.rewritten_text is None:
            return body

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return body

        # Apply rewrite to the extracted text fields
        rewritten = action_result.rewritten_text

        if "messages" in payload:
            for msg in payload["messages"]:
                if msg.get("role") in ("user", "human"):
                    if isinstance(msg.get("content"), str):
                        msg["content"] = rewritten
                        break
        elif "prompt" in payload:
            payload["prompt"] = rewritten

        return json.dumps(payload).encode()

    def apply_downgrade_to_body(self, body: bytes, action_result: ActionResult) -> bytes:
        """If action is downgrade, replace the model in the request body."""
        if action_result.action != "downgrade" or not action_result.downgrade_model:
            return body

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return body

        payload["model"] = action_result.downgrade_model
        return json.dumps(payload).encode()

    def load_policy_rules(self, policy_rules: list[dict]) -> int:
        """Load additional patterns from policy rules stored in the database.

        Each rule dict should have: id, name, category, severity, pattern, description, tags
        """
        count = 0
        for rule in policy_rules:
            try:
                tp = ThreatPattern(
                    id=rule.get("id", f"custom-{count}"),
                    name=rule.get("name", "Custom Rule"),
                    category=rule.get("category", "prompt_injection"),
                    severity=rule.get("severity", "medium"),
                    pattern=rule.get("pattern", ""),
                    description=rule.get("description", ""),
                    tags=rule.get("tags", ["custom"]),
                )
                self._library.add_pattern(tp)
                count += 1
            except Exception as e:
                logger.error("Failed to load policy rule: %s", e)
        logger.info("Loaded %d custom policy rules", count)
        return count

    def update_action_config(self, action_overrides: dict[str, str]) -> None:
        """Update action configuration from policy settings."""
        for severity, action in action_overrides.items():
            self._action_engine.update_action(severity, action)

    def _extract_prompt_text(self, payload: dict) -> str:
        """Extract prompt text from various LLM API request formats."""
        parts: list[str] = []

        # System prompt (Anthropic / OpenAI)
        if "system" in payload:
            system = payload["system"]
            if isinstance(system, str):
                parts.append(system)
            elif isinstance(system, list):
                for item in system:
                    if isinstance(item, dict) and "text" in item:
                        parts.append(item["text"])

        # Messages array (OpenAI / Anthropic chat format)
        if "messages" in payload:
            for msg in payload["messages"]:
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role in ("user", "human", "system"):
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and "text" in item:
                                parts.append(item["text"])

        # Simple prompt field
        if "prompt" in payload:
            parts.append(str(payload["prompt"]))

        return "\n".join(parts)

    def get_stats(self) -> dict:
        """Return engine statistics."""
        stats = {
            "total_patterns": self._library.count(),
            "categories": list(self._library._patterns_by_category.keys()),
            "severity_counts": {
                sev: len(patterns)
                for sev, patterns in self._library._patterns_by_severity.items()
            },
            "action_config": self._action_engine.get_actions(),
            "tier2_enabled": self._enable_tier2,
        }
        if self._enable_tier2:
            tier2 = get_tier2_scanner()
            stats["tier2_index_size"] = tier2.index_size
        return stats


def get_threat_engine() -> ThreatDetectionEngine:
    """Get or create the singleton threat detection engine."""
    global _engine
    if _engine is None:
        _engine = ThreatDetectionEngine()
    return _engine


def reset_threat_engine() -> None:
    """Reset the singleton engine (for testing)."""
    global _engine
    _engine = None
