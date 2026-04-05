"""Main threat detection engine — orchestrates pattern matching, scoring, and action enforcement."""

import json
import logging
from typing import Optional

from app.services.threat_detection.pattern_library import PatternLibrary, ThreatPattern
from app.services.threat_detection.scorer import ThreatScorer, ThreatScore
from app.services.threat_detection.action_engine import PolicyActionEngine, ActionResult

logger = logging.getLogger("sphinx.threat_detection.engine")

# Singleton engine instance
_engine: Optional["ThreatDetectionEngine"] = None


class ThreatDetectionEngine:
    """Tier 1 Threat Detection Engine.

    Orchestrates the pattern library, scorer, and action engine to scan
    incoming prompts and enforce security policies.
    """

    def __init__(
        self,
        patterns_path: str | None = None,
        action_overrides: dict[str, str] | None = None,
        rewrite_templates: dict[str, str] | None = None,
    ):
        self._library = PatternLibrary()
        self._library.load_from_yaml(patterns_path)
        self._scorer = ThreatScorer(self._library)
        self._action_engine = PolicyActionEngine(
            action_overrides=action_overrides,
            rewrite_templates=rewrite_templates,
        )

    @property
    def library(self) -> PatternLibrary:
        return self._library

    @property
    def scorer(self) -> ThreatScorer:
        return self._scorer

    @property
    def action_engine(self) -> PolicyActionEngine:
        return self._action_engine

    def scan(self, text: str) -> ThreatScore:
        """Scan text for threats and return threat score (no enforcement)."""
        return self._scorer.scan(text)

    def evaluate(self, text: str) -> ActionResult:
        """Scan text and evaluate the policy action to take."""
        threat_score = self._scorer.scan(text)
        return self._action_engine.evaluate(text, threat_score)

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
        return {
            "total_patterns": self._library.count(),
            "categories": list(self._library._patterns_by_category.keys()),
            "severity_counts": {
                sev: len(patterns)
                for sev, patterns in self._library._patterns_by_severity.items()
            },
            "action_config": self._action_engine.get_actions(),
        }


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
