"""Routing Policy Evaluator — evaluates routing decisions based on compliance tags,
data sensitivity score, kill-switch state, budget status, and configured routing rules.

Sprint 11: Sensitivity-Based Routing & Budget Downgrade.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from app.services.vectordb.compliance_tagger import ComplianceLabel

logger = logging.getLogger("sphinx.routing_policy")


class RoutingAction(str, Enum):
    ROUTE = "route"
    DOWNGRADE = "downgrade"
    BLOCK = "block"
    DEFAULT = "default"  # No rule matched; use default routing


@dataclass
class RoutingContext:
    """All inputs needed for a routing decision."""
    model_name: str = ""
    tenant_id: str = ""
    api_key_id: str = ""
    compliance_tags: list[str] = field(default_factory=list)
    sensitivity_score: float = 0.0
    requires_private_model: bool = False
    kill_switch_active: bool = False
    kill_switch_action: str = ""
    budget_exceeded: bool = False
    budget_usage_pct: float = 0.0
    request_metadata: dict = field(default_factory=dict)


@dataclass
class RoutingDecision:
    """The result of routing policy evaluation."""
    action: RoutingAction = RoutingAction.DEFAULT
    target_model: str = ""
    target_provider: str = ""
    original_model: str = ""
    reason: str = ""
    matched_rule_id: str = ""
    matched_rule_name: str = ""
    rules_evaluated: int = 0
    evaluation_time_ms: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "target_model": self.target_model,
            "target_provider": self.target_provider,
            "original_model": self.original_model,
            "reason": self.reason,
            "matched_rule_id": self.matched_rule_id,
            "matched_rule_name": self.matched_rule_name,
            "rules_evaluated": self.rules_evaluated,
            "evaluation_time_ms": round(self.evaluation_time_ms, 3),
            "details": self.details,
        }


# Sensitivity tags that require private/on-premise routing
PRIVATE_MODEL_TAGS = {
    ComplianceLabel.PII.value,
    ComplianceLabel.PHI.value,
    ComplianceLabel.IP.value,
}


class RoutingPolicyEvaluator:
    """Evaluates routing rules against a request context.

    Rules are evaluated in priority order (lowest number first).
    First matching rule wins. If no rule matches, returns DEFAULT action.
    """

    def __init__(
        self,
        private_model: str = "llama-3.1-70b",
        private_provider: str = "llama",
        public_model: str = "gpt-4o",
        public_provider: str = "openai",
    ):
        self._private_model = private_model
        self._private_provider = private_provider
        self._public_model = public_model
        self._public_provider = public_provider
        self._rules: list[dict] = []

    def load_rules(self, rules: list[dict]) -> None:
        """Load routing rules sorted by priority."""
        self._rules = sorted(rules, key=lambda r: r.get("priority", 100))
        logger.info("Loaded %d routing rules", len(self._rules))

    def set_model_mapping(
        self,
        private_model: str = "",
        private_provider: str = "",
        public_model: str = "",
        public_provider: str = "",
    ) -> None:
        if private_model:
            self._private_model = private_model
        if private_provider:
            self._private_provider = private_provider
        if public_model:
            self._public_model = public_model
        if public_provider:
            self._public_provider = public_provider

    def evaluate(self, ctx: RoutingContext) -> RoutingDecision:
        """Evaluate all routing rules against the given context.

        Returns the first matching rule's decision, or DEFAULT if none match.
        """
        start = time.monotonic()
        decision = RoutingDecision(
            original_model=ctx.model_name,
            target_model=ctx.model_name,
        )

        # Phase 1: Check sensitivity-to-model mapping (built-in rule)
        sensitivity_decision = self._evaluate_sensitivity(ctx)
        if sensitivity_decision is not None:
            sensitivity_decision.evaluation_time_ms = (time.monotonic() - start) * 1000
            sensitivity_decision.rules_evaluated = 1
            return sensitivity_decision

        # Phase 2: Evaluate configured rules in priority order
        for i, rule in enumerate(self._rules):
            if not rule.get("is_active", True):
                continue
            # Scope check: rule tenant must match or be global
            rule_tenant = rule.get("tenant_id", "*")
            if rule_tenant != "*" and rule_tenant != ctx.tenant_id:
                continue

            if self._matches_condition(rule, ctx):
                try:
                    decision.action = RoutingAction(rule.get("action", "route"))
                except ValueError:
                    logger.warning("Invalid routing action '%s' in rule '%s', skipping",
                                   rule.get("action"), rule.get("name"))
                    continue
                decision.target_model = rule.get("target_model", ctx.model_name)
                decision.target_provider = rule.get("target_provider", "")
                decision.reason = f"Matched rule: {rule.get('name', 'unnamed')}"
                decision.matched_rule_id = str(rule.get("id", ""))
                decision.matched_rule_name = rule.get("name", "")
                decision.rules_evaluated = i + 1
                decision.evaluation_time_ms = (time.monotonic() - start) * 1000
                decision.details = {
                    "condition_type": rule.get("condition_type", ""),
                    "condition": rule.get("condition_json", "{}"),
                }
                logger.info(
                    "Routing rule matched: rule=%s model=%s -> %s reason=%s",
                    decision.matched_rule_name,
                    ctx.model_name,
                    decision.target_model,
                    decision.reason,
                )
                return decision

        # Phase 3: No rule matched
        decision.action = RoutingAction.DEFAULT
        decision.rules_evaluated = len(self._rules)
        decision.reason = "No routing rule matched; using default routing"
        decision.evaluation_time_ms = (time.monotonic() - start) * 1000
        return decision

    def _evaluate_sensitivity(self, ctx: RoutingContext) -> Optional[RoutingDecision]:
        """Built-in sensitivity-to-model mapping.

        If request carries PII/PHI/IP tags → route to private model.
        """
        has_sensitive_tags = bool(
            set(ctx.compliance_tags) & PRIVATE_MODEL_TAGS
        )

        if has_sensitive_tags or ctx.requires_private_model:
            sensitive_tags = list(set(ctx.compliance_tags) & PRIVATE_MODEL_TAGS)
            return RoutingDecision(
                action=RoutingAction.ROUTE,
                target_model=self._private_model,
                target_provider=self._private_provider,
                original_model=ctx.model_name,
                reason=f"Sensitive data detected: {sensitive_tags or ['requires_private_model']}",
                matched_rule_name="builtin:sensitivity_routing",
                details={
                    "sensitive_tags": sensitive_tags,
                    "requires_private_model": ctx.requires_private_model,
                    "sensitivity_score": ctx.sensitivity_score,
                },
            )
        return None

    # Maximum depth for recursive composite conditions (DoS protection)
    MAX_COMPOSITE_DEPTH = 5

    def _matches_condition(self, rule: dict, ctx: RoutingContext, _depth: int = 0) -> bool:
        """Check if a rule's condition matches the routing context."""
        if _depth > self.MAX_COMPOSITE_DEPTH:
            logger.warning("Routing rule exceeded max composite depth (%d), rejecting", self.MAX_COMPOSITE_DEPTH)
            return False

        condition_type = rule.get("condition_type", "")
        try:
            condition = json.loads(rule.get("condition_json", "{}"))
        except (json.JSONDecodeError, TypeError):
            condition = {}

        if condition_type == "sensitivity":
            return self._match_sensitivity(condition, ctx)
        elif condition_type == "budget":
            return self._match_budget(condition, ctx)
        elif condition_type == "compliance_tag":
            return self._match_compliance_tag(condition, ctx)
        elif condition_type == "kill_switch":
            return self._match_kill_switch(condition, ctx)
        elif condition_type == "composite":
            return self._match_composite(condition, ctx, _depth=_depth)
        return False

    def _match_sensitivity(self, condition: dict, ctx: RoutingContext) -> bool:
        tags = set(condition.get("tags", []))
        operator = condition.get("operator", "any")
        if operator == "any":
            return bool(set(ctx.compliance_tags) & tags)
        elif operator == "all":
            return tags.issubset(set(ctx.compliance_tags))
        elif operator == "score_above":
            threshold = condition.get("threshold", 0.5)
            return ctx.sensitivity_score > threshold
        return False

    def _match_budget(self, condition: dict, ctx: RoutingContext) -> bool:
        if condition.get("budget_exceeded"):
            return ctx.budget_exceeded
        threshold_pct = condition.get("usage_above_pct", 100)
        return ctx.budget_usage_pct >= threshold_pct

    def _match_compliance_tag(self, condition: dict, ctx: RoutingContext) -> bool:
        required_tags = set(condition.get("tags", []))
        operator = condition.get("operator", "any")
        if operator == "any":
            return bool(set(ctx.compliance_tags) & required_tags)
        elif operator == "all":
            return required_tags.issubset(set(ctx.compliance_tags))
        elif operator == "none":
            return not bool(set(ctx.compliance_tags) & required_tags)
        return False

    def _match_kill_switch(self, condition: dict, ctx: RoutingContext) -> bool:
        return ctx.kill_switch_active

    def _match_composite(self, condition: dict, ctx: RoutingContext, _depth: int = 0) -> bool:
        """Evaluate multiple sub-conditions with AND/OR logic."""
        operator = condition.get("operator", "and")
        sub_conditions = condition.get("conditions", [])

        if not sub_conditions:
            return False  # Empty conditions should not match

        results = []
        for sub in sub_conditions:
            sub_rule = {"condition_type": sub.get("type", ""), "condition_json": json.dumps(sub.get("condition", {}))}
            results.append(self._matches_condition(sub_rule, ctx, _depth=_depth + 1))

        if operator == "and":
            return all(results)
        elif operator == "or":
            return any(results)
        return False


# Module-level singleton
_evaluator: Optional[RoutingPolicyEvaluator] = None


def get_routing_policy_evaluator() -> RoutingPolicyEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = RoutingPolicyEvaluator()
    return _evaluator
