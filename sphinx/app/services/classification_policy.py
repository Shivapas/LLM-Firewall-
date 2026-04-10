"""Classification Policy Engine — Sprint 3 (Thoth Enhancement).

Implements the ``classification.*`` attribute namespace for Sphinx policy rules,
making Thoth semantic signals first-class citizens in the policy evaluation
context (FR-POL-01 through FR-POL-05).

Sprint 3 tasks implemented
--------------------------
S3-T1  Policy rule DSL extension — ``classification.*`` attribute namespace with
       predicate operators (eq, ne, gt, gte, lt, lte, contains, in).
S3-T2  Attribute binding — ``PolicyEvalContext`` binds ``ClassificationContext``
       fields to the policy evaluation context alongside structural signals.
S3-T3  Rule composition — classification attributes composable with structural
       predicates (threat.risk_level, threat.score, request.model, etc.) via
       AND / OR condition trees.
S3-T4  Graceful degradation — per-rule ``on_unavailable`` field controls
       behaviour when Thoth classification is absent (skip / fail_closed / allow).

Attribute namespace
-------------------
Classification (from Thoth):
  classification.intent           str      Thoth intent category
  classification.risk_level       str      LOW | MEDIUM | HIGH | CRITICAL
  classification.confidence       float    0.00–1.00
  classification.pii_detected     bool
  classification.pii_types        list[str]

Structural (composable, FR-POL-03):
  threat.risk_level   str    low | medium | high | critical  (case-insensitive ordinal)
  threat.score        float  0.0–1.0
  request.model       str
  request.tenant_id   str

Supported operators
-------------------
  eq         equality  (all scalar types)
  ne         not equal
  gt         strictly greater-than   (numeric / risk_level ordinal)
  gte        greater-than-or-equal
  lt         strictly less-than
  lte        less-than-or-equal
  contains   value appears in a list attribute (e.g. pii_types)
  in         attribute scalar value is in a provided list

Rule condition format (JSON)
-----------------------------
A condition is a recursive tree of nodes:

  # Leaf predicate
  {"type": "predicate", "attribute": "classification.intent",
   "operator": "eq", "value": "data_exfiltration"}

  # Compound AND (all predicates and nested conditions must match)
  {"type": "and",
   "predicates": [...],     # optional inline predicates
   "conditions": [...]}     # optional nested sub-condition nodes

  # Compound OR (any predicate or nested condition must match)
  {"type": "or",
   "predicates": [...],
   "conditions": [...]}

Full rule JSON schema (as stored in DB / loaded via load_rules())
-----------------------------------------------------------------
{
    "id":             "<str>",
    "name":           "<str>",
    "priority":       <int>,          # lower = evaluated first
    "is_active":      <bool>,
    "tenant_id":      "<str>",        # "*" = global
    "condition":      <ConditionNode>,
    "action":         "allow|block|route|queue_for_review",
    "audit_severity": "INFO|WARNING|CRITICAL",
    "audit_tag":      "<str>",        # optional tag appended to audit record
    "route_endpoint": "<str|null>",   # target endpoint for route action
    "notify":         "<str|null>",   # notification target for review action
    "on_unavailable": "skip|fail_closed|allow"  # FR-POL-05 degradation mode
}

Example rules (PRD §7.4)
-------------------------
Block high-confidence exfiltration:
  condition: {"type":"and","predicates":[
    {"attribute":"classification.intent","operator":"eq","value":"data_exfiltration"},
    {"attribute":"classification.confidence","operator":"gte","value":0.85}
  ]}
  action: "block", audit_severity: "CRITICAL"

Route Aadhaar PII to on-prem:
  condition: {"type":"and","predicates":[
    {"attribute":"classification.pii_detected","operator":"eq","value":true},
    {"attribute":"classification.pii_types","operator":"contains","value":"AADHAAR"}
  ]}
  action: "route", route_endpoint: "onprem_llm", audit_tag: "DPDPA_SENSITIVE"

Graceful degradation — FR-POL-05:
  on_unavailable: "skip"        — rule is bypassed when classification unavailable
  on_unavailable: "fail_closed" — rule fires (with its action) when unavailable
  on_unavailable: "allow"       — rule is bypassed (synonym for skip; explicit intent)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.services.thoth.models import ClassificationContext

logger = logging.getLogger("sphinx.classification_policy")

# ---------------------------------------------------------------------------
# Risk-level ordinal map — enables gte / lte comparisons on string labels
# ---------------------------------------------------------------------------

_RISK_ORDINAL: dict[str, int] = {
    # Lowercase variants (threat engine)
    "unknown": -1,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
    # Uppercase variants (Thoth)
    "UNKNOWN": -1,
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

# DoS protection — maximum recursion depth for nested condition trees
_MAX_CONDITION_DEPTH = 8


# ---------------------------------------------------------------------------
# S3-T2: PolicyEvalContext — attribute binding
# ---------------------------------------------------------------------------

@dataclass
class PolicyEvalContext:
    """Combined evaluation context for classification policy rules (S3-T2).

    Holds both Thoth classification signals and structural pipeline signals so
    that ``classification.*`` attributes can be composed with ``threat.*`` and
    ``request.*`` attributes in a single rule (FR-POL-03 / S3-T3).

    ``classification_available`` is ``True`` only when Thoth returned a live
    classification (event == "classified").  Rules referencing
    ``classification.*`` attributes will behave per their ``on_unavailable``
    field when this is ``False`` (S3-T4 / FR-POL-05).
    """

    # Thoth classification signals
    classification: Optional[ClassificationContext] = None
    classification_available: bool = False

    # Structural signals from threat detection engine
    threat_risk_level: str = "low"
    threat_score: float = 0.0

    # Request metadata
    tenant_id: str = ""
    model_name: str = ""
    request_id: str = ""


# ---------------------------------------------------------------------------
# ClassificationPolicyResult
# ---------------------------------------------------------------------------

@dataclass
class ClassificationPolicyResult:
    """Outcome of evaluating classification policy rules against a context."""

    action: str = "allow"                   # allow | block | route | queue_for_review
    matched_rule_id: str = ""
    matched_rule_name: str = ""
    reason: str = "no_rule_matched"
    audit_severity: str = "INFO"
    audit_tag: str = ""
    route_endpoint: Optional[str] = None    # For action == "route"
    notify: Optional[str] = None            # For action == "queue_for_review"
    classification_available: bool = True
    rules_evaluated: int = 0
    evaluation_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "matched_rule_id": self.matched_rule_id,
            "matched_rule_name": self.matched_rule_name,
            "reason": self.reason,
            "audit_severity": self.audit_severity,
            "audit_tag": self.audit_tag,
            "route_endpoint": self.route_endpoint,
            "notify": self.notify,
            "classification_available": self.classification_available,
            "rules_evaluated": self.rules_evaluated,
            "evaluation_time_ms": round(self.evaluation_time_ms, 3),
        }


# ---------------------------------------------------------------------------
# S3-T1 / S3-T3: ClassificationPolicyEvaluator
# ---------------------------------------------------------------------------

class ClassificationPolicyEvaluator:
    """Evaluates policy rules that reference ``classification.*`` attributes.

    Rules are processed in ascending priority order; the first matching rule's
    action is returned.  When no rule matches, the default result has
    ``action == "allow"``.

    Thread safety
    -------------
    The evaluator is effectively read-only after ``load_rules()`` completes.
    Rule loading is not concurrency-safe and should be called once at startup.
    """

    def __init__(self) -> None:
        self._rules: list[dict] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_rules(self, rules: list[dict]) -> None:
        """Load and sort rules by priority (ascending = higher precedence)."""
        self._rules = sorted(rules, key=lambda r: r.get("priority", 100))
        logger.info("Classification policy: loaded %d rule(s)", len(self._rules))

    def evaluate(self, ctx: PolicyEvalContext) -> ClassificationPolicyResult:
        """Evaluate loaded rules against *ctx*.

        Returns the first matching rule's decision, or a default allow result
        if no rule matches.
        """
        start = time.monotonic()

        for idx, rule in enumerate(self._rules):
            if not rule.get("is_active", True):
                continue

            # Tenant scope check — "*" matches any tenant
            rule_tenant = rule.get("tenant_id", "*")
            if rule_tenant != "*" and rule_tenant != ctx.tenant_id:
                continue

            # ── S3-T4: Graceful degradation (FR-POL-05) ─────────────────
            on_unavailable = rule.get("on_unavailable", "skip")
            if not ctx.classification_available:
                if on_unavailable == "fail_closed":
                    elapsed = (time.monotonic() - start) * 1000
                    result = self._result_from_rule(rule, ctx, idx + 1, elapsed)
                    result.reason = (
                        f"fail_closed:classification_unavailable:"
                        f"rule={rule.get('name', '')}"
                    )
                    result.classification_available = False
                    logger.warning(
                        "Classification policy FAIL_CLOSED rule=%s tenant=%s",
                        rule.get("name", ""),
                        ctx.tenant_id,
                    )
                    return result
                # "skip" or "allow" — do not match this rule
                continue

            # ── S3-T1 / S3-T3: Evaluate condition tree ──────────────────
            condition = rule.get("condition", {})
            if self._evaluate_condition(condition, ctx, _depth=0):
                elapsed = (time.monotonic() - start) * 1000
                result = self._result_from_rule(rule, ctx, idx + 1, elapsed)
                logger.info(
                    "Classification policy matched: rule=%s action=%s tenant=%s",
                    rule.get("name", ""),
                    result.action,
                    ctx.tenant_id,
                )
                return result

        # No rule matched
        elapsed = (time.monotonic() - start) * 1000
        return ClassificationPolicyResult(
            action="allow",
            reason="no_classification_rule_matched",
            classification_available=ctx.classification_available,
            rules_evaluated=len(self._rules),
            evaluation_time_ms=elapsed,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _result_from_rule(
        rule: dict,
        ctx: PolicyEvalContext,
        rules_evaluated: int,
        elapsed_ms: float,
    ) -> ClassificationPolicyResult:
        return ClassificationPolicyResult(
            action=rule.get("action", "allow"),
            matched_rule_id=str(rule.get("id", "")),
            matched_rule_name=rule.get("name", ""),
            reason=f"matched_rule:{rule.get('name', '')}",
            audit_severity=rule.get("audit_severity", "INFO"),
            audit_tag=rule.get("audit_tag", ""),
            route_endpoint=rule.get("route_endpoint"),
            notify=rule.get("notify"),
            classification_available=ctx.classification_available,
            rules_evaluated=rules_evaluated,
            evaluation_time_ms=elapsed_ms,
        )

    def _evaluate_condition(
        self,
        condition: dict,
        ctx: PolicyEvalContext,
        _depth: int = 0,
    ) -> bool:
        """Recursively evaluate a condition-tree node (S3-T3)."""
        if _depth > _MAX_CONDITION_DEPTH:
            logger.warning(
                "Classification policy condition exceeded max depth (%d), rejecting",
                _MAX_CONDITION_DEPTH,
            )
            return False

        if not condition:
            return False

        node_type = condition.get("type", "predicate")

        if node_type == "predicate":
            return self._evaluate_predicate(
                attribute=condition.get("attribute", ""),
                operator=condition.get("operator", "eq"),
                value=condition.get("value"),
                ctx=ctx,
            )

        if node_type in ("and", "or"):
            # Gather results from inline predicates and nested sub-conditions
            results: list[bool] = []

            for pred in condition.get("predicates", []):
                results.append(
                    self._evaluate_predicate(
                        attribute=pred.get("attribute", ""),
                        operator=pred.get("operator", "eq"),
                        value=pred.get("value"),
                        ctx=ctx,
                    )
                )

            for sub in condition.get("conditions", []):
                results.append(
                    self._evaluate_condition(sub, ctx, _depth=_depth + 1)
                )

            if not results:
                return False  # Empty conditions never match

            return all(results) if node_type == "and" else any(results)

        logger.warning(
            "Classification policy: unknown condition type '%s', skipping", node_type
        )
        return False

    def _evaluate_predicate(
        self,
        attribute: str,
        operator: str,
        value: Any,
        ctx: PolicyEvalContext,
    ) -> bool:
        """Evaluate a single leaf predicate (S3-T1)."""
        attr_val = self._resolve_attribute(attribute, ctx)

        # classification.* attribute requested but classification unavailable:
        # returning False here is defensive; on_unavailable logic in evaluate()
        # should have handled this before reaching a condition evaluation.
        if attr_val is None and attribute.startswith("classification."):
            return False

        try:
            return _apply_operator(operator, attr_val, value, attribute)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Classification policy predicate error attr=%s op=%s val=%r: %s",
                attribute,
                operator,
                value,
                exc,
            )
            return False

    @staticmethod
    def _resolve_attribute(attribute: str, ctx: PolicyEvalContext) -> Any:
        """Resolve a dotted attribute path to its runtime value (S3-T2)."""
        # ── classification.* ────────────────────────────────────────────
        if attribute.startswith("classification."):
            if ctx.classification is None:
                return None
            field_name = attribute[len("classification."):]
            return getattr(ctx.classification, field_name, None)

        # ── threat.* (structural) ────────────────────────────────────────
        if attribute == "threat.risk_level":
            return ctx.threat_risk_level
        if attribute == "threat.score":
            return ctx.threat_score

        # ── request.* ───────────────────────────────────────────────────
        if attribute == "request.model":
            return ctx.model_name
        if attribute == "request.tenant_id":
            return ctx.tenant_id

        logger.warning("Classification policy: unknown attribute '%s'", attribute)
        return None


# ---------------------------------------------------------------------------
# Operator implementation (module-level for clarity)
# ---------------------------------------------------------------------------

def _apply_operator(
    operator: str, attr_val: Any, rule_val: Any, attribute: str
) -> bool:
    """Apply *operator* between the resolved *attr_val* and the rule *rule_val*.

    Handles four value families:
      - bool    (eq / ne)
      - list    (contains / eq)
      - numeric (eq / ne / gt / gte / lt / lte)
      - str     (eq / ne / in / contains; ordinal for risk_level attributes)
    """
    # ── Boolean ─────────────────────────────────────────────────────────
    if isinstance(attr_val, bool):
        if operator == "eq":
            return attr_val == bool(rule_val)
        if operator == "ne":
            return attr_val != bool(rule_val)
        raise ValueError(f"Unsupported operator '{operator}' for bool attribute '{attribute}'")

    # ── List (e.g. pii_types) ────────────────────────────────────────────
    if isinstance(attr_val, list):
        if operator == "contains":
            return rule_val in attr_val
        if operator == "eq":
            return attr_val == rule_val
        if operator == "ne":
            return attr_val != rule_val
        raise ValueError(f"Unsupported operator '{operator}' for list attribute '{attribute}'")

    # ── Numeric (confidence, threat.score) ──────────────────────────────
    if isinstance(attr_val, (int, float)) and not isinstance(attr_val, bool):
        rv = float(rule_val)
        if operator == "eq":
            return attr_val == rv
        if operator == "ne":
            return attr_val != rv
        if operator == "gt":
            return attr_val > rv
        if operator == "gte":
            return attr_val >= rv
        if operator == "lt":
            return attr_val < rv
        if operator == "lte":
            return attr_val <= rv
        raise ValueError(f"Unsupported operator '{operator}' for numeric attribute '{attribute}'")

    # ── String ──────────────────────────────────────────────────────────
    if isinstance(attr_val, str):
        is_risk_attr = attribute in ("classification.risk_level", "threat.risk_level")

        # Ordinal comparison for risk-level strings
        if is_risk_attr and operator in ("gt", "gte", "lt", "lte"):
            attr_ord = _RISK_ORDINAL.get(attr_val, -1)
            rule_ord = _RISK_ORDINAL.get(str(rule_val), -1)
            if operator == "gt":
                return attr_ord > rule_ord
            if operator == "gte":
                return attr_ord >= rule_ord
            if operator == "lt":
                return attr_ord < rule_ord
            if operator == "lte":
                return attr_ord <= rule_ord

        if operator == "eq":
            return attr_val == str(rule_val)
        if operator == "ne":
            return attr_val != str(rule_val)
        if operator == "in":
            return attr_val in list(rule_val)
        if operator == "contains":
            return str(rule_val) in attr_val
        raise ValueError(f"Unsupported operator '{operator}' for string attribute '{attribute}'")

    # ── None / unknown ───────────────────────────────────────────────────
    if operator == "eq":
        return attr_val == rule_val
    if operator == "ne":
        return attr_val != rule_val
    return False


# ---------------------------------------------------------------------------
# Module-level singleton (FR-CFG-02 compatible — rules loaded per policy group)
# ---------------------------------------------------------------------------

_evaluator: Optional[ClassificationPolicyEvaluator] = None


def get_classification_policy_evaluator() -> ClassificationPolicyEvaluator:
    """Return the singleton ``ClassificationPolicyEvaluator``, creating it if needed."""
    global _evaluator
    if _evaluator is None:
        _evaluator = ClassificationPolicyEvaluator()
    return _evaluator
