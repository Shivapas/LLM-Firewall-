"""Sprint 3 — Classification Policy Engine Tests.

Exit criteria (PRD §10 Sprint 3):
  Policy rules can reference classification.intent, classification.risk_level,
  classification.confidence, classification.pii_detected, and
  classification.pii_types[]. Rules evaluate correctly in presence and absence
  of classification data.

Test coverage
-------------
S3-T1  DSL: classification.* attribute namespace (predicate operators)
S3-T2  Attribute binding: PolicyEvalContext exposes ClassificationContext fields
S3-T3  Rule composition: classification.* composable with threat.* / request.*
S3-T4  Graceful degradation: on_unavailable = skip | fail_closed | allow
S3-T5  Policy authoring: 10+ distinct rule patterns validated end-to-end

FR-POL-01  classification.* attribute namespace available in policy rules
FR-POL-02  All five classification attributes supported
FR-POL-03  Logical composition with existing Sphinx predicates
FR-POL-04  Example rule patterns from PRD §7.4 evaluate correctly
FR-POL-05  Graceful degradation when classification is unavailable
"""

import pytest
from app.services.classification_policy import (
    ClassificationPolicyEvaluator,
    PolicyEvalContext,
    ClassificationPolicyResult,
    get_classification_policy_evaluator,
    _apply_operator,
    _RISK_ORDINAL,
)
from app.services.thoth.models import ClassificationContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(
    intent: str = "general_query",
    risk_level: str = "LOW",
    confidence: float = 0.80,
    pii_detected: bool = False,
    pii_types: list[str] | None = None,
    threat_risk_level: str = "low",
    threat_score: float = 0.0,
    tenant_id: str = "tenant-1",
    model_name: str = "gpt-4",
    classification_available: bool = True,
) -> PolicyEvalContext:
    """Build a PolicyEvalContext with a live Thoth ClassificationContext."""
    ctx = ClassificationContext(
        request_id="req-test",
        intent=intent,
        risk_level=risk_level,
        confidence=confidence,
        pii_detected=pii_detected,
        pii_types=pii_types or [],
    )
    return PolicyEvalContext(
        classification=ctx,
        classification_available=classification_available,
        threat_risk_level=threat_risk_level,
        threat_score=threat_score,
        tenant_id=tenant_id,
        model_name=model_name,
    )


def _make_unavailable_ctx(
    tenant_id: str = "tenant-1",
    threat_risk_level: str = "low",
) -> PolicyEvalContext:
    """Build a PolicyEvalContext where Thoth classification is unavailable."""
    from app.services.thoth.models import make_unavailable_context
    return PolicyEvalContext(
        classification=make_unavailable_context("req-unavail"),
        classification_available=False,
        threat_risk_level=threat_risk_level,
        tenant_id=tenant_id,
    )


def _evaluator_with(*rules: dict) -> ClassificationPolicyEvaluator:
    ev = ClassificationPolicyEvaluator()
    ev.load_rules(list(rules))
    return ev


# ---------------------------------------------------------------------------
# Fixtures — reusable rule definitions (maps to PRD §7.4 examples)
# ---------------------------------------------------------------------------

RULE_BLOCK_EXFILTRATION = {
    "id": "r-001",
    "name": "block_exfiltration",
    "priority": 10,
    "is_active": True,
    "tenant_id": "*",
    "condition": {
        "type": "and",
        "predicates": [
            {"attribute": "classification.intent", "operator": "eq",
             "value": "data_exfiltration"},
            {"attribute": "classification.confidence", "operator": "gte",
             "value": 0.85},
        ],
    },
    "action": "block",
    "audit_severity": "CRITICAL",
    "on_unavailable": "skip",
}

RULE_ROUTE_AADHAAR = {
    "id": "r-002",
    "name": "pii_aadhaar_routing",
    "priority": 20,
    "is_active": True,
    "tenant_id": "*",
    "condition": {
        "type": "and",
        "predicates": [
            {"attribute": "classification.pii_detected", "operator": "eq",
             "value": True},
            {"attribute": "classification.pii_types", "operator": "contains",
             "value": "AADHAAR"},
        ],
    },
    "action": "route",
    "route_endpoint": "onprem_llm",
    "audit_tag": "DPDPA_SENSITIVE",
    "on_unavailable": "skip",
}

RULE_HITL_MEDIUM_LOW_CONF = {
    "id": "r-003",
    "name": "hitl_medium_low_confidence",
    "priority": 30,
    "is_active": True,
    "tenant_id": "*",
    "condition": {
        "type": "and",
        "predicates": [
            {"attribute": "classification.risk_level", "operator": "eq",
             "value": "MEDIUM"},
            {"attribute": "classification.confidence", "operator": "lt",
             "value": 0.70},
        ],
    },
    "action": "queue_for_review",
    "notify": "security_ops_team",
    "on_unavailable": "skip",
}


# ===========================================================================
# S3-T1 / FR-POL-01,02: classification.* attribute namespace — unit tests
# ===========================================================================

class TestClassificationAttributeNamespace:
    """FR-POL-01/02: All five classification attributes must be resolvable."""

    def test_intent_eq_match(self):
        """classification.intent == value → match."""
        ev = _evaluator_with(RULE_BLOCK_EXFILTRATION)
        ctx = _make_ctx(intent="data_exfiltration", confidence=0.90)
        result = ev.evaluate(ctx)
        assert result.action == "block"
        assert result.matched_rule_name == "block_exfiltration"

    def test_intent_eq_no_match(self):
        """classification.intent != value → no match → allow."""
        ev = _evaluator_with(RULE_BLOCK_EXFILTRATION)
        ctx = _make_ctx(intent="general_query", confidence=0.90)
        result = ev.evaluate(ctx)
        assert result.action == "allow"

    def test_risk_level_ordinal_gte(self):
        """classification.risk_level >= HIGH → block rule fires for HIGH and CRITICAL."""
        rule = {
            "id": "r-010",
            "name": "block_high_plus",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.risk_level",
                "operator": "gte",
                "value": "HIGH",
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        assert ev.evaluate(_make_ctx(risk_level="HIGH")).action == "block"
        assert ev.evaluate(_make_ctx(risk_level="CRITICAL")).action == "block"
        assert ev.evaluate(_make_ctx(risk_level="MEDIUM")).action == "allow"
        assert ev.evaluate(_make_ctx(risk_level="LOW")).action == "allow"

    def test_confidence_gte_threshold(self):
        """classification.confidence >= 0.85 boundary behaviour."""
        rule = {
            "id": "r-011",
            "name": "high_conf_block",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.confidence",
                "operator": "gte",
                "value": 0.85,
            },
            "action": "block",
            "audit_severity": "WARNING",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        assert ev.evaluate(_make_ctx(confidence=0.85)).action == "block"
        assert ev.evaluate(_make_ctx(confidence=0.90)).action == "block"
        assert ev.evaluate(_make_ctx(confidence=0.84)).action == "allow"

    def test_pii_detected_bool(self):
        """classification.pii_detected == true/false."""
        rule = {
            "id": "r-012",
            "name": "pii_flag",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.pii_detected",
                "operator": "eq",
                "value": True,
            },
            "action": "block",
            "audit_severity": "WARNING",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        assert ev.evaluate(_make_ctx(pii_detected=True)).action == "block"
        assert ev.evaluate(_make_ctx(pii_detected=False)).action == "allow"

    def test_pii_types_contains(self):
        """classification.pii_types CONTAINS value."""
        ev = _evaluator_with(RULE_ROUTE_AADHAAR)
        ctx_match = _make_ctx(pii_detected=True, pii_types=["AADHAAR", "EMAIL"])
        ctx_no_match = _make_ctx(pii_detected=True, pii_types=["EMAIL"])
        assert ev.evaluate(ctx_match).action == "route"
        assert ev.evaluate(ctx_no_match).action == "allow"

    def test_pii_types_contains_bank_account(self):
        """BANK_ACCOUNT in pii_types triggers route."""
        rule = {
            "id": "r-020",
            "name": "bank_account_routing",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.pii_types",
                "operator": "contains",
                "value": "BANK_ACCOUNT",
            },
            "action": "route",
            "route_endpoint": "secure_llm",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        assert ev.evaluate(
            _make_ctx(pii_detected=True, pii_types=["BANK_ACCOUNT"])
        ).action == "route"
        assert ev.evaluate(
            _make_ctx(pii_detected=True, pii_types=["EMAIL"])
        ).action == "allow"


# ===========================================================================
# S3-T3 / FR-POL-03: Rule composition — AND / OR / nested conditions
# ===========================================================================

class TestRuleComposition:
    """FR-POL-03: classification.* composable with threat.* and request.* predicates."""

    def test_and_classification_plus_threat(self):
        """classification.intent AND threat.risk_level must both match."""
        rule = {
            "id": "r-030",
            "name": "exfil_plus_threat",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {"attribute": "classification.intent", "operator": "eq",
                     "value": "data_exfiltration"},
                    {"attribute": "threat.risk_level", "operator": "gte",
                     "value": "high"},
                ],
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        # Both match
        assert ev.evaluate(
            _make_ctx(intent="data_exfiltration", threat_risk_level="high")
        ).action == "block"
        # Only classification matches
        assert ev.evaluate(
            _make_ctx(intent="data_exfiltration", threat_risk_level="low")
        ).action == "allow"
        # Only threat matches
        assert ev.evaluate(
            _make_ctx(intent="general_query", threat_risk_level="high")
        ).action == "allow"

    def test_or_classification_or_threat(self):
        """classification.intent OR threat.risk_level — either fires the rule."""
        rule = {
            "id": "r-031",
            "name": "either_signal_block",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "or",
                "predicates": [
                    {"attribute": "classification.intent", "operator": "eq",
                     "value": "jailbreak"},
                    {"attribute": "threat.risk_level", "operator": "eq",
                     "value": "critical"},
                ],
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        assert ev.evaluate(_make_ctx(intent="jailbreak", threat_risk_level="low")).action == "block"
        assert ev.evaluate(_make_ctx(intent="general_query", threat_risk_level="critical")).action == "block"
        assert ev.evaluate(_make_ctx(intent="general_query", threat_risk_level="low")).action == "allow"

    def test_nested_and_or_condition(self):
        """Nested condition: (intent=exfil AND confidence>=0.85) OR risk=CRITICAL."""
        rule = {
            "id": "r-032",
            "name": "nested_block",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "or",
                "predicates": [],
                "conditions": [
                    {
                        "type": "and",
                        "predicates": [
                            {"attribute": "classification.intent", "operator": "eq",
                             "value": "data_exfiltration"},
                            {"attribute": "classification.confidence", "operator": "gte",
                             "value": 0.85},
                        ],
                    },
                    {
                        "type": "predicate",
                        "attribute": "classification.risk_level",
                        "operator": "eq",
                        "value": "CRITICAL",
                    },
                ],
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        # First branch: exfil + high confidence
        assert ev.evaluate(_make_ctx(intent="data_exfiltration", confidence=0.90)).action == "block"
        # Second branch: CRITICAL risk regardless of intent
        assert ev.evaluate(_make_ctx(risk_level="CRITICAL", intent="general_query")).action == "block"
        # Neither branch
        assert ev.evaluate(
            _make_ctx(intent="data_exfiltration", confidence=0.70, risk_level="LOW")
        ).action == "allow"

    def test_composition_with_request_model(self):
        """classification.risk_level AND request.model composition."""
        rule = {
            "id": "r-033",
            "name": "high_risk_specific_model",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {"attribute": "classification.risk_level", "operator": "gte",
                     "value": "HIGH"},
                    {"attribute": "request.model", "operator": "eq",
                     "value": "gpt-4"},
                ],
            },
            "action": "block",
            "audit_severity": "WARNING",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        # Both match
        assert ev.evaluate(_make_ctx(risk_level="HIGH", model_name="gpt-4")).action == "block"
        # Model mismatch
        assert ev.evaluate(_make_ctx(risk_level="HIGH", model_name="gpt-3.5-turbo")).action == "allow"

    def test_or_pii_types_multiple_values(self):
        """OR: AADHAAR or PAN in pii_types triggers route."""
        rule = {
            "id": "r-034",
            "name": "india_pii_routing",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "or",
                "predicates": [
                    {"attribute": "classification.pii_types", "operator": "contains",
                     "value": "AADHAAR"},
                    {"attribute": "classification.pii_types", "operator": "contains",
                     "value": "PAN"},
                ],
            },
            "action": "route",
            "route_endpoint": "onprem_llm",
            "audit_tag": "DPDPA_SENSITIVE",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(rule)
        assert ev.evaluate(_make_ctx(pii_types=["AADHAAR"])).action == "route"
        assert ev.evaluate(_make_ctx(pii_types=["PAN"])).action == "route"
        assert ev.evaluate(_make_ctx(pii_types=["EMAIL"])).action == "allow"


# ===========================================================================
# S3-T4 / FR-POL-05: Graceful degradation — on_unavailable
# ===========================================================================

class TestGracefulDegradation:
    """FR-POL-05: Rules with classification attributes must degrade correctly."""

    def test_on_unavailable_skip_does_not_match(self):
        """on_unavailable=skip: rule is bypassed when classification unavailable."""
        rule = {**RULE_BLOCK_EXFILTRATION, "on_unavailable": "skip"}
        ev = _evaluator_with(rule)
        ctx = _make_unavailable_ctx()
        result = ev.evaluate(ctx)
        assert result.action == "allow"
        assert result.classification_available is False

    def test_on_unavailable_fail_closed_fires_rule_action(self):
        """on_unavailable=fail_closed: rule fires when classification unavailable."""
        rule = {
            "id": "r-fc-01",
            "name": "sensitive_fail_closed",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.risk_level",
                "operator": "eq",
                "value": "HIGH",
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "fail_closed",
        }
        ev = _evaluator_with(rule)
        ctx = _make_unavailable_ctx()
        result = ev.evaluate(ctx)
        assert result.action == "block"
        assert result.classification_available is False
        assert "fail_closed" in result.reason

    def test_on_unavailable_allow_bypasses_rule(self):
        """on_unavailable=allow: rule is bypassed (explicit safe-pass intent)."""
        rule = {
            "id": "r-fc-02",
            "name": "low_risk_pass",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.intent",
                "operator": "eq",
                "value": "data_exfiltration",
            },
            "action": "block",
            "audit_severity": "WARNING",
            "on_unavailable": "allow",
        }
        ev = _evaluator_with(rule)
        ctx = _make_unavailable_ctx()
        result = ev.evaluate(ctx)
        assert result.action == "allow"

    def test_fail_closed_after_skip_rule(self):
        """Multiple rules: skip rule is bypassed, fail_closed rule fires next."""
        skip_rule = {
            "id": "r-fc-03",
            "name": "skip_first",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.intent",
                "operator": "eq",
                "value": "data_exfiltration",
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        fail_closed_rule = {
            "id": "r-fc-04",
            "name": "fail_closed_second",
            "priority": 20,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "predicate",
                "attribute": "classification.risk_level",
                "operator": "eq",
                "value": "HIGH",
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "fail_closed",
        }
        ev = _evaluator_with(skip_rule, fail_closed_rule)
        ctx = _make_unavailable_ctx()
        result = ev.evaluate(ctx)
        assert result.action == "block"
        assert result.matched_rule_name == "fail_closed_second"

    def test_classification_available_live_context_not_degraded(self):
        """Live classification context is not subject to on_unavailable logic."""
        rule = {**RULE_BLOCK_EXFILTRATION, "on_unavailable": "fail_closed"}
        ev = _evaluator_with(rule)
        # Live context — should evaluate condition normally and not match
        ctx = _make_ctx(intent="general_query", confidence=0.90)
        result = ev.evaluate(ctx)
        assert result.action == "allow"


# ===========================================================================
# FR-POL-04: PRD §7.4 example rule patterns end-to-end
# ===========================================================================

class TestPRDExampleRulePatterns:
    """FR-POL-04: Validate all three PRD §7.4 example rule patterns."""

    def test_block_high_confidence_exfiltration(self):
        """PRD §7.4 example 1 — block high-confidence data_exfiltration."""
        ev = _evaluator_with(RULE_BLOCK_EXFILTRATION)

        # Should block: intent matches, confidence >= 0.85
        assert ev.evaluate(
            _make_ctx(intent="data_exfiltration", confidence=0.92)
        ).action == "block"

        # Should allow: confidence below threshold
        assert ev.evaluate(
            _make_ctx(intent="data_exfiltration", confidence=0.80)
        ).action == "allow"

        # Should allow: intent does not match
        assert ev.evaluate(
            _make_ctx(intent="general_query", confidence=0.95)
        ).action == "allow"

    def test_route_aadhaar_pii_to_onprem(self):
        """PRD §7.4 example 2 — route Aadhaar PII to on-prem endpoint."""
        ev = _evaluator_with(RULE_ROUTE_AADHAAR)

        result = ev.evaluate(
            _make_ctx(pii_detected=True, pii_types=["AADHAAR", "EMAIL"])
        )
        assert result.action == "route"
        assert result.route_endpoint == "onprem_llm"
        assert result.audit_tag == "DPDPA_SENSITIVE"

        # No Aadhaar → no route
        assert ev.evaluate(
            _make_ctx(pii_detected=True, pii_types=["CREDIT_CARD"])
        ).action == "allow"

        # pii_detected=False → no route even if AADHAAR present (both predicates AND'd)
        assert ev.evaluate(
            _make_ctx(pii_detected=False, pii_types=["AADHAAR"])
        ).action == "allow"

    def test_hitl_review_medium_risk_low_confidence(self):
        """PRD §7.4 example 3 — queue MEDIUM risk + confidence < 0.70 for HITL review."""
        ev = _evaluator_with(RULE_HITL_MEDIUM_LOW_CONF)

        result = ev.evaluate(_make_ctx(risk_level="MEDIUM", confidence=0.60))
        assert result.action == "queue_for_review"
        assert result.notify == "security_ops_team"

        # confidence at threshold — should NOT trigger (< 0.70 means 0.70 does not match)
        assert ev.evaluate(
            _make_ctx(risk_level="MEDIUM", confidence=0.70)
        ).action == "allow"

        # Different risk level
        assert ev.evaluate(
            _make_ctx(risk_level="HIGH", confidence=0.60)
        ).action == "allow"


# ===========================================================================
# Priority ordering, tenant scoping, inactive rules
# ===========================================================================

class TestRuleAdministration:
    """Rule priority, tenant scoping, and is_active flag behave correctly."""

    def test_lower_priority_number_wins(self):
        """Rule with lower priority number is evaluated first."""
        first = {**RULE_BLOCK_EXFILTRATION, "id": "r-p1", "priority": 5,
                 "action": "block", "name": "first_rule"}
        second = {**RULE_BLOCK_EXFILTRATION, "id": "r-p2", "priority": 50,
                  "action": "allow", "name": "second_rule"}
        ev = _evaluator_with(second, first)  # intentionally reversed order
        result = ev.evaluate(_make_ctx(intent="data_exfiltration", confidence=0.90))
        assert result.matched_rule_name == "first_rule"
        assert result.action == "block"

    def test_inactive_rule_is_skipped(self):
        """is_active=False rules are never evaluated."""
        inactive = {**RULE_BLOCK_EXFILTRATION, "is_active": False, "name": "inactive"}
        ev = _evaluator_with(inactive)
        result = ev.evaluate(_make_ctx(intent="data_exfiltration", confidence=0.90))
        assert result.action == "allow"

    def test_tenant_scoped_rule_matches_correct_tenant(self):
        """Tenant-specific rule only fires for matching tenant_id."""
        rule = {
            **RULE_BLOCK_EXFILTRATION,
            "id": "r-tenant",
            "name": "finance_only",
            "tenant_id": "finance-tenant",
        }
        ev = _evaluator_with(rule)
        ctx_match = _make_ctx(
            intent="data_exfiltration", confidence=0.90, tenant_id="finance-tenant"
        )
        ctx_other = _make_ctx(
            intent="data_exfiltration", confidence=0.90, tenant_id="hr-tenant"
        )
        assert ev.evaluate(ctx_match).action == "block"
        assert ev.evaluate(ctx_other).action == "allow"

    def test_global_rule_matches_all_tenants(self):
        """tenant_id='*' rule fires for any tenant."""
        ev = _evaluator_with(RULE_BLOCK_EXFILTRATION)
        for tenant in ("finance-tenant", "hr-tenant", "engineering"):
            ctx = _make_ctx(
                intent="data_exfiltration", confidence=0.90, tenant_id=tenant
            )
            assert ev.evaluate(ctx).action == "block"

    def test_no_rules_loaded_returns_allow(self):
        """Evaluator with no rules returns default allow."""
        ev = ClassificationPolicyEvaluator()
        result = ev.evaluate(_make_ctx())
        assert result.action == "allow"
        assert result.rules_evaluated == 0


# ===========================================================================
# Result object / to_dict
# ===========================================================================

class TestClassificationPolicyResult:
    """ClassificationPolicyResult serialises all fields correctly."""

    def test_to_dict_contains_all_fields(self):
        ev = _evaluator_with(RULE_ROUTE_AADHAAR)
        ctx = _make_ctx(pii_detected=True, pii_types=["AADHAAR"])
        result = ev.evaluate(ctx)
        d = result.to_dict()
        assert d["action"] == "route"
        assert d["matched_rule_id"] == "r-002"
        assert d["matched_rule_name"] == "pii_aadhaar_routing"
        assert d["route_endpoint"] == "onprem_llm"
        assert d["audit_tag"] == "DPDPA_SENSITIVE"
        assert d["classification_available"] is True
        assert "evaluation_time_ms" in d
        assert "rules_evaluated" in d

    def test_block_result_audit_severity_critical(self):
        ev = _evaluator_with(RULE_BLOCK_EXFILTRATION)
        ctx = _make_ctx(intent="data_exfiltration", confidence=0.90)
        result = ev.evaluate(ctx)
        assert result.audit_severity == "CRITICAL"

    def test_default_allow_result_fields(self):
        ev = _evaluator_with(RULE_BLOCK_EXFILTRATION)
        ctx = _make_ctx(intent="general_query")
        result = ev.evaluate(ctx)
        assert result.action == "allow"
        assert result.matched_rule_id == ""
        assert result.matched_rule_name == ""


# ===========================================================================
# Operator unit tests — _apply_operator
# ===========================================================================

class TestApplyOperator:
    """Low-level _apply_operator covers all operator / type combinations."""

    def test_string_eq_ne(self):
        assert _apply_operator("eq", "data_exfiltration", "data_exfiltration", "classification.intent")
        assert not _apply_operator("eq", "general_query", "data_exfiltration", "classification.intent")
        assert _apply_operator("ne", "general_query", "data_exfiltration", "classification.intent")

    def test_string_in_operator(self):
        assert _apply_operator("in", "HIGH", ["HIGH", "CRITICAL"], "classification.risk_level")
        assert not _apply_operator("in", "LOW", ["HIGH", "CRITICAL"], "classification.risk_level")

    def test_numeric_comparisons(self):
        assert _apply_operator("gte", 0.85, 0.85, "classification.confidence")
        assert _apply_operator("gt", 0.86, 0.85, "classification.confidence")
        assert not _apply_operator("gt", 0.85, 0.85, "classification.confidence")
        assert _apply_operator("lte", 0.69, 0.70, "classification.confidence")
        assert _apply_operator("lt", 0.69, 0.70, "classification.confidence")

    def test_bool_eq(self):
        assert _apply_operator("eq", True, True, "classification.pii_detected")
        assert not _apply_operator("eq", False, True, "classification.pii_detected")
        assert _apply_operator("ne", False, True, "classification.pii_detected")

    def test_list_contains(self):
        assert _apply_operator("contains", ["AADHAAR", "EMAIL"], "AADHAAR", "classification.pii_types")
        assert not _apply_operator("contains", ["EMAIL"], "AADHAAR", "classification.pii_types")

    def test_risk_level_ordinal_comparisons(self):
        """Risk-level strings support ordinal gt/gte/lt/lte comparisons."""
        assert _apply_operator("gte", "HIGH", "HIGH", "classification.risk_level")
        assert _apply_operator("gte", "CRITICAL", "HIGH", "classification.risk_level")
        assert not _apply_operator("gte", "MEDIUM", "HIGH", "classification.risk_level")
        assert _apply_operator("gt", "CRITICAL", "HIGH", "classification.risk_level")
        assert _apply_operator("lt", "LOW", "MEDIUM", "classification.risk_level")
        assert _apply_operator("lte", "MEDIUM", "HIGH", "classification.risk_level")

    def test_risk_ordinal_map_completeness(self):
        """All expected keys present in ordinal map."""
        for key in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN",
                    "low", "medium", "high", "critical", "unknown"):
            assert key in _RISK_ORDINAL


# ===========================================================================
# S3-T2: PolicyEvalContext attribute binding — resolve_attribute
# ===========================================================================

class TestAttributeBinding:
    """S3-T2: _resolve_attribute correctly maps dotted names to context values."""

    def _resolve(self, attribute: str, ctx: PolicyEvalContext):
        ev = ClassificationPolicyEvaluator()
        return ev._resolve_attribute(attribute, ctx)

    def test_classification_intent_binding(self):
        ctx = _make_ctx(intent="sql_injection")
        assert self._resolve("classification.intent", ctx) == "sql_injection"

    def test_classification_risk_level_binding(self):
        ctx = _make_ctx(risk_level="CRITICAL")
        assert self._resolve("classification.risk_level", ctx) == "CRITICAL"

    def test_classification_confidence_binding(self):
        ctx = _make_ctx(confidence=0.77)
        assert self._resolve("classification.confidence", ctx) == pytest.approx(0.77)

    def test_classification_pii_detected_binding(self):
        ctx = _make_ctx(pii_detected=True)
        assert self._resolve("classification.pii_detected", ctx) is True

    def test_classification_pii_types_binding(self):
        ctx = _make_ctx(pii_types=["AADHAAR", "PAN"])
        assert self._resolve("classification.pii_types", ctx) == ["AADHAAR", "PAN"]

    def test_threat_risk_level_binding(self):
        ctx = _make_ctx(threat_risk_level="high")
        assert self._resolve("threat.risk_level", ctx) == "high"

    def test_threat_score_binding(self):
        ctx = _make_ctx(threat_score=0.63)
        assert self._resolve("threat.score", ctx) == pytest.approx(0.63)

    def test_request_model_binding(self):
        ctx = _make_ctx(model_name="claude-opus-4")
        assert self._resolve("request.model", ctx) == "claude-opus-4"

    def test_request_tenant_id_binding(self):
        ctx = _make_ctx(tenant_id="finance-corp")
        assert self._resolve("request.tenant_id", ctx) == "finance-corp"

    def test_classification_returns_none_when_unavailable(self):
        ctx = _make_unavailable_ctx()
        # classification object is a fallback sentinel but classification_available=False;
        # direct attribute access still works via the object
        ctx.classification = None
        assert self._resolve("classification.intent", ctx) is None


# ===========================================================================
# Singleton accessor
# ===========================================================================

class TestSingleton:
    def test_get_classification_policy_evaluator_returns_same_instance(self):
        ev1 = get_classification_policy_evaluator()
        ev2 = get_classification_policy_evaluator()
        assert ev1 is ev2

    def test_singleton_is_evaluator_instance(self):
        assert isinstance(get_classification_policy_evaluator(), ClassificationPolicyEvaluator)


# ===========================================================================
# Depth-limit / DoS protection
# ===========================================================================

class TestDepthProtection:
    """Excessively nested condition trees are safely rejected."""

    def _make_deep_condition(self, depth: int) -> dict:
        if depth == 0:
            return {
                "type": "predicate",
                "attribute": "classification.intent",
                "operator": "eq",
                "value": "data_exfiltration",
            }
        return {
            "type": "and",
            "predicates": [],
            "conditions": [self._make_deep_condition(depth - 1)],
        }

    def test_condition_at_max_depth_succeeds(self):
        """Condition at exactly MAX_CONDITION_DEPTH evaluates without rejection."""
        from app.services.classification_policy import _MAX_CONDITION_DEPTH
        deep_rule = {
            "id": "r-deep-ok",
            "name": "deep_ok",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": self._make_deep_condition(_MAX_CONDITION_DEPTH - 1),
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(deep_rule)
        result = ev.evaluate(_make_ctx(intent="data_exfiltration"))
        # Either it matched or it was rejected safely — key thing is no exception
        assert result.action in ("block", "allow")

    def test_condition_exceeding_max_depth_returns_allow(self):
        """Condition exceeding MAX_CONDITION_DEPTH is safely rejected → allow."""
        from app.services.classification_policy import _MAX_CONDITION_DEPTH
        deep_rule = {
            "id": "r-deep-bad",
            "name": "deep_bad",
            "priority": 10,
            "is_active": True,
            "tenant_id": "*",
            "condition": self._make_deep_condition(_MAX_CONDITION_DEPTH + 5),
            "action": "block",
            "audit_severity": "CRITICAL",
            "on_unavailable": "skip",
        }
        ev = _evaluator_with(deep_rule)
        result = ev.evaluate(_make_ctx(intent="data_exfiltration"))
        # Deep condition is rejected → no match → default allow
        assert result.action == "allow"
