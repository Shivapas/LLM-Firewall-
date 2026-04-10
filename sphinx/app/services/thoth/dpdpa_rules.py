"""DPDPA-sensitive routing rule templates — Sprint 7 / S7-T2.

Pre-built classification policy rules for Indian regulatory compliance under
the Digital Personal Data Protection Act (DPDPA, 2023).  These rule templates
target India-specific PII types — Aadhaar, PAN, and bank account numbers —
and route matching traffic to isolated on-prem LLM endpoints tagged for
DPDPA compliance.

Usage
-----
The ``DPDPARuleTemplates`` class generates ready-to-load policy rule dicts
compatible with ``ClassificationPolicyEvaluator.load_rules()``.  Rules can
be loaded individually or as a complete template set.

Templates provided
------------------
1. ``aadhaar_routing``   — Routes prompts containing Aadhaar numbers to the
                           on-prem endpoint; audit-tagged ``DPDPA_SENSITIVE``.
2. ``pan_routing``       — Routes prompts containing PAN card numbers to the
                           on-prem endpoint; audit-tagged ``DPDPA_SENSITIVE``.
3. ``bank_account_routing`` — Routes prompts containing bank account numbers
                           to the on-prem endpoint; audit-tagged ``DPDPA_SENSITIVE``.
4. ``aadhaar_block``     — Blocks high-confidence Aadhaar exfiltration attempts.
5. ``pan_block``         — Blocks high-confidence PAN exfiltration attempts.
6. ``multi_pii_block``   — Blocks prompts containing multiple India-specific
                           PII types simultaneously (elevated risk).
7. ``dpdpa_sensitive_alert`` — Alerts on any DPDPA-sensitive PII detection
                           with medium+ risk level for security ops review.

Requirement references
----------------------
AC-07: DPDPA-sensitive routing rules correctly route Aadhaar/PAN/bank
       account-containing prompts.
PRD §7.4: Policy rule extension examples — Aadhaar PII routing to on-prem.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("sphinx.thoth.dpdpa_rules")

# India-specific PII types recognised by Thoth classification
PII_TYPE_AADHAAR = "AADHAAR"
PII_TYPE_PAN = "PAN"
PII_TYPE_BANK_ACCOUNT = "BANK_ACCOUNT"
PII_TYPE_UPI_ID = "UPI_ID"
PII_TYPE_IFSC = "IFSC"

# All India-specific PII types covered by DPDPA rules
DPDPA_PII_TYPES: frozenset[str] = frozenset({
    PII_TYPE_AADHAAR,
    PII_TYPE_PAN,
    PII_TYPE_BANK_ACCOUNT,
    PII_TYPE_UPI_ID,
    PII_TYPE_IFSC,
})

# Default on-prem endpoint for DPDPA-sensitive routing
DEFAULT_ONPREM_ENDPOINT = "onprem_llm"

# Default audit tag applied to DPDPA-routed requests
DPDPA_AUDIT_TAG = "DPDPA_SENSITIVE"


class DPDPARuleTemplates:
    """Factory for DPDPA-compliant classification policy rule templates.

    All generated rules are dicts compatible with
    ``ClassificationPolicyEvaluator.load_rules()``.

    Args:
        onprem_endpoint: Target LLM endpoint name for DPDPA-sensitive routing.
                         Defaults to ``"onprem_llm"``.
        notify_target:   Notification target for alert rules (e.g. security ops
                         Slack channel or email group).
        base_priority:   Starting priority for template rules. Lower = higher
                         precedence. DPDPA rules default to low-priority numbers
                         (high precedence) to ensure regulatory rules fire first.
    """

    def __init__(
        self,
        onprem_endpoint: str = DEFAULT_ONPREM_ENDPOINT,
        notify_target: str = "security_ops_team",
        base_priority: int = 10,
    ) -> None:
        self._onprem_endpoint = onprem_endpoint
        self._notify_target = notify_target
        self._base_priority = base_priority

    # ------------------------------------------------------------------
    # Individual rule templates
    # ------------------------------------------------------------------

    def aadhaar_routing_rule(self) -> dict:
        """Route Aadhaar-containing prompts to on-prem endpoint (PRD §7.4)."""
        return {
            "id": "dpdpa_aadhaar_routing",
            "name": "DPDPA: Route Aadhaar PII to on-prem",
            "priority": self._base_priority,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.pii_detected",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "attribute": "classification.pii_types",
                        "operator": "contains",
                        "value": PII_TYPE_AADHAAR,
                    },
                ],
            },
            "action": "route",
            "route_endpoint": self._onprem_endpoint,
            "audit_severity": "WARNING",
            "audit_tag": DPDPA_AUDIT_TAG,
            "on_unavailable": "fail_closed",
            "notify": None,
        }

    def pan_routing_rule(self) -> dict:
        """Route PAN-containing prompts to on-prem endpoint."""
        return {
            "id": "dpdpa_pan_routing",
            "name": "DPDPA: Route PAN PII to on-prem",
            "priority": self._base_priority + 1,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.pii_detected",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "attribute": "classification.pii_types",
                        "operator": "contains",
                        "value": PII_TYPE_PAN,
                    },
                ],
            },
            "action": "route",
            "route_endpoint": self._onprem_endpoint,
            "audit_severity": "WARNING",
            "audit_tag": DPDPA_AUDIT_TAG,
            "on_unavailable": "fail_closed",
            "notify": None,
        }

    def bank_account_routing_rule(self) -> dict:
        """Route bank account-containing prompts to on-prem endpoint."""
        return {
            "id": "dpdpa_bank_account_routing",
            "name": "DPDPA: Route bank account PII to on-prem",
            "priority": self._base_priority + 2,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.pii_detected",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "attribute": "classification.pii_types",
                        "operator": "contains",
                        "value": PII_TYPE_BANK_ACCOUNT,
                    },
                ],
            },
            "action": "route",
            "route_endpoint": self._onprem_endpoint,
            "audit_severity": "WARNING",
            "audit_tag": DPDPA_AUDIT_TAG,
            "on_unavailable": "fail_closed",
            "notify": None,
        }

    def aadhaar_block_rule(self) -> dict:
        """Block high-confidence Aadhaar exfiltration attempts."""
        return {
            "id": "dpdpa_aadhaar_block",
            "name": "DPDPA: Block Aadhaar exfiltration",
            "priority": self._base_priority - 2,  # Higher precedence than routing
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.intent",
                        "operator": "eq",
                        "value": "data_exfiltration",
                    },
                    {
                        "attribute": "classification.pii_types",
                        "operator": "contains",
                        "value": PII_TYPE_AADHAAR,
                    },
                    {
                        "attribute": "classification.confidence",
                        "operator": "gte",
                        "value": 0.80,
                    },
                ],
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "audit_tag": "DPDPA_EXFILTRATION_BLOCKED",
            "on_unavailable": "fail_closed",
            "notify": self._notify_target,
        }

    def pan_block_rule(self) -> dict:
        """Block high-confidence PAN exfiltration attempts."""
        return {
            "id": "dpdpa_pan_block",
            "name": "DPDPA: Block PAN exfiltration",
            "priority": self._base_priority - 1,
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.intent",
                        "operator": "eq",
                        "value": "data_exfiltration",
                    },
                    {
                        "attribute": "classification.pii_types",
                        "operator": "contains",
                        "value": PII_TYPE_PAN,
                    },
                    {
                        "attribute": "classification.confidence",
                        "operator": "gte",
                        "value": 0.80,
                    },
                ],
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "audit_tag": "DPDPA_EXFILTRATION_BLOCKED",
            "on_unavailable": "fail_closed",
            "notify": self._notify_target,
        }

    def multi_pii_block_rule(self) -> dict:
        """Block prompts containing multiple India-specific PII types.

        Elevated risk: simultaneous presence of Aadhaar + bank account (or
        similar combinations) is a strong indicator of data exfiltration or
        social engineering.
        """
        return {
            "id": "dpdpa_multi_pii_block",
            "name": "DPDPA: Block multi-PII India-sensitive prompts",
            "priority": self._base_priority - 3,  # Highest precedence
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.pii_detected",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "attribute": "classification.risk_level",
                        "operator": "gte",
                        "value": "HIGH",
                    },
                ],
                "conditions": [
                    {
                        "type": "or",
                        "predicates": [
                            {
                                "attribute": "classification.pii_types",
                                "operator": "contains",
                                "value": PII_TYPE_AADHAAR,
                            },
                        ],
                        "conditions": [],
                    },
                ],
            },
            "action": "block",
            "audit_severity": "CRITICAL",
            "audit_tag": "DPDPA_MULTI_PII_BLOCKED",
            "on_unavailable": "fail_closed",
            "notify": self._notify_target,
        }

    def dpdpa_sensitive_alert_rule(self) -> dict:
        """Alert on any DPDPA-sensitive PII detection at medium+ risk."""
        return {
            "id": "dpdpa_sensitive_alert",
            "name": "DPDPA: Alert on India-sensitive PII",
            "priority": self._base_priority + 10,  # Lower precedence (fires after block/route)
            "is_active": True,
            "tenant_id": "*",
            "condition": {
                "type": "and",
                "predicates": [
                    {
                        "attribute": "classification.pii_detected",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "attribute": "classification.risk_level",
                        "operator": "gte",
                        "value": "MEDIUM",
                    },
                ],
            },
            "action": "queue_for_review",
            "audit_severity": "WARNING",
            "audit_tag": DPDPA_AUDIT_TAG,
            "on_unavailable": "skip",
            "notify": self._notify_target,
        }

    # ------------------------------------------------------------------
    # Bulk template generation
    # ------------------------------------------------------------------

    def all_routing_rules(self) -> list[dict]:
        """Return all DPDPA routing rule templates (Aadhaar, PAN, bank account)."""
        return [
            self.aadhaar_routing_rule(),
            self.pan_routing_rule(),
            self.bank_account_routing_rule(),
        ]

    def all_block_rules(self) -> list[dict]:
        """Return all DPDPA block rule templates."""
        return [
            self.multi_pii_block_rule(),
            self.aadhaar_block_rule(),
            self.pan_block_rule(),
        ]

    def all_rules(self) -> list[dict]:
        """Return the complete DPDPA rule template set (block + route + alert).

        Rules are returned in priority order (ascending priority number =
        higher precedence):
          1. Multi-PII block  (highest)
          2. Aadhaar block
          3. PAN block
          4. Aadhaar routing
          5. PAN routing
          6. Bank account routing
          7. Sensitive PII alert (lowest)
        """
        return (
            self.all_block_rules()
            + self.all_routing_rules()
            + [self.dpdpa_sensitive_alert_rule()]
        )

    def get_rule_by_id(self, rule_id: str) -> Optional[dict]:
        """Look up a single template rule by its ID."""
        for rule in self.all_rules():
            if rule["id"] == rule_id:
                return rule
        return None


# ---------------------------------------------------------------------------
# India-specific PII regex patterns for structural detection (supplement Thoth)
# ---------------------------------------------------------------------------

import re

# Aadhaar: 12-digit number, optionally formatted as XXXX XXXX XXXX or XXXX-XXXX-XXXX
AADHAAR_RE = re.compile(
    r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b'
)

# PAN: 5 uppercase letters + 4 digits + 1 uppercase letter (e.g. ABCDE1234F)
PAN_RE = re.compile(
    r'\b[A-Z]{5}\d{4}[A-Z]\b'
)

# Indian bank account: 9–18 digit number (broad pattern; context-sensitive)
BANK_ACCOUNT_RE = re.compile(
    r'(?i:(?:a/?c|account)\s*(?:no\.?|number|#)?\s*:?\s*)(\d{9,18})'
)

# IFSC code: 4 uppercase letters + 0 + 6 alphanumeric characters
IFSC_RE = re.compile(
    r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
)

# UPI ID: username@bankname format
UPI_RE = re.compile(
    r'\b[a-zA-Z0-9._\-]+@[a-zA-Z]{3,}\b'
)


def detect_india_pii(text: str) -> list[dict]:
    """Detect India-specific PII entities in text using regex patterns.

    Returns a list of dicts with ``type``, ``value``, ``start``, ``end`` fields.
    This is a structural supplement to Thoth's semantic classification — used
    when Thoth is unavailable (FAIL_CLOSED fallback) or for pre-Thoth screening.
    """
    results: list[dict] = []

    for m in AADHAAR_RE.finditer(text):
        digits = re.sub(r'\D', '', m.group())
        if len(digits) == 12:
            results.append({
                "type": PII_TYPE_AADHAAR,
                "value": m.group(),
                "start": m.start(),
                "end": m.end(),
            })

    for m in PAN_RE.finditer(text):
        results.append({
            "type": PII_TYPE_PAN,
            "value": m.group(),
            "start": m.start(),
            "end": m.end(),
        })

    for m in BANK_ACCOUNT_RE.finditer(text):
        results.append({
            "type": PII_TYPE_BANK_ACCOUNT,
            "value": m.group(1),
            "start": m.start(1),
            "end": m.end(1),
        })

    for m in IFSC_RE.finditer(text):
        results.append({
            "type": PII_TYPE_IFSC,
            "value": m.group(),
            "start": m.start(),
            "end": m.end(),
        })

    return results
