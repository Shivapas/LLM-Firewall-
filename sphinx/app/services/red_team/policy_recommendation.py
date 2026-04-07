"""Sprint 24B — Red Team → Policy Recommendation Engine.

Analyzes red team probe results and generates concrete policy rules
that would have blocked detected vulnerabilities. Supports one-click
import of recommended rules into the active policy engine.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Category → policy rule templates
# ---------------------------------------------------------------------------

_RULE_TEMPLATES: dict[str, list[dict]] = {
    "injection": [
        {
            "rule_name": "Block prompt injection patterns",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(ignore\s+(previous|above|all)\s+instructions|system\s*prompt|you\s+are\s+now|new\s+instructions)",
            "description": "Block common prompt injection phrases that attempt to override system instructions.",
        },
        {
            "rule_name": "Block indirect injection via document content",
            "rule_type": "block",
            "severity": "high",
            "stage": "input",
            "pattern": r"(<!--.*inject|<\s*script|hidden\s+instruction|IMPORTANT:\s*ignore)",
            "description": "Block indirect injection patterns embedded in document or context content.",
        },
    ],
    "jailbreak": [
        {
            "rule_name": "Block DAN-style jailbreak attempts",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(DAN\s+mode|do\s+anything\s+now|jailbreak|developer\s+mode\s+enabled)",
            "description": "Block DAN variants and developer-mode jailbreak patterns.",
        },
        {
            "rule_name": "Block role-play bypass patterns",
            "rule_type": "block",
            "severity": "high",
            "stage": "input",
            "pattern": r"(pretend\s+you\s+are|act\s+as\s+if|role[\s-]*play\s+as|you\s+are\s+an?\s+unrestricted)",
            "description": "Block role-play instructions designed to bypass safety guidelines.",
        },
    ],
    "pii_extraction": [
        {
            "rule_name": "Block PII solicitation patterns",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(social\s+security|credit\s+card|SSN|bank\s+account|password|secret\s+key)",
            "description": "Block prompts designed to extract PII or sensitive credentials.",
        },
        {
            "rule_name": "Block training data extraction attempts",
            "rule_type": "block",
            "severity": "high",
            "stage": "input",
            "pattern": r"(training\s+data|repeat\s+verbatim|exact\s+text|memorized\s+content)",
            "description": "Block attempts to extract training data or memorized content.",
        },
    ],
    "tool_call_injection": [
        {
            "rule_name": "Block unauthorized tool invocations",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(execute\s+function|call\s+tool|invoke\s+api|run\s+command|shell_exec|os\.system)",
            "description": "Block attempts to invoke unauthorized tools or system commands via prompt.",
        },
        {
            "rule_name": "Block parameter tampering in tool calls",
            "rule_type": "block",
            "severity": "high",
            "stage": "input",
            "pattern": r"(override\s+param|modify\s+argument|change\s+target|redirect\s+output)",
            "description": "Block attempts to tamper with tool call parameters.",
        },
    ],
    "memory_poisoning": [
        {
            "rule_name": "Block instruction-like content in memory writes",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(remember\s+to\s+always|from\s+now\s+on|in\s+future\s+sessions|override\s+policy)",
            "description": "Block instruction-like content being injected into agent memory stores.",
        },
        {
            "rule_name": "Block context poisoning via retrieval",
            "rule_type": "block",
            "severity": "high",
            "stage": "input",
            "pattern": r"(inject\s+into\s+memory|plant\s+instruction|poison\s+context|delayed\s+trigger)",
            "description": "Block patterns associated with context poisoning and delayed trigger attacks.",
        },
    ],
    "privilege_escalation": [
        {
            "rule_name": "Block role manipulation attempts",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(escalate\s+privileges|admin\s+mode|grant\s+access|elevate\s+role|sudo|superuser)",
            "description": "Block attempts to manipulate agent roles or escalate permissions.",
        },
        {
            "rule_name": "Block scope expansion requests",
            "rule_type": "block",
            "severity": "high",
            "stage": "input",
            "pattern": r"(expand\s+scope|remove\s+restriction|unlock\s+capability|bypass\s+limit)",
            "description": "Block attempts to expand agent scope beyond authorized boundaries.",
        },
    ],
    "multi_step_attack": [
        {
            "rule_name": "Block reconnaissance-then-exploit chains",
            "rule_type": "block",
            "severity": "critical",
            "stage": "input",
            "pattern": r"(list\s+all\s+tools|enumerate\s+capabilities|what\s+can\s+you\s+access|reveal\s+internals)",
            "description": "Block reconnaissance probes that precede multi-step attack chains.",
        },
        {
            "rule_name": "Deploy cross-turn behavioral analysis",
            "rule_type": "monitor",
            "severity": "high",
            "stage": "input",
            "pattern": r"(step\s+\d|phase\s+\d|next\s+inject|now\s+exfiltrate|chain\s+attack)",
            "description": "Monitor for sequential attack patterns spanning multiple conversation turns.",
        },
    ],
}


class PolicyRecommendation:
    """A single policy rule recommendation derived from red team findings."""

    def __init__(
        self,
        campaign_id: str,
        category: str,
        priority: str,
        rule_name: str,
        rule_type: str,
        pattern: str,
        description: str,
        severity: str,
        stage: str,
        source_probe_ids: list[str],
    ):
        self.id = str(uuid.uuid4())
        self.campaign_id = campaign_id
        self.category = category
        self.priority = priority
        self.rule_name = rule_name
        self.rule_type = rule_type
        self.pattern = pattern
        self.description = description
        self.severity = severity
        self.stage = stage
        self.source_probe_ids = source_probe_ids
        self.imported = False
        self.imported_at: Optional[datetime] = None
        self.imported_rule_id: Optional[str] = None
        self.created_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "category": self.category,
            "priority": self.priority,
            "rule_name": self.rule_name,
            "rule_type": self.rule_type,
            "pattern": self.pattern,
            "description": self.description,
            "severity": self.severity,
            "stage": self.stage,
            "source_probe_ids": self.source_probe_ids,
            "imported": self.imported,
            "imported_at": self.imported_at.isoformat() if self.imported_at else None,
            "imported_rule_id": self.imported_rule_id,
            "created_at": self.created_at.isoformat(),
        }

    def to_policy_rule(self) -> dict:
        """Convert recommendation to a policy rule dict suitable for import."""
        return {
            "id": f"rt-{self.id[:8]}",
            "name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "pattern": self.pattern,
            "description": self.description,
            "action": self.rule_type,
            "stage": self.stage,
            "tags": [f"red-team:{self.campaign_id[:8]}", f"category:{self.category}"],
            "is_active": True,
            "source": "red_team_recommendation",
            "recommendation_id": self.id,
        }


# ---------------------------------------------------------------------------
# In-memory recommendation store
# ---------------------------------------------------------------------------

_recommendations: dict[str, PolicyRecommendation] = {}
_campaign_recommendations: dict[str, list[str]] = {}  # campaign_id -> [rec_ids]


def generate_recommendations(campaign) -> list[PolicyRecommendation]:
    """Analyze a completed campaign's probe results and generate policy recommendations.

    For each category with detected vulnerabilities, generates concrete policy rules
    with regex patterns and severity levels that would block the detected attacks.
    """
    detected = [r for r in campaign.results if r.detected]
    if not detected:
        return []

    # Group detected probes by category
    by_category: dict[str, list] = {}
    for r in detected:
        by_category.setdefault(r.category, []).append(r)

    recommendations: list[PolicyRecommendation] = []

    for category, results in by_category.items():
        templates = _RULE_TEMPLATES.get(category, [])
        if not templates:
            continue

        # Determine priority from max severity found
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_sev = max(results, key=lambda r: severity_rank.get(r.severity.value, 0))
        priority = max_sev.severity.value

        source_probe_ids = [r.probe_id for r in results]

        for template in templates:
            rec = PolicyRecommendation(
                campaign_id=campaign.id,
                category=category,
                priority=priority,
                rule_name=template["rule_name"],
                rule_type=template["rule_type"],
                pattern=template["pattern"],
                description=template["description"],
                severity=template["severity"],
                stage=template["stage"],
                source_probe_ids=source_probe_ids,
            )
            recommendations.append(rec)
            _recommendations[rec.id] = rec

    # Track by campaign
    rec_ids = [r.id for r in recommendations]
    _campaign_recommendations[campaign.id] = rec_ids

    return recommendations


def get_recommendations_for_campaign(campaign_id: str) -> list[dict]:
    """Return all recommendations for a campaign."""
    rec_ids = _campaign_recommendations.get(campaign_id, [])
    return [_recommendations[rid].to_dict() for rid in rec_ids if rid in _recommendations]


def get_recommendation(recommendation_id: str) -> Optional[PolicyRecommendation]:
    """Look up a single recommendation by ID."""
    return _recommendations.get(recommendation_id)


def import_recommendation(recommendation_id: str) -> Optional[dict]:
    """One-click import: convert a recommendation into an active policy rule.

    Returns the generated policy rule dict, or None if not found.
    """
    rec = _recommendations.get(recommendation_id)
    if not rec:
        return None
    if rec.imported:
        return rec.to_policy_rule()

    rule = rec.to_policy_rule()
    rec.imported = True
    rec.imported_at = datetime.now(timezone.utc)
    rec.imported_rule_id = rule["id"]
    return rule


def import_all_recommendations(campaign_id: str) -> list[dict]:
    """Import all recommendations for a campaign as active policy rules."""
    rec_ids = _campaign_recommendations.get(campaign_id, [])
    rules = []
    for rid in rec_ids:
        rule = import_recommendation(rid)
        if rule:
            rules.append(rule)
    return rules


def list_all_recommendations() -> list[dict]:
    """List all recommendations across all campaigns."""
    return [r.to_dict() for r in sorted(
        _recommendations.values(), key=lambda x: x.created_at, reverse=True
    )]
