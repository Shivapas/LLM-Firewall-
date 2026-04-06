"""Sprint 19: Policy Coverage Map.

Visualize which OWASP LLM Top 10 items have active rules.
Coverage gaps are highlighted.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.policy_coverage")

# OWASP Top 10 for LLM Applications (2025)
OWASP_LLM_TOP_10 = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": "Manipulating LLMs via crafted inputs to override instructions.",
        "categories": ["prompt_injection", "indirect_injection"],
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "description": "Failing to validate LLM outputs before passing to downstream systems.",
        "categories": ["output_injection", "xss", "code_injection"],
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "description": "Tampering with training data to introduce vulnerabilities.",
        "categories": ["data_poisoning", "backdoor"],
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "description": "Causing resource exhaustion through expensive queries.",
        "categories": ["dos", "resource_exhaustion", "rate_limit"],
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "description": "Compromised components, plugins, or pre-trained models.",
        "categories": ["supply_chain", "plugin_vulnerability", "mcp_risk"],
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "description": "LLMs inadvertently revealing confidential data.",
        "categories": ["data_extraction", "pii_leakage", "credential_leak"],
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "description": "Plugins with insufficient access controls.",
        "categories": ["plugin_insecure", "tool_abuse", "mcp_tool_risk"],
    },
    "LLM08": {
        "name": "Excessive Agency",
        "description": "LLMs granted too much autonomy or permissions.",
        "categories": ["excessive_agency", "scope_violation", "agent_overreach"],
    },
    "LLM09": {
        "name": "Overreliance",
        "description": "Uncritical trust in LLM-generated content.",
        "categories": ["hallucination", "misinformation"],
    },
    "LLM10": {
        "name": "Model Theft",
        "description": "Unauthorized access to or extraction of LLM models.",
        "categories": ["model_theft", "model_extraction", "api_abuse"],
    },
}


class OWASPCoverageItem(BaseModel):
    owasp_id: str = ""
    name: str = ""
    description: str = ""
    expected_categories: list[str] = Field(default_factory=list)
    matching_rules: list[str] = Field(default_factory=list)  # rule names
    matching_rule_count: int = 0
    is_covered: bool = False


class PolicyCoverageMap(BaseModel):
    generated_at: str = ""
    total_owasp_items: int = 10
    covered_items: int = 0
    coverage_percentage: float = 0.0
    items: list[OWASPCoverageItem] = Field(default_factory=list)
    gap_items: list[str] = Field(default_factory=list)  # OWASP IDs with no coverage


class PolicyCoverageService:
    """Maps active security rules to OWASP LLM Top 10 categories."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    async def get_coverage_map(self) -> PolicyCoverageMap:
        """Build coverage map from active security rules."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        # Gather active rules
        active_rules: list[dict] = []
        if self._session_factory:
            from sqlalchemy import select
            from app.models.api_key import SecurityRule
            async with self._session_factory() as db:
                result = await db.execute(
                    select(SecurityRule).where(SecurityRule.is_active == True)
                )
                for r in result.scalars().all():
                    tags = []
                    try:
                        tags = json.loads(r.tags_json) if r.tags_json else []
                    except Exception:
                        pass
                    active_rules.append({
                        "name": r.name,
                        "category": r.category,
                        "tags": tags,
                    })

        # Also include built-in threat patterns
        try:
            from app.services.threat_detection.engine import get_threat_engine
            engine = get_threat_engine()
            for pattern in engine.library.patterns:
                active_rules.append({
                    "name": pattern.name,
                    "category": pattern.category,
                    "tags": pattern.tags if hasattr(pattern, "tags") else [],
                })
        except Exception:
            pass

        # Build coverage items
        items = []
        covered_count = 0
        gap_ids = []

        for owasp_id, info in OWASP_LLM_TOP_10.items():
            matching = []
            for rule in active_rules:
                rule_cat = rule.get("category", "").lower()
                rule_tags = [t.lower() for t in rule.get("tags", [])]
                rule_name = rule.get("name", "").lower()

                for expected_cat in info["categories"]:
                    if (
                        expected_cat in rule_cat
                        or expected_cat in rule_tags
                        or expected_cat in rule_name
                    ):
                        matching.append(rule["name"])
                        break

            is_covered = len(matching) > 0
            if is_covered:
                covered_count += 1
            else:
                gap_ids.append(owasp_id)

            items.append(OWASPCoverageItem(
                owasp_id=owasp_id,
                name=info["name"],
                description=info["description"],
                expected_categories=info["categories"],
                matching_rules=matching[:10],
                matching_rule_count=len(matching),
                is_covered=is_covered,
            ))

        total = len(OWASP_LLM_TOP_10)
        return PolicyCoverageMap(
            generated_at=now.isoformat(),
            total_owasp_items=total,
            covered_items=covered_count,
            coverage_percentage=round((covered_count / total * 100) if total > 0 else 0.0, 1),
            items=items,
            gap_items=gap_ids,
        )


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[PolicyCoverageService] = None


def get_policy_coverage_service(session_factory=None) -> PolicyCoverageService:
    global _service
    if _service is None:
        _service = PolicyCoverageService(session_factory=session_factory)
    return _service
