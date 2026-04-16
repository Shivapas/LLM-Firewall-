"""SP-362: Gap analysis engine for uncovered OWASP requirements.

For each uncovered or partially-covered requirement, lists:
  - Requirement description
  - Sphinx modules that partially address it
  - Recommended configuration change

SP-362 acceptance criteria:
  - Gap analysis generates correctly for a staging config with 2 modules disabled
  - Recommendations are actionable
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from app.services.owasp.coverage_engine import (
    CategoryScore,
    CoverageResult,
    OWASPCoverageEngine,
    get_owasp_coverage_engine,
)

logger = logging.getLogger("sphinx.owasp.gap_analysis")

# ---------------------------------------------------------------------------
# Per-category requirements and remediation guidance
# ---------------------------------------------------------------------------

_CATEGORY_REQUIREMENTS: dict[str, dict] = {
    "LLM01": {
        "name": "Prompt Injection",
        "requirements": [
            {
                "id": "LLM01-R1",
                "description": "Input scanning for direct prompt injection patterns",
                "primary_modules": ["threat_detection", "multilingual_detector"],
                "remediation": "Enable threat_detection_enabled=true and multilingual_enabled=true for multi-language injection detection.",
            },
            {
                "id": "LLM01-R2",
                "description": "Indirect prompt injection detection in RAG content",
                "primary_modules": ["ipia_engine", "rag_pipeline"],
                "remediation": "Enable ipia_enabled=true with ipia_default_threshold=0.50 for embedding-based RAG injection detection.",
            },
            {
                "id": "LLM01-R3",
                "description": "Memory store instruction scanning",
                "primary_modules": ["memory_firewall"],
                "remediation": "Enable memory_firewall_enabled=true to scan agent memory writes for injected instructions.",
            },
            {
                "id": "LLM01-R4",
                "description": "Session-level cross-turn risk accumulation",
                "primary_modules": ["session_security"],
                "remediation": "Enable session_security_enabled=true for cross-turn injection escalation detection.",
            },
        ],
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "requirements": [
            {
                "id": "LLM02-R1",
                "description": "PII/PHI detection and redaction in inputs and outputs",
                "primary_modules": ["data_shield", "output_scanner"],
                "remediation": "Enable data_shield_enabled=true and output_scanner_enabled=true for comprehensive PII/PHI protection.",
            },
            {
                "id": "LLM02-R2",
                "description": "Credential and secret scanning",
                "primary_modules": ["data_shield"],
                "remediation": "Ensure DataShield credential scanner is active with data_shield_enabled=true.",
            },
            {
                "id": "LLM02-R3",
                "description": "Audit trail for data access events",
                "primary_modules": ["audit_system"],
                "remediation": "Enable audit_enabled=true with tamper-evident hash chain for compliance.",
            },
            {
                "id": "LLM02-R4",
                "description": "SIEM export for real-time monitoring",
                "primary_modules": ["siem_export"],
                "remediation": "Enable siem_export_enabled=true with your SIEM endpoint for real-time security event monitoring.",
            },
        ],
    },
    "LLM03": {
        "name": "Supply Chain Vulnerabilities",
        "requirements": [
            {
                "id": "LLM03-R1",
                "description": "Model artifact scanning and provenance verification",
                "primary_modules": ["model_scanner"],
                "remediation": "Enable model_scanner_enabled=true for pre-deployment model scanning.",
            },
            {
                "id": "LLM03-R2",
                "description": "Inference endpoint integrity monitoring",
                "primary_modules": ["model_fingerprint"],
                "remediation": "Enable fingerprint_enabled=true with supply_chain_scoring_enabled=true for real-time model swap detection.",
            },
            {
                "id": "LLM03-R3",
                "description": "Provider health monitoring and failover",
                "primary_modules": ["circuit_breaker", "routing_engine"],
                "remediation": "Enable circuit_breaker_enabled=true and routing_enabled=true for provider health monitoring.",
            },
            {
                "id": "LLM03-R4",
                "description": "Agent-to-agent communication security",
                "primary_modules": ["a2a_firewall"],
                "remediation": "Enable a2a_firewall_enabled=true with mTLS and message signing for inter-agent security.",
            },
        ],
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "requirements": [
            {
                "id": "LLM04-R1",
                "description": "Vector database chunk integrity scanning",
                "primary_modules": ["vectordb_proxy"],
                "remediation": "Enable vectordb_proxy_enabled=true for namespace isolation and chunk scanning.",
            },
            {
                "id": "LLM04-R2",
                "description": "Model artifact integrity verification",
                "primary_modules": ["model_scanner"],
                "remediation": "Enable model_scanner_enabled=true for cryptographic model provenance verification.",
            },
            {
                "id": "LLM04-R3",
                "description": "Stylometric deviation detection for model tampering",
                "primary_modules": ["model_fingerprint"],
                "remediation": "Enable fingerprint_enabled=true to detect stylometric shifts indicating model poisoning.",
            },
            {
                "id": "LLM04-R4",
                "description": "Semantic cache poisoning prevention",
                "primary_modules": ["semantic_cache"],
                "remediation": "Enable semantic_cache_enabled=true with cache security controls.",
            },
        ],
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "requirements": [
            {
                "id": "LLM05-R1",
                "description": "Response content scanning for code injection and policy violations",
                "primary_modules": ["output_scanner"],
                "remediation": "Enable output_scanner_enabled=true for response content analysis.",
            },
            {
                "id": "LLM05-R2",
                "description": "Threat pattern matching on LLM outputs",
                "primary_modules": ["threat_detection"],
                "remediation": "Ensure threat_detection_enabled=true with post-inference scanning.",
            },
            {
                "id": "LLM05-R3",
                "description": "Semantic classification of responses",
                "primary_modules": ["thoth_classifier"],
                "remediation": "Enable thoth_enabled=true with thoth_post_inference_enabled=true for ML-based response classification.",
            },
        ],
    },
    "LLM06": {
        "name": "Excessive Agency",
        "requirements": [
            {
                "id": "LLM06-R1",
                "description": "Tool call scope enforcement and allowlisting",
                "primary_modules": ["mcp_guardrails", "agent_scope"],
                "remediation": "Enable mcp_guardrails_enabled=true and agent_scope_enabled=true for MCP tool access control.",
            },
            {
                "id": "LLM06-R2",
                "description": "Human-in-the-loop approval for high-risk actions",
                "primary_modules": ["hitl"],
                "remediation": "Enable hitl_enabled=true for risk-based human approval workflows.",
            },
            {
                "id": "LLM06-R3",
                "description": "Emergency traffic termination",
                "primary_modules": ["kill_switch"],
                "remediation": "Enable kill_switch_enabled=true for instant provider/tenant disablement.",
            },
            {
                "id": "LLM06-R4",
                "description": "Agent-to-agent scope enforcement",
                "primary_modules": ["a2a_firewall"],
                "remediation": "Enable a2a_firewall_enabled=true for inter-agent permission boundaries.",
            },
        ],
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "requirements": [
            {
                "id": "LLM07-R1",
                "description": "Canary token injection and leakage detection",
                "primary_modules": ["canary_token"],
                "remediation": "Enable canary_token_enabled=true with a unique canary_token_secret_key for system prompt leakage detection.",
            },
        ],
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "requirements": [
            {
                "id": "LLM08-R1",
                "description": "Indirect prompt injection detection in RAG chunks",
                "primary_modules": ["ipia_engine"],
                "remediation": "Enable ipia_enabled=true for embedding-based indirect prompt injection detection in RAG content.",
            },
            {
                "id": "LLM08-R2",
                "description": "RAG query intent classification and filtering",
                "primary_modules": ["rag_pipeline"],
                "remediation": "Enable rag_firewall_enabled=true for query classification before RAG retrieval.",
            },
            {
                "id": "LLM08-R3",
                "description": "Vector database access control and namespace isolation",
                "primary_modules": ["vectordb_proxy"],
                "remediation": "Enable vectordb_proxy_enabled=true for tenant-level namespace isolation.",
            },
        ],
    },
    "LLM09": {
        "name": "Misinformation",
        "requirements": [
            {
                "id": "LLM09-R1",
                "description": "Semantic classification for factual accuracy assessment",
                "primary_modules": ["thoth_classifier"],
                "remediation": "Enable thoth_enabled=true for ML-based misinformation classification.",
            },
            {
                "id": "LLM09-R2",
                "description": "EU AI Act transparency requirements",
                "primary_modules": ["eu_ai_act"],
                "remediation": "Enable eu_ai_act_enabled=true for AI-generated content disclosure and risk classification.",
            },
        ],
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "requirements": [
            {
                "id": "LLM10-R1",
                "description": "Per-tenant rate limiting",
                "primary_modules": ["rate_limiter"],
                "remediation": "Enable rate_limiter_enabled=true with per-key TPM limits.",
            },
            {
                "id": "LLM10-R2",
                "description": "Token budget enforcement with auto-downgrade",
                "primary_modules": ["token_budget"],
                "remediation": "Enable token_budget_enabled=true for per-request token consumption limits.",
            },
            {
                "id": "LLM10-R3",
                "description": "Cost tracking and budget alerting",
                "primary_modules": ["cost_tracker"],
                "remediation": "Enable cost_tracker_enabled=true for provider-level cost tracking.",
            },
            {
                "id": "LLM10-R4",
                "description": "Provider health-based circuit breaking",
                "primary_modules": ["circuit_breaker"],
                "remediation": "Enable circuit_breaker_enabled=true to prevent runaway calls to degraded providers.",
            },
        ],
    },
}


@dataclass
class GapItem:
    """A single gap identified in OWASP coverage."""

    requirement_id: str
    category_id: str
    category_name: str
    description: str
    addressing_modules: list[str] = field(default_factory=list)
    disabled_modules: list[str] = field(default_factory=list)
    remediation: str = ""
    severity: str = "MEDIUM"  # HIGH if primary module disabled, MEDIUM otherwise

    def to_dict(self) -> dict:
        return {
            "requirement_id": self.requirement_id,
            "category_id": self.category_id,
            "category_name": self.category_name,
            "description": self.description,
            "addressing_modules": self.addressing_modules,
            "disabled_modules": self.disabled_modules,
            "remediation": self.remediation,
            "severity": self.severity,
        }


@dataclass
class GapAnalysisResult:
    """Complete gap analysis result."""

    gaps: list[GapItem] = field(default_factory=list)
    total_requirements: int = 0
    covered_requirements: int = 0
    gap_count: int = 0
    coverage_percentage: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_requirements": self.total_requirements,
            "covered_requirements": self.covered_requirements,
            "gap_count": self.gap_count,
            "coverage_percentage": round(self.coverage_percentage, 1),
            "gaps": [g.to_dict() for g in self.gaps],
        }


class GapAnalysisEngine:
    """Analyses OWASP coverage gaps and generates remediation recommendations.

    SP-362 acceptance criteria:
      - Gap analysis generates for config with 2 modules disabled
      - Recommendations are actionable
    """

    def __init__(
        self,
        coverage_engine: OWASPCoverageEngine | None = None,
    ) -> None:
        self._coverage_engine = coverage_engine or get_owasp_coverage_engine()

    def analyse(
        self,
        active_config: dict[str, bool] | None = None,
        coverage_result: CoverageResult | None = None,
    ) -> GapAnalysisResult:
        """Run gap analysis against the active configuration.

        Args:
            active_config: Module enabled/disabled map.
            coverage_result: Pre-computed coverage (if available).

        Returns:
            GapAnalysisResult with identified gaps and remediation.
        """
        if coverage_result is None:
            coverage_result = self._coverage_engine.compute_coverage(active_config)

        # Resolve which modules are enabled
        registry = self._coverage_engine.registry
        module_enabled: dict[str, bool] = {}
        for mod_key, mod in registry.modules.items():
            if active_config is not None and mod.config_key in active_config:
                module_enabled[mod_key] = active_config[mod.config_key]
            else:
                module_enabled[mod_key] = mod.default_enabled

        gaps: list[GapItem] = []
        total_reqs = 0
        covered_reqs = 0

        for cat_id, cat_reqs in _CATEGORY_REQUIREMENTS.items():
            for req in cat_reqs.get("requirements", []):
                total_reqs += 1
                primary_modules = req.get("primary_modules", [])

                # Check if any primary module is disabled
                disabled = [
                    m for m in primary_modules
                    if not module_enabled.get(m, False)
                ]
                enabled = [
                    m for m in primary_modules
                    if module_enabled.get(m, False)
                ]

                if disabled:
                    # Map module keys to display names
                    disabled_names = []
                    enabled_names = []
                    for m in disabled:
                        mod_info = registry.modules.get(m)
                        disabled_names.append(mod_info.name if mod_info else m)
                    for m in enabled:
                        mod_info = registry.modules.get(m)
                        enabled_names.append(mod_info.name if mod_info else m)

                    severity = "HIGH" if len(disabled) == len(primary_modules) else "MEDIUM"

                    gaps.append(GapItem(
                        requirement_id=req["id"],
                        category_id=cat_id,
                        category_name=cat_reqs["name"],
                        description=req["description"],
                        addressing_modules=enabled_names,
                        disabled_modules=disabled_names,
                        remediation=req["remediation"],
                        severity=severity,
                    ))
                else:
                    covered_reqs += 1

        gap_count = len(gaps)
        coverage_pct = (covered_reqs / total_reqs * 100.0) if total_reqs > 0 else 0.0

        return GapAnalysisResult(
            gaps=gaps,
            total_requirements=total_reqs,
            covered_requirements=covered_reqs,
            gap_count=gap_count,
            coverage_percentage=coverage_pct,
        )

    def get_top_gaps(
        self,
        active_config: dict[str, bool] | None = None,
        limit: int = 3,
    ) -> list[dict]:
        """Return the top N most impactful gaps.

        Sorted by severity (HIGH first) then by category order.
        """
        result = self.analyse(active_config)
        sorted_gaps = sorted(
            result.gaps,
            key=lambda g: (0 if g.severity == "HIGH" else 1, g.category_id),
        )
        return [g.to_dict() for g in sorted_gaps[:limit]]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[GapAnalysisEngine] = None


def get_gap_analysis_engine() -> GapAnalysisEngine:
    """Get or create the singleton GapAnalysisEngine."""
    global _engine
    if _engine is None:
        _engine = GapAnalysisEngine()
    return _engine


def reset_gap_analysis_engine() -> None:
    """Reset the singleton (for testing)."""
    global _engine
    _engine = None
