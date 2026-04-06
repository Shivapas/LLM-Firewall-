"""Agent Risk Score — Sprint 17.

Aggregate risk score per agent based on:
1. Connected tool risk scores (from MCP discovery)
2. Violation history (from agent scope enforcement)
3. Scope breadth (number of allowed servers/tools/context tags)

Risk scores update dynamically as tool connections and violation
history change. Displayed in the MCP guardrails dashboard.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.mcp.agent_risk_score")


# ── Constants ────────────────────────────────────────────────────────────

# Weight factors for composite risk score (sum = 1.0)
WEIGHT_TOOL_RISK = 0.45
WEIGHT_VIOLATION_HISTORY = 0.30
WEIGHT_SCOPE_BREADTH = 0.25

# Scope breadth normalization thresholds
MAX_SERVERS_FOR_NORMALIZATION = 10
MAX_TOOLS_FOR_NORMALIZATION = 50
MAX_SCOPES_FOR_NORMALIZATION = 20

# Violation decay: recent violations count more
VIOLATION_DECAY_HOURS = 24  # violations older than this count less


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class AgentRiskBreakdown:
    """Detailed breakdown of an agent's risk score."""
    agent_id: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    # Component scores
    tool_risk_component: float = 0.0
    violation_component: float = 0.0
    scope_breadth_component: float = 0.0
    # Detail
    connected_tools_count: int = 0
    max_tool_risk: float = 0.0
    avg_tool_risk: float = 0.0
    violation_count_24h: int = 0
    total_violations: int = 0
    allowed_servers_count: int = 0
    allowed_tools_count: int = 0
    context_scopes_count: int = 0
    contributing_factors: list[str] = field(default_factory=list)
    computed_at: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level,
            "tool_risk_component": round(self.tool_risk_component, 4),
            "violation_component": round(self.violation_component, 4),
            "scope_breadth_component": round(self.scope_breadth_component, 4),
            "connected_tools_count": self.connected_tools_count,
            "max_tool_risk": round(self.max_tool_risk, 4),
            "avg_tool_risk": round(self.avg_tool_risk, 4),
            "violation_count_24h": self.violation_count_24h,
            "total_violations": self.total_violations,
            "allowed_servers_count": self.allowed_servers_count,
            "allowed_tools_count": self.allowed_tools_count,
            "context_scopes_count": self.context_scopes_count,
            "contributing_factors": self.contributing_factors,
            "computed_at": self.computed_at,
        }


def _classify_risk_level(score: float) -> str:
    """Classify a 0.0–1.0 score into a risk level."""
    if score >= 0.7:
        return "critical"
    if score >= 0.4:
        return "high"
    if score >= 0.2:
        return "medium"
    return "low"


# ── Agent Risk Score Service ─────────────────────────────────────────────


class AgentRiskScoreService:
    """Computes and caches aggregate risk scores per agent.

    Inputs:
    - Tool risk scores from MCP discovery service
    - Violation records from agent scope service
    - Agent account scope configuration

    The composite score is weighted:
    - 45% tool risk (max risk of connected tools)
    - 30% violation history (normalized count in last 24h)
    - 25% scope breadth (normalized server/tool/scope counts)
    """

    def __init__(self, discovery_service=None, scope_service=None, audit_service=None):
        self._discovery_service = discovery_service
        self._scope_service = scope_service
        self._audit_service = audit_service
        # Cache: agent_id -> AgentRiskBreakdown
        self._cache: dict[str, AgentRiskBreakdown] = {}

    def set_services(self, discovery_service=None, scope_service=None, audit_service=None):
        """Set/update service dependencies after init."""
        if discovery_service is not None:
            self._discovery_service = discovery_service
        if scope_service is not None:
            self._scope_service = scope_service
        if audit_service is not None:
            self._audit_service = audit_service

    def compute_risk_score(
        self,
        agent_id: str,
        tool_risk_scores: list[float] | None = None,
        violation_count_24h: int | None = None,
        total_violations: int | None = None,
        allowed_servers_count: int | None = None,
        allowed_tools_count: int | None = None,
        context_scopes_count: int | None = None,
    ) -> AgentRiskBreakdown:
        """Compute the aggregate risk score for an agent.

        Accepts explicit inputs or pulls from connected services.
        """
        # Resolve inputs from services if not explicitly provided
        if tool_risk_scores is None:
            tool_risk_scores = self._get_tool_risk_scores(agent_id)
        if violation_count_24h is None:
            violation_count_24h = self._get_violation_count_24h(agent_id)
        if total_violations is None:
            total_violations = self._get_total_violations(agent_id)
        if allowed_servers_count is None or allowed_tools_count is None or context_scopes_count is None:
            s, t, c = self._get_scope_breadth(agent_id)
            if allowed_servers_count is None:
                allowed_servers_count = s
            if allowed_tools_count is None:
                allowed_tools_count = t
            if context_scopes_count is None:
                context_scopes_count = c

        # ── Component 1: Tool Risk ──────────────────────────────────
        max_tool_risk = max(tool_risk_scores) if tool_risk_scores else 0.0
        avg_tool_risk = sum(tool_risk_scores) / len(tool_risk_scores) if tool_risk_scores else 0.0
        # Use weighted blend of max and average (max dominates)
        tool_risk_component = 0.7 * max_tool_risk + 0.3 * avg_tool_risk

        # ── Component 2: Violation History ──────────────────────────
        # Normalize: 0 violations = 0, 10+ = 1.0
        violation_normalized = min(violation_count_24h / 10.0, 1.0) if violation_count_24h else 0.0
        violation_component = violation_normalized

        # ── Component 3: Scope Breadth ──────────────────────────────
        server_norm = min(allowed_servers_count / MAX_SERVERS_FOR_NORMALIZATION, 1.0)
        tool_norm = min(allowed_tools_count / MAX_TOOLS_FOR_NORMALIZATION, 1.0)
        scope_norm = min(context_scopes_count / MAX_SCOPES_FOR_NORMALIZATION, 1.0)
        scope_breadth_component = (server_norm + tool_norm + scope_norm) / 3.0

        # ── Composite Score ─────────────────────────────────────────
        composite = (
            WEIGHT_TOOL_RISK * tool_risk_component
            + WEIGHT_VIOLATION_HISTORY * violation_component
            + WEIGHT_SCOPE_BREADTH * scope_breadth_component
        )
        composite = min(max(composite, 0.0), 1.0)

        # Contributing factors
        factors: list[str] = []
        if max_tool_risk >= 0.7:
            factors.append("critical_tool_connected")
        if max_tool_risk >= 0.4:
            factors.append("high_risk_tools")
        if violation_count_24h >= 5:
            factors.append("frequent_violations")
        if violation_count_24h >= 1:
            factors.append("recent_violations")
        if allowed_servers_count >= 5:
            factors.append("broad_server_access")
        if allowed_tools_count >= 20:
            factors.append("broad_tool_access")
        if not factors:
            factors.append("normal_operation")

        breakdown = AgentRiskBreakdown(
            agent_id=agent_id,
            risk_score=composite,
            risk_level=_classify_risk_level(composite),
            tool_risk_component=tool_risk_component,
            violation_component=violation_component,
            scope_breadth_component=scope_breadth_component,
            connected_tools_count=len(tool_risk_scores),
            max_tool_risk=max_tool_risk,
            avg_tool_risk=avg_tool_risk,
            violation_count_24h=violation_count_24h,
            total_violations=total_violations,
            allowed_servers_count=allowed_servers_count,
            allowed_tools_count=allowed_tools_count,
            context_scopes_count=context_scopes_count,
            contributing_factors=factors,
            computed_at=datetime.now(timezone.utc).isoformat(),
        )

        self._cache[agent_id] = breakdown
        logger.info(
            "Agent risk score: agent=%s score=%.4f level=%s factors=%s",
            agent_id, composite, breakdown.risk_level, factors,
        )
        return breakdown

    def get_cached_score(self, agent_id: str) -> AgentRiskBreakdown | None:
        """Get cached risk score for an agent (without recomputing)."""
        return self._cache.get(agent_id)

    def get_all_scores(self) -> dict[str, AgentRiskBreakdown]:
        """Get all cached agent risk scores."""
        return dict(self._cache)

    def recompute_all(self, agent_ids: list[str]) -> dict[str, AgentRiskBreakdown]:
        """Recompute risk scores for all specified agents."""
        results: dict[str, AgentRiskBreakdown] = {}
        for agent_id in agent_ids:
            results[agent_id] = self.compute_risk_score(agent_id)
        return results

    # ── Internal: service data resolution ────────────────────────────

    def _get_tool_risk_scores(self, agent_id: str) -> list[float]:
        """Get tool risk scores from discovery service for agent's connected tools."""
        if not self._discovery_service:
            return []
        try:
            servers = self._discovery_service.list_servers()
            scores: list[float] = []
            for server in servers:
                if hasattr(server, "connected_agents") and agent_id in (server.connected_agents or []):
                    caps = self._discovery_service.get_capabilities(server.server_name)
                    for cap in caps:
                        if hasattr(cap, "risk_score"):
                            scores.append(cap.risk_score)
            return scores
        except Exception:
            logger.warning("Failed to get tool risk scores for agent=%s", agent_id)
            return []

    def _get_violation_count_24h(self, agent_id: str) -> int:
        """Get violation count in last 24h from scope service."""
        if not self._scope_service:
            return 0
        try:
            violations = self._scope_service.list_violations(agent_id=agent_id)
            # Count all recent violations (in-memory list doesn't have time filter,
            # so we return total as approximation unless timestamps available)
            return len(violations)
        except Exception:
            return 0

    def _get_total_violations(self, agent_id: str) -> int:
        """Get total violation count from scope service."""
        if not self._scope_service:
            return 0
        try:
            counts = self._scope_service.get_violation_counts(agent_id=agent_id)
            return sum(counts.values())
        except Exception:
            return 0

    def _get_scope_breadth(self, agent_id: str) -> tuple[int, int, int]:
        """Get scope breadth (servers, tools, scopes) from scope service."""
        if not self._scope_service:
            return (0, 0, 0)
        try:
            account = self._scope_service.get_account(agent_id)
            if not account:
                return (0, 0, 0)
            return (
                len(account.allowed_mcp_servers),
                len(account.allowed_tools),
                len(account.context_scope),
            )
        except Exception:
            return (0, 0, 0)


# ── Singleton ────────────────────────────────────────────────────────────

_agent_risk_score_service: AgentRiskScoreService | None = None


def get_agent_risk_score_service(
    discovery_service=None,
    scope_service=None,
    audit_service=None,
) -> AgentRiskScoreService:
    """Get or create the singleton agent risk score service."""
    global _agent_risk_score_service
    if _agent_risk_score_service is None:
        _agent_risk_score_service = AgentRiskScoreService(
            discovery_service=discovery_service,
            scope_service=scope_service,
            audit_service=audit_service,
        )
    return _agent_risk_score_service


def reset_agent_risk_score_service() -> None:
    """Reset for testing."""
    global _agent_risk_score_service
    _agent_risk_score_service = None
