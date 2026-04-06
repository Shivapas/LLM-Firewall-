"""MCP Guardrails Dashboard — Sprint 17.

Live dashboard providing:
- Per-agent connectivity status
- Violation counts (last 24h)
- Kill-switch events
- Tool call volume by agent
- Agent risk scores
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger("sphinx.mcp.dashboard")


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class AgentStatus:
    """Connectivity and health status for a single agent."""
    agent_id: str = ""
    display_name: str = ""
    is_active: bool = True
    connected_servers: list[str] = field(default_factory=list)
    allowed_tools_count: int = 0
    violation_count_24h: int = 0
    tool_call_count: int = 0
    risk_score: float = 0.0
    risk_level: str = "low"

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "is_active": self.is_active,
            "connected_servers": self.connected_servers,
            "allowed_tools_count": self.allowed_tools_count,
            "violation_count_24h": self.violation_count_24h,
            "tool_call_count": self.tool_call_count,
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level,
        }


@dataclass
class KillSwitchEvent:
    """Kill-switch event for dashboard display."""
    model_name: str = ""
    action: str = ""
    event_type: str = ""
    activated_by: str = ""
    reason: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "action": self.action,
            "event_type": self.event_type,
            "activated_by": self.activated_by,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


@dataclass
class DashboardSnapshot:
    """Full dashboard snapshot with all metrics."""
    # Summary
    total_agents: int = 0
    active_agents: int = 0
    total_mcp_servers: int = 0
    total_tool_calls: int = 0
    total_violations_24h: int = 0
    active_kill_switches: int = 0
    # Per-agent
    agent_statuses: list[AgentStatus] = field(default_factory=list)
    # Kill-switch events
    kill_switch_events: list[KillSwitchEvent] = field(default_factory=list)
    # Tool call volume by agent
    tool_call_volume: dict[str, int] = field(default_factory=dict)
    # Agent risk scores
    agent_risk_scores: dict[str, dict] = field(default_factory=dict)
    # Timestamp
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_agents": self.total_agents,
                "active_agents": self.active_agents,
                "total_mcp_servers": self.total_mcp_servers,
                "total_tool_calls": self.total_tool_calls,
                "total_violations_24h": self.total_violations_24h,
                "active_kill_switches": self.active_kill_switches,
            },
            "agent_statuses": [a.to_dict() for a in self.agent_statuses],
            "kill_switch_events": [k.to_dict() for k in self.kill_switch_events],
            "tool_call_volume": self.tool_call_volume,
            "agent_risk_scores": self.agent_risk_scores,
            "generated_at": self.generated_at,
        }


# ── Dashboard Service ────────────────────────────────────────────────────


class GuardrailDashboardService:
    """Aggregates data from multiple services to produce a live dashboard.

    Pulls from:
    - AgentScopeService: agent accounts, violations
    - MCPDiscoveryService: MCP servers, capabilities
    - ToolCallAuditService: tool call volumes
    - AgentRiskScoreService: risk scores
    - KillSwitch service: active kill-switches and events
    """

    def __init__(
        self,
        scope_service=None,
        discovery_service=None,
        audit_service=None,
        risk_score_service=None,
    ):
        self._scope_service = scope_service
        self._discovery_service = discovery_service
        self._audit_service = audit_service
        self._risk_score_service = risk_score_service

    def set_services(
        self,
        scope_service=None,
        discovery_service=None,
        audit_service=None,
        risk_score_service=None,
    ):
        """Update service dependencies."""
        if scope_service is not None:
            self._scope_service = scope_service
        if discovery_service is not None:
            self._discovery_service = discovery_service
        if audit_service is not None:
            self._audit_service = audit_service
        if risk_score_service is not None:
            self._risk_score_service = risk_score_service

    def get_snapshot(self) -> DashboardSnapshot:
        """Generate a full dashboard snapshot from live service data."""
        snapshot = DashboardSnapshot(
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        # ── Agent statuses ──────────────────────────────────────────
        agents = self._get_agents()
        snapshot.total_agents = len(agents)
        snapshot.active_agents = sum(1 for a in agents if a.is_active)

        # ── MCP servers ─────────────────────────────────────────────
        snapshot.total_mcp_servers = self._get_server_count()

        # ── Tool call volume ────────────────────────────────────────
        tool_call_volume = self._get_tool_call_volume()
        snapshot.tool_call_volume = tool_call_volume
        snapshot.total_tool_calls = sum(tool_call_volume.values())

        # ── Violation counts ────────────────────────────────────────
        total_violations = 0
        for agent in agents:
            v_count = self._get_violation_count(agent.agent_id)
            agent.violation_count_24h = v_count
            total_violations += v_count
        snapshot.total_violations_24h = total_violations

        # ── Tool call counts per agent ──────────────────────────────
        for agent in agents:
            agent.tool_call_count = tool_call_volume.get(agent.agent_id, 0)

        # ── Risk scores ─────────────────────────────────────────────
        risk_scores: dict[str, dict] = {}
        for agent in agents:
            score_breakdown = self._get_risk_score(agent.agent_id)
            if score_breakdown:
                agent.risk_score = score_breakdown.get("risk_score", 0.0)
                agent.risk_level = score_breakdown.get("risk_level", "low")
                risk_scores[agent.agent_id] = score_breakdown
        snapshot.agent_risk_scores = risk_scores

        # ── Kill-switch events ──────────────────────────────────────
        snapshot.kill_switch_events = self._get_kill_switch_events()
        snapshot.active_kill_switches = sum(
            1 for e in snapshot.kill_switch_events if e.event_type == "activated"
        )

        snapshot.agent_statuses = agents
        return snapshot

    def get_agent_detail(self, agent_id: str) -> dict | None:
        """Get detailed status for a specific agent."""
        if not self._scope_service:
            return None

        account = self._scope_service.get_account(agent_id)
        if not account:
            return None

        violations = self._scope_service.list_violations(agent_id=agent_id, limit=50)
        violation_counts = self._scope_service.get_violation_counts(agent_id=agent_id)

        audit_records = []
        if self._audit_service:
            audit_records = [
                r.to_dict() for r in
                self._audit_service.list_records(agent_id=agent_id, limit=50)
            ]

        risk_score = self._get_risk_score(agent_id)

        return {
            "agent": account.to_dict(),
            "violations": [v.to_dict() for v in violations],
            "violation_counts": violation_counts,
            "recent_tool_calls": audit_records,
            "risk_score": risk_score,
        }

    # ── Internal helpers ─────────────────────────────────────────────

    def _get_agents(self) -> list[AgentStatus]:
        """Get agent statuses from scope service."""
        if not self._scope_service:
            return []

        accounts = self._scope_service.list_accounts()
        statuses: list[AgentStatus] = []
        for account in accounts:
            statuses.append(AgentStatus(
                agent_id=account.agent_id,
                display_name=account.display_name,
                is_active=account.is_active,
                connected_servers=list(account.allowed_mcp_servers),
                allowed_tools_count=len(account.allowed_tools),
            ))
        return statuses

    def _get_server_count(self) -> int:
        """Get total MCP server count from discovery service."""
        if not self._discovery_service:
            return 0
        try:
            return len(self._discovery_service.list_servers())
        except Exception:
            return 0

    def _get_tool_call_volume(self) -> dict[str, int]:
        """Get tool call volume by agent from audit service."""
        if not self._audit_service:
            return {}
        try:
            return self._audit_service.get_agent_tool_call_volume()
        except Exception:
            return {}

    def _get_violation_count(self, agent_id: str) -> int:
        """Get violation count for an agent."""
        if not self._scope_service:
            return 0
        try:
            counts = self._scope_service.get_violation_counts(agent_id=agent_id)
            return sum(counts.values())
        except Exception:
            return 0

    def _get_risk_score(self, agent_id: str) -> dict | None:
        """Get risk score for an agent."""
        if not self._risk_score_service:
            return None
        try:
            cached = self._risk_score_service.get_cached_score(agent_id)
            if cached:
                return cached.to_dict()
            return None
        except Exception:
            return None

    def _get_kill_switch_events(self) -> list[KillSwitchEvent]:
        """Get recent kill-switch events."""
        try:
            from app.services.kill_switch import get_kill_switch_audit_log
            events = get_kill_switch_audit_log()
            return [
                KillSwitchEvent(
                    model_name=e.get("model_name", ""),
                    action=e.get("action", ""),
                    event_type=e.get("event_type", ""),
                    activated_by=e.get("activated_by", ""),
                    reason=e.get("reason", ""),
                    timestamp=e.get("created_at", ""),
                )
                for e in (events if isinstance(events, list) else [])
            ]
        except Exception:
            logger.debug("Could not fetch kill-switch events", exc_info=True)
            return []


# ── Singleton ────────────────────────────────────────────────────────────

_dashboard_service: GuardrailDashboardService | None = None


def get_guardrail_dashboard_service(
    scope_service=None,
    discovery_service=None,
    audit_service=None,
    risk_score_service=None,
) -> GuardrailDashboardService:
    """Get or create the singleton dashboard service."""
    global _dashboard_service
    if _dashboard_service is None:
        _dashboard_service = GuardrailDashboardService(
            scope_service=scope_service,
            discovery_service=discovery_service,
            audit_service=audit_service,
            risk_score_service=risk_score_service,
        )
    return _dashboard_service


def reset_guardrail_dashboard_service() -> None:
    """Reset for testing."""
    global _dashboard_service
    _dashboard_service = None
