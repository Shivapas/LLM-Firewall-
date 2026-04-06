"""Sprint 19: Security Operations Dashboard.

Unified dashboard providing:
- Request volume & block rate
- Top threats (by category/severity)
- Top tenants (by volume/violations)
- Token budget consumption
- Active kill-switches
- Recent incidents
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.security_ops")


# ── Response Models ────────────────────────────────────────────────────────


class RequestVolumeStats(BaseModel):
    total_requests: int = 0
    allowed_requests: int = 0
    blocked_requests: int = 0
    rerouted_requests: int = 0
    rate_limited_requests: int = 0
    block_rate: float = 0.0  # percentage


class ThreatSummary(BaseModel):
    category: str = ""
    severity: str = ""
    count: int = 0


class TenantSummary(BaseModel):
    tenant_id: str = ""
    request_count: int = 0
    block_count: int = 0
    block_rate: float = 0.0
    total_tokens: int = 0


class BudgetConsumption(BaseModel):
    tenant_id: str = ""
    api_key_id: str = ""
    total_tokens: int = 0
    budget_limit: int = 0
    usage_percentage: float = 0.0


class KillSwitchSummary(BaseModel):
    model_name: str = ""
    action: str = ""
    fallback_model: str = ""
    activated_by: str = ""
    reason: str = ""
    activated_at: str = ""


class IncidentSummary(BaseModel):
    id: str = ""
    incident_type: str = ""
    severity: str = ""
    title: str = ""
    status: str = ""
    created_at: str = ""


class SecurityDashboardData(BaseModel):
    generated_at: str = ""
    period_hours: int = 24
    request_volume: RequestVolumeStats = Field(default_factory=RequestVolumeStats)
    top_threats: list[ThreatSummary] = Field(default_factory=list)
    top_tenants: list[TenantSummary] = Field(default_factory=list)
    budget_consumption: list[BudgetConsumption] = Field(default_factory=list)
    active_kill_switches: list[KillSwitchSummary] = Field(default_factory=list)
    recent_incidents: list[IncidentSummary] = Field(default_factory=list)


# ── Service ────────────────────────────────────────────────────────────────


class SecurityOpsDashboardService:
    """Aggregates data from audit logs, kill-switches, incidents, and budgets."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    async def get_dashboard(self, period_hours: int = 24) -> SecurityDashboardData:
        """Build the security operations dashboard snapshot."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=period_hours)
        cutoff_ts = cutoff.timestamp()

        dashboard = SecurityDashboardData(
            generated_at=now.isoformat(),
            period_hours=period_hours,
        )

        if not self._session_factory:
            return dashboard

        from sqlalchemy import select, func
        from app.models.api_key import AuditLog, KillSwitch, SecurityIncident

        async with self._session_factory() as db:
            # ── Request volume ──
            result = await db.execute(
                select(
                    func.count(AuditLog.id),
                    func.count(AuditLog.id).filter(AuditLog.action == "allowed"),
                    func.count(AuditLog.id).filter(AuditLog.action == "blocked"),
                    func.count(AuditLog.id).filter(AuditLog.action == "rerouted"),
                    func.count(AuditLog.id).filter(AuditLog.action == "rate_limited"),
                ).where(AuditLog.event_timestamp >= cutoff_ts)
            )
            row = result.one()
            total = int(row[0])
            blocked = int(row[2])
            dashboard.request_volume = RequestVolumeStats(
                total_requests=total,
                allowed_requests=int(row[1]),
                blocked_requests=blocked,
                rerouted_requests=int(row[3]),
                rate_limited_requests=int(row[4]),
                block_rate=round((blocked / total * 100) if total > 0 else 0.0, 2),
            )

            # ── Top threats (from metadata) ──
            threat_rows = await db.execute(
                select(
                    AuditLog.action_taken,
                    func.count(AuditLog.id).label("cnt"),
                )
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.action == "blocked")
                .group_by(AuditLog.action_taken)
                .order_by(func.count(AuditLog.id).desc())
                .limit(10)
            )
            dashboard.top_threats = [
                ThreatSummary(category=r[0] or "unknown", severity="high", count=int(r[1]))
                for r in threat_rows.all()
            ]

            # ── Top tenants ──
            tenant_rows = await db.execute(
                select(
                    AuditLog.tenant_id,
                    func.count(AuditLog.id).label("total"),
                    func.count(AuditLog.id).filter(AuditLog.action == "blocked").label("blocks"),
                    func.coalesce(func.sum(AuditLog.prompt_tokens + AuditLog.completion_tokens), 0).label("tokens"),
                )
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .group_by(AuditLog.tenant_id)
                .order_by(func.count(AuditLog.id).desc())
                .limit(10)
            )
            for r in tenant_rows.all():
                t_total = int(r[1])
                t_blocks = int(r[2])
                dashboard.top_tenants.append(TenantSummary(
                    tenant_id=r[0] or "",
                    request_count=t_total,
                    block_count=t_blocks,
                    block_rate=round((t_blocks / t_total * 100) if t_total > 0 else 0.0, 2),
                    total_tokens=int(r[3]),
                ))

            # ── Active kill-switches ──
            ks_rows = await db.execute(
                select(KillSwitch).where(KillSwitch.is_active == True)
            )
            for ks in ks_rows.scalars().all():
                dashboard.active_kill_switches.append(KillSwitchSummary(
                    model_name=ks.model_name,
                    action=ks.action,
                    fallback_model=ks.fallback_model or "",
                    activated_by=ks.activated_by,
                    reason=ks.reason,
                    activated_at=ks.created_at.isoformat() if ks.created_at else "",
                ))

            # ── Recent incidents ──
            inc_rows = await db.execute(
                select(SecurityIncident)
                .order_by(SecurityIncident.created_at.desc())
                .limit(20)
            )
            for inc in inc_rows.scalars().all():
                dashboard.recent_incidents.append(IncidentSummary(
                    id=str(inc.id),
                    incident_type=inc.incident_type,
                    severity=inc.severity,
                    title=inc.title,
                    status=inc.status,
                    created_at=inc.created_at.isoformat() if inc.created_at else "",
                ))

        return dashboard


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[SecurityOpsDashboardService] = None


def get_security_ops_dashboard(session_factory=None) -> SecurityOpsDashboardService:
    global _service
    if _service is None:
        _service = SecurityOpsDashboardService(session_factory=session_factory)
    return _service
