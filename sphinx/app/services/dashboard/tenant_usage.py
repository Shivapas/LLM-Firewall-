"""Sprint 19: Tenant Usage Dashboard.

Per-tenant view: request volume, block rate, token usage,
policy violations, cost estimate. Scoped to tenant admins.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.tenant_usage")

# Approximate cost per 1K tokens (can be overridden)
DEFAULT_COST_PER_1K_PROMPT = 0.03
DEFAULT_COST_PER_1K_COMPLETION = 0.06


class TenantUsageStats(BaseModel):
    tenant_id: str = ""
    period_hours: int = 24
    generated_at: str = ""
    # Volume
    total_requests: int = 0
    allowed_requests: int = 0
    blocked_requests: int = 0
    block_rate: float = 0.0
    # Tokens
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    # Cost
    estimated_cost_usd: float = 0.0
    # Violations
    policy_violations: int = 0
    # Models
    models_used: list[str] = Field(default_factory=list)
    requests_by_model: dict = Field(default_factory=dict)


class TenantUsageDashboardService:
    """Per-tenant usage dashboard."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    async def get_tenant_usage(self, tenant_id: str, period_hours: int = 24) -> TenantUsageStats:
        """Build usage stats for a specific tenant."""
        now = datetime.now(timezone.utc)
        cutoff_ts = (now - timedelta(hours=period_hours)).timestamp()

        stats = TenantUsageStats(
            tenant_id=tenant_id,
            period_hours=period_hours,
            generated_at=now.isoformat(),
        )

        if not self._session_factory:
            return stats

        from sqlalchemy import select, func
        from app.models.api_key import AuditLog

        async with self._session_factory() as db:
            # Aggregate request volume
            result = await db.execute(
                select(
                    func.count(AuditLog.id),
                    func.count(AuditLog.id).filter(AuditLog.action == "allowed"),
                    func.count(AuditLog.id).filter(AuditLog.action == "blocked"),
                    func.coalesce(func.sum(AuditLog.prompt_tokens), 0),
                    func.coalesce(func.sum(AuditLog.completion_tokens), 0),
                )
                .where(AuditLog.tenant_id == tenant_id)
                .where(AuditLog.event_timestamp >= cutoff_ts)
            )
            row = result.one()
            total = int(row[0])
            blocked = int(row[2])
            prompt_tokens = int(row[3])
            completion_tokens = int(row[4])

            stats.total_requests = total
            stats.allowed_requests = int(row[1])
            stats.blocked_requests = blocked
            stats.block_rate = round((blocked / total * 100) if total > 0 else 0.0, 2)
            stats.prompt_tokens = prompt_tokens
            stats.completion_tokens = completion_tokens
            stats.total_tokens = prompt_tokens + completion_tokens
            stats.estimated_cost_usd = round(
                (prompt_tokens / 1000) * DEFAULT_COST_PER_1K_PROMPT
                + (completion_tokens / 1000) * DEFAULT_COST_PER_1K_COMPLETION,
                4,
            )

            # Policy violations (blocked + rate_limited)
            viol_result = await db.execute(
                select(func.count(AuditLog.id))
                .where(AuditLog.tenant_id == tenant_id)
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.action.in_(["blocked", "rate_limited"]))
            )
            stats.policy_violations = int(viol_result.scalar() or 0)

            # Models used
            model_rows = await db.execute(
                select(AuditLog.model, func.count(AuditLog.id))
                .where(AuditLog.tenant_id == tenant_id)
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.model != "")
                .group_by(AuditLog.model)
                .order_by(func.count(AuditLog.id).desc())
            )
            models = {}
            model_names = []
            for r in model_rows.all():
                model_names.append(r[0])
                models[r[0]] = int(r[1])
            stats.models_used = model_names
            stats.requests_by_model = models

        return stats

    async def list_tenants_summary(self, period_hours: int = 24, limit: int = 50) -> list[TenantUsageStats]:
        """List usage summaries for all tenants."""
        if not self._session_factory:
            return []

        from sqlalchemy import select, func
        from app.models.api_key import AuditLog

        cutoff_ts = (datetime.now(timezone.utc) - timedelta(hours=period_hours)).timestamp()

        async with self._session_factory() as db:
            rows = await db.execute(
                select(AuditLog.tenant_id)
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.tenant_id != "")
                .group_by(AuditLog.tenant_id)
                .order_by(func.count(AuditLog.id).desc())
                .limit(limit)
            )
            tenant_ids = [r[0] for r in rows.all()]

        results = []
        for tid in tenant_ids:
            stats = await self.get_tenant_usage(tid, period_hours)
            results.append(stats)

        return results


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[TenantUsageDashboardService] = None


def get_tenant_usage_dashboard(session_factory=None) -> TenantUsageDashboardService:
    global _service
    if _service is None:
        _service = TenantUsageDashboardService(session_factory=session_factory)
    return _service
