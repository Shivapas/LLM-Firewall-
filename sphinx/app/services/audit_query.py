"""Sprint 18: Audit log query API service.

Query audit records by tenant, date range, model, action, risk level,
policy version.  Paginated response.
"""

from __future__ import annotations

import logging
import math
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.audit.query")


class AuditQueryParams(BaseModel):
    """Query parameters for audit log search."""
    tenant_id: Optional[str] = None
    model: Optional[str] = None
    action: Optional[str] = None
    risk_level: Optional[str] = None  # critical, high, medium, low
    policy_version: Optional[str] = None
    start_timestamp: Optional[float] = None
    end_timestamp: Optional[float] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


class AuditRecordResponse(BaseModel):
    """Single audit record in query response."""
    event_id: str
    timestamp: float
    request_hash: str
    tenant_id: str
    project_id: str
    api_key_id: str
    model: str
    provider: str
    action: str
    policy_version: str
    status_code: int
    latency_ms: float
    prompt_tokens: int
    completion_tokens: int
    risk_score: float
    action_taken: str
    enforcement_duration_ms: float
    record_hash: str
    previous_hash: str
    chain_sequence: int


class PaginatedAuditResponse(BaseModel):
    """Paginated audit log response."""
    records: list[AuditRecordResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# Risk level thresholds
RISK_THRESHOLDS = {
    "critical": (0.9, 1.0),
    "high": (0.7, 0.9),
    "medium": (0.4, 0.7),
    "low": (0.0, 0.4),
}


class AuditQueryService:
    """Service for querying audit logs with filtering and pagination."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    async def query(self, params: AuditQueryParams) -> PaginatedAuditResponse:
        """Execute a filtered, paginated audit log query."""
        from app.models.api_key import AuditLog
        from sqlalchemy import select, func

        if not self._session_factory:
            return PaginatedAuditResponse(records=[], total=0, page=1, page_size=params.page_size, total_pages=0)

        async with self._session_factory() as db:
            # Build base filter
            base_query = select(AuditLog)
            count_query = select(func.count(AuditLog.id))

            conditions = []
            if params.tenant_id:
                conditions.append(AuditLog.tenant_id == params.tenant_id)
            if params.model:
                conditions.append(AuditLog.model == params.model)
            if params.action:
                conditions.append(AuditLog.action == params.action)
            if params.policy_version:
                conditions.append(AuditLog.policy_version == params.policy_version)
            if params.start_timestamp is not None:
                conditions.append(AuditLog.event_timestamp >= params.start_timestamp)
            if params.end_timestamp is not None:
                conditions.append(AuditLog.event_timestamp <= params.end_timestamp)
            if params.risk_level and params.risk_level in RISK_THRESHOLDS:
                lo, hi = RISK_THRESHOLDS[params.risk_level]
                conditions.append(AuditLog.risk_score >= lo)
                conditions.append(AuditLog.risk_score < hi)

            for cond in conditions:
                base_query = base_query.where(cond)
                count_query = count_query.where(cond)

            # Get total count
            total_result = await db.execute(count_query)
            total = total_result.scalar() or 0

            # Paginated query
            offset = (params.page - 1) * params.page_size
            data_query = (
                base_query
                .order_by(AuditLog.event_timestamp.desc())
                .offset(offset)
                .limit(params.page_size)
            )
            result = await db.execute(data_query)
            records = result.scalars().all()

            total_pages = max(1, math.ceil(total / params.page_size))

            return PaginatedAuditResponse(
                records=[
                    AuditRecordResponse(
                        event_id=str(r.id),
                        timestamp=r.event_timestamp,
                        request_hash=r.request_hash,
                        tenant_id=r.tenant_id,
                        project_id=r.project_id,
                        api_key_id=r.api_key_id,
                        model=r.model,
                        provider=r.provider,
                        action=r.action,
                        policy_version=r.policy_version,
                        status_code=r.status_code,
                        latency_ms=r.latency_ms,
                        prompt_tokens=r.prompt_tokens,
                        completion_tokens=r.completion_tokens,
                        risk_score=r.risk_score,
                        action_taken=r.action_taken,
                        enforcement_duration_ms=r.enforcement_duration_ms,
                        record_hash=r.record_hash,
                        previous_hash=r.previous_hash,
                        chain_sequence=r.chain_sequence,
                    )
                    for r in records
                ],
                total=total,
                page=params.page,
                page_size=params.page_size,
                total_pages=total_pages,
            )


# Module-level singleton
_audit_query_service: Optional[AuditQueryService] = None


def get_audit_query_service(session_factory=None) -> AuditQueryService:
    global _audit_query_service
    if _audit_query_service is None:
        _audit_query_service = AuditQueryService(session_factory=session_factory)
    return _audit_query_service
