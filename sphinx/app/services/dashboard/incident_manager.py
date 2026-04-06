"""Sprint 19: Incident Management Service.

Creates and manages incident records for:
- Critical threat detections
- Namespace isolation breaches (attempted)
- Kill-switch activations
- Tier 2 ML findings
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.incident_manager")


class CreateIncidentRequest(BaseModel):
    incident_type: str  # critical_threat, namespace_breach, kill_switch_activation, tier2_finding
    severity: str = "high"  # critical, high, medium, low
    title: str = ""
    description: str = ""
    tenant_id: str = ""
    source_event_id: str = ""
    metadata: dict = Field(default_factory=dict)


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None  # open, investigating, resolved, dismissed
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class IncidentRecord(BaseModel):
    id: str = ""
    incident_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    tenant_id: str = ""
    source_event_id: str = ""
    status: str = ""
    assigned_to: str = ""
    resolution_notes: str = ""
    resolved_at: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class IncidentStats(BaseModel):
    total: int = 0
    open: int = 0
    investigating: int = 0
    resolved: int = 0
    dismissed: int = 0
    by_type: dict = Field(default_factory=dict)
    by_severity: dict = Field(default_factory=dict)


class IncidentManagementService:
    """CRUD + statistics for security incidents."""

    VALID_TYPES = {"critical_threat", "namespace_breach", "kill_switch_activation", "tier2_finding"}
    VALID_SEVERITIES = {"critical", "high", "medium", "low"}
    VALID_STATUSES = {"open", "investigating", "resolved", "dismissed"}

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    async def create_incident(self, req: CreateIncidentRequest) -> IncidentRecord:
        """Create a new security incident."""
        from app.models.api_key import SecurityIncident

        incident = SecurityIncident(
            id=uuid.uuid4(),
            incident_type=req.incident_type,
            severity=req.severity,
            title=req.title,
            description=req.description,
            tenant_id=req.tenant_id,
            source_event_id=req.source_event_id,
            metadata_json=json.dumps(req.metadata),
        )

        if self._session_factory:
            async with self._session_factory() as db:
                db.add(incident)
                await db.commit()
                await db.refresh(incident)

        logger.warning(
            "Incident created: type=%s severity=%s title=%s",
            req.incident_type, req.severity, req.title,
        )

        return self._to_record(incident)

    async def update_incident(self, incident_id: str, req: UpdateIncidentRequest) -> Optional[IncidentRecord]:
        """Update an incident's status, assignment, or resolution."""
        if not self._session_factory:
            return None

        from sqlalchemy import select
        from app.models.api_key import SecurityIncident

        async with self._session_factory() as db:
            result = await db.execute(
                select(SecurityIncident).where(SecurityIncident.id == uuid.UUID(incident_id))
            )
            incident = result.scalar_one_or_none()
            if not incident:
                return None

            if req.status is not None:
                incident.status = req.status
                if req.status == "resolved":
                    incident.resolved_at = datetime.now(timezone.utc)
            if req.assigned_to is not None:
                incident.assigned_to = req.assigned_to
            if req.resolution_notes is not None:
                incident.resolution_notes = req.resolution_notes

            await db.commit()
            await db.refresh(incident)
            return self._to_record(incident)

    async def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        """Get a single incident by ID."""
        if not self._session_factory:
            return None

        from sqlalchemy import select
        from app.models.api_key import SecurityIncident

        async with self._session_factory() as db:
            result = await db.execute(
                select(SecurityIncident).where(SecurityIncident.id == uuid.UUID(incident_id))
            )
            incident = result.scalar_one_or_none()
            if not incident:
                return None
            return self._to_record(incident)

    async def list_incidents(
        self,
        incident_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[IncidentRecord]:
        """List incidents with optional filters."""
        if not self._session_factory:
            return []

        from sqlalchemy import select
        from app.models.api_key import SecurityIncident

        async with self._session_factory() as db:
            query = select(SecurityIncident).order_by(SecurityIncident.created_at.desc())
            if incident_type:
                query = query.where(SecurityIncident.incident_type == incident_type)
            if severity:
                query = query.where(SecurityIncident.severity == severity)
            if status:
                query = query.where(SecurityIncident.status == status)
            if tenant_id:
                query = query.where(SecurityIncident.tenant_id == tenant_id)
            query = query.limit(limit)

            result = await db.execute(query)
            return [self._to_record(inc) for inc in result.scalars().all()]

    async def get_stats(self) -> IncidentStats:
        """Get incident statistics."""
        if not self._session_factory:
            return IncidentStats()

        from sqlalchemy import select, func
        from app.models.api_key import SecurityIncident

        async with self._session_factory() as db:
            # Total
            total_result = await db.execute(select(func.count(SecurityIncident.id)))
            total = int(total_result.scalar() or 0)

            # By status
            status_rows = await db.execute(
                select(SecurityIncident.status, func.count(SecurityIncident.id))
                .group_by(SecurityIncident.status)
            )
            status_map = {r[0]: int(r[1]) for r in status_rows.all()}

            # By type
            type_rows = await db.execute(
                select(SecurityIncident.incident_type, func.count(SecurityIncident.id))
                .group_by(SecurityIncident.incident_type)
            )
            type_map = {r[0]: int(r[1]) for r in type_rows.all()}

            # By severity
            sev_rows = await db.execute(
                select(SecurityIncident.severity, func.count(SecurityIncident.id))
                .group_by(SecurityIncident.severity)
            )
            sev_map = {r[0]: int(r[1]) for r in sev_rows.all()}

            return IncidentStats(
                total=total,
                open=status_map.get("open", 0),
                investigating=status_map.get("investigating", 0),
                resolved=status_map.get("resolved", 0),
                dismissed=status_map.get("dismissed", 0),
                by_type=type_map,
                by_severity=sev_map,
            )

    def _to_record(self, inc) -> IncidentRecord:
        metadata = {}
        try:
            metadata = json.loads(inc.metadata_json) if inc.metadata_json else {}
        except Exception:
            pass

        return IncidentRecord(
            id=str(inc.id),
            incident_type=inc.incident_type or "",
            severity=inc.severity or "high",
            title=inc.title or "",
            description=inc.description or "",
            tenant_id=inc.tenant_id or "",
            source_event_id=inc.source_event_id or "",
            status=inc.status or "open",
            assigned_to=inc.assigned_to or "",
            resolution_notes=inc.resolution_notes or "",
            resolved_at=inc.resolved_at.isoformat() if inc.resolved_at else None,
            metadata=metadata,
            created_at=inc.created_at.isoformat() if inc.created_at else "",
            updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
        )


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[IncidentManagementService] = None


def get_incident_management_service(session_factory=None) -> IncidentManagementService:
    global _service
    if _service is None:
        _service = IncidentManagementService(session_factory=session_factory)
    return _service
