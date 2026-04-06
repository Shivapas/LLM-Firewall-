"""Sprint 18: Compliance report generation — GDPR, HIPAA, SOC 2, PCI-DSS.

Each report aggregates audit data over a configurable date range
and returns structured JSON.  PDF export is handled by returning the
structured data for downstream renderers.
"""

from __future__ import annotations

import io
import json
import logging
import time
import zipfile
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.compliance")


# ─── Request / Response models ────────────────────────────────────────────


class ReportRequest(BaseModel):
    """Common request for all compliance reports."""
    tenant_id: Optional[str] = None
    start_timestamp: Optional[float] = None
    end_timestamp: Optional[float] = None
    days: int = Field(default=30, ge=1, le=365)


class GDPRReport(BaseModel):
    """GDPR compliance report."""
    report_type: str = "GDPR"
    generated_at: str = ""
    period_start: str = ""
    period_end: str = ""
    tenant_id: str = ""
    total_requests: int = 0
    pii_detected_count: int = 0
    pii_redacted_count: int = 0
    data_lineage_evidence: list[dict] = Field(default_factory=list)
    retention_policy_status: str = "compliant"
    summary: str = ""


class HIPAAReport(BaseModel):
    """HIPAA compliance report."""
    report_type: str = "HIPAA"
    generated_at: str = ""
    period_start: str = ""
    period_end: str = ""
    tenant_id: str = ""
    total_requests: int = 0
    phi_encounter_count: int = 0
    phi_access_events: list[dict] = Field(default_factory=list)
    redaction_evidence: list[dict] = Field(default_factory=list)
    anonymized_patient_records: int = 0
    summary: str = ""


class SOC2PCIDSSReport(BaseModel):
    """SOC 2 / PCI-DSS evidence export report."""
    report_type: str = "SOC2_PCIDSS"
    generated_at: str = ""
    period_start: str = ""
    period_end: str = ""
    tenant_id: str = ""
    access_controls_log: list[dict] = Field(default_factory=list)
    policy_change_log: list[dict] = Field(default_factory=list)
    incident_log: list[dict] = Field(default_factory=list)
    total_access_events: int = 0
    total_policy_changes: int = 0
    total_incidents: int = 0
    summary: str = ""


# ─── Service ──────────────────────────────────────────────────────────────


class ComplianceReportService:
    """Generates GDPR, HIPAA, and SOC 2 / PCI-DSS reports from audit data."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    def _resolve_period(self, req: ReportRequest) -> tuple[float, float]:
        now = time.time()
        end_ts = req.end_timestamp or now
        start_ts = req.start_timestamp or (end_ts - req.days * 86400)
        return start_ts, end_ts

    @staticmethod
    def _ts_to_iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    # ── GDPR ──────────────────────────────────────────────────────────

    async def generate_gdpr_report(self, req: ReportRequest) -> GDPRReport:
        start_ts, end_ts = self._resolve_period(req)
        tenant_id = req.tenant_id or "*"

        from app.models.api_key import AuditLog
        from sqlalchemy import select, func

        total = 0
        pii_detected = 0
        pii_redacted = 0
        lineage: list[dict] = []

        if self._session_factory:
            async with self._session_factory() as db:
                query = select(AuditLog).where(
                    AuditLog.event_timestamp >= start_ts,
                    AuditLog.event_timestamp <= end_ts,
                )
                if tenant_id != "*":
                    query = query.where(AuditLog.tenant_id == tenant_id)

                count_q = select(func.count(AuditLog.id)).where(
                    AuditLog.event_timestamp >= start_ts,
                    AuditLog.event_timestamp <= end_ts,
                )
                if tenant_id != "*":
                    count_q = count_q.where(AuditLog.tenant_id == tenant_id)
                total = (await db.execute(count_q)).scalar() or 0

                # Scan metadata for PII events
                result = await db.execute(query.order_by(AuditLog.event_timestamp.desc()).limit(10000))
                records = result.scalars().all()

                for r in records:
                    meta = {}
                    try:
                        meta = json.loads(r.metadata_json) if r.metadata_json else {}
                    except (json.JSONDecodeError, TypeError):
                        pass
                    if meta.get("pii_detected"):
                        pii_detected += 1
                    if meta.get("pii_redacted") or r.action_taken == "redact":
                        pii_redacted += 1
                    if meta.get("pii_detected") or meta.get("pii_redacted"):
                        lineage.append({
                            "event_id": str(r.id),
                            "timestamp": self._ts_to_iso(r.event_timestamp),
                            "model": r.model,
                            "action_taken": r.action_taken,
                            "pii_types": meta.get("pii_types", []),
                        })

        return GDPRReport(
            generated_at=self._ts_to_iso(time.time()),
            period_start=self._ts_to_iso(start_ts),
            period_end=self._ts_to_iso(end_ts),
            tenant_id=tenant_id,
            total_requests=total,
            pii_detected_count=pii_detected,
            pii_redacted_count=pii_redacted,
            data_lineage_evidence=lineage[:100],
            retention_policy_status="compliant",
            summary=(
                f"GDPR report for tenant {tenant_id}: "
                f"{total} total requests, {pii_detected} PII detections, "
                f"{pii_redacted} PII redactions."
            ),
        )

    # ── HIPAA ─────────────────────────────────────────────────────────

    async def generate_hipaa_report(self, req: ReportRequest) -> HIPAAReport:
        start_ts, end_ts = self._resolve_period(req)
        tenant_id = req.tenant_id or "*"

        from app.models.api_key import AuditLog
        from sqlalchemy import select, func

        total = 0
        phi_encounters = 0
        access_events: list[dict] = []
        redaction_evidence: list[dict] = []
        patient_records_set: set[str] = set()

        if self._session_factory:
            async with self._session_factory() as db:
                count_q = select(func.count(AuditLog.id)).where(
                    AuditLog.event_timestamp >= start_ts,
                    AuditLog.event_timestamp <= end_ts,
                )
                if tenant_id != "*":
                    count_q = count_q.where(AuditLog.tenant_id == tenant_id)
                total = (await db.execute(count_q)).scalar() or 0

                query = select(AuditLog).where(
                    AuditLog.event_timestamp >= start_ts,
                    AuditLog.event_timestamp <= end_ts,
                )
                if tenant_id != "*":
                    query = query.where(AuditLog.tenant_id == tenant_id)
                result = await db.execute(query.order_by(AuditLog.event_timestamp.desc()).limit(10000))
                records = result.scalars().all()

                for r in records:
                    meta = {}
                    try:
                        meta = json.loads(r.metadata_json) if r.metadata_json else {}
                    except (json.JSONDecodeError, TypeError):
                        pass

                    if meta.get("phi_detected") or meta.get("phi_encounter"):
                        phi_encounters += 1
                        access_events.append({
                            "event_id": str(r.id),
                            "timestamp": self._ts_to_iso(r.event_timestamp),
                            "model": r.model,
                            "api_key_id": r.api_key_id,
                            "action_taken": r.action_taken,
                            "phi_types": meta.get("phi_types", []),
                        })
                        patient_id = meta.get("anonymized_record_id", "")
                        if patient_id:
                            patient_records_set.add(patient_id)

                    if meta.get("phi_redacted") or r.action_taken == "redact":
                        redaction_evidence.append({
                            "event_id": str(r.id),
                            "timestamp": self._ts_to_iso(r.event_timestamp),
                            "redacted_fields": meta.get("redacted_fields", []),
                        })

        return HIPAAReport(
            generated_at=self._ts_to_iso(time.time()),
            period_start=self._ts_to_iso(start_ts),
            period_end=self._ts_to_iso(end_ts),
            tenant_id=tenant_id,
            total_requests=total,
            phi_encounter_count=phi_encounters,
            phi_access_events=access_events[:100],
            redaction_evidence=redaction_evidence[:100],
            anonymized_patient_records=len(patient_records_set),
            summary=(
                f"HIPAA report for tenant {tenant_id}: "
                f"{total} total requests, {phi_encounters} PHI encounters, "
                f"{len(patient_records_set)} unique anonymized patient records."
            ),
        )

    # ── SOC 2 / PCI-DSS ──────────────────────────────────────────────

    async def generate_soc2_pcidss_report(self, req: ReportRequest) -> SOC2PCIDSSReport:
        start_ts, end_ts = self._resolve_period(req)
        tenant_id = req.tenant_id or "*"

        from app.models.api_key import AuditLog, KillSwitchAuditLog, PolicyVersionSnapshot, Incident
        from sqlalchemy import select, func

        access_controls: list[dict] = []
        policy_changes: list[dict] = []
        incidents: list[dict] = []

        if self._session_factory:
            async with self._session_factory() as db:
                # Access controls log from audit_logs (blocked, rate_limited actions)
                access_q = (
                    select(AuditLog)
                    .where(
                        AuditLog.event_timestamp >= start_ts,
                        AuditLog.event_timestamp <= end_ts,
                        AuditLog.action.in_(["blocked", "rate_limited", "rerouted"]),
                    )
                    .order_by(AuditLog.event_timestamp.desc())
                    .limit(500)
                )
                if tenant_id != "*":
                    access_q = access_q.where(AuditLog.tenant_id == tenant_id)
                result = await db.execute(access_q)
                for r in result.scalars().all():
                    access_controls.append({
                        "event_id": str(r.id),
                        "timestamp": self._ts_to_iso(r.event_timestamp),
                        "tenant_id": r.tenant_id,
                        "action": r.action,
                        "model": r.model,
                        "risk_score": r.risk_score,
                        "policy_version": r.policy_version,
                    })

                # Policy change log from policy_version_snapshots
                try:
                    policy_q = (
                        select(PolicyVersionSnapshot)
                        .order_by(PolicyVersionSnapshot.created_at.desc())
                        .limit(200)
                    )
                    pv_result = await db.execute(policy_q)
                    for pv in pv_result.scalars().all():
                        policy_changes.append({
                            "snapshot_id": str(pv.id),
                            "policy_id": str(pv.policy_id),
                            "version": pv.version,
                            "name": pv.name,
                            "policy_type": pv.policy_type,
                            "created_by": pv.created_by,
                            "created_at": pv.created_at.isoformat() if pv.created_at else "",
                        })
                except Exception:
                    logger.warning("Could not load policy version snapshots", exc_info=True)

                # Incident log
                try:
                    incident_q = (
                        select(Incident)
                        .order_by(Incident.created_at.desc())
                        .limit(200)
                    )
                    if tenant_id != "*":
                        incident_q = incident_q.where(Incident.tenant_id == tenant_id)
                    inc_result = await db.execute(incident_q)
                    for inc in inc_result.scalars().all():
                        incidents.append({
                            "incident_id": str(inc.id),
                            "type": inc.incident_type,
                            "tenant_id": inc.tenant_id,
                            "risk_level": inc.risk_level,
                            "action_taken": inc.action_taken,
                            "created_at": inc.created_at.isoformat() if inc.created_at else "",
                        })
                except Exception:
                    logger.warning("Could not load incidents", exc_info=True)

                # Kill-switch audit log
                try:
                    ks_q = (
                        select(KillSwitchAuditLog)
                        .order_by(KillSwitchAuditLog.created_at.desc())
                        .limit(100)
                    )
                    ks_result = await db.execute(ks_q)
                    for ks in ks_result.scalars().all():
                        incidents.append({
                            "incident_id": str(ks.id),
                            "type": f"kill_switch_{ks.event_type}",
                            "model_name": ks.model_name,
                            "activated_by": ks.activated_by,
                            "reason": ks.reason,
                            "created_at": ks.created_at.isoformat() if ks.created_at else "",
                        })
                except Exception:
                    logger.warning("Could not load kill-switch audit logs", exc_info=True)

        return SOC2PCIDSSReport(
            generated_at=self._ts_to_iso(time.time()),
            period_start=self._ts_to_iso(start_ts),
            period_end=self._ts_to_iso(end_ts),
            tenant_id=tenant_id,
            access_controls_log=access_controls,
            policy_change_log=policy_changes,
            incident_log=incidents,
            total_access_events=len(access_controls),
            total_policy_changes=len(policy_changes),
            total_incidents=len(incidents),
            summary=(
                f"SOC 2 / PCI-DSS evidence for tenant {tenant_id}: "
                f"{len(access_controls)} access control events, "
                f"{len(policy_changes)} policy changes, "
                f"{len(incidents)} incidents."
            ),
        )

    # ── ZIP archive export ────────────────────────────────────────────

    async def export_evidence_zip(self, req: ReportRequest) -> bytes:
        """Generate a ZIP archive containing all three reports as JSON files."""
        gdpr = await self.generate_gdpr_report(req)
        hipaa = await self.generate_hipaa_report(req)
        soc2 = await self.generate_soc2_pcidss_report(req)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("gdpr_report.json", gdpr.model_dump_json(indent=2))
            zf.writestr("hipaa_report.json", hipaa.model_dump_json(indent=2))
            zf.writestr("soc2_pcidss_report.json", soc2.model_dump_json(indent=2))
        return buf.getvalue()


# Module-level singleton
_compliance_service: Optional[ComplianceReportService] = None


def get_compliance_report_service(session_factory=None) -> ComplianceReportService:
    global _compliance_service
    if _compliance_service is None:
        _compliance_service = ComplianceReportService(session_factory=session_factory)
    return _compliance_service
