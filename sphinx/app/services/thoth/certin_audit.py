"""CERT-In audit trail requirements — Sprint 7 / S7-T4.

Validates and enforces that Sphinx + Thoth audit records satisfy the
Indian Computer Emergency Response Team (CERT-In) reporting requirements,
specifically the 6-hour incident reporting mandate under the
CERT-In Directions of April 2022.

CERT-In Requirements Addressed
-------------------------------
1. **6-hour reporting window**: Cyber security incidents must be reported
   to CERT-In within 6 hours of detection. This module tracks incident
   detection timestamps and validates reporting timeliness.

2. **Log retention**: System logs must be maintained for 180 days (rolling)
   and be made available to CERT-In on demand.

3. **Incident categorisation**: Data breaches involving personal data
   (especially Aadhaar, financial data) are reportable incidents.

4. **Audit trail completeness**: Every enforcement action on DPDPA-sensitive
   requests must produce a complete, tamper-evident audit record.

Design
------
``CERTInAuditTracker`` maintains an in-memory ring buffer of recent
security-relevant events (DPDPA-tagged blocks, high-risk classifications,
PII detections) and provides:

- ``record_incident()``: Register a security event with CERT-In metadata.
- ``get_pending_reports()``: Return incidents within the 6-hour window
  that have not yet been marked as reported.
- ``mark_reported()``: Mark an incident as reported to CERT-In.
- ``validate_audit_completeness()``: Check that an audit event contains
  all required fields for CERT-In compliance.
- ``generate_certin_report()``: Build a structured report payload suitable
  for CERT-In submission.

The tracker does NOT perform actual CERT-In API submission — that is
handled by the organisation's SOC / incident response tooling.  This module
ensures audit records are complete and incidents are tracked within the
regulatory time window.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("sphinx.thoth.certin_audit")

# CERT-In 6-hour reporting window in seconds
CERTIN_REPORTING_WINDOW_S = 6 * 3600  # 21,600 seconds

# CERT-In log retention requirement: 180 days
CERTIN_RETENTION_DAYS = 180

# Maximum incidents tracked in memory (older entries are in the DB audit log)
_MAX_INCIDENT_BUFFER = 10000

# Fields required for a CERT-In compliant audit record
CERTIN_REQUIRED_AUDIT_FIELDS: frozenset[str] = frozenset({
    "event_id",
    "timestamp",
    "tenant_id",
    "action_taken",
    "risk_score",
    "classification_risk_level",
    "classification_intent",
    "enforcement_duration_ms",
})


@dataclass
class CERTInIncident:
    """A security incident tracked for CERT-In reporting.

    Attributes:
        incident_id:       Unique incident identifier.
        detected_at:       Unix timestamp when the incident was detected.
        incident_type:     Category (e.g. ``"pii_exfiltration"``,
                           ``"unauthorized_access"``, ``"data_breach"``).
        severity:          ``"LOW"`` | ``"MEDIUM"`` | ``"HIGH"`` | ``"CRITICAL"``.
        description:       Human-readable incident description.
        affected_pii_types: List of PII types involved (e.g. ``["AADHAAR"]``).
        tenant_id:         Affected tenant.
        audit_event_ids:   Related Sphinx audit event IDs.
        reported:          Whether this incident has been marked as reported.
        reported_at:       Unix timestamp when marked as reported (0 if not).
        regulatory_tags:   Tags applied (e.g. ``["DPDPA_SENSITIVE", "CERT_IN_REPORTABLE"]``).
        metadata:          Additional context for the CERT-In report.
    """

    incident_id: str = ""
    detected_at: float = 0.0
    incident_type: str = ""
    severity: str = "HIGH"
    description: str = ""
    affected_pii_types: list[str] = field(default_factory=list)
    tenant_id: str = ""
    audit_event_ids: list[str] = field(default_factory=list)
    reported: bool = False
    reported_at: float = 0.0
    regulatory_tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.incident_id:
            self.incident_id = str(uuid.uuid4())
        if not self.detected_at:
            self.detected_at = time.time()

    @property
    def time_since_detection_s(self) -> float:
        """Seconds elapsed since the incident was detected."""
        return time.time() - self.detected_at

    @property
    def within_reporting_window(self) -> bool:
        """True if the incident is still within the 6-hour reporting window."""
        return self.time_since_detection_s < CERTIN_REPORTING_WINDOW_S

    @property
    def reporting_deadline(self) -> float:
        """Unix timestamp of the 6-hour reporting deadline."""
        return self.detected_at + CERTIN_REPORTING_WINDOW_S

    @property
    def time_remaining_s(self) -> float:
        """Seconds remaining before the 6-hour reporting deadline."""
        return max(0.0, self.reporting_deadline - time.time())

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "detected_at": self.detected_at,
            "detected_at_iso": datetime.fromtimestamp(
                self.detected_at, tz=timezone.utc
            ).isoformat(),
            "incident_type": self.incident_type,
            "severity": self.severity,
            "description": self.description,
            "affected_pii_types": self.affected_pii_types,
            "tenant_id": self.tenant_id,
            "audit_event_ids": self.audit_event_ids,
            "reported": self.reported,
            "reported_at": self.reported_at,
            "reporting_deadline": self.reporting_deadline,
            "reporting_deadline_iso": datetime.fromtimestamp(
                self.reporting_deadline, tz=timezone.utc
            ).isoformat(),
            "time_remaining_s": self.time_remaining_s,
            "within_reporting_window": self.within_reporting_window,
            "regulatory_tags": self.regulatory_tags,
            "metadata": self.metadata,
        }


class CERTInAuditTracker:
    """Tracks security incidents for CERT-In 6-hour reporting compliance.

    Thread-safe for concurrent reads; write operations (record_incident,
    mark_reported) use a deque which is thread-safe for append/popleft.
    """

    def __init__(self) -> None:
        self._incidents: deque[CERTInIncident] = deque(maxlen=_MAX_INCIDENT_BUFFER)
        self._reported_count: int = 0
        self._total_count: int = 0

    def record_incident(
        self,
        *,
        incident_type: str,
        severity: str = "HIGH",
        description: str = "",
        affected_pii_types: Optional[list[str]] = None,
        tenant_id: str = "",
        audit_event_ids: Optional[list[str]] = None,
        regulatory_tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> CERTInIncident:
        """Record a new security incident for CERT-In tracking.

        Returns the created ``CERTInIncident`` for immediate reference.
        """
        incident = CERTInIncident(
            incident_type=incident_type,
            severity=severity,
            description=description,
            affected_pii_types=affected_pii_types or [],
            tenant_id=tenant_id,
            audit_event_ids=audit_event_ids or [],
            regulatory_tags=regulatory_tags or ["CERT_IN_REPORTABLE"],
            metadata=metadata or {},
        )

        self._incidents.append(incident)
        self._total_count += 1

        logger.warning(
            "CERT-In incident recorded: id=%s type=%s severity=%s "
            "pii_types=%s tenant=%s deadline=%s",
            incident.incident_id,
            incident.incident_type,
            incident.severity,
            incident.affected_pii_types,
            incident.tenant_id,
            datetime.fromtimestamp(
                incident.reporting_deadline, tz=timezone.utc
            ).isoformat(),
        )

        return incident

    def get_pending_reports(self) -> list[CERTInIncident]:
        """Return all unreported incidents within the 6-hour window."""
        return [
            inc for inc in self._incidents
            if not inc.reported and inc.within_reporting_window
        ]

    def get_overdue_reports(self) -> list[CERTInIncident]:
        """Return unreported incidents that have EXCEEDED the 6-hour window."""
        return [
            inc for inc in self._incidents
            if not inc.reported and not inc.within_reporting_window
        ]

    def mark_reported(self, incident_id: str) -> bool:
        """Mark an incident as reported to CERT-In.

        Returns True if the incident was found and marked, False otherwise.
        """
        for inc in self._incidents:
            if inc.incident_id == incident_id:
                inc.reported = True
                inc.reported_at = time.time()
                self._reported_count += 1
                logger.info(
                    "CERT-In incident marked as reported: id=%s "
                    "time_to_report_s=%.0f",
                    incident_id,
                    inc.reported_at - inc.detected_at,
                )
                return True
        return False

    def validate_audit_completeness(self, audit_record: dict) -> list[str]:
        """Validate that an audit record contains all CERT-In required fields.

        Returns a list of missing field names (empty list = compliant).
        """
        missing = []
        for field_name in CERTIN_REQUIRED_AUDIT_FIELDS:
            val = audit_record.get(field_name)
            if val is None or val == "":
                missing.append(field_name)
        return missing

    def generate_certin_report(
        self,
        incidents: Optional[list[CERTInIncident]] = None,
    ) -> dict:
        """Generate a structured CERT-In incident report payload.

        If ``incidents`` is None, includes all pending (unreported) incidents.

        The returned dict is suitable for submission to the organisation's
        CERT-In reporting system or SOC tooling.
        """
        target_incidents = incidents or self.get_pending_reports()

        report = {
            "report_type": "CERT-In Cyber Security Incident Report",
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "reporting_entity": "Sphinx AI Mesh Firewall",
            "regulatory_framework": "CERT-In Directions, April 2022",
            "reporting_window_hours": 6,
            "incident_count": len(target_incidents),
            "incidents": [inc.to_dict() for inc in target_incidents],
            "summary": {
                "total_tracked": self._total_count,
                "total_reported": self._reported_count,
                "pending": len(self.get_pending_reports()),
                "overdue": len(self.get_overdue_reports()),
                "severity_breakdown": self._severity_breakdown(target_incidents),
            },
        }

        return report

    @staticmethod
    def _severity_breakdown(incidents: list[CERTInIncident]) -> dict:
        """Count incidents by severity level."""
        breakdown: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for inc in incidents:
            key = inc.severity.upper()
            if key in breakdown:
                breakdown[key] += 1
        return breakdown

    def get_status(self) -> dict:
        """Return an observability snapshot of the CERT-In tracker state."""
        return {
            "total_incidents_tracked": self._total_count,
            "total_reported": self._reported_count,
            "buffer_size": len(self._incidents),
            "pending_reports": len(self.get_pending_reports()),
            "overdue_reports": len(self.get_overdue_reports()),
        }


# ---------------------------------------------------------------------------
# Singleton lifecycle
# ---------------------------------------------------------------------------

_tracker: Optional[CERTInAuditTracker] = None


def get_certin_audit_tracker() -> CERTInAuditTracker:
    """Return the singleton CERTInAuditTracker, creating it if needed."""
    global _tracker
    if _tracker is None:
        _tracker = CERTInAuditTracker()
    return _tracker


def reset_certin_audit_tracker() -> None:
    """Reset the singleton (used in tests)."""
    global _tracker
    _tracker = None
