"""EU AI Act Article 11 & Article 14 documentation services — Sprint 22.

Article 14: Human oversight documentation
- Which agents/applications have HITL (Human-in-the-Loop) checkpoints
- Who is designated as the human overseer
- Audit of oversight events (approval, rejection, escalation)

Article 11: Technical documentation package
- System architecture summary
- Training data description (for fine-tuned models)
- Accuracy and robustness measures
- Exportable as structured document (JSON/dict for PDF rendering)
"""

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.multilingual.eu_ai_act_docs")


# ──────────────────────────────────────────────────────────────────────────────
# Article 14 — Human Oversight
# ──────────────────────────────────────────────────────────────────────────────


class OversightEventType(str, Enum):
    """Types of human oversight events."""
    APPROVAL = "approval"
    REJECTION = "rejection"
    ESCALATION = "escalation"
    REVIEW = "review"
    OVERRIDE = "override"
    AUDIT = "audit"


class HITLCheckpointType(str, Enum):
    """Types of human-in-the-loop checkpoints."""
    PRE_DEPLOYMENT = "pre_deployment"
    RUNTIME_APPROVAL = "runtime_approval"
    OUTPUT_REVIEW = "output_review"
    PERIODIC_AUDIT = "periodic_audit"
    EXCEPTION_HANDLING = "exception_handling"
    ESCALATION_GATE = "escalation_gate"


@dataclass
class HumanOverseer:
    """A designated human overseer for an AI application."""
    overseer_id: str
    name: str
    role: str
    email: str = ""
    department: str = ""
    authority_level: str = "standard"  # standard, senior, executive
    designated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "overseer_id": self.overseer_id,
            "name": self.name,
            "role": self.role,
            "email": self.email,
            "department": self.department,
            "authority_level": self.authority_level,
            "designated_at": self.designated_at,
        }


@dataclass
class HITLCheckpoint:
    """A human-in-the-loop checkpoint configured for an AI application."""
    checkpoint_id: str
    app_id: str
    checkpoint_type: HITLCheckpointType
    description: str
    is_mandatory: bool = True
    overseer_ids: list[str] = field(default_factory=list)
    trigger_conditions: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "checkpoint_id": self.checkpoint_id,
            "app_id": self.app_id,
            "checkpoint_type": self.checkpoint_type.value,
            "description": self.description,
            "is_mandatory": self.is_mandatory,
            "overseer_ids": self.overseer_ids,
            "trigger_conditions": self.trigger_conditions,
            "created_at": self.created_at,
        }


@dataclass
class OversightEvent:
    """A recorded human oversight event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    app_id: str = ""
    checkpoint_id: str = ""
    overseer_id: str = ""
    event_type: OversightEventType = OversightEventType.REVIEW
    decision: str = ""
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "app_id": self.app_id,
            "checkpoint_id": self.checkpoint_id,
            "overseer_id": self.overseer_id,
            "event_type": self.event_type.value,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class HumanOversightService:
    """EU AI Act Article 14 human oversight documentation service.

    Manages HITL checkpoints, human overseer designations, and oversight
    event audit trails for registered AI applications.
    """

    def __init__(self):
        self._overseers: dict[str, HumanOverseer] = {}
        self._checkpoints: dict[str, HITLCheckpoint] = {}
        self._events: list[OversightEvent] = []
        self._max_events = 10000

    # --- Overseer management ---

    def designate_overseer(
        self,
        name: str,
        role: str,
        email: str = "",
        department: str = "",
        authority_level: str = "standard",
    ) -> HumanOverseer:
        """Designate a human overseer for AI applications."""
        overseer_id = f"overseer-{uuid.uuid4().hex[:12]}"
        overseer = HumanOverseer(
            overseer_id=overseer_id,
            name=name,
            role=role,
            email=email,
            department=department,
            authority_level=authority_level,
        )
        self._overseers[overseer_id] = overseer
        logger.info("Designated human overseer: %s (%s)", name, overseer_id)
        return overseer

    def get_overseer(self, overseer_id: str) -> Optional[HumanOverseer]:
        return self._overseers.get(overseer_id)

    def list_overseers(self) -> list[HumanOverseer]:
        return list(self._overseers.values())

    def remove_overseer(self, overseer_id: str) -> bool:
        return self._overseers.pop(overseer_id, None) is not None

    # --- HITL Checkpoint management ---

    def add_checkpoint(
        self,
        app_id: str,
        checkpoint_type: str,
        description: str,
        is_mandatory: bool = True,
        overseer_ids: Optional[list[str]] = None,
        trigger_conditions: str = "",
    ) -> HITLCheckpoint:
        """Add a HITL checkpoint for an AI application."""
        checkpoint_id = f"cp-{uuid.uuid4().hex[:12]}"
        cp_type = HITLCheckpointType(checkpoint_type)
        checkpoint = HITLCheckpoint(
            checkpoint_id=checkpoint_id,
            app_id=app_id,
            checkpoint_type=cp_type,
            description=description,
            is_mandatory=is_mandatory,
            overseer_ids=overseer_ids or [],
            trigger_conditions=trigger_conditions,
        )
        self._checkpoints[checkpoint_id] = checkpoint
        logger.info("Added HITL checkpoint %s for app %s", checkpoint_id, app_id)
        return checkpoint

    def get_checkpoints(self, app_id: Optional[str] = None) -> list[HITLCheckpoint]:
        """List checkpoints, optionally filtered by app_id."""
        cps = list(self._checkpoints.values())
        if app_id:
            cps = [cp for cp in cps if cp.app_id == app_id]
        return cps

    def remove_checkpoint(self, checkpoint_id: str) -> bool:
        return self._checkpoints.pop(checkpoint_id, None) is not None

    # --- Oversight event logging ---

    def log_oversight_event(
        self,
        app_id: str,
        checkpoint_id: str = "",
        overseer_id: str = "",
        event_type: str = "review",
        decision: str = "",
        reason: str = "",
        metadata: Optional[dict] = None,
    ) -> OversightEvent:
        """Record a human oversight event."""
        event = OversightEvent(
            app_id=app_id,
            checkpoint_id=checkpoint_id,
            overseer_id=overseer_id,
            event_type=OversightEventType(event_type),
            decision=decision,
            reason=reason,
            metadata=metadata or {},
        )
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]
        logger.debug("Oversight event logged: %s (%s)", event.event_id, event_type)
        return event

    def get_oversight_events(
        self,
        app_id: Optional[str] = None,
        overseer_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[OversightEvent]:
        """Query oversight events with optional filtering."""
        events = self._events
        if app_id:
            events = [e for e in events if e.app_id == app_id]
        if overseer_id:
            events = [e for e in events if e.overseer_id == overseer_id]
        if event_type:
            events = [e for e in events if e.event_type.value == event_type]
        return events[-limit:]

    # --- Article 14 documentation generation ---

    def generate_article14_documentation(self, app_id: Optional[str] = None) -> dict:
        """Generate Article 14 human oversight documentation.

        Returns a structured document describing HITL checkpoints,
        designated overseers, and oversight event audit for the
        specified application (or all applications if not specified).
        """
        checkpoints = self.get_checkpoints(app_id)
        events = self.get_oversight_events(app_id=app_id, limit=1000)

        # Gather overseers referenced in checkpoints
        overseer_ids = set()
        for cp in checkpoints:
            overseer_ids.update(cp.overseer_ids)
        overseers = [
            self._overseers[oid].to_dict()
            for oid in overseer_ids
            if oid in self._overseers
        ]

        # Event summary
        event_summary = {
            "total_events": len(events),
            "by_type": {},
        }
        for evt in events:
            t = evt.event_type.value
            event_summary["by_type"][t] = event_summary["by_type"].get(t, 0) + 1

        return {
            "document_type": "EU AI Act Article 14 — Human Oversight Documentation",
            "generated_at": time.time(),
            "scope": {"app_id": app_id} if app_id else {"scope": "all_applications"},
            "section_1_hitl_checkpoints": {
                "total_checkpoints": len(checkpoints),
                "checkpoints": [cp.to_dict() for cp in checkpoints],
            },
            "section_2_designated_overseers": {
                "total_overseers": len(overseers),
                "overseers": overseers,
            },
            "section_3_oversight_event_audit": {
                "event_summary": event_summary,
                "recent_events": [e.to_dict() for e in events[-50:]],
            },
            "section_4_compliance_statement": {
                "article": "Article 14 — Human Oversight",
                "requirement": (
                    "High-risk AI systems shall be designed and developed in such a way "
                    "that they can be effectively overseen by natural persons during the "
                    "period in which the AI system is in use."
                ),
                "measures_implemented": [
                    f"{len(checkpoints)} HITL checkpoint(s) configured",
                    f"{len(overseers)} human overseer(s) designated",
                    f"{len(events)} oversight event(s) recorded",
                ],
            },
        }

    def get_stats(self) -> dict:
        return {
            "total_overseers": len(self._overseers),
            "total_checkpoints": len(self._checkpoints),
            "total_oversight_events": len(self._events),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Article 11 — Technical Documentation
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class TrainingDataDescription:
    """Description of training data for a model (Article 11 requirement)."""
    dataset_name: str = ""
    dataset_size: str = ""
    data_sources: list[str] = field(default_factory=list)
    preprocessing_steps: list[str] = field(default_factory=list)
    known_biases: list[str] = field(default_factory=list)
    data_governance: str = ""

    def to_dict(self) -> dict:
        return {
            "dataset_name": self.dataset_name,
            "dataset_size": self.dataset_size,
            "data_sources": self.data_sources,
            "preprocessing_steps": self.preprocessing_steps,
            "known_biases": self.known_biases,
            "data_governance": self.data_governance,
        }


@dataclass
class AccuracyMeasure:
    """Accuracy and performance measure for a model."""
    metric_name: str
    metric_value: str
    evaluation_dataset: str = ""
    evaluation_date: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "evaluation_dataset": self.evaluation_dataset,
            "evaluation_date": self.evaluation_date,
            "notes": self.notes,
        }


@dataclass
class RobustnessMeasure:
    """Robustness and security measure."""
    measure_name: str
    description: str
    implementation_status: str = "implemented"  # implemented, planned, not_applicable

    def to_dict(self) -> dict:
        return {
            "measure_name": self.measure_name,
            "description": self.description,
            "implementation_status": self.implementation_status,
        }


@dataclass
class TechnicalDocEntry:
    """A registered technical documentation entry for an AI application."""
    app_id: str
    system_description: str = ""
    architecture_summary: str = ""
    intended_purpose: str = ""
    training_data: Optional[TrainingDataDescription] = None
    accuracy_measures: list[AccuracyMeasure] = field(default_factory=list)
    robustness_measures: list[RobustnessMeasure] = field(default_factory=list)
    risk_management: str = ""
    monitoring_plan: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "system_description": self.system_description,
            "architecture_summary": self.architecture_summary,
            "intended_purpose": self.intended_purpose,
            "training_data": self.training_data.to_dict() if self.training_data else None,
            "accuracy_measures": [m.to_dict() for m in self.accuracy_measures],
            "robustness_measures": [m.to_dict() for m in self.robustness_measures],
            "risk_management": self.risk_management,
            "monitoring_plan": self.monitoring_plan,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class TechnicalDocService:
    """EU AI Act Article 11 technical documentation service.

    Generates and manages technical documentation packages including:
    - System architecture summary
    - Training data description
    - Accuracy and robustness measures
    - Exportable document structure (for PDF rendering)
    """

    def __init__(self):
        self._entries: dict[str, TechnicalDocEntry] = {}

    def create_entry(
        self,
        app_id: str,
        system_description: str = "",
        architecture_summary: str = "",
        intended_purpose: str = "",
        risk_management: str = "",
        monitoring_plan: str = "",
    ) -> TechnicalDocEntry:
        """Create a technical documentation entry for an AI application."""
        entry = TechnicalDocEntry(
            app_id=app_id,
            system_description=system_description,
            architecture_summary=architecture_summary,
            intended_purpose=intended_purpose,
            risk_management=risk_management,
            monitoring_plan=monitoring_plan,
        )
        self._entries[app_id] = entry
        logger.info("Created Article 11 tech doc entry for app %s", app_id)
        return entry

    def get_entry(self, app_id: str) -> Optional[TechnicalDocEntry]:
        return self._entries.get(app_id)

    def set_training_data(
        self,
        app_id: str,
        dataset_name: str = "",
        dataset_size: str = "",
        data_sources: Optional[list[str]] = None,
        preprocessing_steps: Optional[list[str]] = None,
        known_biases: Optional[list[str]] = None,
        data_governance: str = "",
    ) -> Optional[TechnicalDocEntry]:
        """Set training data description for an application's tech doc."""
        entry = self._entries.get(app_id)
        if not entry:
            return None
        entry.training_data = TrainingDataDescription(
            dataset_name=dataset_name,
            dataset_size=dataset_size,
            data_sources=data_sources or [],
            preprocessing_steps=preprocessing_steps or [],
            known_biases=known_biases or [],
            data_governance=data_governance,
        )
        entry.updated_at = time.time()
        return entry

    def add_accuracy_measure(
        self,
        app_id: str,
        metric_name: str,
        metric_value: str,
        evaluation_dataset: str = "",
        evaluation_date: str = "",
        notes: str = "",
    ) -> Optional[TechnicalDocEntry]:
        """Add an accuracy measure to an application's tech doc."""
        entry = self._entries.get(app_id)
        if not entry:
            return None
        entry.accuracy_measures.append(AccuracyMeasure(
            metric_name=metric_name,
            metric_value=metric_value,
            evaluation_dataset=evaluation_dataset,
            evaluation_date=evaluation_date,
            notes=notes,
        ))
        entry.updated_at = time.time()
        return entry

    def add_robustness_measure(
        self,
        app_id: str,
        measure_name: str,
        description: str,
        implementation_status: str = "implemented",
    ) -> Optional[TechnicalDocEntry]:
        """Add a robustness measure to an application's tech doc."""
        entry = self._entries.get(app_id)
        if not entry:
            return None
        entry.robustness_measures.append(RobustnessMeasure(
            measure_name=measure_name,
            description=description,
            implementation_status=implementation_status,
        ))
        entry.updated_at = time.time()
        return entry

    def generate_article11_package(self, app_id: str) -> Optional[dict]:
        """Generate the full Article 11 technical documentation package.

        Returns a structured document suitable for PDF export.
        Returns None if no entry exists for the given app_id.
        """
        entry = self._entries.get(app_id)
        if not entry:
            return None

        # Try to enrich with EU AI Act application data
        app_info = None
        try:
            from app.services.multilingual.eu_ai_act import get_eu_ai_act_service
            svc = get_eu_ai_act_service()
            app = svc.get_application(app_id)
            if app:
                app_info = app.to_dict()
        except Exception:
            pass

        # Try to get human oversight info
        oversight_info = None
        try:
            oversight_svc = get_human_oversight_service()
            checkpoints = oversight_svc.get_checkpoints(app_id)
            if checkpoints:
                oversight_info = {
                    "total_checkpoints": len(checkpoints),
                    "checkpoints": [cp.to_dict() for cp in checkpoints],
                }
        except Exception:
            pass

        doc_hash = hashlib.sha256(
            f"{app_id}:{entry.updated_at}".encode()
        ).hexdigest()[:16]

        package = {
            "document_type": "EU AI Act Article 11 — Technical Documentation",
            "document_id": f"art11-{doc_hash}",
            "generated_at": time.time(),
            "section_1_general_description": {
                "app_id": app_id,
                "system_description": entry.system_description,
                "intended_purpose": entry.intended_purpose,
                "application_info": app_info,
            },
            "section_2_system_architecture": {
                "architecture_summary": entry.architecture_summary,
                "sphinx_firewall_integration": {
                    "component": "Sphinx LLM Firewall",
                    "role": "Input/output scanning, threat detection, policy enforcement",
                    "features": [
                        "Multi-tier threat detection (Tier 1 regex + Tier 2 ML)",
                        "Multilingual threat detection (52 languages)",
                        "Cross-language attack detection",
                        "PII/PHI data shield",
                        "Output scanning and guardrails",
                        "Audit trail with hash chain integrity",
                    ],
                },
            },
            "section_3_training_data": entry.training_data.to_dict() if entry.training_data else {
                "note": "No fine-tuned model — using foundation model via API"
            },
            "section_4_accuracy_measures": {
                "measures": [m.to_dict() for m in entry.accuracy_measures],
            },
            "section_5_robustness_measures": {
                "measures": [m.to_dict() for m in entry.robustness_measures],
                "sphinx_security_measures": [
                    {"measure": "Prompt injection detection", "status": "active"},
                    {"measure": "Jailbreak detection", "status": "active"},
                    {"measure": "Data extraction prevention", "status": "active"},
                    {"measure": "Rate limiting", "status": "active"},
                    {"measure": "Circuit breaker", "status": "active"},
                    {"measure": "Kill switch", "status": "active"},
                ],
            },
            "section_6_risk_management": {
                "risk_management_plan": entry.risk_management,
            },
            "section_7_monitoring": {
                "monitoring_plan": entry.monitoring_plan,
                "sphinx_monitoring": {
                    "audit_logging": "Immutable hash-chain audit trail",
                    "performance_monitoring": "p99 latency tracking",
                    "threat_monitoring": "Real-time threat detection dashboard",
                },
            },
            "section_8_human_oversight": oversight_info or {
                "note": "See Article 14 documentation for human oversight details"
            },
        }

        return package

    def remove_entry(self, app_id: str) -> bool:
        return self._entries.pop(app_id, None) is not None

    def get_stats(self) -> dict:
        return {
            "total_entries": len(self._entries),
            "entries_with_training_data": sum(
                1 for e in self._entries.values() if e.training_data
            ),
            "entries_with_accuracy_measures": sum(
                1 for e in self._entries.values() if e.accuracy_measures
            ),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Singletons
# ──────────────────────────────────────────────────────────────────────────────

_oversight_service: Optional[HumanOversightService] = None
_tech_doc_service: Optional[TechnicalDocService] = None


def get_human_oversight_service() -> HumanOversightService:
    global _oversight_service
    if _oversight_service is None:
        _oversight_service = HumanOversightService()
    return _oversight_service


def reset_human_oversight_service() -> None:
    global _oversight_service
    _oversight_service = None


def get_technical_doc_service() -> TechnicalDocService:
    global _tech_doc_service
    if _tech_doc_service is None:
        _tech_doc_service = TechnicalDocService()
    return _tech_doc_service


def reset_technical_doc_service() -> None:
    global _tech_doc_service
    _tech_doc_service = None
