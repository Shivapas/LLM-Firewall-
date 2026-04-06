"""EU AI Act risk classification + transparency event logging.

Implements:
- Risk classification schema for AI systems governed by Sphinx (Article 6/Annex III)
- Dashboard display of each registered AI application's EU AI Act risk tier
- Transparency event logging per Article 50 (AI-generated content markers)

Risk Tiers:
- Prohibited: Unacceptable risk (social scoring, real-time biometric, etc.)
- High-Risk: Annex III systems (critical infrastructure, employment, law enforcement, etc.)
- Limited: Limited transparency obligations (chatbots, deepfakes, etc.)
- Minimal: No additional obligations (spam filters, games, etc.)
"""

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.multilingual.eu_ai_act")


class EURiskTier(str, Enum):
    """EU AI Act risk classification tiers."""
    PROHIBITED = "prohibited"
    HIGH_RISK = "high_risk"
    LIMITED = "limited"
    MINIMAL = "minimal"


# Risk classification criteria — maps use-case categories to risk tiers
_RISK_CLASSIFICATION_RULES: list[dict] = [
    # Prohibited (Article 5)
    {"category": "social_scoring", "tier": EURiskTier.PROHIBITED,
     "description": "Social scoring by public authorities"},
    {"category": "real_time_biometric", "tier": EURiskTier.PROHIBITED,
     "description": "Real-time remote biometric identification in public spaces"},
    {"category": "subliminal_manipulation", "tier": EURiskTier.PROHIBITED,
     "description": "Subliminal manipulation beyond consciousness"},
    {"category": "vulnerability_exploitation", "tier": EURiskTier.PROHIBITED,
     "description": "Exploitation of vulnerabilities of specific groups"},
    {"category": "predictive_policing", "tier": EURiskTier.PROHIBITED,
     "description": "Predictive policing based solely on profiling"},
    {"category": "emotion_recognition_workplace", "tier": EURiskTier.PROHIBITED,
     "description": "Emotion recognition in workplace or education (non-safety)"},
    # High-Risk (Annex III)
    {"category": "critical_infrastructure", "tier": EURiskTier.HIGH_RISK,
     "description": "Management and operation of critical infrastructure"},
    {"category": "education_training", "tier": EURiskTier.HIGH_RISK,
     "description": "Education and vocational training access/assessment"},
    {"category": "employment_hr", "tier": EURiskTier.HIGH_RISK,
     "description": "Employment, worker management, and recruitment"},
    {"category": "essential_services", "tier": EURiskTier.HIGH_RISK,
     "description": "Access to essential private/public services and benefits"},
    {"category": "law_enforcement", "tier": EURiskTier.HIGH_RISK,
     "description": "Law enforcement investigation and prosecution"},
    {"category": "migration_border", "tier": EURiskTier.HIGH_RISK,
     "description": "Migration, asylum, and border control management"},
    {"category": "justice_democracy", "tier": EURiskTier.HIGH_RISK,
     "description": "Administration of justice and democratic processes"},
    {"category": "biometric_categorization", "tier": EURiskTier.HIGH_RISK,
     "description": "Biometric categorization of natural persons"},
    {"category": "medical_device", "tier": EURiskTier.HIGH_RISK,
     "description": "AI systems that are medical devices or safety components"},
    {"category": "creditworthiness", "tier": EURiskTier.HIGH_RISK,
     "description": "Creditworthiness assessment of natural persons"},
    # Limited (Article 50)
    {"category": "chatbot", "tier": EURiskTier.LIMITED,
     "description": "Chatbot — interaction with natural persons"},
    {"category": "deepfake", "tier": EURiskTier.LIMITED,
     "description": "Deep fake generation — synthetic image/audio/video"},
    {"category": "content_generation", "tier": EURiskTier.LIMITED,
     "description": "AI-generated text published as information"},
    {"category": "emotion_recognition_other", "tier": EURiskTier.LIMITED,
     "description": "Emotion recognition systems (non-prohibited contexts)"},
    # Minimal
    {"category": "spam_filter", "tier": EURiskTier.MINIMAL,
     "description": "Spam filtering"},
    {"category": "gaming", "tier": EURiskTier.MINIMAL,
     "description": "AI in video games"},
    {"category": "inventory_management", "tier": EURiskTier.MINIMAL,
     "description": "Inventory management systems"},
    {"category": "general_assistant", "tier": EURiskTier.MINIMAL,
     "description": "General-purpose AI assistant (non-high-risk context)"},
]


@dataclass
class AIApplication:
    """A registered AI application with its EU AI Act classification."""
    app_id: str
    name: str
    description: str
    category: str
    risk_tier: EURiskTier
    provider: str = ""
    model: str = ""
    tenant_id: str = ""
    registered_at: float = field(default_factory=time.time)
    last_assessed_at: float = field(default_factory=time.time)
    compliance_notes: str = ""
    requires_conformity_assessment: bool = False
    requires_transparency_logging: bool = False

    def __post_init__(self):
        self.requires_conformity_assessment = self.risk_tier == EURiskTier.HIGH_RISK
        self.requires_transparency_logging = self.risk_tier in (
            EURiskTier.HIGH_RISK, EURiskTier.LIMITED
        )

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "risk_tier": self.risk_tier.value,
            "provider": self.provider,
            "model": self.model,
            "tenant_id": self.tenant_id,
            "registered_at": self.registered_at,
            "last_assessed_at": self.last_assessed_at,
            "compliance_notes": self.compliance_notes,
            "requires_conformity_assessment": self.requires_conformity_assessment,
            "requires_transparency_logging": self.requires_transparency_logging,
        }


@dataclass
class TransparencyEvent:
    """Transparency event per EU AI Act Article 50.

    Records AI-generated content markers including model, generation timestamp,
    and output hash for transparency evidence.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    app_id: str = ""
    tenant_id: str = ""
    model: str = ""
    provider: str = ""
    generation_timestamp: float = field(default_factory=time.time)
    output_hash: str = ""
    input_hash: str = ""
    content_type: str = "text"  # text, image, audio, video
    is_ai_generated: bool = True
    watermark_applied: bool = False
    disclosure_text: str = "This content was generated by an AI system."
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "app_id": self.app_id,
            "tenant_id": self.tenant_id,
            "model": self.model,
            "provider": self.provider,
            "generation_timestamp": self.generation_timestamp,
            "output_hash": self.output_hash,
            "input_hash": self.input_hash,
            "content_type": self.content_type,
            "is_ai_generated": self.is_ai_generated,
            "watermark_applied": self.watermark_applied,
            "disclosure_text": self.disclosure_text,
            "metadata": self.metadata,
        }


@dataclass
class RiskClassificationDashboard:
    """Dashboard summary of EU AI Act risk classifications."""
    total_applications: int = 0
    prohibited_count: int = 0
    high_risk_count: int = 0
    limited_count: int = 0
    minimal_count: int = 0
    applications: list[dict] = field(default_factory=list)
    transparency_events_total: int = 0
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "total_applications": self.total_applications,
            "risk_distribution": {
                "prohibited": self.prohibited_count,
                "high_risk": self.high_risk_count,
                "limited": self.limited_count,
                "minimal": self.minimal_count,
            },
            "applications": self.applications,
            "transparency_events_total": self.transparency_events_total,
            "last_updated": self.last_updated,
        }


class EUAIActService:
    """EU AI Act risk classification and transparency logging service.

    Manages:
    - Registration and classification of AI applications
    - Risk tier assignment based on use-case category
    - Transparency event logging for every model response
    - Dashboard with risk tier distribution
    """

    def __init__(self):
        self._applications: dict[str, AIApplication] = {}
        self._transparency_events: list[TransparencyEvent] = []
        self._max_events = 10000
        self._classification_rules = list(_RISK_CLASSIFICATION_RULES)

    def classify_risk(self, category: str) -> EURiskTier:
        """Classify risk tier based on use-case category.

        Returns the risk tier for the given category, or MINIMAL as default.
        """
        for rule in self._classification_rules:
            if rule["category"] == category:
                return rule["tier"]
        return EURiskTier.MINIMAL

    def register_application(
        self,
        name: str,
        description: str,
        category: str,
        provider: str = "",
        model: str = "",
        tenant_id: str = "",
        compliance_notes: str = "",
    ) -> AIApplication:
        """Register a new AI application and classify its risk tier."""
        app_id = f"app-{uuid.uuid4().hex[:12]}"
        risk_tier = self.classify_risk(category)

        app = AIApplication(
            app_id=app_id,
            name=name,
            description=description,
            category=category,
            risk_tier=risk_tier,
            provider=provider,
            model=model,
            tenant_id=tenant_id,
            compliance_notes=compliance_notes,
        )
        self._applications[app_id] = app
        logger.info("Registered AI application %s (%s) — risk tier: %s",
                     name, app_id, risk_tier.value)
        return app

    def get_application(self, app_id: str) -> Optional[AIApplication]:
        """Get a registered application by ID."""
        return self._applications.get(app_id)

    def list_applications(self, risk_tier: Optional[EURiskTier] = None) -> list[AIApplication]:
        """List all registered applications, optionally filtered by risk tier."""
        apps = list(self._applications.values())
        if risk_tier is not None:
            apps = [a for a in apps if a.risk_tier == risk_tier]
        return apps

    def update_classification(self, app_id: str, category: str) -> Optional[AIApplication]:
        """Re-classify an application's risk tier."""
        app = self._applications.get(app_id)
        if not app:
            return None
        app.category = category
        app.risk_tier = self.classify_risk(category)
        app.last_assessed_at = time.time()
        app.requires_conformity_assessment = app.risk_tier == EURiskTier.HIGH_RISK
        app.requires_transparency_logging = app.risk_tier in (
            EURiskTier.HIGH_RISK, EURiskTier.LIMITED
        )
        return app

    def remove_application(self, app_id: str) -> bool:
        """Remove a registered application."""
        return self._applications.pop(app_id, None) is not None

    def log_transparency_event(
        self,
        app_id: str = "",
        tenant_id: str = "",
        model: str = "",
        provider: str = "",
        output_content: str = "",
        input_content: str = "",
        content_type: str = "text",
        metadata: Optional[dict] = None,
    ) -> TransparencyEvent:
        """Log a transparency event per EU AI Act Article 50.

        Records model, generation timestamp, and output hash for every model response.
        """
        output_hash = hashlib.sha256(output_content.encode("utf-8")).hexdigest()[:32] if output_content else ""
        input_hash = hashlib.sha256(input_content.encode("utf-8")).hexdigest()[:32] if input_content else ""

        event = TransparencyEvent(
            app_id=app_id,
            tenant_id=tenant_id,
            model=model,
            provider=provider,
            generation_timestamp=time.time(),
            output_hash=output_hash,
            input_hash=input_hash,
            content_type=content_type,
            metadata=metadata or {},
        )

        self._transparency_events.append(event)

        # Evict old events if over capacity
        if len(self._transparency_events) > self._max_events:
            self._transparency_events = self._transparency_events[-self._max_events:]

        logger.debug("Transparency event logged: %s (model=%s, hash=%s)",
                      event.event_id, model, output_hash)
        return event

    def get_transparency_events(
        self,
        app_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[TransparencyEvent]:
        """Query transparency events with optional filtering."""
        events = self._transparency_events
        if app_id:
            events = [e for e in events if e.app_id == app_id]
        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        return events[-limit:]

    def get_dashboard(self) -> RiskClassificationDashboard:
        """Generate the EU AI Act risk classification dashboard."""
        apps = list(self._applications.values())
        return RiskClassificationDashboard(
            total_applications=len(apps),
            prohibited_count=sum(1 for a in apps if a.risk_tier == EURiskTier.PROHIBITED),
            high_risk_count=sum(1 for a in apps if a.risk_tier == EURiskTier.HIGH_RISK),
            limited_count=sum(1 for a in apps if a.risk_tier == EURiskTier.LIMITED),
            minimal_count=sum(1 for a in apps if a.risk_tier == EURiskTier.MINIMAL),
            applications=[a.to_dict() for a in apps],
            transparency_events_total=len(self._transparency_events),
        )

    def get_classification_rules(self) -> list[dict]:
        """Return all risk classification rules."""
        return [
            {
                "category": r["category"],
                "tier": r["tier"].value,
                "description": r["description"],
            }
            for r in self._classification_rules
        ]

    def get_stats(self) -> dict:
        """Return service statistics."""
        return {
            "total_applications": len(self._applications),
            "total_transparency_events": len(self._transparency_events),
            "classification_rules": len(self._classification_rules),
            "risk_distribution": {
                "prohibited": sum(1 for a in self._applications.values() if a.risk_tier == EURiskTier.PROHIBITED),
                "high_risk": sum(1 for a in self._applications.values() if a.risk_tier == EURiskTier.HIGH_RISK),
                "limited": sum(1 for a in self._applications.values() if a.risk_tier == EURiskTier.LIMITED),
                "minimal": sum(1 for a in self._applications.values() if a.risk_tier == EURiskTier.MINIMAL),
            },
        }


# Singleton
_service: Optional[EUAIActService] = None


def get_eu_ai_act_service() -> EUAIActService:
    """Get or create the singleton EU AI Act service."""
    global _service
    if _service is None:
        _service = EUAIActService()
    return _service


def reset_eu_ai_act_service() -> None:
    """Reset the singleton service (for testing)."""
    global _service
    _service = None
