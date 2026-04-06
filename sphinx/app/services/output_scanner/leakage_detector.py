"""Regulated Data Leakage Detector — detects when regulated data from the input
pipeline appears in model output.

Matches output content against compliance tags from the input scanning phase.
If regulated data (PII/PHI/IP) appears in the output, triggers redaction + incident logging.
"""

import logging
from dataclasses import dataclass, field

from app.services.data_shield.pii_recognizer import PIIEntity, PIIType

logger = logging.getLogger("sphinx.output_scanner.leakage_detector")

# Mapping from compliance tags to entity type groups
_TAG_TO_ENTITY_TYPES: dict[str, set[str]] = {
    "PII": {"EMAIL", "PHONE", "SSN", "DATE_OF_BIRTH", "ADDRESS", "NAME"},
    "PHI": {"PATIENT_ID", "DIAGNOSIS_CODE", "MEDICATION", "PROVIDER_NAME", "MRN"},
    "IP": {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY",
        "GITHUB_TOKEN", "GITHUB_PAT", "SLACK_TOKEN", "STRIPE_KEY",
        "GOOGLE_API_KEY", "AZURE_KEY", "GENERIC_API_KEY", "CREDIT_CARD",
        "PRIVATE_KEY", "CONNECTION_STRING", "JWT_TOKEN", "BEARER_TOKEN",
    },
}


@dataclass
class LeakageIncident:
    """A single detected data leakage incident."""
    compliance_tag: str
    entity_type: str
    entity_value: str
    confidence: float
    severity: str  # "critical", "high", "medium"


@dataclass
class LeakageDetectionResult:
    """Result of regulated data leakage detection."""
    leakage_detected: bool = False
    incidents: list[LeakageIncident] = field(default_factory=list)
    compliance_tags_violated: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "leakage_detected": self.leakage_detected,
            "incident_count": len(self.incidents),
            "compliance_tags_violated": self.compliance_tags_violated,
            "incidents": [
                {
                    "tag": i.compliance_tag,
                    "entity_type": i.entity_type,
                    "severity": i.severity,
                }
                for i in self.incidents
            ],
        }


def _severity_for_tag(tag: str) -> str:
    """Determine severity based on compliance tag."""
    if tag == "PHI":
        return "critical"
    if tag == "IP":
        return "critical"
    return "high"


class LeakageDetector:
    """Detects regulated data leakage in model output based on input compliance tags."""

    def detect(
        self,
        entities: list[PIIEntity],
        input_compliance_tags: list[str],
    ) -> LeakageDetectionResult:
        """Check if any detected output entities match the compliance tags from input scanning.

        Args:
            entities: Entities detected in the output content.
            input_compliance_tags: Tags from the input Data Shield scan (e.g., ["PII", "PHI"]).

        Returns:
            LeakageDetectionResult indicating whether regulated data leaked.
        """
        if not entities or not input_compliance_tags:
            return LeakageDetectionResult()

        incidents: list[LeakageIncident] = []
        violated_tags: set[str] = set()

        for tag in input_compliance_tags:
            regulated_types = _TAG_TO_ENTITY_TYPES.get(tag, set())
            if not regulated_types:
                continue

            for entity in entities:
                etype = entity.entity_type.value if isinstance(entity.entity_type, PIIType) else str(entity.entity_type)
                if etype in regulated_types:
                    violated_tags.add(tag)
                    incidents.append(LeakageIncident(
                        compliance_tag=tag,
                        entity_type=etype,
                        entity_value=entity.value[:20] + "..." if len(entity.value) > 20 else entity.value,
                        confidence=entity.confidence,
                        severity=_severity_for_tag(tag),
                    ))

        if incidents:
            logger.warning(
                "Regulated data leakage detected: %d incidents, violated tags: %s",
                len(incidents), sorted(violated_tags),
            )

        return LeakageDetectionResult(
            leakage_detected=bool(incidents),
            incidents=incidents,
            compliance_tags_violated=sorted(violated_tags),
        )
