"""Redaction Engine — replaces detected PII/PHI/credential entities with placeholder tokens.

Preserves sentence structure for model coherence by using descriptive placeholders
like [REDACTED-EMAIL], [REDACTED-SSN], etc.
"""

import logging
from dataclasses import dataclass

from app.services.data_shield.pii_recognizer import PIIEntity, PIIType

logger = logging.getLogger("sphinx.data_shield.redaction")

# Placeholder templates per entity type
_PLACEHOLDER_MAP: dict[str, str] = {
    # PII
    "EMAIL": "[REDACTED-EMAIL]",
    "PHONE": "[REDACTED-PHONE]",
    "SSN": "[REDACTED-SSN]",
    "DATE_OF_BIRTH": "[REDACTED-DOB]",
    "ADDRESS": "[REDACTED-ADDRESS]",
    "NAME": "[REDACTED-NAME]",
    # PHI
    "PATIENT_ID": "[REDACTED-PATIENT-ID]",
    "DIAGNOSIS_CODE": "[REDACTED-DX-CODE]",
    "MEDICATION": "[REDACTED-MEDICATION]",
    "PROVIDER_NAME": "[REDACTED-PROVIDER]",
    "MRN": "[REDACTED-MRN]",
    # Credentials
    "OPENAI_API_KEY": "[REDACTED-API-KEY]",
    "ANTHROPIC_API_KEY": "[REDACTED-API-KEY]",
    "AWS_ACCESS_KEY": "[REDACTED-AWS-KEY]",
    "AWS_SECRET_KEY": "[REDACTED-AWS-SECRET]",
    "GITHUB_TOKEN": "[REDACTED-GITHUB-TOKEN]",
    "GITHUB_PAT": "[REDACTED-GITHUB-TOKEN]",
    "SLACK_TOKEN": "[REDACTED-SLACK-TOKEN]",
    "STRIPE_KEY": "[REDACTED-STRIPE-KEY]",
    "GOOGLE_API_KEY": "[REDACTED-API-KEY]",
    "AZURE_KEY": "[REDACTED-AZURE-KEY]",
    "GENERIC_API_KEY": "[REDACTED-API-KEY]",
    "CREDIT_CARD": "[REDACTED-CC]",
    "PRIVATE_KEY": "[REDACTED-PRIVATE-KEY]",
    "CONNECTION_STRING": "[REDACTED-CONN-STRING]",
    "JWT_TOKEN": "[REDACTED-JWT]",
    "BEARER_TOKEN": "[REDACTED-BEARER-TOKEN]",
}


@dataclass
class RedactionResult:
    """Result of redacting text."""
    original_text: str
    redacted_text: str
    entities_redacted: list[PIIEntity]
    redaction_count: int

    def to_dict(self) -> dict:
        return {
            "redacted_text": self.redacted_text,
            "redaction_count": self.redaction_count,
            "entity_types": list({e.entity_type.value for e in self.entities_redacted}),
        }


class RedactionEngine:
    """Replaces detected entities with placeholder tokens in text."""

    def __init__(self, custom_placeholders: dict[str, str] | None = None):
        self._placeholders = dict(_PLACEHOLDER_MAP)
        if custom_placeholders:
            self._placeholders.update(custom_placeholders)

    def redact(self, text: str, entities: list[PIIEntity]) -> RedactionResult:
        """Redact all detected entities from text, preserving sentence structure."""
        if not entities:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                entities_redacted=[],
                redaction_count=0,
            )

        # Sort by position descending so replacements don't shift offsets
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        redacted = text
        applied: list[PIIEntity] = []
        seen_ranges: list[tuple[int, int]] = []

        for entity in sorted_entities:
            # Skip overlapping entities
            if any(s <= entity.start < e or s < entity.end <= e for s, e in seen_ranges):
                continue

            placeholder = self._get_placeholder(entity)
            redacted = redacted[:entity.start] + placeholder + redacted[entity.end:]
            applied.append(entity)
            seen_ranges.append((entity.start, entity.end))

        logger.debug("Redacted %d entities from text", len(applied))
        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            entities_redacted=list(reversed(applied)),  # restore original order
            redaction_count=len(applied),
        )

    def _get_placeholder(self, entity: PIIEntity) -> str:
        """Get the placeholder string for an entity type."""
        type_value = entity.entity_type.value if isinstance(entity.entity_type, PIIType) else str(entity.entity_type)
        return self._placeholders.get(type_value, f"[REDACTED-{type_value}]")
