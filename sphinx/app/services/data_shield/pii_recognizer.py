"""PII Entity Recognizer — detects names, emails, phones, SSNs, DOBs, and addresses.

Uses a combination of regex patterns and heuristic rules for reliable detection
without heavy NLP dependencies. Architecture supports plugging in spaCy NER later.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class PIIType(str, Enum):
    """All entity types across PII, PHI, and credential scanners."""
    # PII types
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    ADDRESS = "ADDRESS"
    NAME = "NAME"
    # PHI types
    PATIENT_ID = "PATIENT_ID"
    DIAGNOSIS_CODE = "DIAGNOSIS_CODE"
    MEDICATION = "MEDICATION"
    PROVIDER_NAME = "PROVIDER_NAME"
    MRN = "MRN"
    # Credential types
    OPENAI_API_KEY = "OPENAI_API_KEY"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    GITHUB_PAT = "GITHUB_PAT"
    SLACK_TOKEN = "SLACK_TOKEN"
    STRIPE_KEY = "STRIPE_KEY"
    GOOGLE_API_KEY = "GOOGLE_API_KEY"
    ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"
    AZURE_KEY = "AZURE_KEY"
    GENERIC_API_KEY = "GENERIC_API_KEY"
    CREDIT_CARD = "CREDIT_CARD"
    PRIVATE_KEY = "PRIVATE_KEY"
    CONNECTION_STRING = "CONNECTION_STRING"
    JWT_TOKEN = "JWT_TOKEN"
    BEARER_TOKEN = "BEARER_TOKEN"


@dataclass
class PIIEntity:
    """A detected PII entity with position and type information."""
    entity_type: PIIType
    value: str
    start: int
    end: int
    confidence: float = 1.0

    def __repr__(self) -> str:
        return f"PIIEntity({self.entity_type.value}, {self.start}:{self.end}, conf={self.confidence:.2f})"


# ── Compiled regex patterns ─────────────────────────────────────────────

# Email: standard RFC-like pattern
_EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

# Phone: US formats — (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx, +1xxxxxxxxxx
_PHONE_RE = re.compile(
    r'(?<!\d)'                          # no digit before
    r'(?:'
    r'\+?1[\s.\-]?'                     # optional country code
    r')?'
    r'(?:'
    r'\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}'  # (xxx) xxx-xxxx
    r'|'
    r'\d{3}[\s.\-]\d{3}[\s.\-]\d{4}'        # xxx-xxx-xxxx / xxx.xxx.xxxx
    r')'
    r'(?!\d)'                           # no digit after
)

# SSN: xxx-xx-xxxx (with or without dashes)
_SSN_RE = re.compile(
    r'\b(?!000|666|9\d\d)\d{3}[\-\s]?(?!00)\d{2}[\-\s]?(?!0000)\d{4}\b'
)

# Date of birth: various date formats preceded by DOB/birth keywords
_DOB_KEYWORD_RE = re.compile(
    r'(?:date\s+of\s+birth|dob|d\.o\.b\.?|birth\s*date|born\s+on)',
    re.IGNORECASE,
)

_DATE_RE = re.compile(
    r'\b(?:'
    r'\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}'    # MM/DD/YYYY or DD-MM-YYYY
    r'|'
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}'  # Month DD, YYYY
    r'|'
    r'\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4}'    # DD Month YYYY
    r')\b',
    re.IGNORECASE,
)

# Street address heuristic
_ADDRESS_RE = re.compile(
    r'\b\d{1,6}\s+'                                          # street number
    r'(?:[A-Z][a-z]+\s*){1,4}'                              # street name words
    r'(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Drive|Dr\.?|'
    r'Road|Rd\.?|Lane|Ln\.?|Court|Ct\.?|Place|Pl\.?|Way|'
    r'Circle|Cir\.?|Trail|Trl\.?|Parkway|Pkwy\.?)\b',
    re.IGNORECASE,
)

# Name detection: context-based (preceded by common name indicators)
# Uses inline (?i:...) for keyword part only; name capture requires Title Case
_NAME_CONTEXT_RE = re.compile(
    r'(?:(?i:my\s+name\s+is\s+|name:\s*|patient(?:\s+name)?:\s*|'
    r'dear\s+|attn:\s*|attention:\s*|'
    r'from:\s*|to:\s*|contact:\s*|'
    r'mr\.?\s+|mrs\.?\s+|ms\.?\s+|dr\.?\s+|prof\.?\s+))'
    r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})',
)


class PIIRecognizer:
    """Detects PII entities in text using regex patterns and heuristic rules."""

    def scan(self, text: str) -> list[PIIEntity]:
        """Scan text and return all detected PII entities."""
        entities: list[PIIEntity] = []

        entities.extend(self._scan_emails(text))
        entities.extend(self._scan_phones(text))
        entities.extend(self._scan_ssns(text))
        entities.extend(self._scan_dobs(text))
        entities.extend(self._scan_addresses(text))
        entities.extend(self._scan_names(text))

        # Deduplicate overlapping entities (keep higher confidence)
        entities = self._deduplicate(entities)
        return entities

    def _scan_emails(self, text: str) -> list[PIIEntity]:
        return [
            PIIEntity(
                entity_type=PIIType.EMAIL,
                value=m.group(),
                start=m.start(),
                end=m.end(),
                confidence=0.99,
            )
            for m in _EMAIL_RE.finditer(text)
        ]

    def _scan_phones(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _PHONE_RE.finditer(text):
            # Filter out numbers that look like SSNs or years
            digits = re.sub(r'\D', '', m.group())
            if len(digits) < 10 or len(digits) > 11:
                continue
            results.append(
                PIIEntity(
                    entity_type=PIIType.PHONE,
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence=0.95,
                )
            )
        return results

    def _scan_ssns(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _SSN_RE.finditer(text):
            val = m.group()
            digits = re.sub(r'\D', '', val)
            # Must be exactly 9 digits and contain separator or be preceded by SSN keyword
            has_separator = '-' in val or ' ' in val
            ssn_context = bool(re.search(
                r'(?:ssn|social\s+security|ss#)',
                text[max(0, m.start() - 40):m.start()],
                re.IGNORECASE,
            ))
            if len(digits) == 9 and (has_separator or ssn_context):
                results.append(
                    PIIEntity(
                        entity_type=PIIType.SSN,
                        value=val,
                        start=m.start(),
                        end=m.end(),
                        confidence=0.97 if has_separator else 0.85,
                    )
                )
        return results

    def _scan_dobs(self, text: str) -> list[PIIEntity]:
        results = []
        for km in _DOB_KEYWORD_RE.finditer(text):
            # Look for a date within 30 chars after the keyword
            search_region = text[km.end():km.end() + 50]
            dm = _DATE_RE.search(search_region)
            if dm:
                abs_start = km.end() + dm.start()
                abs_end = km.end() + dm.end()
                results.append(
                    PIIEntity(
                        entity_type=PIIType.DATE_OF_BIRTH,
                        value=dm.group(),
                        start=abs_start,
                        end=abs_end,
                        confidence=0.93,
                    )
                )
        return results

    def _scan_addresses(self, text: str) -> list[PIIEntity]:
        return [
            PIIEntity(
                entity_type=PIIType.ADDRESS,
                value=m.group(),
                start=m.start(),
                end=m.end(),
                confidence=0.88,
            )
            for m in _ADDRESS_RE.finditer(text)
        ]

    def _scan_names(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _NAME_CONTEXT_RE.finditer(text):
            name = m.group(1).strip()
            if len(name) > 2:
                # Calculate absolute position of the captured group
                full_match = m.group(0)
                name_offset = full_match.index(name)
                abs_start = m.start() + name_offset
                abs_end = abs_start + len(name)
                results.append(
                    PIIEntity(
                        entity_type=PIIType.NAME,
                        value=name,
                        start=abs_start,
                        end=abs_end,
                        confidence=0.80,
                    )
                )
        return results

    def _deduplicate(self, entities: list[PIIEntity]) -> list[PIIEntity]:
        """Remove overlapping entities, keeping the one with higher confidence."""
        if not entities:
            return entities
        entities.sort(key=lambda e: (e.start, -e.confidence))
        result: list[PIIEntity] = []
        for entity in entities:
            if result and entity.start < result[-1].end:
                # Overlapping — keep higher confidence
                if entity.confidence > result[-1].confidence:
                    result[-1] = entity
            else:
                result.append(entity)
        return result
