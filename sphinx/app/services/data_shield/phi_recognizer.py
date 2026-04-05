"""PHI Recognizer — HIPAA Protected Health Information extensions.

Detects: patient IDs, diagnosis codes (ICD-10), medication names,
provider names, and Medical Record Numbers (MRNs).
"""

import re
from dataclasses import dataclass
from enum import Enum

from app.services.data_shield.pii_recognizer import PIIEntity, PIIType


class PHIType(str, Enum):
    PATIENT_ID = "PATIENT_ID"
    DIAGNOSIS_CODE = "DIAGNOSIS_CODE"
    MEDICATION = "MEDICATION"
    PROVIDER_NAME = "PROVIDER_NAME"
    MRN = "MRN"


# ── Compiled regex patterns ─────────────────────────────────────────────

# Patient ID: "patient id: 12345", "patient #12345", "PID: ABC-12345"
_PATIENT_ID_RE = re.compile(
    r'(?:patient\s*(?:id|#|number|no\.?)|pid)\s*[:=#]?\s*'
    r'([A-Za-z0-9\-]{3,20})',
    re.IGNORECASE,
)

# ICD-10 diagnosis codes: A00-Z99 format with optional decimal subcodes
_ICD10_RE = re.compile(
    r'\b(?:ICD[\-\s]?10\s*[:=]?\s*)?'
    r'([A-TV-Z]\d{2}(?:\.\d{1,4})?)\b'
)

# ICD-10 with explicit context
_ICD10_CONTEXT_RE = re.compile(
    r'(?:diagnosis|dx|icd[\-\s]?10|diagnostic\s+code)\s*[:=]?\s*'
    r'([A-TV-Z]\d{2}(?:\.\d{1,4})?)',
    re.IGNORECASE,
)

# Common medication names (top prescribed + high-risk medications)
_MEDICATIONS = [
    "lisinopril", "atorvastatin", "metformin", "amlodipine", "metoprolol",
    "omeprazole", "losartan", "albuterol", "gabapentin", "hydrochlorothiazide",
    "sertraline", "simvastatin", "montelukast", "escitalopram", "rosuvastatin",
    "bupropion", "furosemide", "pantoprazole", "duloxetine", "prednisone",
    "tamsulosin", "meloxicam", "carvedilol", "trazodone", "pravastatin",
    "citalopram", "amoxicillin", "azithromycin", "ciprofloxacin", "doxycycline",
    "ibuprofen", "acetaminophen", "aspirin", "warfarin", "heparin",
    "insulin", "levothyroxine", "oxycodone", "hydrocodone", "morphine",
    "fentanyl", "tramadol", "diazepam", "lorazepam", "alprazolam",
    "clonazepam", "zolpidem", "quetiapine", "risperidone", "aripiprazole",
    "fluoxetine", "paroxetine", "venlafaxine", "lithium", "lamotrigine",
    "valproic acid", "carbamazepine", "phenytoin", "levetiracetam",
    "sumatriptan", "ondansetron", "methylphenidate", "amphetamine",
    "sildenafil", "tadalafil", "finasteride", "dutasteride",
]

_MEDICATION_PATTERN = '|'.join(re.escape(med) for med in _MEDICATIONS)
_MEDICATION_RE = re.compile(
    r'\b(' + _MEDICATION_PATTERN + r')\b',
    re.IGNORECASE,
)

# Medication with dosage context
_MEDICATION_DOSAGE_RE = re.compile(
    r'(?:prescribed|taking|medication|rx|drug)\s*[:=]?\s*'
    r'([A-Za-z]+(?:\s+[A-Za-z]+)?)\s+'
    r'\d+\s*(?:mg|mcg|ml|g|units?|iu)\b',
    re.IGNORECASE,
)

# Provider name: "Dr. Smith", "physician: Jane Doe", "provider: ..."
_PROVIDER_RE = re.compile(
    r'(?:'
    r'(?:physician|provider|doctor|attending|surgeon|specialist|'
    r'nurse\s+practitioner|np|pa)\s*[:=]?\s*'
    r'(?:Dr\.?\s+)?'
    r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})'
    r')',
    re.IGNORECASE,
)

# MRN: Medical Record Number — "MRN: 123456", "MRN# ABC12345"
_MRN_RE = re.compile(
    r'(?:mrn|medical\s+record\s*(?:number|no\.?|#))\s*[:=#]?\s*'
    r'([A-Za-z0-9\-]{4,20})',
    re.IGNORECASE,
)


class PHIRecognizer:
    """Detects HIPAA Protected Health Information entities."""

    def scan(self, text: str) -> list[PIIEntity]:
        """Scan text and return all detected PHI entities."""
        entities: list[PIIEntity] = []

        entities.extend(self._scan_patient_ids(text))
        entities.extend(self._scan_diagnosis_codes(text))
        entities.extend(self._scan_medications(text))
        entities.extend(self._scan_provider_names(text))
        entities.extend(self._scan_mrns(text))

        return entities

    def _scan_patient_ids(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _PATIENT_ID_RE.finditer(text):
            pid_value = m.group(1)
            results.append(
                PIIEntity(
                    entity_type=PIIType(PHIType.PATIENT_ID.value),
                    value=pid_value,
                    start=m.start(1),
                    end=m.end(1),
                    confidence=0.92,
                )
            )
        return results

    def _scan_diagnosis_codes(self, text: str) -> list[PIIEntity]:
        results = []
        seen_positions: set[int] = set()

        # First: context-based (higher confidence)
        for m in _ICD10_CONTEXT_RE.finditer(text):
            code = m.group(1)
            results.append(
                PIIEntity(
                    entity_type=PIIType(PHIType.DIAGNOSIS_CODE.value),
                    value=code,
                    start=m.start(1),
                    end=m.end(1),
                    confidence=0.95,
                )
            )
            seen_positions.add(m.start(1))

        # Second: standalone ICD-10 codes (lower confidence, only with "ICD" prefix)
        for m in _ICD10_RE.finditer(text):
            if m.start(1) not in seen_positions and 'ICD' in text[max(0, m.start() - 10):m.start()].upper():
                results.append(
                    PIIEntity(
                        entity_type=PIIType(PHIType.DIAGNOSIS_CODE.value),
                        value=m.group(1),
                        start=m.start(1),
                        end=m.end(1),
                        confidence=0.85,
                    )
                )

        return results

    def _scan_medications(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _MEDICATION_RE.finditer(text):
            results.append(
                PIIEntity(
                    entity_type=PIIType(PHIType.MEDICATION.value),
                    value=m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence=0.90,
                )
            )
        return results

    def _scan_provider_names(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _PROVIDER_RE.finditer(text):
            name = m.group(1).strip()
            if len(name) > 2:
                results.append(
                    PIIEntity(
                        entity_type=PIIType(PHIType.PROVIDER_NAME.value),
                        value=name,
                        start=m.start(1),
                        end=m.end(1),
                        confidence=0.85,
                    )
                )
        return results

    def _scan_mrns(self, text: str) -> list[PIIEntity]:
        results = []
        for m in _MRN_RE.finditer(text):
            mrn_value = m.group(1)
            results.append(
                PIIEntity(
                    entity_type=PIIType(PHIType.MRN.value),
                    value=mrn_value,
                    start=m.start(1),
                    end=m.end(1),
                    confidence=0.94,
                )
            )
        return results
