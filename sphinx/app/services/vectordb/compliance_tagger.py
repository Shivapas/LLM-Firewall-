"""Compliance Tagger — tags retrieved chunks with compliance labels
(PII / IP / Regulated) before context assembly.

Sprint 10: Vector DB Firewall Hardening & Observability.

Labels are used in downstream routing decisions — e.g., PII-tagged chunks
trigger routing to on-premise models, IP-tagged chunks require additional
approval, and Regulated chunks enforce data residency constraints.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("sphinx.vectordb.compliance_tagger")


class ComplianceLabel(str, Enum):
    """Compliance classification labels for retrieved chunks."""
    PII = "PII"                 # Personally Identifiable Information
    PHI = "PHI"                 # Protected Health Information
    IP = "IP"                   # Intellectual Property
    REGULATED = "REGULATED"     # Regulatory-controlled data (GDPR, HIPAA, SOX, etc.)
    PUBLIC = "PUBLIC"           # No compliance restrictions
    INTERNAL = "INTERNAL"       # Internal use only
    CONFIDENTIAL = "CONFIDENTIAL"  # Confidential business data


@dataclass
class ComplianceTag:
    """A single compliance tag applied to a chunk."""
    label: ComplianceLabel
    confidence: float = 1.0
    source: str = ""  # What triggered the tag: "metadata", "content_scan", "policy_rule"
    detail: str = ""  # Additional detail about the match

    def to_dict(self) -> dict:
        return {
            "label": self.label.value,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "detail": self.detail,
        }


@dataclass
class ChunkComplianceResult:
    """Compliance tagging result for a single chunk."""
    chunk_id: str = ""
    tags: list[ComplianceTag] = field(default_factory=list)
    highest_sensitivity: str = "PUBLIC"
    requires_private_model: bool = False
    requires_approval: bool = False
    data_residency_required: bool = False

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "tags": [t.to_dict() for t in self.tags],
            "highest_sensitivity": self.highest_sensitivity,
            "requires_private_model": self.requires_private_model,
            "requires_approval": self.requires_approval,
            "data_residency_required": self.data_residency_required,
        }

    @property
    def label_names(self) -> list[str]:
        return [t.label.value for t in self.tags]


@dataclass
class BatchComplianceResult:
    """Compliance tagging result for a batch of chunks."""
    total_chunks: int = 0
    tagged_chunks: int = 0
    chunk_results: list[ChunkComplianceResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    any_requires_private_model: bool = False
    any_requires_approval: bool = False
    any_data_residency_required: bool = False

    def to_dict(self) -> dict:
        return {
            "total_chunks": self.total_chunks,
            "tagged_chunks": self.tagged_chunks,
            "summary": self.summary,
            "any_requires_private_model": self.any_requires_private_model,
            "any_requires_approval": self.any_requires_approval,
            "any_data_residency_required": self.any_data_residency_required,
            "chunk_results": [r.to_dict() for r in self.chunk_results],
        }


@dataclass
class CompliancePolicy:
    """Policy configuration for compliance tagging."""
    # Metadata field names that indicate compliance labels
    pii_metadata_fields: list[str] = field(
        default_factory=lambda: ["pii", "contains_pii", "has_pii"]
    )
    phi_metadata_fields: list[str] = field(
        default_factory=lambda: ["phi", "contains_phi", "has_phi", "hipaa"]
    )
    ip_metadata_fields: list[str] = field(
        default_factory=lambda: ["ip", "intellectual_property", "proprietary", "trade_secret"]
    )
    regulated_metadata_fields: list[str] = field(
        default_factory=lambda: ["regulated", "gdpr", "hipaa", "sox", "pci", "compliance"]
    )
    confidential_metadata_fields: list[str] = field(
        default_factory=lambda: ["confidential", "classification"]
    )

    # Content patterns for PII detection
    pii_content_patterns: list[str] = field(
        default_factory=lambda: [
            r"\b\d{3}-\d{2}-\d{4}\b",              # SSN
            r"\b[A-Z]{2}\d{6,8}\b",                 # Passport
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit card
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",  # Email
            r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # Phone number
        ]
    )

    # Content patterns for PHI detection
    phi_content_patterns: list[str] = field(
        default_factory=lambda: [
            r"\b(?:patient|medical|diagnosis|prescription|treatment|icd-?\d{1,2})\b",
            r"\b(?:blood\s*type|allergies|medication)\b",
        ]
    )

    # Content patterns for IP detection
    ip_content_patterns: list[str] = field(
        default_factory=lambda: [
            r"\b(?:patent|trade\s*secret|proprietary|confidential\s*algorithm)\b",
            r"\b(?:internal\s*only|do\s*not\s*distribute)\b",
        ]
    )

    # Sensitivity ordering (higher index = more sensitive)
    scan_content: bool = True
    scan_metadata: bool = True


# Sensitivity hierarchy — used to determine highest sensitivity
_SENSITIVITY_ORDER = {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "IP": 3,
    "REGULATED": 4,
    "PII": 5,
    "PHI": 6,
}

# Labels that trigger downstream routing decisions
_PRIVATE_MODEL_LABELS = {ComplianceLabel.PII, ComplianceLabel.PHI, ComplianceLabel.REGULATED}
_APPROVAL_LABELS = {ComplianceLabel.IP, ComplianceLabel.CONFIDENTIAL}
_RESIDENCY_LABELS = {ComplianceLabel.REGULATED, ComplianceLabel.PHI}


class ComplianceTagger:
    """Tags retrieved chunks with compliance labels before context assembly.

    Two-phase tagging:
    1. Metadata scan — check document metadata fields for compliance indicators
    2. Content scan — regex patterns on document content for PII/PHI/IP detection

    Tags are non-destructive — they annotate chunks, not filter them.
    Downstream routing policy uses tags to make model selection decisions.
    """

    def __init__(self, policy: Optional[CompliancePolicy] = None):
        self._policy = policy or CompliancePolicy()
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for content scanning."""
        pattern_groups = {
            "pii": self._policy.pii_content_patterns,
            "phi": self._policy.phi_content_patterns,
            "ip": self._policy.ip_content_patterns,
        }
        for group_name, patterns in pattern_groups.items():
            compiled = []
            for p in patterns:
                try:
                    compiled.append(re.compile(p, re.IGNORECASE))
                except re.error:
                    logger.error("Invalid compliance pattern in %s: %s", group_name, p)
            self._compiled_patterns[group_name] = compiled

    def tag_chunks(
        self, documents: list[dict[str, Any]]
    ) -> BatchComplianceResult:
        """Tag a batch of document chunks with compliance labels.

        Args:
            documents: List of document dicts with 'id', 'content', 'metadata'

        Returns:
            BatchComplianceResult with per-chunk compliance tags
        """
        result = BatchComplianceResult(total_chunks=len(documents))
        summary: dict[str, int] = {}

        for doc in documents:
            chunk_result = self._tag_single_chunk(doc)
            result.chunk_results.append(chunk_result)

            if chunk_result.tags:
                result.tagged_chunks += 1

            # Update summary counts
            for tag in chunk_result.tags:
                label_name = tag.label.value
                summary[label_name] = summary.get(label_name, 0) + 1

            # Aggregate routing decisions
            if chunk_result.requires_private_model:
                result.any_requires_private_model = True
            if chunk_result.requires_approval:
                result.any_requires_approval = True
            if chunk_result.data_residency_required:
                result.any_data_residency_required = True

            # Inject compliance tags into document metadata
            doc.setdefault("metadata", {})
            doc["metadata"]["compliance_tags"] = chunk_result.label_names
            doc["metadata"]["highest_sensitivity"] = chunk_result.highest_sensitivity
            doc["metadata"]["requires_private_model"] = chunk_result.requires_private_model

        result.summary = summary
        return result

    def _tag_single_chunk(self, doc: dict[str, Any]) -> ChunkComplianceResult:
        """Tag a single document chunk."""
        chunk_id = str(doc.get("id", ""))
        content = str(doc.get("content", ""))
        metadata = doc.get("metadata", {})

        chunk_result = ChunkComplianceResult(chunk_id=chunk_id)

        # Phase 1: Metadata scan
        if self._policy.scan_metadata and metadata:
            self._scan_metadata(metadata, chunk_result)

        # Phase 2: Content scan
        if self._policy.scan_content and content:
            self._scan_content(content, chunk_result)

        # Determine highest sensitivity
        chunk_result.highest_sensitivity = self._get_highest_sensitivity(chunk_result.tags)

        # Determine routing decisions
        tag_labels = {t.label for t in chunk_result.tags}
        chunk_result.requires_private_model = bool(tag_labels & _PRIVATE_MODEL_LABELS)
        chunk_result.requires_approval = bool(tag_labels & _APPROVAL_LABELS)
        chunk_result.data_residency_required = bool(tag_labels & _RESIDENCY_LABELS)

        return chunk_result

    def _scan_metadata(
        self, metadata: dict[str, Any], result: ChunkComplianceResult
    ) -> None:
        """Scan metadata fields for compliance indicators."""
        meta_lower = {k.lower(): v for k, v in metadata.items()}

        # Check PII fields
        for field_name in self._policy.pii_metadata_fields:
            if field_name.lower() in meta_lower:
                val = meta_lower[field_name.lower()]
                if self._is_truthy(val):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.PII,
                        confidence=1.0,
                        source="metadata",
                        detail=f"field:{field_name}",
                    ))
                    break

        # Check PHI fields
        for field_name in self._policy.phi_metadata_fields:
            if field_name.lower() in meta_lower:
                val = meta_lower[field_name.lower()]
                if self._is_truthy(val):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.PHI,
                        confidence=1.0,
                        source="metadata",
                        detail=f"field:{field_name}",
                    ))
                    break

        # Check IP fields
        for field_name in self._policy.ip_metadata_fields:
            if field_name.lower() in meta_lower:
                val = meta_lower[field_name.lower()]
                if self._is_truthy(val):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.IP,
                        confidence=1.0,
                        source="metadata",
                        detail=f"field:{field_name}",
                    ))
                    break

        # Check Regulated fields
        for field_name in self._policy.regulated_metadata_fields:
            if field_name.lower() in meta_lower:
                val = meta_lower[field_name.lower()]
                if self._is_truthy(val):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.REGULATED,
                        confidence=1.0,
                        source="metadata",
                        detail=f"field:{field_name}",
                    ))
                    break

        # Check Confidential fields
        for field_name in self._policy.confidential_metadata_fields:
            if field_name.lower() in meta_lower:
                val = meta_lower[field_name.lower()]
                if isinstance(val, str) and val.lower() in ("confidential", "secret", "top_secret"):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.CONFIDENTIAL,
                        confidence=1.0,
                        source="metadata",
                        detail=f"field:{field_name}={val}",
                    ))
                    break
                elif self._is_truthy(val):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.CONFIDENTIAL,
                        confidence=0.8,
                        source="metadata",
                        detail=f"field:{field_name}",
                    ))
                    break

        # Check explicit compliance_tags in metadata
        existing_tags = metadata.get("compliance_tags", [])
        if isinstance(existing_tags, list):
            for tag_str in existing_tags:
                try:
                    label = ComplianceLabel(tag_str.upper())
                    if not any(t.label == label for t in result.tags):
                        result.tags.append(ComplianceTag(
                            label=label,
                            confidence=1.0,
                            source="metadata",
                            detail="pre-tagged",
                        ))
                except ValueError:
                    pass

    def _scan_content(
        self, content: str, result: ChunkComplianceResult
    ) -> None:
        """Scan content for compliance-relevant patterns."""
        # PII patterns
        for pattern in self._compiled_patterns.get("pii", []):
            match = pattern.search(content)
            if match:
                if not any(t.label == ComplianceLabel.PII and t.source == "content_scan" for t in result.tags):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.PII,
                        confidence=0.9,
                        source="content_scan",
                        detail=f"pattern_match:{pattern.pattern[:40]}",
                    ))
                break

        # PHI patterns
        for pattern in self._compiled_patterns.get("phi", []):
            match = pattern.search(content)
            if match:
                if not any(t.label == ComplianceLabel.PHI and t.source == "content_scan" for t in result.tags):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.PHI,
                        confidence=0.8,
                        source="content_scan",
                        detail=f"pattern_match:{pattern.pattern[:40]}",
                    ))
                break

        # IP patterns
        for pattern in self._compiled_patterns.get("ip", []):
            match = pattern.search(content)
            if match:
                if not any(t.label == ComplianceLabel.IP and t.source == "content_scan" for t in result.tags):
                    result.tags.append(ComplianceTag(
                        label=ComplianceLabel.IP,
                        confidence=0.7,
                        source="content_scan",
                        detail=f"pattern_match:{pattern.pattern[:40]}",
                    ))
                break

    @staticmethod
    def _is_truthy(value: Any) -> bool:
        """Check if a metadata value is truthy."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "t", "y")
        if isinstance(value, (int, float)):
            return value > 0
        return bool(value)

    @staticmethod
    def _get_highest_sensitivity(tags: list[ComplianceTag]) -> str:
        """Get the highest sensitivity level from a list of tags."""
        if not tags:
            return "PUBLIC"
        max_order = -1
        highest = "PUBLIC"
        for tag in tags:
            order = _SENSITIVITY_ORDER.get(tag.label.value, 0)
            if order > max_order:
                max_order = order
                highest = tag.label.value
        return highest


# ── Singleton ──────────────────────────────────────────────────────────

_tagger: Optional[ComplianceTagger] = None


def get_compliance_tagger() -> ComplianceTagger:
    global _tagger
    if _tagger is None:
        _tagger = ComplianceTagger()
    return _tagger


def reset_compliance_tagger() -> None:
    global _tagger
    _tagger = None
