"""MCP Compliance Tagging — Sprint 17.

Tag MCP tool responses with compliance labels based on content scan.
Labels flow into routing and audit pipeline.

Compliance labels:
- PII: personally identifiable information detected
- PHI: protected health information detected
- FINANCIAL: financial data (card numbers, account numbers)
- CREDENTIALS: secrets, API keys, passwords
- GDPR: GDPR-relevant personal data
- HIPAA: HIPAA-relevant health data
- INTERNAL_ONLY: content marked for internal use
- PUBLIC: safe for external consumption
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("sphinx.mcp.compliance_tagger")


# ── Compliance Labels ────────────────────────────────────────────────────

COMPLIANCE_LABELS = {
    "PII",
    "PHI",
    "FINANCIAL",
    "CREDENTIALS",
    "GDPR",
    "HIPAA",
    "INTERNAL_ONLY",
    "PUBLIC",
}


# ── Pattern Definitions ─────────────────────────────────────────────────

_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                     # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),         # phone
    re.compile(r"\b\d{1,5}\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln)\b", re.IGNORECASE),  # address
]

_PHI_PATTERNS = [
    re.compile(r"\b(diagnosis|patient|medical\s+record|mrn|dob|date\s+of\s+birth|icd[-\s]?10|npi)\b", re.IGNORECASE),
    re.compile(r"\b(prescription|medication|dosage|allergy|blood\s+type|lab\s+result)\b", re.IGNORECASE),
]

_FINANCIAL_PATTERNS = [
    re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),  # credit card
    re.compile(r"\b(routing\s+number|account\s+number|iban|swift|bic)\b", re.IGNORECASE),
    re.compile(r"\b\d{9,18}\b"),  # long numeric (potential account number)
]

_CREDENTIAL_PATTERNS = [
    re.compile(r"(api[_-]?key|secret[_-]?key|access[_-]?token|bearer\s+token|password)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})\b"),  # known API key formats
]

_INTERNAL_PATTERNS = [
    re.compile(r"\b(confidential|internal\s+only|restricted|proprietary|do\s+not\s+distribute)\b", re.IGNORECASE),
]


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class ComplianceTagResult:
    """Result of compliance tagging on content."""
    tags: list[str] = field(default_factory=list)
    matches: dict[str, list[str]] = field(default_factory=dict)  # tag -> matched excerpts
    is_sensitive: bool = False

    def to_dict(self) -> dict:
        return {
            "tags": self.tags,
            "matches": self.matches,
            "is_sensitive": self.is_sensitive,
        }


@dataclass
class TaggedResponse:
    """MCP tool response with compliance tags applied."""
    original_content: Any = None
    compliance_tags: list[str] = field(default_factory=list)
    is_sensitive: bool = False
    scan_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "compliance_tags": self.compliance_tags,
            "is_sensitive": self.is_sensitive,
            "scan_details": self.scan_details,
        }


# ── Compliance Tagging Service ───────────────────────────────────────────


class ComplianceTaggingService:
    """Scans MCP tool responses and applies compliance labels.

    Content is scanned against pattern libraries for PII, PHI, financial
    data, credentials, and internal-only markers. Tags are applied and
    flow into the routing and audit pipeline.
    """

    def __init__(self):
        self._custom_patterns: dict[str, list[re.Pattern]] = {}

    def scan_content(self, content: str) -> ComplianceTagResult:
        """Scan text content and return compliance tags."""
        tags: list[str] = []
        matches: dict[str, list[str]] = {}

        # PII scan
        pii_matches = self._find_matches(content, _PII_PATTERNS)
        if pii_matches:
            tags.append("PII")
            tags.append("GDPR")
            matches["PII"] = pii_matches[:5]  # limit excerpts

        # PHI scan
        phi_matches = self._find_matches(content, _PHI_PATTERNS)
        if phi_matches:
            tags.append("PHI")
            tags.append("HIPAA")
            matches["PHI"] = phi_matches[:5]

        # Financial scan
        fin_matches = self._find_matches(content, _FINANCIAL_PATTERNS)
        if fin_matches:
            tags.append("FINANCIAL")
            matches["FINANCIAL"] = fin_matches[:5]

        # Credential scan
        cred_matches = self._find_matches(content, _CREDENTIAL_PATTERNS)
        if cred_matches:
            tags.append("CREDENTIALS")
            matches["CREDENTIALS"] = cred_matches[:5]

        # Internal-only scan
        internal_matches = self._find_matches(content, _INTERNAL_PATTERNS)
        if internal_matches:
            tags.append("INTERNAL_ONLY")
            matches["INTERNAL_ONLY"] = internal_matches[:5]

        # Custom patterns
        for label, patterns in self._custom_patterns.items():
            custom_matches = self._find_matches(content, patterns)
            if custom_matches:
                if label not in tags:
                    tags.append(label)
                matches[label] = custom_matches[:5]

        # If no sensitive tags, mark as PUBLIC
        if not tags:
            tags.append("PUBLIC")

        # Deduplicate
        tags = list(dict.fromkeys(tags))

        is_sensitive = any(t in {"PII", "PHI", "FINANCIAL", "CREDENTIALS", "HIPAA", "GDPR"} for t in tags)

        return ComplianceTagResult(
            tags=tags,
            matches=matches,
            is_sensitive=is_sensitive,
        )

    def tag_response(
        self,
        content: Any,
        agent_id: str = "",
        tool_name: str = "",
        mcp_server: str = "",
    ) -> TaggedResponse:
        """Tag an MCP tool response with compliance labels.

        Converts content to string for scanning, applies tags, and returns
        a TaggedResponse that can be used by routing and audit pipelines.
        """
        if content is None:
            return TaggedResponse(
                original_content=content,
                compliance_tags=["PUBLIC"],
                is_sensitive=False,
            )

        text = content if isinstance(content, str) else str(content)
        result = self.scan_content(text)

        logger.info(
            "Compliance tags: agent=%s tool=%s server=%s tags=%s sensitive=%s",
            agent_id, tool_name, mcp_server, result.tags, result.is_sensitive,
        )

        return TaggedResponse(
            original_content=content,
            compliance_tags=result.tags,
            is_sensitive=result.is_sensitive,
            scan_details={
                "agent_id": agent_id,
                "tool_name": tool_name,
                "mcp_server": mcp_server,
                "match_count": sum(len(v) for v in result.matches.values()),
                "tags": result.tags,
            },
        )

    def add_custom_pattern(self, label: str, pattern: str) -> None:
        """Add a custom compliance pattern for a given label."""
        compiled = re.compile(pattern, re.IGNORECASE)
        if label not in self._custom_patterns:
            self._custom_patterns[label] = []
        self._custom_patterns[label].append(compiled)
        logger.info("Added custom compliance pattern for label=%s", label)

    def list_labels(self) -> list[str]:
        """List all available compliance labels."""
        labels = list(COMPLIANCE_LABELS)
        labels.extend(k for k in self._custom_patterns if k not in labels)
        return sorted(labels)

    # ── Internal ──────────────────────────────────────────────────────

    @staticmethod
    def _find_matches(content: str, patterns: list[re.Pattern]) -> list[str]:
        """Find all matches from a list of patterns in content."""
        matches: list[str] = []
        for pattern in patterns:
            for m in pattern.finditer(content):
                matched_text = m.group(0)
                # Truncate long matches for safety
                if len(matched_text) > 50:
                    matched_text = matched_text[:50] + "..."
                matches.append(matched_text)
        return matches


# ── Singleton ────────────────────────────────────────────────────────────

_compliance_tagging_service: ComplianceTaggingService | None = None


def get_compliance_tagging_service() -> ComplianceTaggingService:
    """Get or create the singleton compliance tagging service."""
    global _compliance_tagging_service
    if _compliance_tagging_service is None:
        _compliance_tagging_service = ComplianceTaggingService()
    return _compliance_tagging_service


def reset_compliance_tagging_service() -> None:
    """Reset for testing."""
    global _compliance_tagging_service
    _compliance_tagging_service = None
