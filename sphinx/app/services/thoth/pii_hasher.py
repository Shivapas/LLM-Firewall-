"""Prompt content hashing for PII fields — Sprint 7 / S7-T3.

Provides configurable PII field hashing before prompt content is transmitted
to the Thoth classification API.  This satisfies DPDPA data minimisation
requirements by ensuring that raw PII values (Aadhaar, PAN, bank account
numbers, etc.) never leave the Sphinx enforcement boundary in plaintext.

Design
------
``PIIHasher`` operates on the raw prompt text string *before* it is packed
into a ``ClassificationRequest``.  It:

1. Detects India-specific PII patterns using the structural regex detectors
   from ``dpdpa_rules.detect_india_pii()``.
2. Replaces each detected PII value with a deterministic, one-way SHA-256
   hash (salted with a configurable secret).
3. Returns the scrubbed text along with a manifest of hashed fields for
   audit trail purposes.

The hashing is **deterministic** — the same PII value always produces the
same hash (given the same salt).  This allows Thoth to detect repeated PII
patterns without seeing the raw values, preserving classification fidelity
for intent and risk analysis.

Configuration
-------------
- ``pii_hashing_enabled``:   Master switch (default: False).
- ``pii_hashing_salt``:      HMAC salt for deterministic hashing.
- ``pii_hashing_pii_types``: Comma-separated PII types to hash
                             (default: ``"AADHAAR,PAN,BANK_ACCOUNT"``).

Requirement references
----------------------
PRD §9:     Prompt content hashing option to satisfy DPDPA.
OQ-02:      Does Thoth support prompt content hashing / pseudonymisation?
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from app.services.thoth.dpdpa_rules import (
    AADHAAR_RE,
    PAN_RE,
    BANK_ACCOUNT_RE,
    IFSC_RE,
    PII_TYPE_AADHAAR,
    PII_TYPE_PAN,
    PII_TYPE_BANK_ACCOUNT,
    PII_TYPE_IFSC,
    DPDPA_PII_TYPES,
)

logger = logging.getLogger("sphinx.thoth.pii_hasher")

# Default PII types to hash before Thoth transmission
DEFAULT_HASH_PII_TYPES: frozenset[str] = frozenset({
    PII_TYPE_AADHAAR,
    PII_TYPE_PAN,
    PII_TYPE_BANK_ACCOUNT,
})


@dataclass
class PIIHashResult:
    """Result of PII hashing on prompt content.

    Attributes:
        original_text:   The original prompt text (NOT stored — for reference only).
        hashed_text:     The prompt text with PII fields replaced by hashes.
        fields_hashed:   Number of PII fields that were hashed.
        hash_manifest:   List of dicts describing each hashed field for audit:
                         ``{"type": "AADHAAR", "position": [start, end],
                            "hash": "sha256:abc123..."}``.
        pii_types_found: Set of PII type strings detected in the text.
    """

    original_text: str = ""
    hashed_text: str = ""
    fields_hashed: int = 0
    hash_manifest: list[dict] = field(default_factory=list)
    pii_types_found: set[str] = field(default_factory=set)

    def to_audit_dict(self) -> dict:
        """Serialise for inclusion in audit records (excludes raw text)."""
        return {
            "pii_hashing_applied": self.fields_hashed > 0,
            "fields_hashed": self.fields_hashed,
            "pii_types_found": sorted(self.pii_types_found),
            "hash_manifest": self.hash_manifest,
        }


class PIIHasher:
    """Hashes PII fields in prompt text before Thoth API transmission.

    Thread-safe: all methods are pure functions over the instance config.
    A single ``PIIHasher`` instance can be shared across concurrent requests.

    Args:
        salt:       HMAC salt for deterministic hashing. MUST be kept secret.
                    If empty, a non-secret default is used (suitable for dev only).
        pii_types:  Set of PII type strings to hash. PII types not in this set
                    are left unhashed in the text. Defaults to Aadhaar, PAN,
                    and bank account numbers.
    """

    def __init__(
        self,
        salt: str = "",
        pii_types: Optional[frozenset[str]] = None,
    ) -> None:
        self._salt = (salt or "sphinx-dev-salt-not-for-production").encode("utf-8")
        self._pii_types = pii_types or DEFAULT_HASH_PII_TYPES

    def _hash_value(self, value: str, pii_type: str) -> str:
        """Compute a deterministic, salted hash of a PII value.

        Format: ``[PII_TYPE:sha256_hex_prefix]`` — the hash is truncated to
        16 hex chars (64 bits) for readability while retaining collision
        resistance sufficient for classification purposes.
        """
        digest = hmac.new(
            self._salt,
            f"{pii_type}:{value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]
        return f"[{pii_type}:{digest}]"

    def hash_pii_in_text(self, text: str) -> PIIHashResult:
        """Detect and hash PII fields in the given text.

        Returns a ``PIIHashResult`` with the scrubbed text and audit manifest.
        Replacements are applied in reverse offset order to preserve character
        positions for sequential replacements.
        """
        if not text:
            return PIIHashResult(original_text=text, hashed_text=text)

        # Collect all PII matches with their positions
        matches: list[tuple[int, int, str, str]] = []  # (start, end, type, value)

        if PII_TYPE_AADHAAR in self._pii_types:
            for m in AADHAAR_RE.finditer(text):
                digits = re.sub(r'\D', '', m.group())
                if len(digits) == 12:
                    matches.append((m.start(), m.end(), PII_TYPE_AADHAAR, m.group()))

        if PII_TYPE_PAN in self._pii_types:
            for m in PAN_RE.finditer(text):
                matches.append((m.start(), m.end(), PII_TYPE_PAN, m.group()))

        if PII_TYPE_BANK_ACCOUNT in self._pii_types:
            for m in BANK_ACCOUNT_RE.finditer(text):
                matches.append((m.start(1), m.end(1), PII_TYPE_BANK_ACCOUNT, m.group(1)))

        if PII_TYPE_IFSC in self._pii_types:
            for m in IFSC_RE.finditer(text):
                matches.append((m.start(), m.end(), PII_TYPE_IFSC, m.group()))

        if not matches:
            return PIIHashResult(original_text=text, hashed_text=text)

        # Sort by start position descending for safe in-place replacement
        matches.sort(key=lambda x: x[0], reverse=True)

        hashed_text = text
        manifest: list[dict] = []
        pii_types_found: set[str] = set()

        for start, end, pii_type, value in matches:
            hash_replacement = self._hash_value(value, pii_type)
            hashed_text = hashed_text[:start] + hash_replacement + hashed_text[end:]
            manifest.append({
                "type": pii_type,
                "position": [start, end],
                "hash": hash_replacement,
            })
            pii_types_found.add(pii_type)

        # Reverse manifest to match original text order
        manifest.reverse()

        result = PIIHashResult(
            original_text=text,
            hashed_text=hashed_text,
            fields_hashed=len(matches),
            hash_manifest=manifest,
            pii_types_found=pii_types_found,
        )

        logger.info(
            "PIIHasher: hashed %d field(s) — types=%s",
            result.fields_hashed,
            sorted(pii_types_found),
        )
        return result


# ---------------------------------------------------------------------------
# Singleton lifecycle
# ---------------------------------------------------------------------------

_hasher: Optional[PIIHasher] = None


def get_pii_hasher() -> Optional[PIIHasher]:
    """Return the singleton PIIHasher, or None if not initialised."""
    return _hasher


def initialize_pii_hasher(
    salt: str = "",
    pii_types_csv: str = "AADHAAR,PAN,BANK_ACCOUNT",
) -> PIIHasher:
    """Create and register the singleton PIIHasher.

    Args:
        salt:           HMAC salt for deterministic hashing.
        pii_types_csv:  Comma-separated PII types to hash.
    """
    global _hasher
    pii_types = frozenset(
        t.strip().upper() for t in pii_types_csv.split(",") if t.strip()
    )
    _hasher = PIIHasher(salt=salt, pii_types=pii_types)
    logger.info(
        "PIIHasher initialised: pii_types=%s",
        sorted(pii_types),
    )
    return _hasher


def reset_pii_hasher() -> None:
    """Reset the singleton (used in tests)."""
    global _hasher
    _hasher = None
