"""Reversible Redaction Vault — stores original PII values for post-response de-tokenization.

Generates unique reversible tokens per entity and stores the original value in a
tenant-scoped in-memory vault (with optional Redis backing). Tokens can be resolved
back to original values within the same request session.
"""

import logging
import secrets
import time
from dataclasses import dataclass, field
from threading import Lock

from app.services.data_shield.pii_recognizer import PIIEntity, PIIType

logger = logging.getLogger("sphinx.data_shield.vault")


@dataclass
class VaultEntry:
    """A stored original value with metadata."""
    token: str
    entity_type: str
    original_value: str
    tenant_id: str
    session_id: str
    created_at: float = field(default_factory=time.time)
    ttl_seconds: int = 300  # 5-minute default TTL


class RedactionVault:
    """Tenant-scoped vault for reversible redaction tokens.

    Stores original values keyed by unique tokens. Supports TTL-based expiry.
    Thread-safe for concurrent access.
    """

    def __init__(self, default_ttl: int = 300):
        self._store: dict[str, VaultEntry] = {}
        self._lock = Lock()
        self._default_ttl = default_ttl

    def tokenize(
        self,
        entity: PIIEntity,
        tenant_id: str,
        session_id: str,
    ) -> str:
        """Store an entity's original value and return a reversible token.

        The token format is: <<VAULT:TYPE:random_hex>> which is distinct from
        standard redaction placeholders and can be detected for de-tokenization.
        """
        type_value = entity.entity_type.value if isinstance(entity.entity_type, PIIType) else str(entity.entity_type)
        token_id = secrets.token_hex(8)
        token = f"<<VAULT:{type_value}:{token_id}>>"

        entry = VaultEntry(
            token=token,
            entity_type=type_value,
            original_value=entity.value,
            tenant_id=tenant_id,
            session_id=session_id,
            ttl_seconds=self._default_ttl,
        )

        with self._lock:
            self._store[token] = entry

        logger.debug("Stored vault entry: token=%s type=%s tenant=%s", token, type_value, tenant_id)
        return token

    def detokenize(self, text: str, tenant_id: str, session_id: str) -> str:
        """Replace all vault tokens in text with their original values.

        Only resolves tokens belonging to the specified tenant and session.
        """
        with self._lock:
            self._evict_expired()
            for token, entry in self._store.items():
                if entry.tenant_id == tenant_id and entry.session_id == session_id:
                    if token in text:
                        text = text.replace(token, entry.original_value)
        return text

    def resolve_token(self, token: str, tenant_id: str) -> str | None:
        """Resolve a single vault token to its original value.

        Returns None if token not found, expired, or belongs to different tenant.
        """
        with self._lock:
            self._evict_expired()
            entry = self._store.get(token)
            if entry and entry.tenant_id == tenant_id:
                return entry.original_value
        return None

    def redact_with_tokens(
        self,
        text: str,
        entities: list[PIIEntity],
        tenant_id: str,
        session_id: str,
    ) -> str:
        """Redact entities using reversible vault tokens instead of static placeholders."""
        if not entities:
            return text

        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        redacted = text
        seen_ranges: list[tuple[int, int]] = []

        for entity in sorted_entities:
            if any(s <= entity.start < e or s < entity.end <= e for s, e in seen_ranges):
                continue
            token = self.tokenize(entity, tenant_id, session_id)
            redacted = redacted[:entity.start] + token + redacted[entity.end:]
            seen_ranges.append((entity.start, entity.end))

        return redacted

    def clear_session(self, tenant_id: str, session_id: str) -> int:
        """Remove all vault entries for a specific session. Returns count removed."""
        with self._lock:
            to_remove = [
                token for token, entry in self._store.items()
                if entry.tenant_id == tenant_id and entry.session_id == session_id
            ]
            for token in to_remove:
                del self._store[token]
        return len(to_remove)

    def _evict_expired(self) -> None:
        """Remove expired entries (must be called while holding lock)."""
        now = time.time()
        expired = [
            token for token, entry in self._store.items()
            if now - entry.created_at > entry.ttl_seconds
        ]
        for token in expired:
            del self._store[token]
        if expired:
            logger.debug("Evicted %d expired vault entries", len(expired))

    @property
    def size(self) -> int:
        """Current number of entries in the vault."""
        with self._lock:
            return len(self._store)
