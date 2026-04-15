"""SP-330: CanaryTokenGenerator — HMAC-SHA256 signed session canary tokens.

Generates unique, non-guessable 12-character base62 canary tokens per session.
Tokens are HMAC-SHA256 signed using UUID v4 + session_id as input, with
TTL-managed in-memory storage (TTL = session duration).

Security invariants:
  - Token MUST NOT appear in audit logs (privacy requirement)
  - Token MUST be unique per session
  - Token MUST expire when session ends (TTL)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from threading import Lock
from typing import Optional

logger = logging.getLogger("sphinx.canary.generator")

# Base62 alphabet (alphanumeric, no ambiguous chars)
_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _bytes_to_base62(data: bytes, length: int = 12) -> str:
    """Convert raw bytes to a base62-encoded string of fixed length."""
    num = int.from_bytes(data, "big")
    result: list[str] = []
    base = len(_BASE62_ALPHABET)
    while len(result) < length:
        num, remainder = divmod(num, base)
        result.append(_BASE62_ALPHABET[remainder])
    return "".join(reversed(result))


class CanaryToken:
    """Represents a single session-scoped canary token."""

    __slots__ = ("token", "session_id", "created_at", "expires_at", "nonce")

    def __init__(
        self,
        token: str,
        session_id: str,
        created_at: float,
        expires_at: float,
        nonce: str,
    ) -> None:
        self.token = token
        self.session_id = session_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.nonce = nonce

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def __repr__(self) -> str:
        return f"CanaryToken(session={self.session_id!r}, expired={self.is_expired})"


class CanaryTokenGenerator:
    """HMAC-SHA256 signed canary token generator with TTL-managed store.

    SP-330 acceptance criteria:
      - Unique token per session
      - Token not logged in audit trail
      - TTL expiry confirmed
    """

    def __init__(
        self,
        secret_key: str = "sphinx-canary-default-key",
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self._secret_key = secret_key.encode("utf-8")
        self._default_ttl = default_ttl_seconds
        self._store: dict[str, CanaryToken] = {}  # session_id → CanaryToken
        self._token_index: dict[str, str] = {}  # token → session_id (O(1) lookup)
        self._lock = Lock()
        self._total_generated = 0
        self._total_expired = 0

    def generate(
        self,
        session_id: str,
        ttl_seconds: Optional[float] = None,
    ) -> CanaryToken:
        """Generate a new HMAC-SHA256 signed canary token for a session.

        Args:
            session_id: Unique session identifier.
            ttl_seconds: Token lifetime; defaults to ``default_ttl_seconds``.

        Returns:
            A :class:`CanaryToken` with a 12-char base62 token string.
        """
        nonce = str(uuid.uuid4())
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = time.time()

        # HMAC-SHA256: sign (nonce + session_id) with secret key
        message = f"{nonce}:{session_id}".encode("utf-8")
        signature = hmac.new(self._secret_key, message, hashlib.sha256).digest()

        # Convert first 9 bytes (72 bits) to 12-char base62
        token_str = _bytes_to_base62(signature[:9], length=12)

        canary = CanaryToken(
            token=token_str,
            session_id=session_id,
            created_at=now,
            expires_at=now + ttl,
            nonce=nonce,
        )

        with self._lock:
            # Remove previous token for this session if exists
            old = self._store.pop(session_id, None)
            if old:
                self._token_index.pop(old.token, None)

            self._store[session_id] = canary
            self._token_index[token_str] = session_id
            self._total_generated += 1

        logger.debug(
            "Canary token generated for session=%s ttl=%.0fs",
            session_id,
            ttl,
        )
        return canary

    def get_token_for_session(self, session_id: str) -> Optional[CanaryToken]:
        """Retrieve the active canary token for a session."""
        with self._lock:
            canary = self._store.get(session_id)
            if canary and canary.is_expired:
                self._remove_expired(session_id)
                return None
            return canary

    def lookup_session_by_token(self, token: str) -> Optional[str]:
        """O(1) reverse lookup: token → session_id. Returns None if expired."""
        with self._lock:
            session_id = self._token_index.get(token)
            if session_id is None:
                return None
            canary = self._store.get(session_id)
            if canary and canary.is_expired:
                self._remove_expired(session_id)
                return None
            return session_id

    def is_active_token(self, token: str) -> bool:
        """Check if a token string belongs to any active session."""
        return self.lookup_session_by_token(token) is not None

    def expire_session(self, session_id: str) -> bool:
        """Manually expire/remove a session's canary token."""
        with self._lock:
            return self._remove_expired(session_id)

    def prune_expired(self) -> int:
        """Remove all expired tokens from the store. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            expired_sessions = [
                sid for sid, ct in self._store.items() if now > ct.expires_at
            ]
            for sid in expired_sessions:
                self._remove_expired(sid)
                removed += 1
        return removed

    def _remove_expired(self, session_id: str) -> bool:
        """Remove a session's token from store and index. Must hold lock."""
        canary = self._store.pop(session_id, None)
        if canary:
            self._token_index.pop(canary.token, None)
            self._total_expired += 1
            return True
        return False

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._store)

    @property
    def total_generated(self) -> int:
        return self._total_generated

    @property
    def total_expired(self) -> int:
        return self._total_expired

    def get_all_active_tokens(self) -> set[str]:
        """Return all active (non-expired) token strings for scanning."""
        now = time.time()
        with self._lock:
            return {
                ct.token
                for ct in self._store.values()
                if now <= ct.expires_at
            }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_generator: Optional[CanaryTokenGenerator] = None


def get_canary_generator(
    secret_key: str = "sphinx-canary-default-key",
    default_ttl_seconds: float = 3600.0,
) -> CanaryTokenGenerator:
    """Get or create the singleton canary token generator."""
    global _generator
    if _generator is None:
        _generator = CanaryTokenGenerator(
            secret_key=secret_key,
            default_ttl_seconds=default_ttl_seconds,
        )
    return _generator


def reset_canary_generator() -> None:
    """Reset the singleton (for testing)."""
    global _generator
    _generator = None
