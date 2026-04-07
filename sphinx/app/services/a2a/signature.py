"""A2A Message Signature Verification — Sprint 27.

Verifies A2A message signatures on receipt:
- HMAC-SHA256 signature over message content + metadata
- Reject messages from unregistered agents or with invalid signatures
- Block replay attacks via nonce tracking with configurable TTL

The nonce store tracks used nonces within a sliding window to prevent
replay of intercepted messages.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("sphinx.a2a.signature")


@dataclass
class SignatureComponents:
    """Components used to compute a message signature."""
    sender_agent_id: str
    receiver_agent_id: str
    content: str
    nonce: str
    timestamp: float

    def canonical_string(self) -> str:
        """Produce the canonical string for signature computation."""
        return (
            f"{self.sender_agent_id}\n"
            f"{self.receiver_agent_id}\n"
            f"{self.content}\n"
            f"{self.nonce}\n"
            f"{self.timestamp}"
        )


class NonceStore:
    """Tracks used nonces to prevent replay attacks.

    Nonces are stored with their timestamp and evicted after the TTL expires.
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._nonces: dict[str, float] = {}

    def is_used(self, nonce: str) -> bool:
        """Check if a nonce has already been used (within TTL window)."""
        self._evict_expired()
        return nonce in self._nonces

    def mark_used(self, nonce: str, timestamp: Optional[float] = None):
        """Mark a nonce as used."""
        self._nonces[nonce] = timestamp if timestamp is not None else time.time()

    def _evict_expired(self):
        """Remove nonces older than the TTL."""
        cutoff = time.time() - self._ttl
        expired = [n for n, ts in self._nonces.items() if ts < cutoff]
        for n in expired:
            del self._nonces[n]

    def count(self) -> int:
        self._evict_expired()
        return len(self._nonces)

    def clear(self):
        self._nonces.clear()


class MessageSignatureVerifier:
    """Verifies HMAC-SHA256 signatures on A2A messages and tracks nonces."""

    def __init__(self, nonce_ttl_seconds: int = 300):
        self._nonce_store = NonceStore(ttl_seconds=nonce_ttl_seconds)
        self._signing_secrets: dict[str, str] = {}
        self._stats = {
            "verified": 0,
            "rejected_invalid": 0,
            "rejected_replay": 0,
            "rejected_no_secret": 0,
        }

    def register_secret(self, agent_id: str, secret: str):
        """Register a signing secret for an agent."""
        self._signing_secrets[agent_id] = secret

    def remove_secret(self, agent_id: str):
        """Remove signing secret for an agent."""
        self._signing_secrets.pop(agent_id, None)

    def compute_signature(self, message) -> str:
        """Compute the expected HMAC-SHA256 signature for a message.

        Raises ValueError if no signing secret is registered for the sender.
        """
        secret = self._signing_secrets.get(message.sender_agent_id)
        if not secret:
            raise ValueError(f"No signing secret registered for agent {message.sender_agent_id}")
        components = SignatureComponents(
            sender_agent_id=message.sender_agent_id,
            receiver_agent_id=message.receiver_agent_id,
            content=message.content,
            nonce=message.nonce,
            timestamp=message.timestamp,
        )
        return hmac.new(
            secret.encode("utf-8"),
            components.canonical_string().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, message) -> dict:
        """Verify the signature and nonce of an A2A message.

        Returns dict with:
        - valid: bool
        - nonce_valid: bool
        - reason: str (on failure)
        """
        sender = message.sender_agent_id
        secret = self._signing_secrets.get(sender)

        if not secret:
            self._stats["rejected_no_secret"] += 1
            return {
                "valid": False,
                "nonce_valid": True,
                "reason": f"No signing secret registered for agent {sender}",
            }

        if not message.signature:
            self._stats["rejected_invalid"] += 1
            return {
                "valid": False,
                "nonce_valid": True,
                "reason": "Missing message signature",
            }

        if not message.nonce:
            self._stats["rejected_invalid"] += 1
            return {
                "valid": False,
                "nonce_valid": True,
                "reason": "Missing message nonce",
            }

        # Check nonce replay
        if self._nonce_store.is_used(message.nonce):
            self._stats["rejected_replay"] += 1
            return {
                "valid": False,
                "nonce_valid": False,
                "reason": "Replay attack detected: nonce already used",
            }

        # Compute expected signature
        try:
            expected = self.compute_signature(message)
        except ValueError:
            self._stats["rejected_no_secret"] += 1
            return {
                "valid": False,
                "nonce_valid": True,
                "reason": f"Cannot compute signature for agent {sender}",
            }
        if not hmac.compare_digest(message.signature, expected):
            self._stats["rejected_invalid"] += 1
            return {
                "valid": False,
                "nonce_valid": True,
                "reason": "Signature mismatch",
            }

        # All valid — mark nonce as used
        self._nonce_store.mark_used(message.nonce, message.timestamp or time.time())
        self._stats["verified"] += 1

        return {"valid": True, "nonce_valid": True}

    def get_stats(self) -> dict:
        return dict(self._stats)

    def nonce_count(self) -> int:
        return self._nonce_store.count()

    def reset(self):
        self._nonce_store.clear()
        self._signing_secrets.clear()
        self._stats = {
            "verified": 0,
            "rejected_invalid": 0,
            "rejected_replay": 0,
            "rejected_no_secret": 0,
        }


# ── Singleton ────────────────────────────────────────────────────────────

_verifier: Optional[MessageSignatureVerifier] = None


def get_signature_verifier() -> MessageSignatureVerifier:
    global _verifier
    if _verifier is None:
        _verifier = MessageSignatureVerifier()
    return _verifier


def reset_signature_verifier():
    global _verifier
    _verifier = None
