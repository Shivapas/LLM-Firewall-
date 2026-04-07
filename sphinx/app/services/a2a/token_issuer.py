"""Agent Identity Token Issuance — Sprint 27.

Issues signed JWT tokens to each registered agent service account.
Tokens carry:
- agent_id: unique identifier for the agent
- allowed_downstream: list of agent IDs this agent may message
- permission_scope: permission scopes granted (e.g., "read", "write", "execute")
- exp: token expiry (Unix timestamp)
- iat: issued-at timestamp
- jti: unique token identifier for revocation

Supports token validation, revocation, and refresh.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("sphinx.a2a.token_issuer")


@dataclass
class AgentRegistration:
    """Registered agent service account for A2A communication."""
    agent_id: str
    display_name: str = ""
    allowed_downstream: list[str] = field(default_factory=list)
    permission_scope: list[str] = field(default_factory=list)
    signing_secret: str = ""
    is_active: bool = True
    registered_at: str = ""
    token_ttl_seconds: int = 3600

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "allowed_downstream": self.allowed_downstream,
            "permission_scope": self.permission_scope,
            "is_active": self.is_active,
            "registered_at": self.registered_at,
            "token_ttl_seconds": self.token_ttl_seconds,
        }


@dataclass
class IssuedToken:
    """Represents an issued JWT token for an agent."""
    token: str
    agent_id: str
    jti: str
    issued_at: float
    expires_at: float

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "agent_id": self.agent_id,
            "jti": self.jti,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


class AgentTokenIssuer:
    """Issues and validates signed JWT tokens for registered agents.

    Uses HMAC-SHA256 for signing. Tokens are base64url-encoded JSON
    with header.payload.signature structure matching JWT conventions.
    """

    def __init__(self, master_secret: str = "sphinx-a2a-master-secret"):
        self._master_secret = master_secret
        self._registered_agents: dict[str, AgentRegistration] = {}
        self._revoked_jtis: set[str] = set()
        self._stats = {
            "tokens_issued": 0,
            "tokens_validated": 0,
            "tokens_rejected": 0,
            "tokens_revoked": 0,
        }

    def register_agent(
        self,
        agent_id: str,
        display_name: str = "",
        allowed_downstream: Optional[list[str]] = None,
        permission_scope: Optional[list[str]] = None,
        token_ttl_seconds: int = 3600,
    ) -> AgentRegistration:
        """Register an agent service account for A2A communication."""
        signing_secret = self._derive_agent_secret(agent_id)
        reg = AgentRegistration(
            agent_id=agent_id,
            display_name=display_name or agent_id,
            allowed_downstream=allowed_downstream or [],
            permission_scope=permission_scope or ["read", "write"],
            signing_secret=signing_secret,
            is_active=True,
            registered_at=datetime.now(timezone.utc).isoformat(),
            token_ttl_seconds=token_ttl_seconds,
        )
        self._registered_agents[agent_id] = reg
        logger.info("Registered agent %s for A2A communication", agent_id)
        return reg

    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent, revoking its ability to obtain tokens."""
        if agent_id in self._registered_agents:
            self._registered_agents[agent_id].is_active = False
            logger.info("Unregistered agent %s", agent_id)
            return True
        return False

    def is_registered(self, agent_id: str) -> bool:
        reg = self._registered_agents.get(agent_id)
        return reg is not None and reg.is_active

    def get_agent(self, agent_id: str) -> Optional[AgentRegistration]:
        return self._registered_agents.get(agent_id)

    def list_agents(self) -> list[dict]:
        return [r.to_dict() for r in self._registered_agents.values()]

    def issue_token(self, agent_id: str) -> IssuedToken:
        """Issue a signed JWT token for a registered agent."""
        reg = self._registered_agents.get(agent_id)
        if not reg or not reg.is_active:
            raise ValueError(f"Agent {agent_id} is not registered or inactive")

        now = time.time()
        jti = uuid.uuid4().hex[:16]

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "agent_id": agent_id,
            "allowed_downstream": reg.allowed_downstream,
            "permission_scope": reg.permission_scope,
            "iat": now,
            "exp": now + reg.token_ttl_seconds,
            "jti": jti,
        }

        token = self._encode_jwt(header, payload, reg.signing_secret)
        self._stats["tokens_issued"] += 1

        logger.info("Issued token for agent %s (jti=%s, ttl=%ds)",
                     agent_id, jti, reg.token_ttl_seconds)

        return IssuedToken(
            token=token,
            agent_id=agent_id,
            jti=jti,
            issued_at=now,
            expires_at=now + reg.token_ttl_seconds,
        )

    def validate_token(self, token: str, expected_agent_id: str = "") -> dict:
        """Validate a JWT token and return claims or rejection reason."""
        self._stats["tokens_validated"] += 1

        if not token:
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": "Empty token"}

        parts = token.split(".")
        if len(parts) != 3:
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": "Malformed token structure"}

        try:
            payload_json = urlsafe_b64decode(parts[1] + "==")
            payload = json.loads(payload_json)
        except Exception:
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": "Cannot decode token payload"}

        agent_id = payload.get("agent_id", "")

        # Check agent registration
        reg = self._registered_agents.get(agent_id)
        if not reg or not reg.is_active:
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": f"Agent {agent_id} not registered"}

        # Verify agent ID matches expectation
        if expected_agent_id and agent_id != expected_agent_id:
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": "Token agent_id mismatch"}

        # Verify signature
        expected_sig = self._compute_signature(
            parts[0] + "." + parts[1], reg.signing_secret
        )
        if not hmac.compare_digest(parts[2], expected_sig):
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": "Invalid token signature"}

        # Check revocation
        jti = payload.get("jti", "")
        if jti in self._revoked_jtis:
            self._stats["tokens_rejected"] += 1
            return {"valid": False, "reason": "Token has been revoked"}

        # Check expiry
        exp = payload.get("exp", 0)
        if exp and time.time() > exp:
            self._stats["tokens_rejected"] += 1
            return {
                "valid": False,
                "expired": True,
                "reason": "Token has expired",
                "agent_id": agent_id,
            }

        return {
            "valid": True,
            "agent_id": agent_id,
            "allowed_downstream": payload.get("allowed_downstream", []),
            "permission_scope": payload.get("permission_scope", []),
            "jti": jti,
            "expired": False,
        }

    def revoke_token(self, jti: str) -> bool:
        """Revoke a token by its JTI (JWT ID)."""
        self._revoked_jtis.add(jti)
        self._stats["tokens_revoked"] += 1
        logger.info("Revoked token jti=%s", jti)
        return True

    def get_signing_secret(self, agent_id: str) -> str:
        """Return the signing secret for a registered agent."""
        reg = self._registered_agents.get(agent_id)
        if reg:
            return reg.signing_secret
        return ""

    def get_stats(self) -> dict:
        return dict(self._stats)

    def _derive_agent_secret(self, agent_id: str) -> str:
        """Derive a per-agent signing secret from the master secret."""
        return hmac.new(
            self._master_secret.encode("utf-8"),
            agent_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _encode_jwt(self, header: dict, payload: dict, secret: str) -> str:
        """Encode a JWT token with header.payload.signature."""
        h = urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p = urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig = self._compute_signature(f"{h}.{p}", secret)
        return f"{h}.{p}.{sig}"

    def _compute_signature(self, data: str, secret: str) -> str:
        """Compute HMAC-SHA256 signature."""
        return hmac.new(
            secret.encode("utf-8"),
            data.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


# ── Singleton ────────────────────────────────────────────────────────────

_issuer: Optional[AgentTokenIssuer] = None


def get_token_issuer() -> AgentTokenIssuer:
    global _issuer
    if _issuer is None:
        _issuer = AgentTokenIssuer()
    return _issuer


def reset_token_issuer():
    global _issuer
    _issuer = None
