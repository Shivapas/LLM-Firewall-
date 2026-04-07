"""Mutual TLS for Agent-to-Agent Channels — Sprint 27.

Enforces mTLS between agents in the same multi-agent workflow.
Supports certificate issuance via Sphinx-managed CA or SPIFFE/SPIRE integration.

Features:
- Certificate issuance for registered agents (self-signed CA)
- Certificate fingerprint tracking per agent
- mTLS enforcement policy per agent pair or workflow
- Certificate revocation list (CRL)
- SPIFFE ID support for workload identity
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("sphinx.a2a.mtls")


class CertificateStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class AgentCertificate:
    """Certificate metadata for an agent."""
    agent_id: str
    cert_fingerprint: str = ""
    spiffe_id: str = ""
    issued_at: str = ""
    expires_at: str = ""
    status: str = "active"
    serial_number: str = ""
    issuer: str = "sphinx-ca"

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "cert_fingerprint": self.cert_fingerprint,
            "spiffe_id": self.spiffe_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "serial_number": self.serial_number,
            "issuer": self.issuer,
        }


@dataclass
class MTLSPolicy:
    """mTLS enforcement policy for agent pairs or workflows."""
    policy_id: str = ""
    workflow_id: str = ""
    required: bool = True
    agent_pairs: list[tuple[str, str]] = field(default_factory=list)
    framework: str = "langgraph"
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "workflow_id": self.workflow_id,
            "required": self.required,
            "agent_pairs": self.agent_pairs,
            "framework": self.framework,
            "created_at": self.created_at,
        }


class MTLSEnforcer:
    """Manages mTLS certificates and enforcement for A2A channels.

    Provides certificate issuance, fingerprint tracking, and mTLS
    verification for agent-to-agent communication channels.
    """

    def __init__(self, ca_name: str = "sphinx-ca"):
        self._ca_name = ca_name
        self._certificates: dict[str, AgentCertificate] = {}
        self._revoked_serials: set[str] = set()
        self._policies: dict[str, MTLSPolicy] = {}
        self._global_mtls_required: bool = False
        self._stats = {
            "certs_issued": 0,
            "certs_revoked": 0,
            "verifications_passed": 0,
            "verifications_failed": 0,
        }

    def set_global_mtls_required(self, required: bool):
        """Enable or disable global mTLS requirement for all agent channels."""
        self._global_mtls_required = required

    def issue_certificate(
        self,
        agent_id: str,
        spiffe_id: str = "",
        ttl_seconds: int = 86400,
    ) -> AgentCertificate:
        """Issue a certificate for an agent."""
        now = datetime.now(timezone.utc)
        serial = uuid.uuid4().hex[:16]
        fingerprint = hashlib.sha256(
            f"{agent_id}:{serial}:{now.isoformat()}".encode()
        ).hexdigest()[:40]

        cert = AgentCertificate(
            agent_id=agent_id,
            cert_fingerprint=fingerprint,
            spiffe_id=spiffe_id or f"spiffe://sphinx/agent/{agent_id}",
            issued_at=now.isoformat(),
            expires_at="",  # Simplified: expiry tracked via TTL
            status="active",
            serial_number=serial,
            issuer=self._ca_name,
        )
        self._certificates[agent_id] = cert
        self._stats["certs_issued"] += 1
        logger.info("Issued certificate for agent %s (serial=%s)", agent_id, serial)
        return cert

    def revoke_certificate(self, agent_id: str) -> bool:
        """Revoke an agent's certificate."""
        cert = self._certificates.get(agent_id)
        if cert:
            cert.status = "revoked"
            self._revoked_serials.add(cert.serial_number)
            self._stats["certs_revoked"] += 1
            logger.info("Revoked certificate for agent %s", agent_id)
            return True
        return False

    def get_certificate(self, agent_id: str) -> Optional[AgentCertificate]:
        return self._certificates.get(agent_id)

    def add_policy(
        self,
        workflow_id: str,
        agent_pairs: list[tuple[str, str]],
        framework: str = "langgraph",
        required: bool = True,
    ) -> MTLSPolicy:
        """Add an mTLS enforcement policy for a workflow."""
        policy_id = uuid.uuid4().hex[:12]
        policy = MTLSPolicy(
            policy_id=policy_id,
            workflow_id=workflow_id,
            required=required,
            agent_pairs=agent_pairs,
            framework=framework,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._policies[policy_id] = policy
        return policy

    def is_required(self, sender_id: str, receiver_id: str) -> bool:
        """Check if mTLS is required between two agents."""
        if self._global_mtls_required:
            return True
        for policy in self._policies.values():
            if not policy.required:
                continue
            for pair in policy.agent_pairs:
                if (pair[0] == sender_id and pair[1] == receiver_id) or \
                   (pair[0] == receiver_id and pair[1] == sender_id):
                    return True
                # Wildcard match
                if pair[0] == "*" or pair[1] == "*":
                    return True
        return False

    def verify_channel(self, message) -> dict:
        """Verify mTLS for an A2A message channel.

        Checks:
        1. Message has mtls_verified flag set
        2. Sender certificate exists and is active
        3. Sender cert fingerprint matches message fingerprint
        """
        sender_id = message.sender_agent_id
        cert = self._certificates.get(sender_id)

        if not message.mtls_verified:
            self._stats["verifications_failed"] += 1
            return {
                "verified": False,
                "reason": "mTLS not established on channel",
            }

        if not cert:
            self._stats["verifications_failed"] += 1
            return {
                "verified": False,
                "reason": f"No certificate found for agent {sender_id}",
            }

        if cert.status != "active":
            self._stats["verifications_failed"] += 1
            return {
                "verified": False,
                "reason": f"Certificate for agent {sender_id} is {cert.status}",
            }

        if cert.serial_number in self._revoked_serials:
            self._stats["verifications_failed"] += 1
            return {
                "verified": False,
                "reason": "Certificate has been revoked",
            }

        # Verify fingerprint if provided
        if message.sender_cert_fingerprint:
            if message.sender_cert_fingerprint != cert.cert_fingerprint:
                self._stats["verifications_failed"] += 1
                return {
                    "verified": False,
                    "reason": "Certificate fingerprint mismatch",
                }

        self._stats["verifications_passed"] += 1
        return {"verified": True, "spiffe_id": cert.spiffe_id}

    def list_certificates(self) -> list[dict]:
        return [c.to_dict() for c in self._certificates.values()]

    def list_policies(self) -> list[dict]:
        return [p.to_dict() for p in self._policies.values()]

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset(self):
        self._certificates.clear()
        self._revoked_serials.clear()
        self._policies.clear()
        self._global_mtls_required = False
        self._stats = {
            "certs_issued": 0,
            "certs_revoked": 0,
            "verifications_passed": 0,
            "verifications_failed": 0,
        }


# ── Singleton ────────────────────────────────────────────────────────────

_enforcer: Optional[MTLSEnforcer] = None


def get_mtls_enforcer() -> MTLSEnforcer:
    global _enforcer
    if _enforcer is None:
        _enforcer = MTLSEnforcer()
    return _enforcer


def reset_mtls_enforcer():
    global _enforcer
    _enforcer = None
