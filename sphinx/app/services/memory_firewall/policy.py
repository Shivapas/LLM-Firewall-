"""Memory Write Policy Configuration — Sprint 25.

Configurable per-agent memory write policies:
- ALLOW_ALL: no scanning, writes pass through
- SCAN_AND_ALLOW: scan and log but always allow
- SCAN_AND_BLOCK: scan and block suspicious content (default)
- REQUIRE_APPROVAL: scan and hold suspicious content for HITL approval

Provides an admin-facing API for policy CRUD operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.policy")


class WritePolicy(str, Enum):
    ALLOW_ALL = "allow_all"
    SCAN_AND_ALLOW = "scan_and_allow"
    SCAN_AND_BLOCK = "scan_and_block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class AgentWritePolicyConfig:
    """Full policy configuration for one agent."""
    agent_id: str
    policy: WritePolicy = WritePolicy.SCAN_AND_BLOCK
    allowed_backends: list[str] = field(default_factory=list)
    allowed_namespaces: list[str] = field(default_factory=list)
    max_content_length: int = 0  # 0 = no limit
    custom_threshold: float = 0.0  # 0 = use scanner default
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "policy": self.policy.value,
            "allowed_backends": self.allowed_backends,
            "allowed_namespaces": self.allowed_namespaces,
            "max_content_length": self.max_content_length,
            "custom_threshold": self.custom_threshold,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class MemoryWritePolicyStore:
    """In-memory store for per-agent memory write policies.

    Default policy for unknown agents: SCAN_AND_BLOCK.
    """

    DEFAULT_POLICY = WritePolicy.SCAN_AND_BLOCK

    def __init__(self, default_policy: WritePolicy = WritePolicy.SCAN_AND_BLOCK):
        self._default_policy = default_policy
        self._policies: dict[str, AgentWritePolicyConfig] = {}

    @property
    def default_policy(self) -> WritePolicy:
        return self._default_policy

    @default_policy.setter
    def default_policy(self, value: WritePolicy) -> None:
        self._default_policy = value

    def set_policy(
        self,
        agent_id: str,
        policy: WritePolicy | str,
        allowed_backends: list[str] | None = None,
        allowed_namespaces: list[str] | None = None,
        max_content_length: int = 0,
        custom_threshold: float = 0.0,
    ) -> AgentWritePolicyConfig:
        """Create or update a per-agent write policy."""
        if isinstance(policy, str):
            policy = WritePolicy(policy)

        now = datetime.now(timezone.utc).isoformat()
        existing = self._policies.get(agent_id)

        config = AgentWritePolicyConfig(
            agent_id=agent_id,
            policy=policy,
            allowed_backends=allowed_backends or [],
            allowed_namespaces=allowed_namespaces or [],
            max_content_length=max_content_length,
            custom_threshold=custom_threshold,
            created_at=existing.created_at if existing else now,
            updated_at=now,
        )
        self._policies[agent_id] = config
        logger.info("Set memory write policy: agent=%s policy=%s", agent_id, policy.value)
        return config

    def get_policy(self, agent_id: str) -> WritePolicy:
        """Get the effective write policy for an agent."""
        config = self._policies.get(agent_id)
        if config:
            return config.policy
        return self._default_policy

    def get_policy_config(self, agent_id: str) -> AgentWritePolicyConfig | None:
        """Get full policy configuration for an agent."""
        return self._policies.get(agent_id)

    def delete_policy(self, agent_id: str) -> bool:
        """Delete a per-agent policy (agent reverts to default)."""
        if agent_id in self._policies:
            del self._policies[agent_id]
            logger.info("Deleted memory write policy for agent: %s", agent_id)
            return True
        return False

    def list_policies(self) -> list[AgentWritePolicyConfig]:
        """List all configured per-agent policies."""
        return list(self._policies.values())

    def count(self) -> int:
        return len(self._policies)


# ── Singleton ────────────────────────────────────────────────────────────

_policy_store: MemoryWritePolicyStore | None = None


def get_memory_write_policy_store() -> MemoryWritePolicyStore:
    global _policy_store
    if _policy_store is None:
        _policy_store = MemoryWritePolicyStore()
    return _policy_store


def reset_memory_write_policy_store() -> None:
    global _policy_store
    _policy_store = None
