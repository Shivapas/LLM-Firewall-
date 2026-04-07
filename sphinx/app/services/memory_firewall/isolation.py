"""Cross-Agent Memory Isolation — Sprint 26.

Policy enforcement: agent A cannot read memory written by agent B unless
explicitly permitted.  Isolates agent memory namespaces.

Provides:
- Per-agent namespace assignment.
- Explicit cross-agent read permission grants.
- Read interception that blocks unauthorized cross-agent access.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.isolation")


# ── Data Structures ─────────────────────────────────────────────────────


class IsolationAction(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


@dataclass
class CrossAgentPermission:
    """Explicit permission for one agent to read another's memory."""
    permission_id: str = ""
    reader_agent_id: str = ""
    writer_agent_id: str = ""
    namespaces: list[str] = field(default_factory=list)  # empty = all namespaces
    granted_at: str = ""
    granted_by: str = ""  # admin user who granted

    def to_dict(self) -> dict:
        return {
            "permission_id": self.permission_id,
            "reader_agent_id": self.reader_agent_id,
            "writer_agent_id": self.writer_agent_id,
            "namespaces": self.namespaces,
            "granted_at": self.granted_at,
            "granted_by": self.granted_by,
        }


@dataclass
class IsolationCheckResult:
    """Result of a cross-agent memory isolation check."""
    request_id: str = ""
    reader_agent_id: str = ""
    writer_agent_id: str = ""
    content_key: str = ""
    namespace: str = ""
    action: IsolationAction = IsolationAction.ALLOWED
    reason: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "reader_agent_id": self.reader_agent_id,
            "writer_agent_id": self.writer_agent_id,
            "content_key": self.content_key,
            "namespace": self.namespace,
            "action": self.action.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


# ── Memory Isolation Enforcer ──────────────────────────────────────────


class MemoryIsolationEnforcer:
    """Enforces cross-agent memory namespace isolation.

    Default behaviour: an agent may only read memory it wrote itself.
    Admins can grant explicit cross-agent read permissions.
    """

    def __init__(self) -> None:
        # (reader_agent_id, writer_agent_id) -> CrossAgentPermission
        self._permissions: dict[tuple[str, str], CrossAgentPermission] = {}
        # agent_id -> assigned namespace
        self._agent_namespaces: dict[str, str] = {}
        self._audit: list[IsolationCheckResult] = []
        self._stats: dict[str, int] = {
            "total_checks": 0,
            "allowed": 0,
            "blocked": 0,
        }

    # ── Namespace Assignment ────────────────────────────────────────────

    def assign_namespace(self, agent_id: str, namespace: str | None = None) -> str:
        """Assign a memory namespace to an agent.

        If no namespace is provided, uses ``agent:<agent_id>`` as default
        isolated namespace.
        """
        ns = namespace or f"agent:{agent_id}"
        self._agent_namespaces[agent_id] = ns
        logger.info("Assigned namespace: agent=%s namespace=%s", agent_id, ns)
        return ns

    def get_namespace(self, agent_id: str) -> str:
        """Get the namespace assigned to an agent."""
        return self._agent_namespaces.get(agent_id, f"agent:{agent_id}")

    def list_namespaces(self) -> dict[str, str]:
        return dict(self._agent_namespaces)

    # ── Permission Management ───────────────────────────────────────────

    def grant_permission(
        self,
        reader_agent_id: str,
        writer_agent_id: str,
        namespaces: list[str] | None = None,
        granted_by: str = "system",
    ) -> CrossAgentPermission:
        """Grant reader agent permission to read writer agent's memory."""
        perm = CrossAgentPermission(
            permission_id=str(uuid.uuid4()),
            reader_agent_id=reader_agent_id,
            writer_agent_id=writer_agent_id,
            namespaces=namespaces or [],
            granted_at=datetime.now(timezone.utc).isoformat(),
            granted_by=granted_by,
        )
        self._permissions[(reader_agent_id, writer_agent_id)] = perm
        logger.info(
            "Cross-agent permission granted: reader=%s writer=%s by=%s",
            reader_agent_id,
            writer_agent_id,
            granted_by,
        )
        return perm

    def revoke_permission(
        self,
        reader_agent_id: str,
        writer_agent_id: str,
    ) -> bool:
        """Revoke a previously granted cross-agent read permission."""
        key = (reader_agent_id, writer_agent_id)
        if key in self._permissions:
            del self._permissions[key]
            logger.info(
                "Cross-agent permission revoked: reader=%s writer=%s",
                reader_agent_id,
                writer_agent_id,
            )
            return True
        return False

    def get_permission(
        self,
        reader_agent_id: str,
        writer_agent_id: str,
    ) -> CrossAgentPermission | None:
        return self._permissions.get((reader_agent_id, writer_agent_id))

    def list_permissions(
        self, agent_id: str | None = None
    ) -> list[CrossAgentPermission]:
        """List all permissions, optionally filtered by reader agent."""
        perms = list(self._permissions.values())
        if agent_id:
            perms = [p for p in perms if p.reader_agent_id == agent_id]
        return perms

    def get_permitted_writers(self, reader_agent_id: str) -> set[str]:
        """Return set of writer agent IDs that the reader is permitted to access."""
        return {
            writer_id
            for (reader_id, writer_id) in self._permissions
            if reader_id == reader_agent_id
        }

    # ── Isolation Check ─────────────────────────────────────────────────

    def check_read(
        self,
        reader_agent_id: str,
        writer_agent_id: str,
        content_key: str = "",
        namespace: str = "",
    ) -> IsolationCheckResult:
        """Check whether a read is permitted under isolation policy.

        Same-agent reads always pass.  Cross-agent reads require an
        explicit permission grant.
        """
        self._stats["total_checks"] += 1
        now = datetime.now(timezone.utc).isoformat()

        # Same agent — always allowed
        if reader_agent_id == writer_agent_id:
            result = IsolationCheckResult(
                request_id=str(uuid.uuid4()),
                reader_agent_id=reader_agent_id,
                writer_agent_id=writer_agent_id,
                content_key=content_key,
                namespace=namespace,
                action=IsolationAction.ALLOWED,
                reason="Same-agent read",
                timestamp=now,
            )
            self._stats["allowed"] += 1
            self._audit.append(result)
            return result

        # Cross-agent — check permission
        perm = self._permissions.get((reader_agent_id, writer_agent_id))
        if perm:
            # If permission specifies namespaces, check namespace match
            if perm.namespaces and (not namespace or namespace not in perm.namespaces):
                result = IsolationCheckResult(
                    request_id=str(uuid.uuid4()),
                    reader_agent_id=reader_agent_id,
                    writer_agent_id=writer_agent_id,
                    content_key=content_key,
                    namespace=namespace,
                    action=IsolationAction.BLOCKED,
                    reason=(
                        f"Cross-agent permission exists but namespace '{namespace}' "
                        f"not in permitted namespaces {perm.namespaces}"
                    ),
                    timestamp=now,
                )
                self._stats["blocked"] += 1
            else:
                result = IsolationCheckResult(
                    request_id=str(uuid.uuid4()),
                    reader_agent_id=reader_agent_id,
                    writer_agent_id=writer_agent_id,
                    content_key=content_key,
                    namespace=namespace,
                    action=IsolationAction.ALLOWED,
                    reason=f"Explicit cross-agent permission granted by {perm.granted_by}",
                    timestamp=now,
                )
                self._stats["allowed"] += 1
        else:
            result = IsolationCheckResult(
                request_id=str(uuid.uuid4()),
                reader_agent_id=reader_agent_id,
                writer_agent_id=writer_agent_id,
                content_key=content_key,
                namespace=namespace,
                action=IsolationAction.BLOCKED,
                reason="No cross-agent read permission granted",
                timestamp=now,
            )
            self._stats["blocked"] += 1
            logger.warning(
                "Cross-agent read blocked: reader=%s writer=%s key=%s",
                reader_agent_id,
                writer_agent_id,
                content_key,
            )

        self._audit.append(result)
        return result

    # ── Query ───────────────────────────────────────────────────────────

    def get_audit(
        self,
        reader_agent_id: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[IsolationCheckResult]:
        results = self._audit
        if reader_agent_id:
            results = [r for r in results if r.reader_agent_id == reader_agent_id]
        if action:
            results = [r for r in results if r.action.value == action]
        return results[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def permission_count(self) -> int:
        return len(self._permissions)


# ── Singleton ────────────────────────────────────────────────────────────

_enforcer: MemoryIsolationEnforcer | None = None


def get_memory_isolation_enforcer() -> MemoryIsolationEnforcer:
    global _enforcer
    if _enforcer is None:
        _enforcer = MemoryIsolationEnforcer()
    return _enforcer


def reset_memory_isolation_enforcer() -> None:
    global _enforcer
    _enforcer = None
