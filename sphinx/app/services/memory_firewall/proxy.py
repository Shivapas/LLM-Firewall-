"""Memory Store Proxy — Sprint 25.

Intercepts agent memory write operations to Redis, PostgreSQL (pgvector),
and vector stores used as agent memory.  Supports LangChain, AutoGen, and
CrewAI memory abstraction layers.

Write requests are routed through the instruction-pattern scanner before
being forwarded to the backing store.  The proxy creates an immutable audit
record for every write regardless of the scanner verdict.
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

from .instruction_scanner import InstructionPatternScanner, ScanVerdict
from .audit import MemoryWriteAuditLog, MemoryWriteAuditRecord
from .policy import MemoryWritePolicyStore, WritePolicy

logger = logging.getLogger("sphinx.memory_firewall.proxy")


# ── Enums & Data Structures ──────────────────────────────────────────────


class BackendType(str, Enum):
    REDIS = "redis"
    POSTGRES = "postgres"
    PGVECTOR = "pgvector"
    CHROMADB = "chromadb"
    PINECONE = "pinecone"
    MILVUS = "milvus"
    CUSTOM = "custom"


class FrameworkType(str, Enum):
    LANGCHAIN = "langchain"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    CUSTOM = "custom"


class WriteAction(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    PENDING_APPROVAL = "pending_approval"


@dataclass
class MemoryWriteRequest:
    """Represents an agent memory write operation to be intercepted."""
    agent_id: str
    session_id: str = ""
    content: str = ""
    content_key: str = ""
    backend: str = "redis"
    framework: str = "langchain"
    namespace: str = ""
    metadata: dict = field(default_factory=dict)

    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()[:32]


@dataclass
class MemoryWriteResult:
    """Result of a memory write interception."""
    request_id: str
    agent_id: str
    action: WriteAction
    scan_verdict: Optional[ScanVerdict] = None
    reason: str = ""
    audit_record_id: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "action": self.action.value,
            "scan_verdict": self.scan_verdict.to_dict() if self.scan_verdict else None,
            "reason": self.reason,
            "audit_record_id": self.audit_record_id,
            "timestamp": self.timestamp,
        }


# ── Memory Store Proxy ───────────────────────────────────────────────────


class MemoryStoreProxy:
    """Proxy that intercepts agent memory write operations.

    Supported backends: Redis, PostgreSQL/pgvector, ChromaDB, Pinecone, Milvus.
    Supported frameworks: LangChain, AutoGen, CrewAI.

    On each write:
    1. Look up the agent's write policy.
    2. If policy requires scanning, run the instruction-pattern scanner.
    3. Based on verdict + policy, allow / block / quarantine.
    4. Record immutable audit entry.
    """

    SUPPORTED_BACKENDS = {b.value for b in BackendType}
    SUPPORTED_FRAMEWORKS = {f.value for f in FrameworkType}

    def __init__(
        self,
        scanner: InstructionPatternScanner | None = None,
        audit_log: MemoryWriteAuditLog | None = None,
        policy_store: MemoryWritePolicyStore | None = None,
    ):
        self._scanner = scanner or InstructionPatternScanner()
        self._audit_log = audit_log or MemoryWriteAuditLog()
        self._policy_store = policy_store or MemoryWritePolicyStore()
        self._quarantine: list[MemoryWriteRequest] = []
        self._stats: dict[str, int] = {
            "total_writes": 0,
            "allowed": 0,
            "blocked": 0,
            "quarantined": 0,
            "pending_approval": 0,
        }

    @property
    def scanner(self) -> InstructionPatternScanner:
        return self._scanner

    @property
    def audit_log(self) -> MemoryWriteAuditLog:
        return self._audit_log

    @property
    def policy_store(self) -> MemoryWritePolicyStore:
        return self._policy_store

    def intercept_write(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        """Intercept a memory write operation.

        This is the main entry point for the memory firewall proxy.
        """
        start_time = time.monotonic()
        request_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        self._stats["total_writes"] += 1

        # 1. Look up policy for this agent
        policy = self._policy_store.get_policy(request.agent_id)

        # 2. Decide action based on policy
        scan_verdict: Optional[ScanVerdict] = None
        action: WriteAction
        reason: str

        if policy == WritePolicy.ALLOW_ALL:
            action = WriteAction.ALLOWED
            reason = "Policy: allow_all"
        elif policy in (
            WritePolicy.SCAN_AND_ALLOW,
            WritePolicy.SCAN_AND_BLOCK,
            WritePolicy.REQUIRE_APPROVAL,
        ):
            # Run instruction-pattern scanner
            scan_verdict = self._scanner.scan(request.content)

            if not scan_verdict.is_suspicious:
                action = WriteAction.ALLOWED
                reason = "Content passed instruction scan"
            elif policy == WritePolicy.SCAN_AND_ALLOW:
                action = WriteAction.ALLOWED
                reason = f"Suspicious content allowed by policy (score={scan_verdict.risk_score:.2f})"
                logger.warning(
                    "Memory write allowed despite suspicious content: agent=%s score=%.2f",
                    request.agent_id,
                    scan_verdict.risk_score,
                )
            elif policy == WritePolicy.SCAN_AND_BLOCK:
                action = WriteAction.BLOCKED
                reason = f"Blocked: instruction-like content detected (score={scan_verdict.risk_score:.2f})"
                self._quarantine.append(request)
            elif policy == WritePolicy.REQUIRE_APPROVAL:
                action = WriteAction.PENDING_APPROVAL
                reason = f"Pending approval: suspicious content (score={scan_verdict.risk_score:.2f})"
                self._quarantine.append(request)
            else:
                action = WriteAction.BLOCKED
                reason = "Unknown policy action"
        else:
            # Default: scan and block
            scan_verdict = self._scanner.scan(request.content)
            if scan_verdict.is_suspicious:
                action = WriteAction.BLOCKED
                reason = f"Blocked: instruction-like content (score={scan_verdict.risk_score:.2f})"
                self._quarantine.append(request)
            else:
                action = WriteAction.ALLOWED
                reason = "Content passed instruction scan (default policy)"

        # Update stats
        self._stats[action.value] = self._stats.get(action.value, 0) + 1

        elapsed_ms = (time.monotonic() - start_time) * 1000

        # 3. Create audit record
        audit_record = self._audit_log.record_write(
            request_id=request_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            content_hash=request.content_hash(),
            content_key=request.content_key,
            backend=request.backend,
            framework=request.framework,
            namespace=request.namespace,
            scanner_verdict="suspicious" if (scan_verdict and scan_verdict.is_suspicious) else "clean",
            scanner_score=scan_verdict.risk_score if scan_verdict else 0.0,
            matched_patterns=[p["pattern_id"] for p in scan_verdict.matched_patterns] if scan_verdict else [],
            action_taken=action.value,
            reason=reason,
            enforcement_duration_ms=elapsed_ms,
        )

        result = MemoryWriteResult(
            request_id=request_id,
            agent_id=request.agent_id,
            action=action,
            scan_verdict=scan_verdict,
            reason=reason,
            audit_record_id=audit_record.record_id,
            timestamp=now,
        )

        logger.info(
            "Memory write intercepted: agent=%s action=%s reason=%s duration=%.1fms",
            request.agent_id,
            action.value,
            reason,
            elapsed_ms,
        )

        return result

    def get_quarantine(self) -> list[MemoryWriteRequest]:
        """Return list of quarantined write requests."""
        return list(self._quarantine)

    def clear_quarantine(self) -> int:
        """Clear quarantine and return count of cleared items."""
        count = len(self._quarantine)
        self._quarantine.clear()
        return count

    def get_stats(self) -> dict[str, int]:
        """Return proxy statistics."""
        return dict(self._stats)

    def is_backend_supported(self, backend: str) -> bool:
        return backend.lower() in self.SUPPORTED_BACKENDS

    def is_framework_supported(self, framework: str) -> bool:
        return framework.lower() in self.SUPPORTED_FRAMEWORKS


# ── Singleton ────────────────────────────────────────────────────────────

_proxy: MemoryStoreProxy | None = None


def get_memory_store_proxy() -> MemoryStoreProxy:
    """Get or create the singleton memory store proxy."""
    global _proxy
    if _proxy is None:
        _proxy = MemoryStoreProxy()
    return _proxy


def reset_memory_store_proxy() -> None:
    """Reset singleton (for testing)."""
    global _proxy
    _proxy = None
