"""MCP Tool Call Audit Log — Sprint 17.

Per-call audit: agent ID, tool name, MCP server, input hash, output hash,
action taken, compliance tags, timestamp. Every MCP tool call produces a
complete audit record with all required fields.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("sphinx.mcp.tool_call_audit")


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class ToolCallAuditRecord:
    """Immutable audit record for a single MCP tool call."""
    id: str = ""
    agent_id: str = ""
    tool_name: str = ""
    mcp_server: str = ""
    input_hash: str = ""
    output_hash: str = ""
    action: str = "allowed"  # allowed, blocked, filtered, redacted
    compliance_tags: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    request_size_bytes: int = 0
    response_size_bytes: int = 0
    metadata: dict = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "mcp_server": self.mcp_server,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "action": self.action,
            "compliance_tags": self.compliance_tags,
            "latency_ms": self.latency_ms,
            "request_size_bytes": self.request_size_bytes,
            "response_size_bytes": self.response_size_bytes,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


def _hash_content(content: Any) -> str:
    """Compute SHA-256 hash of content (serialized to JSON if not string)."""
    if content is None:
        return hashlib.sha256(b"").hexdigest()
    if isinstance(content, str):
        data = content.encode("utf-8")
    elif isinstance(content, bytes):
        data = content
    else:
        data = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ── Tool Call Audit Service ──────────────────────────────────────────────


class ToolCallAuditService:
    """Records and queries MCP tool call audit logs.

    Every MCP tool invocation goes through this service to produce an
    immutable audit trail with: agent ID, tool name, MCP server, input/output
    hashes, action taken, compliance tags, and timing.
    """

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._records: list[ToolCallAuditRecord] = []

    def record_call(
        self,
        agent_id: str,
        tool_name: str,
        mcp_server: str,
        input_data: Any = None,
        output_data: Any = None,
        action: str = "allowed",
        compliance_tags: list[str] | None = None,
        latency_ms: float = 0.0,
        metadata: dict | None = None,
    ) -> ToolCallAuditRecord:
        """Record an MCP tool call in the audit log."""
        input_payload = input_data if input_data is not None else {}
        output_payload = output_data if output_data is not None else {}

        input_serialized = json.dumps(input_payload, sort_keys=True, default=str) if not isinstance(input_payload, (str, bytes)) else str(input_payload)
        output_serialized = json.dumps(output_payload, sort_keys=True, default=str) if not isinstance(output_payload, (str, bytes)) else str(output_payload)

        record = ToolCallAuditRecord(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            tool_name=tool_name,
            mcp_server=mcp_server,
            input_hash=_hash_content(input_data),
            output_hash=_hash_content(output_data),
            action=action,
            compliance_tags=compliance_tags or [],
            latency_ms=latency_ms,
            request_size_bytes=len(input_serialized.encode("utf-8")),
            response_size_bytes=len(output_serialized.encode("utf-8")),
            metadata=metadata or {},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._records.append(record)
        logger.info(
            "Audit: agent=%s tool=%s server=%s action=%s tags=%s",
            agent_id, tool_name, mcp_server, action, compliance_tags or [],
        )
        return record

    def list_records(
        self,
        agent_id: str | None = None,
        tool_name: str | None = None,
        mcp_server: str | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ToolCallAuditRecord]:
        """Query audit records with optional filters."""
        results = self._records
        if agent_id:
            results = [r for r in results if r.agent_id == agent_id]
        if tool_name:
            results = [r for r in results if r.tool_name == tool_name]
        if mcp_server:
            results = [r for r in results if r.mcp_server == mcp_server]
        if action:
            results = [r for r in results if r.action == action]
        return results[offset:offset + limit]

    def count_records(
        self,
        agent_id: str | None = None,
        tool_name: str | None = None,
        mcp_server: str | None = None,
    ) -> int:
        """Count audit records matching filters."""
        results = self._records
        if agent_id:
            results = [r for r in results if r.agent_id == agent_id]
        if tool_name:
            results = [r for r in results if r.tool_name == tool_name]
        if mcp_server:
            results = [r for r in results if r.mcp_server == mcp_server]
        return len(results)

    def get_agent_tool_call_volume(self) -> dict[str, int]:
        """Get tool call volume grouped by agent ID."""
        volume: dict[str, int] = {}
        for r in self._records:
            volume[r.agent_id] = volume.get(r.agent_id, 0) + 1
        return volume

    def get_records_since(self, since_iso: str) -> list[ToolCallAuditRecord]:
        """Get all records since a given ISO timestamp."""
        return [r for r in self._records if r.timestamp >= since_iso]


# ── Singleton ────────────────────────────────────────────────────────────

_tool_call_audit_service: ToolCallAuditService | None = None


def get_tool_call_audit_service(session_factory=None) -> ToolCallAuditService:
    """Get or create the singleton tool call audit service."""
    global _tool_call_audit_service
    if _tool_call_audit_service is None:
        _tool_call_audit_service = ToolCallAuditService(session_factory=session_factory)
    return _tool_call_audit_service


def reset_tool_call_audit_service() -> None:
    """Reset for testing."""
    global _tool_call_audit_service
    _tool_call_audit_service = None
