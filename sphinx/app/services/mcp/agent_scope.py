"""Per-Agent Scope Enforcement — Sprint 16.

Enforces per-agent access controls:
1. Tool access enforcement: validate tool name is in agent's allowlist
2. Context scope enforcement: filter context to documents within agent scope
3. Field-level redaction: strip sensitive fields per agent's redaction policy

Each agent authenticates via a dedicated service account that carries:
- allowed_mcp_servers: MCP servers the agent may connect to
- allowed_tools: tool names the agent may invoke
- context_scope: document tags/namespaces the agent may access
- redact_fields: field names to strip from content before agent sees it
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("sphinx.mcp.agent_scope")


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class AgentAccount:
    """In-memory representation of an agent service account."""
    agent_id: str
    display_name: str = ""
    description: str = ""
    allowed_mcp_servers: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    context_scope: list[str] = field(default_factory=list)
    redact_fields: list[str] = field(default_factory=list)
    is_active: bool = True

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "description": self.description,
            "allowed_mcp_servers": self.allowed_mcp_servers,
            "allowed_tools": self.allowed_tools,
            "context_scope": self.context_scope,
            "redact_fields": self.redact_fields,
            "is_active": self.is_active,
        }


@dataclass
class ToolCallRequest:
    """Represents an MCP tool call to be validated."""
    agent_id: str
    tool_name: str
    mcp_server: str = ""
    parameters: dict = field(default_factory=dict)


@dataclass
class EnforcementResult:
    """Result of a scope enforcement check."""
    allowed: bool
    action: str = "allowed"  # allowed, blocked, filtered, redacted
    reason: str = ""
    violation_type: str = ""  # tool_blocked, context_filtered, field_redacted


@dataclass
class ContextDocument:
    """A document or chunk in the context assembly pipeline."""
    doc_id: str
    content: str
    tags: list[str] = field(default_factory=list)
    namespace: str = ""
    fields: dict = field(default_factory=dict)


@dataclass
class ScopeViolationRecord:
    """Record of a scope violation for audit."""
    id: str = ""
    agent_id: str = ""
    violation_type: str = ""
    tool_name: str = ""
    mcp_server: str = ""
    resource_id: str = ""
    detail: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "violation_type": self.violation_type,
            "tool_name": self.tool_name,
            "mcp_server": self.mcp_server,
            "resource_id": self.resource_id,
            "detail": self.detail,
            "created_at": self.created_at,
        }


# ── Agent Scope Enforcement Service ──────────────────────────────────────


class AgentScopeService:
    """Enforces per-agent scope policies.

    Manages agent service accounts and enforces:
    - Tool access: only allowed tools on allowed MCP servers
    - Context scope: only documents matching agent's scope tags
    - Field-level redaction: strips configured fields from content
    """

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._accounts: dict[str, AgentAccount] = {}
        self._violations: list[ScopeViolationRecord] = []

    # ── Account Management ────────────────────────────────────────────

    def create_account(
        self,
        agent_id: str,
        display_name: str = "",
        description: str = "",
        allowed_mcp_servers: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        context_scope: list[str] | None = None,
        redact_fields: list[str] | None = None,
    ) -> AgentAccount:
        """Create a new agent service account."""
        if agent_id in self._accounts:
            raise ValueError(f"Agent account already exists: {agent_id}")

        account = AgentAccount(
            agent_id=agent_id,
            display_name=display_name or agent_id,
            description=description,
            allowed_mcp_servers=allowed_mcp_servers or [],
            allowed_tools=allowed_tools or [],
            context_scope=context_scope or [],
            redact_fields=redact_fields or [],
        )
        self._accounts[agent_id] = account
        logger.info("Created agent service account: %s", agent_id)
        return account

    def update_account(
        self,
        agent_id: str,
        display_name: str | None = None,
        description: str | None = None,
        allowed_mcp_servers: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        context_scope: list[str] | None = None,
        redact_fields: list[str] | None = None,
        is_active: bool | None = None,
    ) -> AgentAccount | None:
        """Update an existing agent service account."""
        account = self._accounts.get(agent_id)
        if not account:
            return None

        if display_name is not None:
            account.display_name = display_name
        if description is not None:
            account.description = description
        if allowed_mcp_servers is not None:
            account.allowed_mcp_servers = allowed_mcp_servers
        if allowed_tools is not None:
            account.allowed_tools = allowed_tools
        if context_scope is not None:
            account.context_scope = context_scope
        if redact_fields is not None:
            account.redact_fields = redact_fields
        if is_active is not None:
            account.is_active = is_active

        logger.info("Updated agent service account: %s", agent_id)
        return account

    def get_account(self, agent_id: str) -> AgentAccount | None:
        """Get an agent service account by ID."""
        return self._accounts.get(agent_id)

    def delete_account(self, agent_id: str) -> bool:
        """Delete an agent service account."""
        if agent_id in self._accounts:
            del self._accounts[agent_id]
            logger.info("Deleted agent service account: %s", agent_id)
            return True
        return False

    def list_accounts(self) -> list[AgentAccount]:
        """List all agent service accounts."""
        return list(self._accounts.values())

    # ── Tool Access Enforcement ───────────────────────────────────────

    def enforce_tool_access(self, request: ToolCallRequest) -> EnforcementResult:
        """Validate that an agent is allowed to invoke a tool.

        Checks:
        1. Agent account exists and is active
        2. MCP server is in agent's allowed servers list
        3. Tool name is in agent's allowed tools list

        Returns EnforcementResult with allowed=False if blocked.
        """
        account = self._accounts.get(request.agent_id)

        # Unknown agent → block
        if not account:
            result = EnforcementResult(
                allowed=False,
                action="blocked",
                reason=f"Unknown agent: {request.agent_id}",
                violation_type="tool_blocked",
            )
            self._record_violation(
                agent_id=request.agent_id,
                violation_type="tool_blocked",
                tool_name=request.tool_name,
                mcp_server=request.mcp_server,
                detail=result.reason,
            )
            return result

        # Inactive agent → block
        if not account.is_active:
            result = EnforcementResult(
                allowed=False,
                action="blocked",
                reason=f"Agent account is inactive: {request.agent_id}",
                violation_type="tool_blocked",
            )
            self._record_violation(
                agent_id=request.agent_id,
                violation_type="tool_blocked",
                tool_name=request.tool_name,
                mcp_server=request.mcp_server,
                detail=result.reason,
            )
            return result

        # Check MCP server allowlist (if configured)
        if account.allowed_mcp_servers and request.mcp_server:
            if request.mcp_server not in account.allowed_mcp_servers:
                result = EnforcementResult(
                    allowed=False,
                    action="blocked",
                    reason=f"MCP server '{request.mcp_server}' not in agent's allowed servers",
                    violation_type="tool_blocked",
                )
                self._record_violation(
                    agent_id=request.agent_id,
                    violation_type="tool_blocked",
                    tool_name=request.tool_name,
                    mcp_server=request.mcp_server,
                    detail=result.reason,
                )
                return result

        # Check tool allowlist (if configured)
        if account.allowed_tools:
            if request.tool_name not in account.allowed_tools:
                result = EnforcementResult(
                    allowed=False,
                    action="blocked",
                    reason=f"Tool '{request.tool_name}' not in agent's allowed tools",
                    violation_type="tool_blocked",
                )
                self._record_violation(
                    agent_id=request.agent_id,
                    violation_type="tool_blocked",
                    tool_name=request.tool_name,
                    mcp_server=request.mcp_server,
                    detail=result.reason,
                )
                return result

        logger.debug(
            "Tool access allowed: agent=%s tool=%s server=%s",
            request.agent_id,
            request.tool_name,
            request.mcp_server,
        )
        return EnforcementResult(allowed=True, action="allowed")

    # ── Context Scope Enforcement ─────────────────────────────────────

    def enforce_context_scope(
        self,
        agent_id: str,
        documents: list[ContextDocument],
    ) -> tuple[list[ContextDocument], list[ContextDocument]]:
        """Filter context documents to those within the agent's scope.

        Documents must have at least one tag matching the agent's context_scope
        list, or a namespace matching a scope entry. Documents outside scope
        are removed and logged.

        Returns:
            (allowed_documents, filtered_documents)
        """
        account = self._accounts.get(agent_id)
        if not account:
            # Unknown agent gets no documents
            for doc in documents:
                self._record_violation(
                    agent_id=agent_id,
                    violation_type="context_filtered",
                    resource_id=doc.doc_id,
                    detail=f"Unknown agent; document '{doc.doc_id}' filtered",
                )
            return [], list(documents)

        if not account.is_active:
            for doc in documents:
                self._record_violation(
                    agent_id=agent_id,
                    violation_type="context_filtered",
                    resource_id=doc.doc_id,
                    detail=f"Inactive agent; document '{doc.doc_id}' filtered",
                )
            return [], list(documents)

        # If no scope configured, allow all (no restrictions)
        if not account.context_scope:
            return list(documents), []

        allowed: list[ContextDocument] = []
        filtered: list[ContextDocument] = []

        scope_set = set(account.context_scope)

        for doc in documents:
            # Check if any document tag matches any scope entry
            doc_tags = set(doc.tags)
            if doc_tags & scope_set:
                allowed.append(doc)
                continue

            # Check namespace match
            if doc.namespace and doc.namespace in scope_set:
                allowed.append(doc)
                continue

            # Out of scope → filter
            filtered.append(doc)
            self._record_violation(
                agent_id=agent_id,
                violation_type="context_filtered",
                resource_id=doc.doc_id,
                detail=f"Document '{doc.doc_id}' outside agent scope (tags={doc.tags}, namespace='{doc.namespace}')",
            )

        if filtered:
            logger.info(
                "Context scope enforcement: agent=%s allowed=%d filtered=%d",
                agent_id,
                len(allowed),
                len(filtered),
            )

        return allowed, filtered

    # ── Field-Level Redaction ─────────────────────────────────────────

    def apply_field_redaction(
        self,
        agent_id: str,
        documents: list[ContextDocument],
    ) -> list[ContextDocument]:
        """Apply field-level redaction to documents per agent's redaction policy.

        Strips fields listed in the agent's redact_fields from:
        1. Document fields dict
        2. Document content (regex-based removal of field patterns)

        Returns documents with sensitive fields redacted.
        """
        account = self._accounts.get(agent_id)
        if not account or not account.redact_fields:
            return documents

        redacted_docs: list[ContextDocument] = []
        for doc in documents:
            new_fields = dict(doc.fields)
            content = doc.content
            any_redacted = False

            for field_name in account.redact_fields:
                # Remove from fields dict
                if field_name in new_fields:
                    new_fields[field_name] = "[REDACTED]"
                    any_redacted = True

                # Regex-based content redaction: "field_name: value" or "field_name=value"
                pattern = re.compile(
                    rf'({re.escape(field_name)})\s*[:=]\s*\S+',
                    re.IGNORECASE,
                )
                new_content, count = pattern.subn(rf'\1: [REDACTED]', content)
                if count > 0:
                    content = new_content
                    any_redacted = True

            if any_redacted:
                self._record_violation(
                    agent_id=agent_id,
                    violation_type="field_redacted",
                    resource_id=doc.doc_id,
                    detail=f"Fields redacted from document '{doc.doc_id}': {account.redact_fields}",
                )

            redacted_docs.append(
                ContextDocument(
                    doc_id=doc.doc_id,
                    content=content,
                    tags=doc.tags,
                    namespace=doc.namespace,
                    fields=new_fields,
                )
            )

        return redacted_docs

    # ── Full Pipeline ─────────────────────────────────────────────────

    def enforce_context_pipeline(
        self,
        agent_id: str,
        documents: list[ContextDocument],
    ) -> tuple[list[ContextDocument], list[ContextDocument]]:
        """Run full context enforcement pipeline:
        1. Filter to agent's context scope
        2. Apply field-level redaction to allowed documents

        Returns:
            (processed_documents, filtered_documents)
        """
        allowed, filtered = self.enforce_context_scope(agent_id, documents)
        redacted = self.apply_field_redaction(agent_id, allowed)
        return redacted, filtered

    # ── Violation Log ─────────────────────────────────────────────────

    def list_violations(
        self,
        agent_id: str | None = None,
        violation_type: str | None = None,
        limit: int = 100,
    ) -> list[ScopeViolationRecord]:
        """List scope violations, optionally filtered."""
        results = self._violations
        if agent_id:
            results = [v for v in results if v.agent_id == agent_id]
        if violation_type:
            results = [v for v in results if v.violation_type == violation_type]
        return results[-limit:]

    def get_violation_counts(self, agent_id: str | None = None) -> dict[str, int]:
        """Get violation counts by type."""
        violations = self._violations
        if agent_id:
            violations = [v for v in violations if v.agent_id == agent_id]

        counts: dict[str, int] = {}
        for v in violations:
            counts[v.violation_type] = counts.get(v.violation_type, 0) + 1
        return counts

    # ── Internal ──────────────────────────────────────────────────────

    def _record_violation(
        self,
        agent_id: str,
        violation_type: str,
        tool_name: str = "",
        mcp_server: str = "",
        resource_id: str = "",
        detail: str = "",
    ) -> None:
        record = ScopeViolationRecord(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            violation_type=violation_type,
            tool_name=tool_name,
            mcp_server=mcp_server,
            resource_id=resource_id,
            detail=detail,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._violations.append(record)
        logger.warning(
            "Scope violation [%s]: agent=%s %s",
            violation_type,
            agent_id,
            detail,
        )


# ── Singleton ────────────────────────────────────────────────────────────

_agent_scope_service: AgentScopeService | None = None


def get_agent_scope_service(session_factory=None) -> AgentScopeService:
    """Get or create the singleton agent scope service."""
    global _agent_scope_service
    if _agent_scope_service is None:
        _agent_scope_service = AgentScopeService(session_factory=session_factory)
    return _agent_scope_service


def reset_agent_scope_service() -> None:
    """Reset for testing."""
    global _agent_scope_service
    _agent_scope_service = None
