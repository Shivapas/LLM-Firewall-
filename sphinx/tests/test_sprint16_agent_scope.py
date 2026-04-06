"""Sprint 16 — Per-Agent Scope Enforcement Test Suite.

Tests:
- Agent service account CRUD
- Tool access enforcement: allowed/blocked tool calls
- Context scope enforcement: in-scope/out-of-scope document filtering
- Field-level redaction: sensitive fields stripped from agent context
- Admin API endpoints: create, list, get, update, delete, validate-tool-call, violations
- Acceptance criteria:
  - Out-of-scope tool calls blocked and logged; agent receives access-denied response
  - Context assembly filtered to agent scope; out-of-scope documents absent from agent context
  - Field-level redaction removes configured sensitive fields from agent-visible content
"""

import json
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.services.mcp.agent_scope import (
    AgentAccount,
    AgentScopeService,
    ContextDocument,
    EnforcementResult,
    ToolCallRequest,
    reset_agent_scope_service,
)


# ────────────────────────────────────────────────────────────────────────
# Agent Service Account CRUD Tests
# ────────────────────────────────────────────────────────────────────────


class TestAgentServiceAccountCRUD:
    """Test agent service account creation, retrieval, update, delete."""

    def setup_method(self):
        self.svc = AgentScopeService()

    def test_create_account(self):
        account = self.svc.create_account(
            agent_id="agent-1",
            display_name="Test Agent",
            description="A test agent",
            allowed_mcp_servers=["server-a"],
            allowed_tools=["read_file", "search"],
            context_scope=["finance", "public"],
            redact_fields=["ssn", "email"],
        )
        assert account.agent_id == "agent-1"
        assert account.display_name == "Test Agent"
        assert account.allowed_mcp_servers == ["server-a"]
        assert account.allowed_tools == ["read_file", "search"]
        assert account.context_scope == ["finance", "public"]
        assert account.redact_fields == ["ssn", "email"]
        assert account.is_active is True

    def test_create_duplicate_agent_raises(self):
        self.svc.create_account(agent_id="agent-1")
        with pytest.raises(ValueError, match="already exists"):
            self.svc.create_account(agent_id="agent-1")

    def test_get_account(self):
        self.svc.create_account(agent_id="agent-1", display_name="Agent One")
        account = self.svc.get_account("agent-1")
        assert account is not None
        assert account.display_name == "Agent One"

    def test_get_nonexistent_account(self):
        assert self.svc.get_account("no-such-agent") is None

    def test_list_accounts(self):
        self.svc.create_account(agent_id="a1")
        self.svc.create_account(agent_id="a2")
        accounts = self.svc.list_accounts()
        assert len(accounts) == 2
        ids = {a.agent_id for a in accounts}
        assert ids == {"a1", "a2"}

    def test_update_account(self):
        self.svc.create_account(agent_id="agent-1", allowed_tools=["read_file"])
        updated = self.svc.update_account(
            "agent-1",
            allowed_tools=["read_file", "write_file"],
            is_active=False,
        )
        assert updated is not None
        assert updated.allowed_tools == ["read_file", "write_file"]
        assert updated.is_active is False

    def test_update_nonexistent_returns_none(self):
        assert self.svc.update_account("no-agent") is None

    def test_delete_account(self):
        self.svc.create_account(agent_id="agent-1")
        assert self.svc.delete_account("agent-1") is True
        assert self.svc.get_account("agent-1") is None

    def test_delete_nonexistent_returns_false(self):
        assert self.svc.delete_account("no-agent") is False

    def test_to_dict(self):
        account = self.svc.create_account(
            agent_id="agent-1",
            display_name="Test",
            context_scope=["public"],
        )
        d = account.to_dict()
        assert d["agent_id"] == "agent-1"
        assert d["display_name"] == "Test"
        assert d["context_scope"] == ["public"]
        assert "is_active" in d


# ────────────────────────────────────────────────────────────────────────
# Tool Access Enforcement Tests
# ────────────────────────────────────────────────────────────────────────


class TestToolAccessEnforcement:
    """Test tool access enforcement: allowed/blocked tool calls."""

    def setup_method(self):
        self.svc = AgentScopeService()
        self.svc.create_account(
            agent_id="agent-1",
            allowed_mcp_servers=["server-a", "server-b"],
            allowed_tools=["read_file", "search", "list_files"],
        )

    def test_allowed_tool_call(self):
        request = ToolCallRequest(
            agent_id="agent-1",
            tool_name="read_file",
            mcp_server="server-a",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is True
        assert result.action == "allowed"

    def test_blocked_tool_not_in_allowlist(self):
        """Out-of-scope tool call → blocked and logged."""
        request = ToolCallRequest(
            agent_id="agent-1",
            tool_name="delete_all",
            mcp_server="server-a",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is False
        assert result.action == "blocked"
        assert "not in agent's allowed tools" in result.reason
        assert result.violation_type == "tool_blocked"

        # Verify violation was logged
        violations = self.svc.list_violations(agent_id="agent-1", violation_type="tool_blocked")
        assert len(violations) >= 1
        assert violations[-1].tool_name == "delete_all"

    def test_blocked_mcp_server_not_in_allowlist(self):
        request = ToolCallRequest(
            agent_id="agent-1",
            tool_name="read_file",
            mcp_server="unauthorized-server",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is False
        assert result.action == "blocked"
        assert "not in agent's allowed servers" in result.reason

    def test_unknown_agent_blocked(self):
        request = ToolCallRequest(
            agent_id="unknown-agent",
            tool_name="read_file",
            mcp_server="server-a",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is False
        assert "Unknown agent" in result.reason

    def test_inactive_agent_blocked(self):
        self.svc.update_account("agent-1", is_active=False)
        request = ToolCallRequest(
            agent_id="agent-1",
            tool_name="read_file",
            mcp_server="server-a",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is False
        assert "inactive" in result.reason

    def test_no_tool_restrictions_allows_all(self):
        """Agent with empty allowed_tools list → all tools allowed."""
        self.svc.create_account(
            agent_id="agent-open",
            allowed_mcp_servers=["server-a"],
            allowed_tools=[],
        )
        request = ToolCallRequest(
            agent_id="agent-open",
            tool_name="any_tool",
            mcp_server="server-a",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is True

    def test_no_server_restrictions_allows_all(self):
        """Agent with empty allowed_mcp_servers → all servers allowed."""
        self.svc.create_account(
            agent_id="agent-open-server",
            allowed_mcp_servers=[],
            allowed_tools=["read_file"],
        )
        request = ToolCallRequest(
            agent_id="agent-open-server",
            tool_name="read_file",
            mcp_server="any-server",
        )
        result = self.svc.enforce_tool_access(request)
        assert result.allowed is True


# ────────────────────────────────────────────────────────────────────────
# Context Scope Enforcement Tests
# ────────────────────────────────────────────────────────────────────────


class TestContextScopeEnforcement:
    """Test context scope enforcement: document filtering by agent scope."""

    def setup_method(self):
        self.svc = AgentScopeService()
        self.svc.create_account(
            agent_id="agent-finance",
            context_scope=["finance", "public"],
        )

    def _make_doc(self, doc_id, tags=None, namespace=""):
        return ContextDocument(
            doc_id=doc_id,
            content=f"Content of {doc_id}",
            tags=tags or [],
            namespace=namespace,
        )

    def test_in_scope_documents_allowed(self):
        docs = [
            self._make_doc("doc1", tags=["finance"]),
            self._make_doc("doc2", tags=["public"]),
        ]
        allowed, filtered = self.svc.enforce_context_scope("agent-finance", docs)
        assert len(allowed) == 2
        assert len(filtered) == 0

    def test_out_of_scope_documents_filtered(self):
        """Out-of-scope documents absent from agent context."""
        docs = [
            self._make_doc("doc1", tags=["finance"]),
            self._make_doc("doc2", tags=["hr", "confidential"]),
            self._make_doc("doc3", tags=["engineering"]),
        ]
        allowed, filtered = self.svc.enforce_context_scope("agent-finance", docs)
        assert len(allowed) == 1
        assert allowed[0].doc_id == "doc1"
        assert len(filtered) == 2
        filtered_ids = {d.doc_id for d in filtered}
        assert filtered_ids == {"doc2", "doc3"}

        # Verify violations were logged
        violations = self.svc.list_violations(
            agent_id="agent-finance",
            violation_type="context_filtered",
        )
        assert len(violations) == 2

    def test_namespace_match_allowed(self):
        docs = [self._make_doc("doc1", namespace="finance")]
        allowed, filtered = self.svc.enforce_context_scope("agent-finance", docs)
        assert len(allowed) == 1

    def test_no_scope_allows_all(self):
        """Agent with no context scope → all documents allowed."""
        self.svc.create_account(agent_id="agent-open", context_scope=[])
        docs = [
            self._make_doc("doc1", tags=["secret"]),
            self._make_doc("doc2", tags=["classified"]),
        ]
        allowed, filtered = self.svc.enforce_context_scope("agent-open", docs)
        assert len(allowed) == 2
        assert len(filtered) == 0

    def test_unknown_agent_gets_no_documents(self):
        docs = [self._make_doc("doc1", tags=["public"])]
        allowed, filtered = self.svc.enforce_context_scope("unknown-agent", docs)
        assert len(allowed) == 0
        assert len(filtered) == 1

    def test_inactive_agent_gets_no_documents(self):
        self.svc.update_account("agent-finance", is_active=False)
        docs = [self._make_doc("doc1", tags=["finance"])]
        allowed, filtered = self.svc.enforce_context_scope("agent-finance", docs)
        assert len(allowed) == 0
        assert len(filtered) == 1

    def test_mixed_tag_doc_with_one_matching(self):
        """Document with both in-scope and out-of-scope tags → allowed."""
        docs = [self._make_doc("doc1", tags=["finance", "hr"])]
        allowed, filtered = self.svc.enforce_context_scope("agent-finance", docs)
        assert len(allowed) == 1


# ────────────────────────────────────────────────────────────────────────
# Field-Level Redaction Tests
# ────────────────────────────────────────────────────────────────────────


class TestFieldLevelRedaction:
    """Test field-level redaction: sensitive fields stripped from content."""

    def setup_method(self):
        self.svc = AgentScopeService()
        self.svc.create_account(
            agent_id="agent-redact",
            redact_fields=["ssn", "email", "credit_card"],
        )

    def _make_doc(self, doc_id, content="", fields=None, tags=None):
        return ContextDocument(
            doc_id=doc_id,
            content=content,
            tags=tags or [],
            fields=fields or {},
        )

    def test_field_dict_redaction(self):
        """Fields in document.fields dict are replaced with [REDACTED]."""
        doc = self._make_doc(
            "doc1",
            content="Some text",
            fields={"ssn": "123-45-6789", "name": "John Doe", "email": "john@example.com"},
        )
        result = self.svc.apply_field_redaction("agent-redact", [doc])
        assert len(result) == 1
        assert result[0].fields["ssn"] == "[REDACTED]"
        assert result[0].fields["email"] == "[REDACTED]"
        assert result[0].fields["name"] == "John Doe"  # not in redact list

    def test_content_redaction(self):
        """Sensitive field patterns in content are redacted."""
        doc = self._make_doc(
            "doc1",
            content="Patient ssn: 123-45-6789 and email: test@example.com",
        )
        result = self.svc.apply_field_redaction("agent-redact", [doc])
        assert "[REDACTED]" in result[0].content
        assert "123-45-6789" not in result[0].content
        assert "test@example.com" not in result[0].content

    def test_no_redaction_for_clean_doc(self):
        doc = self._make_doc("doc1", content="No sensitive data here", fields={"name": "John"})
        result = self.svc.apply_field_redaction("agent-redact", [doc])
        assert result[0].content == "No sensitive data here"
        assert result[0].fields["name"] == "John"

    def test_no_redaction_without_policy(self):
        """Agent with no redact_fields → no redaction applied."""
        self.svc.create_account(agent_id="agent-clean", redact_fields=[])
        doc = self._make_doc(
            "doc1",
            content="ssn: 123-45-6789",
            fields={"ssn": "123-45-6789"},
        )
        result = self.svc.apply_field_redaction("agent-clean", [doc])
        assert result[0].fields["ssn"] == "123-45-6789"
        assert "123-45-6789" in result[0].content

    def test_violation_logged_on_redaction(self):
        doc = self._make_doc(
            "doc1",
            fields={"ssn": "123-45-6789"},
        )
        self.svc.apply_field_redaction("agent-redact", [doc])
        violations = self.svc.list_violations(
            agent_id="agent-redact",
            violation_type="field_redacted",
        )
        assert len(violations) >= 1


# ────────────────────────────────────────────────────────────────────────
# Full Pipeline Tests
# ────────────────────────────────────────────────────────────────────────


class TestContextPipeline:
    """Test the combined context scope + field redaction pipeline."""

    def setup_method(self):
        self.svc = AgentScopeService()
        self.svc.create_account(
            agent_id="agent-combo",
            context_scope=["finance"],
            redact_fields=["ssn"],
        )

    def test_pipeline_filters_and_redacts(self):
        docs = [
            ContextDocument(
                doc_id="doc1",
                content="Employee ssn: 123-45-6789",
                tags=["finance"],
                fields={"ssn": "123-45-6789"},
            ),
            ContextDocument(
                doc_id="doc2",
                content="HR data",
                tags=["hr"],
                fields={},
            ),
        ]
        allowed, filtered = self.svc.enforce_context_pipeline("agent-combo", docs)
        # doc2 should be filtered (hr scope)
        assert len(filtered) == 1
        assert filtered[0].doc_id == "doc2"
        # doc1 should be allowed but redacted
        assert len(allowed) == 1
        assert allowed[0].fields["ssn"] == "[REDACTED]"
        assert "123-45-6789" not in allowed[0].content


# ────────────────────────────────────────────────────────────────────────
# Violation Tracking Tests
# ────────────────────────────────────────────────────────────────────────


class TestViolationTracking:
    """Test violation logging and querying."""

    def setup_method(self):
        self.svc = AgentScopeService()
        self.svc.create_account(
            agent_id="agent-1",
            allowed_tools=["read_file"],
            context_scope=["public"],
        )

    def test_violation_counts(self):
        # Generate tool violation
        self.svc.enforce_tool_access(ToolCallRequest(
            agent_id="agent-1", tool_name="delete_all",
        ))
        # Generate context violation
        self.svc.enforce_context_scope("agent-1", [
            ContextDocument(doc_id="d1", content="x", tags=["secret"]),
        ])

        counts = self.svc.get_violation_counts(agent_id="agent-1")
        assert counts.get("tool_blocked", 0) >= 1
        assert counts.get("context_filtered", 0) >= 1

    def test_violation_list_filtered_by_type(self):
        self.svc.enforce_tool_access(ToolCallRequest(
            agent_id="agent-1", tool_name="hack",
        ))
        self.svc.enforce_tool_access(ToolCallRequest(
            agent_id="agent-1", tool_name="exploit",
        ))
        self.svc.enforce_context_scope("agent-1", [
            ContextDocument(doc_id="d1", content="x", tags=["secret"]),
        ])

        tool_violations = self.svc.list_violations(
            agent_id="agent-1", violation_type="tool_blocked",
        )
        assert len(tool_violations) == 2

        ctx_violations = self.svc.list_violations(
            agent_id="agent-1", violation_type="context_filtered",
        )
        assert len(ctx_violations) == 1


# ────────────────────────────────────────────────────────────────────────
# Admin API Tests
# ────────────────────────────────────────────────────────────────────────


class TestAgentScopeAdminAPI:
    """Test agent scope admin API endpoints."""

    @pytest.fixture(autouse=True)
    def setup(self):
        reset_agent_scope_service()
        from app.main import app
        self.client = TestClient(app, raise_server_exceptions=False)
        yield
        reset_agent_scope_service()

    def test_create_agent_account(self):
        resp = self.client.post("/admin/agents", json={
            "agent_id": "api-agent-1",
            "display_name": "API Agent 1",
            "allowed_tools": ["read_file", "search"],
            "allowed_mcp_servers": ["server-a"],
            "context_scope": ["finance"],
            "redact_fields": ["ssn"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "api-agent-1"
        assert data["allowed_tools"] == ["read_file", "search"]

    def test_create_duplicate_agent_returns_409(self):
        self.client.post("/admin/agents", json={"agent_id": "dup-agent"})
        resp = self.client.post("/admin/agents", json={"agent_id": "dup-agent"})
        assert resp.status_code == 409

    def test_list_agents(self):
        self.client.post("/admin/agents", json={"agent_id": "a1"})
        self.client.post("/admin/agents", json={"agent_id": "a2"})
        resp = self.client.get("/admin/agents")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_get_agent(self):
        self.client.post("/admin/agents", json={
            "agent_id": "get-agent",
            "display_name": "Get Agent",
        })
        resp = self.client.get("/admin/agents/get-agent")
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "Get Agent"

    def test_get_nonexistent_agent_returns_404(self):
        resp = self.client.get("/admin/agents/no-agent")
        assert resp.status_code == 404

    def test_update_agent(self):
        self.client.post("/admin/agents", json={"agent_id": "upd-agent"})
        resp = self.client.put("/admin/agents/upd-agent", json={
            "allowed_tools": ["new_tool"],
            "is_active": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed_tools"] == ["new_tool"]
        assert data["is_active"] is False

    def test_delete_agent(self):
        self.client.post("/admin/agents", json={"agent_id": "del-agent"})
        resp = self.client.delete("/admin/agents/del-agent")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
        # Confirm deleted
        resp = self.client.get("/admin/agents/del-agent")
        assert resp.status_code == 404

    def test_validate_tool_call_allowed(self):
        self.client.post("/admin/agents", json={
            "agent_id": "val-agent",
            "allowed_tools": ["read_file"],
            "allowed_mcp_servers": ["server-a"],
        })
        resp = self.client.post("/admin/agents/validate-tool-call", json={
            "agent_id": "val-agent",
            "tool_name": "read_file",
            "mcp_server": "server-a",
        })
        assert resp.status_code == 200
        assert resp.json()["allowed"] is True

    def test_validate_tool_call_blocked(self):
        """Acceptance: out-of-scope tool call blocked; agent receives access-denied."""
        self.client.post("/admin/agents", json={
            "agent_id": "val-agent-2",
            "allowed_tools": ["read_file"],
        })
        resp = self.client.post("/admin/agents/validate-tool-call", json={
            "agent_id": "val-agent-2",
            "tool_name": "delete_everything",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["action"] == "blocked"
        assert "not in agent's allowed tools" in data["reason"]

    def test_violations_endpoint(self):
        # Create agent and trigger violation
        self.client.post("/admin/agents", json={
            "agent_id": "viol-agent",
            "allowed_tools": ["read_file"],
        })
        self.client.post("/admin/agents/validate-tool-call", json={
            "agent_id": "viol-agent",
            "tool_name": "forbidden_tool",
        })
        resp = self.client.get("/admin/agents/viol-agent/violations")
        assert resp.status_code == 200
        violations = resp.json()
        assert len(violations) >= 1
        assert violations[0]["violation_type"] == "tool_blocked"

    def test_violation_counts_endpoint(self):
        self.client.post("/admin/agents", json={
            "agent_id": "count-agent",
            "allowed_tools": ["read_file"],
        })
        self.client.post("/admin/agents/validate-tool-call", json={
            "agent_id": "count-agent",
            "tool_name": "bad_tool_1",
        })
        self.client.post("/admin/agents/validate-tool-call", json={
            "agent_id": "count-agent",
            "tool_name": "bad_tool_2",
        })
        resp = self.client.get("/admin/agents/count-agent/violation-counts")
        assert resp.status_code == 200
        counts = resp.json()
        assert counts.get("tool_blocked", 0) >= 2


# ────────────────────────────────────────────────────────────────────────
# End-to-End Acceptance Tests
# ────────────────────────────────────────────────────────────────────────


class TestAcceptanceCriteria:
    """Sprint 16 acceptance criteria as end-to-end tests."""

    def setup_method(self):
        self.svc = AgentScopeService()

    def test_out_of_scope_tool_blocked_and_logged(self):
        """AC: Out-of-scope tool calls blocked and logged;
        agent receives access-denied response."""
        self.svc.create_account(
            agent_id="scoped-agent",
            allowed_tools=["read_file", "search"],
            allowed_mcp_servers=["server-a"],
        )

        # Attempt out-of-scope tool
        result = self.svc.enforce_tool_access(ToolCallRequest(
            agent_id="scoped-agent",
            tool_name="exec_command",
            mcp_server="server-a",
        ))
        assert result.allowed is False
        assert result.action == "blocked"

        # Attempt out-of-scope server
        result2 = self.svc.enforce_tool_access(ToolCallRequest(
            agent_id="scoped-agent",
            tool_name="read_file",
            mcp_server="evil-server",
        ))
        assert result2.allowed is False

        # Verify both logged
        violations = self.svc.list_violations(agent_id="scoped-agent")
        assert len(violations) == 2

    def test_context_filtered_to_agent_scope(self):
        """AC: Context assembly filtered to agent scope;
        out-of-scope documents absent from agent context."""
        self.svc.create_account(
            agent_id="finance-agent",
            context_scope=["finance", "public"],
        )

        docs = [
            ContextDocument(doc_id="d1", content="Q4 Report", tags=["finance"]),
            ContextDocument(doc_id="d2", content="Public FAQ", tags=["public"]),
            ContextDocument(doc_id="d3", content="HR Records", tags=["hr"]),
            ContextDocument(doc_id="d4", content="Top Secret", tags=["classified"]),
        ]

        allowed, filtered = self.svc.enforce_context_scope("finance-agent", docs)
        allowed_ids = {d.doc_id for d in allowed}
        filtered_ids = {d.doc_id for d in filtered}

        assert allowed_ids == {"d1", "d2"}
        assert filtered_ids == {"d3", "d4"}

    def test_field_level_redaction_strips_sensitive_fields(self):
        """AC: Field-level redaction removes configured sensitive fields
        from agent-visible content in all test cases."""
        self.svc.create_account(
            agent_id="redact-agent",
            context_scope=["finance"],
            redact_fields=["ssn", "email", "credit_card"],
        )

        docs = [
            ContextDocument(
                doc_id="d1",
                content="Employee ssn: 123-45-6789, email: john@co.com, credit_card: 4111-1111-1111-1111",
                tags=["finance"],
                fields={"ssn": "123-45-6789", "email": "john@co.com", "name": "John"},
            ),
        ]

        processed, _ = self.svc.enforce_context_pipeline("redact-agent", docs)
        assert len(processed) == 1
        doc = processed[0]

        # Fields dict redacted
        assert doc.fields["ssn"] == "[REDACTED]"
        assert doc.fields["email"] == "[REDACTED]"
        assert doc.fields["name"] == "John"  # not in redact list

        # Content redacted
        assert "123-45-6789" not in doc.content
        assert "john@co.com" not in doc.content
        assert "4111-1111-1111-1111" not in doc.content
        assert "[REDACTED]" in doc.content
