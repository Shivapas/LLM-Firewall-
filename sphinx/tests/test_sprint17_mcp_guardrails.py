"""Sprint 17 — MCP Guardrails Dashboard & Compliance Tagging Tests.

Comprehensive test coverage for:
1. MCP Tool Call Audit Log
2. Compliance Tagging for MCP Output
3. Agent Risk Score
4. Bulk Scope Policy Import
5. MCP Guardrail Status Dashboard
"""

import json
import pytest

from app.services.mcp.tool_call_audit import (
    ToolCallAuditService,
    ToolCallAuditRecord,
    _hash_content,
    reset_tool_call_audit_service,
)
from app.services.mcp.compliance_tagger import (
    ComplianceTaggingService,
    ComplianceTagResult,
    TaggedResponse,
    reset_compliance_tagging_service,
)
from app.services.mcp.agent_risk_score import (
    AgentRiskScoreService,
    AgentRiskBreakdown,
    _classify_risk_level,
    WEIGHT_TOOL_RISK,
    WEIGHT_VIOLATION_HISTORY,
    WEIGHT_SCOPE_BREADTH,
    reset_agent_risk_score_service,
)
from app.services.mcp.bulk_import import (
    BulkImportService,
    ImportResult,
    reset_bulk_import_service,
)
from app.services.mcp.dashboard import (
    GuardrailDashboardService,
    DashboardSnapshot,
    AgentStatus,
    reset_guardrail_dashboard_service,
)
from app.services.mcp.agent_scope import (
    AgentScopeService,
    AgentAccount,
    ToolCallRequest,
    reset_agent_scope_service,
)


# ═══════════════════════════════════════════════════════════════════════════
# 1. MCP Tool Call Audit Log Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestHashContent:
    """Test content hashing utility."""

    def test_hash_none(self):
        h = _hash_content(None)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_hash_string(self):
        h = _hash_content("hello world")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_dict(self):
        h = _hash_content({"key": "value"})
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_deterministic(self):
        """Same input always produces same hash."""
        h1 = _hash_content({"a": 1, "b": 2})
        h2 = _hash_content({"b": 2, "a": 1})
        assert h1 == h2  # sort_keys=True ensures consistency

    def test_hash_bytes(self):
        h = _hash_content(b"binary data")
        assert len(h) == 64


class TestToolCallAuditService:
    """Test the MCP tool call audit service."""

    def setup_method(self):
        self.svc = ToolCallAuditService()

    def test_record_basic_call(self):
        """Record a basic tool call with all required fields."""
        record = self.svc.record_call(
            agent_id="agent-1",
            tool_name="read_file",
            mcp_server="file-server",
        )
        assert record.agent_id == "agent-1"
        assert record.tool_name == "read_file"
        assert record.mcp_server == "file-server"
        assert record.action == "allowed"
        assert record.input_hash
        assert record.output_hash
        assert record.timestamp
        assert record.id

    def test_record_call_with_data(self):
        """Record a call with input/output data and compliance tags."""
        record = self.svc.record_call(
            agent_id="agent-2",
            tool_name="query_db",
            mcp_server="db-server",
            input_data={"query": "SELECT * FROM users"},
            output_data={"rows": [{"name": "Alice"}]},
            action="allowed",
            compliance_tags=["PII", "GDPR"],
            latency_ms=42.5,
            metadata={"db": "postgres"},
        )
        assert record.compliance_tags == ["PII", "GDPR"]
        assert record.latency_ms == 42.5
        assert record.request_size_bytes > 0
        assert record.response_size_bytes > 0
        assert record.metadata == {"db": "postgres"}

    def test_record_blocked_call(self):
        """Record a blocked tool call."""
        record = self.svc.record_call(
            agent_id="agent-3",
            tool_name="delete_data",
            mcp_server="admin-server",
            action="blocked",
        )
        assert record.action == "blocked"

    def test_list_records_no_filter(self):
        """List all records without filters."""
        self.svc.record_call("a1", "t1", "s1")
        self.svc.record_call("a2", "t2", "s2")
        self.svc.record_call("a1", "t3", "s1")

        records = self.svc.list_records()
        assert len(records) == 3

    def test_list_records_filter_agent(self):
        """Filter records by agent ID."""
        self.svc.record_call("a1", "t1", "s1")
        self.svc.record_call("a2", "t2", "s2")
        self.svc.record_call("a1", "t3", "s1")

        records = self.svc.list_records(agent_id="a1")
        assert len(records) == 2
        assert all(r.agent_id == "a1" for r in records)

    def test_list_records_filter_tool(self):
        """Filter records by tool name."""
        self.svc.record_call("a1", "read", "s1")
        self.svc.record_call("a1", "write", "s1")

        records = self.svc.list_records(tool_name="read")
        assert len(records) == 1

    def test_list_records_filter_action(self):
        """Filter records by action."""
        self.svc.record_call("a1", "t1", "s1", action="allowed")
        self.svc.record_call("a1", "t2", "s1", action="blocked")

        records = self.svc.list_records(action="blocked")
        assert len(records) == 1
        assert records[0].action == "blocked"

    def test_list_records_pagination(self):
        """Test offset and limit for pagination."""
        for i in range(10):
            self.svc.record_call(f"a{i}", "tool", "server")

        page1 = self.svc.list_records(limit=3, offset=0)
        page2 = self.svc.list_records(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0].agent_id != page2[0].agent_id

    def test_count_records(self):
        """Count records with filters."""
        self.svc.record_call("a1", "t1", "s1")
        self.svc.record_call("a1", "t2", "s2")
        self.svc.record_call("a2", "t1", "s1")

        assert self.svc.count_records() == 3
        assert self.svc.count_records(agent_id="a1") == 2
        assert self.svc.count_records(tool_name="t1") == 2

    def test_get_agent_tool_call_volume(self):
        """Get tool call volume grouped by agent."""
        self.svc.record_call("a1", "t1", "s1")
        self.svc.record_call("a1", "t2", "s1")
        self.svc.record_call("a2", "t1", "s1")

        volume = self.svc.get_agent_tool_call_volume()
        assert volume == {"a1": 2, "a2": 1}

    def test_record_to_dict(self):
        """Verify record serialization."""
        record = self.svc.record_call("a1", "t1", "s1", compliance_tags=["PII"])
        d = record.to_dict()
        assert d["agent_id"] == "a1"
        assert d["tool_name"] == "t1"
        assert d["compliance_tags"] == ["PII"]
        assert "id" in d
        assert "timestamp" in d

    def test_get_records_since(self):
        """Get records since a timestamp."""
        self.svc.record_call("a1", "t1", "s1")
        records = self.svc.get_records_since("2000-01-01T00:00:00")
        assert len(records) == 1

        records = self.svc.get_records_since("9999-01-01T00:00:00")
        assert len(records) == 0


# ═══════════════════════════════════════════════════════════════════════════
# 2. Compliance Tagging Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestComplianceTaggingService:
    """Test the compliance tagging service."""

    def setup_method(self):
        self.svc = ComplianceTaggingService()

    def test_scan_clean_content(self):
        """Clean content gets PUBLIC tag."""
        result = self.svc.scan_content("Hello, this is a normal message.")
        assert "PUBLIC" in result.tags
        assert not result.is_sensitive

    def test_scan_pii_ssn(self):
        """Detect SSN as PII."""
        result = self.svc.scan_content("SSN: 123-45-6789")
        assert "PII" in result.tags
        assert "GDPR" in result.tags
        assert result.is_sensitive

    def test_scan_pii_email(self):
        """Detect email as PII."""
        result = self.svc.scan_content("Contact: alice@example.com")
        assert "PII" in result.tags
        assert result.is_sensitive

    def test_scan_pii_phone(self):
        """Detect phone number as PII."""
        result = self.svc.scan_content("Call me at 555-123-4567")
        assert "PII" in result.tags

    def test_scan_phi(self):
        """Detect PHI content."""
        result = self.svc.scan_content("Patient diagnosis: Type 2 diabetes, prescribed metformin")
        assert "PHI" in result.tags
        assert "HIPAA" in result.tags
        assert result.is_sensitive

    def test_scan_phi_medical_record(self):
        """Detect medical record references as PHI."""
        result = self.svc.scan_content("Medical record MRN-12345 shows lab result positive")
        assert "PHI" in result.tags

    def test_scan_financial_credit_card(self):
        """Detect credit card numbers."""
        result = self.svc.scan_content("Card: 4111-1111-1111-1111")
        assert "FINANCIAL" in result.tags
        assert result.is_sensitive

    def test_scan_financial_routing(self):
        """Detect routing/account numbers."""
        result = self.svc.scan_content("Please use routing number 021000021")
        assert "FINANCIAL" in result.tags

    def test_scan_credentials_api_key(self):
        """Detect API keys."""
        result = self.svc.scan_content("api_key: sk-abc123def456ghi789jkl012mno345pqr678")
        assert "CREDENTIALS" in result.tags
        assert result.is_sensitive

    def test_scan_credentials_bearer(self):
        """Detect bearer tokens."""
        result = self.svc.scan_content("Authorization: bearer token: eyJhbGciOiJIUzI1NiJ9")
        assert "CREDENTIALS" in result.tags

    def test_scan_internal_only(self):
        """Detect internal-only markers."""
        result = self.svc.scan_content("CONFIDENTIAL: This document is for internal use only")
        assert "INTERNAL_ONLY" in result.tags

    def test_scan_multiple_tags(self):
        """Content can have multiple compliance tags."""
        content = "Patient: John Doe, SSN: 123-45-6789, diagnosis: hypertension"
        result = self.svc.scan_content(content)
        assert "PII" in result.tags
        assert "PHI" in result.tags
        assert result.is_sensitive

    def test_tag_response(self):
        """Tag an MCP tool response."""
        tagged = self.svc.tag_response(
            content="Patient SSN: 123-45-6789",
            agent_id="agent-1",
            tool_name="get_record",
            mcp_server="ehr-server",
        )
        assert "PII" in tagged.compliance_tags
        assert tagged.is_sensitive
        assert tagged.scan_details["agent_id"] == "agent-1"

    def test_tag_none_response(self):
        """None content gets PUBLIC tag."""
        tagged = self.svc.tag_response(content=None)
        assert tagged.compliance_tags == ["PUBLIC"]
        assert not tagged.is_sensitive

    def test_tag_dict_response(self):
        """Dict content is converted to string for scanning."""
        tagged = self.svc.tag_response(content={"ssn": "123-45-6789"})
        assert "PII" in tagged.compliance_tags

    def test_add_custom_pattern(self):
        """Custom compliance patterns are applied."""
        self.svc.add_custom_pattern("TOXIC", r"\b(harmful|dangerous)\b")
        result = self.svc.scan_content("This content is harmful")
        assert "TOXIC" in result.tags

    def test_list_labels(self):
        """List all available labels."""
        labels = self.svc.list_labels()
        assert "PII" in labels
        assert "PHI" in labels
        assert "FINANCIAL" in labels
        assert "PUBLIC" in labels

    def test_list_labels_with_custom(self):
        """Custom labels appear in label list."""
        self.svc.add_custom_pattern("CUSTOM_LABEL", r"custom")
        labels = self.svc.list_labels()
        assert "CUSTOM_LABEL" in labels

    def test_tagged_response_to_dict(self):
        """Verify TaggedResponse serialization."""
        tagged = self.svc.tag_response("Normal content")
        d = tagged.to_dict()
        assert "compliance_tags" in d
        assert "is_sensitive" in d

    def test_compliance_tag_result_to_dict(self):
        """Verify ComplianceTagResult serialization."""
        result = self.svc.scan_content("SSN: 123-45-6789")
        d = result.to_dict()
        assert "tags" in d
        assert "matches" in d
        assert "is_sensitive" in d

    def test_deduplicate_tags(self):
        """Tags should not have duplicates."""
        result = self.svc.scan_content("SSN: 123-45-6789 email: a@b.com phone: 555-123-4567")
        # PII should appear only once even with multiple matches
        assert result.tags.count("PII") == 1


# ═══════════════════════════════════════════════════════════════════════════
# 3. Agent Risk Score Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestClassifyRiskLevel:
    """Test the risk level classifier."""

    def test_critical(self):
        assert _classify_risk_level(0.7) == "critical"
        assert _classify_risk_level(1.0) == "critical"

    def test_high(self):
        assert _classify_risk_level(0.4) == "high"
        assert _classify_risk_level(0.69) == "high"

    def test_medium(self):
        assert _classify_risk_level(0.2) == "medium"
        assert _classify_risk_level(0.39) == "medium"

    def test_low(self):
        assert _classify_risk_level(0.0) == "low"
        assert _classify_risk_level(0.19) == "low"


class TestAgentRiskScoreService:
    """Test the agent risk score computation."""

    def setup_method(self):
        self.svc = AgentRiskScoreService()

    def test_compute_zero_risk(self):
        """Agent with no tools, violations, or scope scores 0."""
        breakdown = self.svc.compute_risk_score(
            agent_id="safe-agent",
            tool_risk_scores=[],
            violation_count_24h=0,
            total_violations=0,
            allowed_servers_count=0,
            allowed_tools_count=0,
            context_scopes_count=0,
        )
        assert breakdown.risk_score == 0.0
        assert breakdown.risk_level == "low"
        assert "normal_operation" in breakdown.contributing_factors

    def test_compute_critical_tool_risk(self):
        """Agent with a critical-risk tool scores high on tool component."""
        breakdown = self.svc.compute_risk_score(
            agent_id="risky-agent",
            tool_risk_scores=[0.9, 0.3, 0.1],
            violation_count_24h=0,
            total_violations=0,
            allowed_servers_count=1,
            allowed_tools_count=3,
            context_scopes_count=1,
        )
        assert breakdown.max_tool_risk == 0.9
        assert breakdown.tool_risk_component > 0.5
        assert "critical_tool_connected" in breakdown.contributing_factors

    def test_compute_violation_heavy(self):
        """Agent with many violations scores high on violation component."""
        breakdown = self.svc.compute_risk_score(
            agent_id="violator",
            tool_risk_scores=[0.1],
            violation_count_24h=10,
            total_violations=50,
            allowed_servers_count=1,
            allowed_tools_count=1,
            context_scopes_count=1,
        )
        assert breakdown.violation_component == 1.0
        assert "frequent_violations" in breakdown.contributing_factors

    def test_compute_broad_scope(self):
        """Agent with broad scope scores high on scope component."""
        breakdown = self.svc.compute_risk_score(
            agent_id="broad-agent",
            tool_risk_scores=[0.1],
            violation_count_24h=0,
            total_violations=0,
            allowed_servers_count=10,
            allowed_tools_count=50,
            context_scopes_count=20,
        )
        assert breakdown.scope_breadth_component == 1.0
        assert "broad_server_access" in breakdown.contributing_factors
        assert "broad_tool_access" in breakdown.contributing_factors

    def test_composite_weights_sum_to_one(self):
        """Risk weights should sum to 1.0."""
        assert abs(WEIGHT_TOOL_RISK + WEIGHT_VIOLATION_HISTORY + WEIGHT_SCOPE_BREADTH - 1.0) < 0.001

    def test_risk_score_clamped(self):
        """Risk score is clamped to [0.0, 1.0]."""
        breakdown = self.svc.compute_risk_score(
            agent_id="extreme",
            tool_risk_scores=[1.0, 1.0, 1.0],
            violation_count_24h=100,
            total_violations=500,
            allowed_servers_count=100,
            allowed_tools_count=100,
            context_scopes_count=100,
        )
        assert 0.0 <= breakdown.risk_score <= 1.0

    def test_cached_score(self):
        """Scores are cached after computation."""
        self.svc.compute_risk_score(
            "agent-1", tool_risk_scores=[0.5], violation_count_24h=0,
            total_violations=0, allowed_servers_count=1,
            allowed_tools_count=2, context_scopes_count=1,
        )
        cached = self.svc.get_cached_score("agent-1")
        assert cached is not None
        assert cached.agent_id == "agent-1"

    def test_get_all_scores(self):
        """Get all cached scores."""
        self.svc.compute_risk_score(
            "a1", tool_risk_scores=[], violation_count_24h=0,
            total_violations=0, allowed_servers_count=0,
            allowed_tools_count=0, context_scopes_count=0,
        )
        self.svc.compute_risk_score(
            "a2", tool_risk_scores=[], violation_count_24h=0,
            total_violations=0, allowed_servers_count=0,
            allowed_tools_count=0, context_scopes_count=0,
        )
        scores = self.svc.get_all_scores()
        assert len(scores) == 2

    def test_recompute_all(self):
        """Recompute scores for multiple agents."""
        results = self.svc.recompute_all(["a1", "a2", "a3"])
        assert len(results) == 3

    def test_breakdown_to_dict(self):
        """Verify serialization of risk breakdown."""
        breakdown = self.svc.compute_risk_score(
            "agent-1", tool_risk_scores=[0.5], violation_count_24h=2,
            total_violations=5, allowed_servers_count=2,
            allowed_tools_count=10, context_scopes_count=3,
        )
        d = breakdown.to_dict()
        assert "risk_score" in d
        assert "risk_level" in d
        assert "contributing_factors" in d
        assert "computed_at" in d

    def test_risk_with_service_dependencies(self):
        """Risk score resolves inputs from connected services."""
        scope_svc = AgentScopeService()
        scope_svc.create_account(
            "test-agent",
            allowed_mcp_servers=["server-1", "server-2"],
            allowed_tools=["tool-a", "tool-b", "tool-c"],
            context_scope=["scope-1"],
        )

        risk_svc = AgentRiskScoreService(scope_service=scope_svc)
        breakdown = risk_svc.compute_risk_score(
            "test-agent",
            tool_risk_scores=[0.3, 0.6],
            violation_count_24h=1,
            total_violations=3,
        )
        assert breakdown.allowed_servers_count == 2
        assert breakdown.allowed_tools_count == 3
        assert breakdown.context_scopes_count == 1


# ═══════════════════════════════════════════════════════════════════════════
# 4. Bulk Import Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestBulkImportValidation:
    """Test policy validation for bulk import."""

    def setup_method(self):
        self.svc = BulkImportService()

    def test_valid_policy(self):
        """Valid policy passes validation."""
        errors = self.svc.validate_policy({
            "agent_id": "agent-1",
            "display_name": "Agent One",
            "allowed_mcp_servers": ["server-1"],
            "allowed_tools": ["tool-a"],
        })
        assert errors == []

    def test_missing_agent_id(self):
        """Missing agent_id is caught."""
        errors = self.svc.validate_policy({"display_name": "No ID"})
        assert any("agent_id" in e for e in errors)

    def test_empty_agent_id(self):
        """Empty agent_id is caught."""
        errors = self.svc.validate_policy({"agent_id": ""})
        assert any("agent_id" in e for e in errors)

    def test_invalid_list_field(self):
        """Non-list value for list field is caught."""
        errors = self.svc.validate_policy({
            "agent_id": "a1",
            "allowed_tools": "not-a-list",
        })
        assert any("allowed_tools" in e for e in errors)

    def test_invalid_list_items(self):
        """Non-string items in list field are caught."""
        errors = self.svc.validate_policy({
            "agent_id": "a1",
            "allowed_tools": [123, 456],
        })
        assert any("allowed_tools" in e for e in errors)

    def test_invalid_string_field(self):
        """Non-string value for string field is caught."""
        errors = self.svc.validate_policy({
            "agent_id": "a1",
            "display_name": 123,
        })
        assert any("display_name" in e for e in errors)

    def test_invalid_boolean_field(self):
        """Non-boolean is_active is caught."""
        errors = self.svc.validate_policy({
            "agent_id": "a1",
            "is_active": "yes",
        })
        assert any("is_active" in e for e in errors)

    def test_unknown_fields_warning(self):
        """Unknown fields generate a warning."""
        errors = self.svc.validate_policy({
            "agent_id": "a1",
            "unknown_field": "value",
        })
        assert any("Unknown fields" in e for e in errors)

    def test_non_dict_policy(self):
        """Non-dict policy is rejected."""
        errors = self.svc.validate_policy("not-a-dict")
        assert errors


class TestBulkImportService:
    """Test the bulk import service."""

    def setup_method(self):
        self.scope_svc = AgentScopeService()
        self.svc = BulkImportService(scope_service=self.scope_svc)

    def test_import_single_agent(self):
        """Import a single agent policy."""
        result = self.svc.import_policies([{
            "agent_id": "agent-1",
            "display_name": "Agent One",
            "allowed_tools": ["tool-a"],
        }])
        assert result.created == 1
        assert result.total == 1
        assert self.scope_svc.get_account("agent-1") is not None

    def test_import_multiple_agents(self):
        """Import multiple agent policies at once."""
        policies = [
            {"agent_id": f"agent-{i}", "display_name": f"Agent {i}"}
            for i in range(5)
        ]
        result = self.svc.import_policies(policies)
        assert result.created == 5
        assert result.total == 5
        assert len(self.scope_svc.list_accounts()) == 5

    def test_import_update_existing(self):
        """Existing agents are updated."""
        self.scope_svc.create_account("agent-1", display_name="Old Name")
        result = self.svc.import_policies([{
            "agent_id": "agent-1",
            "display_name": "New Name",
        }])
        assert result.updated == 1
        assert self.scope_svc.get_account("agent-1").display_name == "New Name"

    def test_import_skip_existing(self):
        """Skip existing agents when update_existing=False."""
        self.scope_svc.create_account("agent-1", display_name="Original")
        result = self.svc.import_policies(
            [{"agent_id": "agent-1", "display_name": "Updated"}],
            update_existing=False,
        )
        assert result.skipped == 1
        assert self.scope_svc.get_account("agent-1").display_name == "Original"

    def test_import_with_validation_errors(self):
        """Policies with validation errors are skipped."""
        result = self.svc.import_policies([
            {"agent_id": "good-agent"},
            {"display_name": "Missing ID"},  # no agent_id
            {"agent_id": "another-good"},
        ])
        assert result.created == 2
        assert result.skipped == 1
        assert len(result.errors) == 1

    def test_dry_run(self):
        """Dry run validates but doesn't create accounts."""
        result = self.svc.import_policies(
            [{"agent_id": "agent-1"}],
            dry_run=True,
        )
        assert result.created == 1
        assert result.dry_run is True
        assert self.scope_svc.get_account("agent-1") is None

    def test_parse_json_array(self):
        """Parse JSON array input."""
        raw = json.dumps([{"agent_id": "a1"}, {"agent_id": "a2"}])
        policies = self.svc.parse_json(raw)
        assert len(policies) == 2

    def test_parse_json_object_with_policies_key(self):
        """Parse JSON object with policies key."""
        raw = json.dumps({"policies": [{"agent_id": "a1"}]})
        policies = self.svc.parse_json(raw)
        assert len(policies) == 1

    def test_parse_json_single_object(self):
        """Parse JSON single object."""
        raw = json.dumps({"agent_id": "a1"})
        policies = self.svc.parse_json(raw)
        assert len(policies) == 1

    def test_no_scope_service_raises(self):
        """Importing without scope service raises RuntimeError."""
        svc = BulkImportService()
        with pytest.raises(RuntimeError, match="Scope service not configured"):
            svc.import_policies([{"agent_id": "a1"}])

    def test_import_result_to_dict(self):
        """Verify result serialization."""
        result = self.svc.import_policies([{"agent_id": "a1"}])
        d = result.to_dict()
        assert d["created"] == 1
        assert d["total"] == 1
        assert d["dry_run"] is False


# ═══════════════════════════════════════════════════════════════════════════
# 5. Dashboard Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestGuardrailDashboardService:
    """Test the MCP guardrails dashboard."""

    def setup_method(self):
        self.scope_svc = AgentScopeService()
        self.audit_svc = ToolCallAuditService()
        self.risk_svc = AgentRiskScoreService(scope_service=self.scope_svc)
        self.dashboard = GuardrailDashboardService(
            scope_service=self.scope_svc,
            audit_service=self.audit_svc,
            risk_score_service=self.risk_svc,
        )

    def test_empty_dashboard(self):
        """Dashboard with no agents or data."""
        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_agents == 0
        assert snapshot.active_agents == 0
        assert snapshot.total_tool_calls == 0
        assert snapshot.generated_at

    def test_dashboard_with_agents(self):
        """Dashboard shows agent statuses."""
        self.scope_svc.create_account("a1", display_name="Agent 1")
        self.scope_svc.create_account("a2", display_name="Agent 2")

        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_agents == 2
        assert snapshot.active_agents == 2
        assert len(snapshot.agent_statuses) == 2

    def test_dashboard_tool_call_volume(self):
        """Dashboard shows tool call volume per agent."""
        self.scope_svc.create_account("a1")
        self.audit_svc.record_call("a1", "tool1", "server1")
        self.audit_svc.record_call("a1", "tool2", "server1")
        self.audit_svc.record_call("a2", "tool1", "server1")

        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_tool_calls == 3
        assert snapshot.tool_call_volume.get("a1") == 2
        assert snapshot.tool_call_volume.get("a2") == 1

    def test_dashboard_violations(self):
        """Dashboard shows violation counts."""
        self.scope_svc.create_account("a1", allowed_tools=["allowed_tool"])
        # Create a violation
        self.scope_svc.enforce_tool_access(ToolCallRequest(
            agent_id="a1", tool_name="forbidden_tool", mcp_server="s1",
        ))

        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_violations_24h >= 1

    def test_dashboard_risk_scores(self):
        """Dashboard includes risk scores when computed."""
        self.scope_svc.create_account("a1", allowed_tools=["tool1"])
        self.risk_svc.compute_risk_score(
            "a1", tool_risk_scores=[0.5], violation_count_24h=0,
            total_violations=0, allowed_servers_count=1,
            allowed_tools_count=1, context_scopes_count=1,
        )

        snapshot = self.dashboard.get_snapshot()
        assert "a1" in snapshot.agent_risk_scores
        # Agent status should reflect the risk score
        a1_status = next(a for a in snapshot.agent_statuses if a.agent_id == "a1")
        assert a1_status.risk_score > 0

    def test_dashboard_inactive_agents(self):
        """Dashboard distinguishes active from inactive agents."""
        self.scope_svc.create_account("active")
        self.scope_svc.create_account("inactive")
        self.scope_svc.update_account("inactive", is_active=False)

        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_agents == 2
        assert snapshot.active_agents == 1

    def test_dashboard_snapshot_to_dict(self):
        """Verify snapshot serialization."""
        self.scope_svc.create_account("a1")
        snapshot = self.dashboard.get_snapshot()
        d = snapshot.to_dict()
        assert "summary" in d
        assert "agent_statuses" in d
        assert "tool_call_volume" in d
        assert "generated_at" in d

    def test_agent_detail(self):
        """Get detailed view for a specific agent."""
        self.scope_svc.create_account("a1", display_name="Agent 1")
        self.audit_svc.record_call("a1", "tool1", "server1")

        detail = self.dashboard.get_agent_detail("a1")
        assert detail is not None
        assert detail["agent"]["agent_id"] == "a1"
        assert "violations" in detail
        assert "recent_tool_calls" in detail

    def test_agent_detail_not_found(self):
        """Agent detail returns None for unknown agent."""
        detail = self.dashboard.get_agent_detail("nonexistent")
        assert detail is None

    def test_agent_status_to_dict(self):
        """Verify AgentStatus serialization."""
        status = AgentStatus(
            agent_id="a1",
            display_name="Agent 1",
            is_active=True,
            connected_servers=["s1"],
            allowed_tools_count=5,
            violation_count_24h=2,
            tool_call_count=10,
            risk_score=0.35,
            risk_level="medium",
        )
        d = status.to_dict()
        assert d["agent_id"] == "a1"
        assert d["risk_score"] == 0.35


# ═══════════════════════════════════════════════════════════════════════════
# 6. Integration / End-to-End Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSprint17Integration:
    """Integration tests combining multiple Sprint 17 services."""

    def setup_method(self):
        self.scope_svc = AgentScopeService()
        self.audit_svc = ToolCallAuditService()
        self.compliance_svc = ComplianceTaggingService()
        self.risk_svc = AgentRiskScoreService(
            scope_service=self.scope_svc,
            audit_service=self.audit_svc,
        )
        self.bulk_svc = BulkImportService(scope_service=self.scope_svc)
        self.dashboard = GuardrailDashboardService(
            scope_service=self.scope_svc,
            audit_service=self.audit_svc,
            risk_score_service=self.risk_svc,
        )

    def test_full_flow_tool_call_with_compliance(self):
        """Full flow: agent makes tool call, response is compliance-tagged, audit recorded."""
        # 1. Create agent
        self.scope_svc.create_account(
            "agent-1", allowed_tools=["get_patient"], allowed_mcp_servers=["ehr"],
        )

        # 2. Enforce tool access
        result = self.scope_svc.enforce_tool_access(
            ToolCallRequest(agent_id="agent-1", tool_name="get_patient", mcp_server="ehr"),
        )
        assert result.allowed

        # 3. Simulate tool response with compliance scan
        response_content = "Patient: John Doe, SSN: 123-45-6789, diagnosis: diabetes"
        tagged = self.compliance_svc.tag_response(
            content=response_content,
            agent_id="agent-1",
            tool_name="get_patient",
            mcp_server="ehr",
        )
        assert "PII" in tagged.compliance_tags
        assert "PHI" in tagged.compliance_tags
        assert tagged.is_sensitive

        # 4. Record audit with compliance tags
        audit = self.audit_svc.record_call(
            agent_id="agent-1",
            tool_name="get_patient",
            mcp_server="ehr",
            input_data={"patient_id": "P123"},
            output_data=response_content,
            compliance_tags=tagged.compliance_tags,
            latency_ms=15.2,
        )
        assert audit.compliance_tags == tagged.compliance_tags

        # 5. Check dashboard reflects the data
        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_agents == 1
        assert snapshot.total_tool_calls == 1

    def test_bulk_import_then_dashboard(self):
        """Bulk import agents, then verify dashboard shows them."""
        policies = [
            {"agent_id": f"fleet-{i}", "display_name": f"Fleet Agent {i}",
             "allowed_tools": ["read", "write"]}
            for i in range(10)
        ]
        result = self.bulk_svc.import_policies(policies)
        assert result.created == 10

        snapshot = self.dashboard.get_snapshot()
        assert snapshot.total_agents == 10
        assert snapshot.active_agents == 10

    def test_risk_score_updates_with_violations(self):
        """Risk score increases when violations are recorded."""
        self.scope_svc.create_account(
            "agent-v", allowed_tools=["safe_tool"],
        )

        # Initial score (no violations)
        score1 = self.risk_svc.compute_risk_score(
            "agent-v", tool_risk_scores=[0.1],
        )

        # Generate violations
        for _ in range(5):
            self.scope_svc.enforce_tool_access(
                ToolCallRequest(agent_id="agent-v", tool_name="forbidden", mcp_server="s1"),
            )

        # Recompute — violations should raise the score
        score2 = self.risk_svc.compute_risk_score(
            "agent-v", tool_risk_scores=[0.1],
        )
        assert score2.risk_score > score1.risk_score
        assert score2.violation_count_24h > 0

    def test_compliance_tags_flow_to_audit(self):
        """Compliance tags from scanner are recorded in audit trail."""
        # Scan content
        tagged = self.compliance_svc.tag_response("api_key: sk-supersecretkey12345678901234567890")
        assert "CREDENTIALS" in tagged.compliance_tags

        # Record audit with tags
        record = self.audit_svc.record_call(
            agent_id="a1", tool_name="get_config", mcp_server="config-server",
            compliance_tags=tagged.compliance_tags,
        )

        # Verify audit has tags
        records = self.audit_svc.list_records(agent_id="a1")
        assert len(records) == 1
        assert "CREDENTIALS" in records[0].compliance_tags


# ═══════════════════════════════════════════════════════════════════════════
# 7. Singleton Reset Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSingletonResets:
    """Verify singleton reset functions work for test isolation."""

    def test_reset_tool_call_audit(self):
        from app.services.mcp.tool_call_audit import get_tool_call_audit_service, reset_tool_call_audit_service
        svc1 = get_tool_call_audit_service()
        reset_tool_call_audit_service()
        svc2 = get_tool_call_audit_service()
        assert svc1 is not svc2

    def test_reset_compliance_tagger(self):
        from app.services.mcp.compliance_tagger import get_compliance_tagging_service, reset_compliance_tagging_service
        svc1 = get_compliance_tagging_service()
        reset_compliance_tagging_service()
        svc2 = get_compliance_tagging_service()
        assert svc1 is not svc2

    def test_reset_agent_risk_score(self):
        from app.services.mcp.agent_risk_score import get_agent_risk_score_service, reset_agent_risk_score_service
        svc1 = get_agent_risk_score_service()
        reset_agent_risk_score_service()
        svc2 = get_agent_risk_score_service()
        assert svc1 is not svc2

    def test_reset_bulk_import(self):
        from app.services.mcp.bulk_import import get_bulk_import_service, reset_bulk_import_service
        svc1 = get_bulk_import_service()
        reset_bulk_import_service()
        svc2 = get_bulk_import_service()
        assert svc1 is not svc2

    def test_reset_dashboard(self):
        from app.services.mcp.dashboard import get_guardrail_dashboard_service, reset_guardrail_dashboard_service
        svc1 = get_guardrail_dashboard_service()
        reset_guardrail_dashboard_service()
        svc2 = get_guardrail_dashboard_service()
        assert svc1 is not svc2
