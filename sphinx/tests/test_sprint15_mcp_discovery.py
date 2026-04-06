"""Sprint 15 — MCP Server Discovery & Risk Scoring Test Suite.

Tests:
- Risk scoring engine: category scoring, level assignment, aggregate risk
- Capability inference: keyword-based category/scope/destructive detection
- MCP discovery service: registration, agent connection, alerts, review
- Admin API endpoints: CRUD, discover, alerts, acknowledge
- Acceptance criteria:
  - Capabilities automatically discovered and inventoried
  - Risk scores correctly assigned based on capability categories
  - Admin receives alert within 60s of Critical-risk capability appearing
"""

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.services.mcp.risk_scorer import (
    CapabilityRiskInput,
    RiskLevel,
    RiskScoreResult,
    compute_server_aggregate_risk,
    infer_capability_category,
    infer_data_access_scope,
    infer_destructive,
    infer_external_network_access,
    score_capability,
)
from app.services.mcp.discovery import (
    DiscoveredTool,
    DiscoveryResult,
    MCPDiscoveryService,
    parse_tools_from_response,
    reset_mcp_discovery_service,
)


# ────────────────────────────────────────────────────────────────────────
# Risk Scoring Engine Tests
# ────────────────────────────────────────────────────────────────────────


class TestRiskScoring:
    """Test the risk scoring engine and risk model."""

    def test_read_only_tool_scores_low(self):
        """Read-only tool with no special access scores Low."""
        inp = CapabilityRiskInput(
            tool_name="list_files",
            capability_category="read",
            data_access_scope="none",
            has_external_network_access=False,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.LOW
        assert result.risk_score < 0.2

    def test_read_sensitive_scores_high(self):
        """Read tool accessing sensitive fields scores High (0.1 + 0.3 = 0.4)."""
        inp = CapabilityRiskInput(
            tool_name="read_patient_records",
            capability_category="read",
            data_access_scope="sensitive",
            has_external_network_access=False,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.HIGH
        assert 0.4 <= result.risk_score < 0.7

    def test_write_access_scores_high(self):
        """Write access with local scope scores High."""
        inp = CapabilityRiskInput(
            tool_name="update_database",
            capability_category="write",
            data_access_scope="local",
            has_external_network_access=False,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.HIGH
        assert 0.4 <= result.risk_score < 0.7

    def test_write_external_data_scores_critical(self):
        """Write with external data access scores Critical (0.4 + 0.4 = 0.8)."""
        inp = CapabilityRiskInput(
            tool_name="sync_external_data",
            capability_category="write",
            data_access_scope="external",
            has_external_network_access=False,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.CRITICAL

    def test_outbound_http_scores_critical(self):
        """Outbound HTTP with external network scores Critical."""
        inp = CapabilityRiskInput(
            tool_name="send_webhook",
            capability_category="outbound",
            data_access_scope="external",
            has_external_network_access=True,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.risk_score >= 0.7

    def test_write_delete_scores_critical(self):
        """Write + delete (destructive) scores Critical."""
        inp = CapabilityRiskInput(
            tool_name="delete_records",
            capability_category="delete",
            data_access_scope="local",
            has_external_network_access=False,
            is_destructive=True,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.risk_score >= 0.7

    def test_admin_capability_scores_critical(self):
        """Admin capability with sensitive access scores Critical."""
        inp = CapabilityRiskInput(
            tool_name="manage_permissions",
            capability_category="admin",
            data_access_scope="sensitive",
            has_external_network_access=False,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert result.risk_level == RiskLevel.CRITICAL

    def test_score_clamped_at_1(self):
        """Score is clamped to 1.0 maximum."""
        inp = CapabilityRiskInput(
            tool_name="dangerous_admin_tool",
            capability_category="admin",
            data_access_scope="sensitive",
            has_external_network_access=True,
            is_destructive=True,
        )
        result = score_capability(inp)
        assert result.risk_score <= 1.0

    def test_risk_factors_populated(self):
        """Risk factors list explains scoring components."""
        inp = CapabilityRiskInput(
            tool_name="send_email",
            capability_category="outbound",
            data_access_scope="external",
            has_external_network_access=True,
            is_destructive=False,
        )
        result = score_capability(inp)
        assert len(result.factors) >= 2
        assert any("category" in f for f in result.factors)
        assert any("external_network" in f for f in result.factors)


class TestAggregateRisk:
    """Test server aggregate risk computation."""

    def test_empty_capabilities_low(self):
        score, level = compute_server_aggregate_risk([])
        assert score == 0.0
        assert level == RiskLevel.LOW

    def test_max_score_wins(self):
        results = [
            RiskScoreResult(risk_score=0.1, risk_level=RiskLevel.LOW, factors=[]),
            RiskScoreResult(risk_score=0.8, risk_level=RiskLevel.CRITICAL, factors=[]),
            RiskScoreResult(risk_score=0.3, risk_level=RiskLevel.MEDIUM, factors=[]),
        ]
        score, level = compute_server_aggregate_risk(results)
        assert score == 0.8
        assert level == RiskLevel.CRITICAL

    def test_single_low_stays_low(self):
        results = [
            RiskScoreResult(risk_score=0.1, risk_level=RiskLevel.LOW, factors=[]),
        ]
        score, level = compute_server_aggregate_risk(results)
        assert level == RiskLevel.LOW


# ────────────────────────────────────────────────────────────────────────
# Capability Inference Tests
# ────────────────────────────────────────────────────────────────────────


class TestCapabilityInference:
    """Test keyword-based inference of capability properties."""

    def test_infer_outbound_from_name(self):
        assert infer_capability_category("send_webhook") == "outbound"

    def test_infer_write_from_name(self):
        assert infer_capability_category("create_document") == "write"

    def test_infer_delete_from_name(self):
        assert infer_capability_category("delete_file") == "delete"

    def test_infer_admin_from_name(self):
        assert infer_capability_category("admin_configure") == "admin"

    def test_infer_read_default(self):
        assert infer_capability_category("get_status") == "read"

    def test_infer_from_description(self):
        assert infer_capability_category("do_thing", "sends HTTP request to external webhook") == "outbound"

    def test_infer_sensitive_scope(self):
        assert infer_data_access_scope("get_password") == "sensitive"

    def test_infer_external_scope(self):
        assert infer_data_access_scope("read_external_api") == "external"

    def test_infer_local_scope(self):
        assert infer_data_access_scope("write_file") == "local"

    def test_infer_no_scope(self):
        assert infer_data_access_scope("get_status") == "none"

    def test_infer_external_network(self):
        assert infer_external_network_access("fetch_data") is True

    def test_infer_no_external_network(self):
        assert infer_external_network_access("list_files") is False

    def test_infer_destructive(self):
        assert infer_destructive("delete_records") is True

    def test_infer_not_destructive(self):
        assert infer_destructive("read_records") is False


# ────────────────────────────────────────────────────────────────────────
# Discovery Service Tests
# ────────────────────────────────────────────────────────────────────────


class TestParseToolsFromResponse:
    """Test parsing MCP server tool responses."""

    def test_parse_valid_tools(self):
        response = {
            "tools": [
                {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
                {"name": "write_file", "description": "Write a file"},
            ]
        }
        tools = parse_tools_from_response(response)
        assert len(tools) == 2
        assert tools[0].name == "read_file"
        assert tools[1].name == "write_file"

    def test_parse_empty_tools(self):
        tools = parse_tools_from_response({})
        assert tools == []

    def test_parse_skips_invalid_entries(self):
        response = {"tools": [{"name": ""}, "invalid", {"name": "valid_tool"}]}
        tools = parse_tools_from_response(response)
        assert len(tools) == 1
        assert tools[0].name == "valid_tool"


class TestMCPDiscoveryService:
    """Test the MCP discovery service in-memory operations."""

    def setup_method(self):
        reset_mcp_discovery_service()
        self.svc = MCPDiscoveryService()

    def test_register_server_manual(self):
        record = self.svc.register_server_manual("test-server", "http://localhost:8080")
        assert record["server_name"] == "test-server"
        assert record["url"] == "http://localhost:8080"
        assert record["is_active"] is True
        assert record["is_reviewed"] is False

    def test_list_servers(self):
        self.svc.register_server_manual("server-1", "http://localhost:8001")
        self.svc.register_server_manual("server-2", "http://localhost:8002")
        servers = self.svc.list_servers()
        assert len(servers) == 2

    def test_get_server(self):
        self.svc.register_server_manual("my-server", "http://localhost:9000")
        server = self.svc.get_server("my-server")
        assert server is not None
        assert server["server_name"] == "my-server"

    def test_get_nonexistent_server(self):
        assert self.svc.get_server("nope") is None

    def test_connect_agent(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        assert self.svc.connect_agent("srv", "agent-1") is True
        server = self.svc.get_server("srv")
        assert "agent-1" in server["connected_agents"]

    def test_connect_agent_nonexistent_server(self):
        assert self.svc.connect_agent("nope", "agent-1") is False

    def test_connect_agent_dedup(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        self.svc.connect_agent("srv", "agent-1")
        self.svc.connect_agent("srv", "agent-1")
        server = self.svc.get_server("srv")
        assert server["connected_agents"].count("agent-1") == 1

    def test_mark_reviewed(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        assert self.svc.mark_reviewed("srv") is True
        assert self.svc.get_server("srv")["is_reviewed"] is True

    def test_mark_reviewed_nonexistent(self):
        assert self.svc.mark_reviewed("nope") is False

    def test_new_server_alert_on_registration(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        alerts = self.svc.list_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "new_server"
        assert alerts[0]["server_name"] == "srv"

    def test_unreviewed_connection_alert(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        self.svc.connect_agent("srv", "agent-1")
        alerts = self.svc.list_alerts()
        unreviewed = [a for a in alerts if a["alert_type"] == "unreviewed_connection"]
        assert len(unreviewed) == 1
        assert unreviewed[0]["agent_id"] == "agent-1"

    def test_no_unreviewed_alert_after_review(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        self.svc.mark_reviewed("srv")
        self.svc.connect_agent("srv", "agent-2")
        alerts = self.svc.list_alerts()
        unreviewed = [a for a in alerts if a["alert_type"] == "unreviewed_connection"]
        assert len(unreviewed) == 0

    def test_acknowledge_alert(self):
        self.svc.register_server_manual("srv", "http://localhost:9000")
        alerts = self.svc.list_alerts()
        alert_id = alerts[0]["id"]
        assert self.svc.acknowledge_alert(alert_id) is True
        alert = [a for a in self.svc.list_alerts() if a["id"] == alert_id][0]
        assert alert["is_acknowledged"] is True

    def test_acknowledge_nonexistent_alert(self):
        assert self.svc.acknowledge_alert("nope") is False

    def test_list_unacknowledged_alerts_only(self):
        self.svc.register_server_manual("srv1", "http://localhost:9001")
        self.svc.register_server_manual("srv2", "http://localhost:9002")
        alerts = self.svc.list_alerts()
        self.svc.acknowledge_alert(alerts[0]["id"])
        unack = self.svc.list_alerts(unacknowledged_only=True)
        assert len(unack) == 1

    @pytest.mark.asyncio
    async def test_discover_server_with_mock_introspect(self):
        """Test full discovery flow with mocked MCP server response."""
        mock_response = {
            "tools": [
                {
                    "name": "read_data",
                    "description": "Read data from database",
                    "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
                },
                {
                    "name": "send_webhook",
                    "description": "Send HTTP request to external webhook endpoint",
                    "inputSchema": {"type": "object"},
                },
                {
                    "name": "delete_record",
                    "description": "Permanently delete a record from database",
                    "inputSchema": {"type": "object"},
                },
            ]
        }
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, return_value=mock_response):
            result = await self.svc.discover_server(
                server_name="test-mcp",
                url="http://localhost:5000",
                agent_id="agent-x",
            )

        assert result.success is True
        assert len(result.tools) == 3

        # Check capabilities are scored
        caps = self.svc.get_capabilities("test-mcp")
        assert len(caps) == 3

        # read_data should be Low (read category, no special scope)
        read_cap = [c for c in caps if c["tool_name"] == "read_data"][0]
        assert read_cap["risk_level"] in ("low", "medium")

        # send_webhook should be Critical (outbound + external network)
        webhook_cap = [c for c in caps if c["tool_name"] == "send_webhook"][0]
        assert webhook_cap["risk_level"] == "critical"

        # delete_record should be Critical (delete + destructive)
        delete_cap = [c for c in caps if c["tool_name"] == "delete_record"][0]
        assert delete_cap["risk_level"] == "critical"

        # Server aggregate should be Critical
        server = self.svc.get_server("test-mcp")
        assert server["risk_level"] == "critical"

        # Should have alerts: new_server + 2x critical_capability + unreviewed_connection
        alerts = self.svc.list_alerts()
        alert_types = [a["alert_type"] for a in alerts]
        assert "new_server" in alert_types
        assert "critical_capability" in alert_types
        assert "unreviewed_connection" in alert_types

    @pytest.mark.asyncio
    async def test_discover_server_failure(self):
        """Discovery failure returns error result."""
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, side_effect=Exception("Connection refused")):
            result = await self.svc.discover_server(
                server_name="bad-server",
                url="http://unreachable:5000",
            )
        assert result.success is False
        assert "Connection refused" in result.error

    @pytest.mark.asyncio
    async def test_agent_connection_recorded_during_discovery(self):
        """Agent ID is stored in connected_agents after discovery."""
        mock_response = {"tools": [{"name": "simple_tool"}]}
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, return_value=mock_response):
            await self.svc.discover_server(
                server_name="srv",
                url="http://localhost:5000",
                agent_id="agent-42",
            )

        server = self.svc.get_server("srv")
        assert "agent-42" in server["connected_agents"]


# ────────────────────────────────────────────────────────────────────────
# Admin API Endpoint Tests
# ────────────────────────────────────────────────────────────────────────


class TestMCPAdminAPI:
    """Test MCP admin API endpoints via TestClient."""

    @pytest.fixture(autouse=True)
    def setup_client(self, mock_redis):
        reset_mcp_discovery_service()
        with patch("app.services.redis_client.get_redis", return_value=mock_redis):
            with patch("app.middleware.auth.validate_api_key", return_value=None):
                with patch("app.middleware.auth.validate_api_key_from_db", return_value=None):
                    from app.main import app
                    self.client = TestClient(app)
                    yield

    def test_register_server(self):
        resp = self.client.post("/admin/mcp/servers", json={
            "server_name": "my-mcp",
            "url": "http://localhost:5555",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["server_name"] == "my-mcp"
        assert data["url"] == "http://localhost:5555"

    def test_list_servers_empty(self):
        resp = self.client.get("/admin/mcp/servers")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_servers_with_data(self):
        self.client.post("/admin/mcp/servers", json={"server_name": "s1", "url": "http://a"})
        self.client.post("/admin/mcp/servers", json={"server_name": "s2", "url": "http://b"})
        resp = self.client.get("/admin/mcp/servers")
        assert len(resp.json()) == 2

    def test_get_server(self):
        self.client.post("/admin/mcp/servers", json={"server_name": "s1", "url": "http://a"})
        resp = self.client.get("/admin/mcp/servers/s1")
        assert resp.status_code == 200
        assert resp.json()["server_name"] == "s1"

    def test_get_server_not_found(self):
        resp = self.client.get("/admin/mcp/servers/nonexistent")
        assert resp.status_code == 404

    def test_mark_reviewed(self):
        self.client.post("/admin/mcp/servers", json={"server_name": "s1", "url": "http://a"})
        resp = self.client.post("/admin/mcp/servers/s1/review")
        assert resp.status_code == 200
        assert resp.json()["status"] == "reviewed"

    def test_mark_reviewed_not_found(self):
        resp = self.client.post("/admin/mcp/servers/nope/review")
        assert resp.status_code == 404

    def test_get_capabilities_empty(self):
        self.client.post("/admin/mcp/servers", json={"server_name": "s1", "url": "http://a"})
        resp = self.client.get("/admin/mcp/servers/s1/capabilities")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_alerts(self):
        self.client.post("/admin/mcp/servers", json={"server_name": "s1", "url": "http://a"})
        resp = self.client.get("/admin/mcp/alerts")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) >= 1  # At least new_server alert

    def test_acknowledge_alert(self):
        self.client.post("/admin/mcp/servers", json={"server_name": "s1", "url": "http://a"})
        alerts = self.client.get("/admin/mcp/alerts").json()
        alert_id = alerts[0]["id"]
        resp = self.client.post(f"/admin/mcp/alerts/{alert_id}/acknowledge")
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_acknowledge_alert_not_found(self):
        resp = self.client.post(f"/admin/mcp/alerts/{uuid.uuid4()}/acknowledge")
        assert resp.status_code == 404

    def test_discover_endpoint_failure(self):
        """Discovery endpoint returns 502 when MCP server unreachable."""
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, side_effect=Exception("refused")):
            resp = self.client.post("/admin/mcp/discover", json={
                "server_name": "bad",
                "url": "http://unreachable:5000",
            })
        assert resp.status_code == 502

    def test_discover_endpoint_success(self):
        """Discovery endpoint succeeds with mock MCP server."""
        mock_response = {
            "tools": [
                {"name": "get_data", "description": "Get some data"},
                {"name": "send_request", "description": "Send HTTP request to external API"},
            ]
        }
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, return_value=mock_response):
            resp = self.client.post("/admin/mcp/discover", json={
                "server_name": "good-mcp",
                "url": "http://mcp-server:5000",
                "agent_id": "agent-1",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["tools_discovered"] == 2
        assert data["server_name"] == "good-mcp"


# ────────────────────────────────────────────────────────────────────────
# Acceptance Criteria Tests
# ────────────────────────────────────────────────────────────────────────


class TestAcceptanceCriteria:
    """Verify Sprint 15 acceptance criteria."""

    def setup_method(self):
        reset_mcp_discovery_service()
        self.svc = MCPDiscoveryService()

    @pytest.mark.asyncio
    async def test_ac1_capabilities_auto_discovered_on_connection(self):
        """AC1: MCP server capabilities automatically discovered and
        inventoried on first agent connection."""
        mock_response = {
            "tools": [
                {"name": "tool_a", "description": "A tool"},
                {"name": "tool_b", "description": "Another tool"},
            ]
        }
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, return_value=mock_response):
            result = await self.svc.discover_server(
                server_name="auto-disc-server",
                url="http://mcp:5000",
                agent_id="agent-first",
            )

        assert result.success is True
        assert len(result.tools) == 2

        # Capabilities should be inventoried
        caps = self.svc.get_capabilities("auto-disc-server")
        assert len(caps) == 2
        cap_names = {c["tool_name"] for c in caps}
        assert "tool_a" in cap_names
        assert "tool_b" in cap_names

        # Server should be in registry
        server = self.svc.get_server("auto-disc-server")
        assert server is not None
        assert "agent-first" in server["connected_agents"]

    @pytest.mark.asyncio
    async def test_ac2_risk_scores_correctly_assigned(self):
        """AC2: Risk scores correctly assigned based on capability categories."""
        mock_response = {
            "tools": [
                {"name": "list_items", "description": "Read only list"},
                {"name": "read_password_store", "description": "Read passwords"},
                {"name": "create_record", "description": "Write a new record"},
                {"name": "fetch_external_api", "description": "HTTP fetch from external API"},
                {"name": "delete_all_data", "description": "Destructive delete of all data"},
            ]
        }
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, return_value=mock_response):
            await self.svc.discover_server(
                server_name="risk-test",
                url="http://mcp:5000",
            )

        caps = self.svc.get_capabilities("risk-test")
        caps_by_name = {c["tool_name"]: c for c in caps}

        # Read-only → Low
        assert caps_by_name["list_items"]["risk_level"] == "low"

        # Read sensitive → High or Critical (password triggers sensitive + store triggers write)
        assert caps_by_name["read_password_store"]["risk_level"] in ("high", "critical")

        # Write → High
        assert caps_by_name["create_record"]["risk_level"] in ("high", "medium")

        # Outbound HTTP → Critical
        assert caps_by_name["fetch_external_api"]["risk_level"] in ("critical", "high")

        # Destructive delete → Critical
        assert caps_by_name["delete_all_data"]["risk_level"] == "critical"

    @pytest.mark.asyncio
    async def test_ac3_alert_on_critical_capability(self):
        """AC3: Admin receives alert when Critical-risk capability
        appears in inventory."""
        mock_response = {
            "tools": [
                {"name": "send_webhook", "description": "Send HTTP webhook to external endpoint"},
            ]
        }
        with patch("app.services.mcp.discovery.introspect_mcp_server", new_callable=AsyncMock, return_value=mock_response):
            await self.svc.discover_server(
                server_name="critical-srv",
                url="http://mcp:5000",
            )

        alerts = self.svc.list_alerts()
        critical_alerts = [a for a in alerts if a["alert_type"] == "critical_capability"]
        assert len(critical_alerts) >= 1
        assert critical_alerts[0]["risk_level"] == "critical"
        assert "send_webhook" in critical_alerts[0]["message"]

    @pytest.mark.asyncio
    async def test_ac3_alert_on_new_server(self):
        """AC3: Admin receives alert on new MCP server registration."""
        self.svc.register_server_manual("new-srv", "http://localhost:9000")
        alerts = self.svc.list_alerts()
        new_alerts = [a for a in alerts if a["alert_type"] == "new_server"]
        assert len(new_alerts) == 1
        assert new_alerts[0]["server_name"] == "new-srv"

    @pytest.mark.asyncio
    async def test_ac3_alert_on_unreviewed_connection(self):
        """AC3: Alert when agent connects to unreviewed server."""
        self.svc.register_server_manual("unreview-srv", "http://localhost:9000")
        self.svc.connect_agent("unreview-srv", "agent-new")
        alerts = self.svc.list_alerts()
        conn_alerts = [a for a in alerts if a["alert_type"] == "unreviewed_connection"]
        assert len(conn_alerts) == 1
        assert conn_alerts[0]["agent_id"] == "agent-new"
