"""MCP Automated Capability Discovery — Sprint 15.

On agent connection: enumerate MCP server capabilities via protocol
introspection. Extract tool names, parameter schemas, required permissions.
Also generates risk alerts for new servers and critical capabilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

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

logger = logging.getLogger("sphinx.mcp.discovery")


# ── Data structures ──────────────────────────────────────────────────────


class DiscoveredTool:
    """A tool discovered from an MCP server."""

    def __init__(
        self,
        name: str,
        description: str = "",
        parameter_schema: dict | None = None,
        required_permissions: list[str] | None = None,
    ):
        self.name = name
        self.description = description
        self.parameter_schema = parameter_schema or {}
        self.required_permissions = required_permissions or []

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameter_schema": self.parameter_schema,
            "required_permissions": self.required_permissions,
        }


class DiscoveryResult:
    """Result of capability discovery for an MCP server."""

    def __init__(
        self,
        server_name: str,
        url: str,
        protocol_version: str = "1.0",
        tools: list[DiscoveredTool] | None = None,
        error: str | None = None,
    ):
        self.server_name = server_name
        self.url = url
        self.protocol_version = protocol_version
        self.tools = tools or []
        self.error = error

    @property
    def success(self) -> bool:
        return self.error is None


# ── MCP Protocol introspection ───────────────────────────────────────────


async def introspect_mcp_server(
    url: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Call an MCP server's capability listing endpoint.

    Expects a JSON-RPC style response with tool definitions.
    Falls back to a simple GET /tools endpoint.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Try JSON-RPC tools/list method
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "tools/list",
                "params": {},
            }
            resp = await client.post(url, json=rpc_payload)
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    return data["result"]
                return data
    except Exception as exc:
        logger.warning("MCP introspection failed for %s: %s", url, exc)
        raise


def parse_tools_from_response(response: dict) -> list[DiscoveredTool]:
    """Parse tool definitions from an MCP server response."""
    tools_data = response.get("tools", [])
    if not isinstance(tools_data, list):
        tools_data = []

    tools: list[DiscoveredTool] = []
    for t in tools_data:
        if not isinstance(t, dict):
            continue
        name = t.get("name", "")
        if not name:
            continue
        tools.append(
            DiscoveredTool(
                name=name,
                description=t.get("description", ""),
                parameter_schema=t.get("inputSchema", t.get("parameters", {})),
                required_permissions=t.get("permissions", []),
            )
        )
    return tools


# ── Discovery orchestrator ───────────────────────────────────────────────


class MCPDiscoveryService:
    """Orchestrates MCP server discovery and risk scoring.

    Works with in-memory or database-backed storage depending on
    whether a session_factory is provided.
    """

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        # In-memory registry for servers (keyed by server_name)
        self._servers: dict[str, dict] = {}
        self._capabilities: dict[str, list[dict]] = {}  # server_name -> capabilities
        self._alerts: list[dict] = []

    # ── Public API ─────────────────────────────────────────────────────

    async def discover_server(
        self,
        server_name: str,
        url: str,
        agent_id: str = "",
        protocol_version: str = "1.0",
    ) -> DiscoveryResult:
        """Discover and register an MCP server's capabilities.

        Steps:
        1. Introspect the server to list tools
        2. Score each tool for risk
        3. Store server + capabilities in registry
        4. Generate alerts for new registrations / critical capabilities
        """
        is_new_server = server_name not in self._servers

        # Introspect
        try:
            response = await introspect_mcp_server(url)
            tools = parse_tools_from_response(response)
        except Exception as exc:
            return DiscoveryResult(
                server_name=server_name,
                url=url,
                protocol_version=protocol_version,
                error=str(exc),
            )

        # Score each tool
        scored_capabilities: list[dict] = []
        risk_results: list[RiskScoreResult] = []

        for tool in tools:
            category = infer_capability_category(tool.name, tool.description)
            scope = infer_data_access_scope(tool.name, tool.description)
            external = infer_external_network_access(tool.name, tool.description)
            destructive = infer_destructive(tool.name, tool.description)

            risk_input = CapabilityRiskInput(
                tool_name=tool.name,
                capability_category=category,
                data_access_scope=scope,
                has_external_network_access=external,
                is_destructive=destructive,
                description=tool.description,
            )
            result = score_capability(risk_input)
            risk_results.append(result)

            cap = {
                "id": str(uuid.uuid4()),
                "tool_name": tool.name,
                "description": tool.description,
                "parameter_schema": tool.parameter_schema,
                "required_permissions": tool.required_permissions,
                "capability_category": category,
                "data_access_scope": scope,
                "has_external_network_access": external,
                "is_destructive": destructive,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "risk_factors": result.factors,
            }
            scored_capabilities.append(cap)

        # Aggregate server risk
        agg_score, agg_level = compute_server_aggregate_risk(risk_results)

        # Update in-memory registry
        now = datetime.now(timezone.utc)
        connected_agents = self._servers.get(server_name, {}).get("connected_agents", [])
        if agent_id and agent_id not in connected_agents:
            connected_agents = connected_agents + [agent_id]

        server_record = {
            "server_name": server_name,
            "url": url,
            "protocol_version": protocol_version,
            "connected_agents": connected_agents,
            "capabilities_json": json.dumps([t.to_dict() for t in tools]),
            "aggregate_risk_score": agg_score,
            "risk_level": agg_level.value,
            "is_reviewed": False,
            "is_active": True,
            "last_seen_at": now.isoformat(),
            "discovered_at": now.isoformat(),
        }
        self._servers[server_name] = server_record
        self._capabilities[server_name] = scored_capabilities

        # Generate alerts
        if is_new_server:
            self._emit_alert(
                alert_type="new_server",
                server_name=server_name,
                risk_level=agg_level.value,
                message=f"New MCP server registered: {server_name} (risk: {agg_level.value})",
            )

        for cap in scored_capabilities:
            if cap["risk_level"] == "critical":
                self._emit_alert(
                    alert_type="critical_capability",
                    server_name=server_name,
                    tool_name=cap["tool_name"],
                    risk_level="critical",
                    message=f"Critical-risk capability discovered: {cap['tool_name']} on {server_name}",
                )

        if agent_id and not server_record.get("is_reviewed", False):
            self._emit_alert(
                alert_type="unreviewed_connection",
                server_name=server_name,
                agent_id=agent_id,
                risk_level="high",
                message=f"Agent {agent_id} connected to unreviewed server: {server_name}",
            )

        # Persist to DB if session factory available
        if self._session_factory:
            await self._persist_to_db(server_record, scored_capabilities)

        logger.info(
            "Discovered %d tools on MCP server %s (risk: %s / %.2f)",
            len(tools),
            server_name,
            agg_level.value,
            agg_score,
        )

        return DiscoveryResult(
            server_name=server_name,
            url=url,
            protocol_version=protocol_version,
            tools=tools,
        )

    def register_server_manual(
        self,
        server_name: str,
        url: str,
        protocol_version: str = "1.0",
        agent_id: str = "",
    ) -> dict:
        """Register an MCP server manually without introspection."""
        now = datetime.now(timezone.utc)
        connected_agents = []
        if agent_id:
            connected_agents = [agent_id]

        server_record = {
            "server_name": server_name,
            "url": url,
            "protocol_version": protocol_version,
            "connected_agents": connected_agents,
            "capabilities_json": "[]",
            "aggregate_risk_score": 0.0,
            "risk_level": "low",
            "is_reviewed": False,
            "is_active": True,
            "last_seen_at": now.isoformat(),
            "discovered_at": now.isoformat(),
        }
        is_new = server_name not in self._servers
        self._servers[server_name] = server_record
        self._capabilities.setdefault(server_name, [])

        if is_new:
            self._emit_alert(
                alert_type="new_server",
                server_name=server_name,
                risk_level="low",
                message=f"New MCP server registered (manual): {server_name}",
            )

        return server_record

    def connect_agent(self, server_name: str, agent_id: str) -> bool:
        """Record an agent connecting to an MCP server."""
        server = self._servers.get(server_name)
        if not server:
            return False
        if agent_id not in server["connected_agents"]:
            server["connected_agents"].append(agent_id)
        server["last_seen_at"] = datetime.now(timezone.utc).isoformat()

        if not server.get("is_reviewed", False):
            self._emit_alert(
                alert_type="unreviewed_connection",
                server_name=server_name,
                agent_id=agent_id,
                risk_level="high",
                message=f"Agent {agent_id} connected to unreviewed server: {server_name}",
            )
        return True

    def mark_reviewed(self, server_name: str) -> bool:
        """Mark a server as reviewed by admin."""
        server = self._servers.get(server_name)
        if not server:
            return False
        server["is_reviewed"] = True
        return True

    def list_servers(self) -> list[dict]:
        """List all registered MCP servers."""
        return list(self._servers.values())

    def get_server(self, server_name: str) -> dict | None:
        """Get a specific server by name."""
        return self._servers.get(server_name)

    def get_capabilities(self, server_name: str) -> list[dict]:
        """Get scored capabilities for a server."""
        return self._capabilities.get(server_name, [])

    def list_alerts(self, unacknowledged_only: bool = False) -> list[dict]:
        """List risk alerts."""
        if unacknowledged_only:
            return [a for a in self._alerts if not a.get("is_acknowledged")]
        return list(self._alerts)

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "admin") -> bool:
        """Acknowledge an alert."""
        for alert in self._alerts:
            if alert["id"] == alert_id:
                alert["is_acknowledged"] = True
                alert["acknowledged_by"] = acknowledged_by
                return True
        return False

    # ── Internal ─────────────────────────────────────────────────────

    def _emit_alert(
        self,
        alert_type: str,
        server_name: str,
        risk_level: str = "high",
        message: str = "",
        tool_name: str = "",
        agent_id: str = "",
    ) -> None:
        alert = {
            "id": str(uuid.uuid4()),
            "alert_type": alert_type,
            "server_name": server_name,
            "tool_name": tool_name,
            "agent_id": agent_id,
            "risk_level": risk_level,
            "message": message,
            "is_acknowledged": False,
            "acknowledged_by": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._alerts.append(alert)
        logger.warning("MCP Risk Alert [%s]: %s", alert_type, message)

    async def _persist_to_db(self, server_record: dict, capabilities: list[dict]) -> None:
        """Persist server and capabilities to database."""
        try:
            from app.models.api_key import MCPServer, MCPCapability, MCPRiskAlert
            from sqlalchemy import select

            async with self._session_factory() as db:
                # Upsert server
                result = await db.execute(
                    select(MCPServer).where(
                        MCPServer.server_name == server_record["server_name"]
                    )
                )
                existing = result.scalar_one_or_none()

                if existing:
                    existing.url = server_record["url"]
                    existing.protocol_version = server_record["protocol_version"]
                    existing.connected_agents = server_record["connected_agents"]
                    existing.capabilities_json = server_record["capabilities_json"]
                    existing.aggregate_risk_score = server_record["aggregate_risk_score"]
                    existing.risk_level = server_record["risk_level"]
                    existing.last_seen_at = datetime.now(timezone.utc)
                else:
                    db.add(MCPServer(
                        server_name=server_record["server_name"],
                        url=server_record["url"],
                        protocol_version=server_record["protocol_version"],
                        connected_agents=server_record["connected_agents"],
                        capabilities_json=server_record["capabilities_json"],
                        aggregate_risk_score=server_record["aggregate_risk_score"],
                        risk_level=server_record["risk_level"],
                        is_reviewed=False,
                        is_active=True,
                        last_seen_at=datetime.now(timezone.utc),
                    ))

                # Add capabilities
                server_result = await db.execute(
                    select(MCPServer).where(
                        MCPServer.server_name == server_record["server_name"]
                    )
                )
                server_obj = server_result.scalar_one_or_none()
                if server_obj:
                    for cap in capabilities:
                        db.add(MCPCapability(
                            server_id=server_obj.id,
                            tool_name=cap["tool_name"],
                            description=cap.get("description", ""),
                            parameter_schema_json=json.dumps(cap.get("parameter_schema", {})),
                            required_permissions=cap.get("required_permissions", []),
                            capability_category=cap["capability_category"],
                            data_access_scope=cap["data_access_scope"],
                            has_external_network_access=cap["has_external_network_access"],
                            is_destructive=cap["is_destructive"],
                            risk_score=cap["risk_score"],
                            risk_level=cap["risk_level"],
                        ))

                # Persist alerts
                for alert in self._alerts:
                    if not alert.get("_persisted"):
                        db.add(MCPRiskAlert(
                            alert_type=alert["alert_type"],
                            server_id=server_obj.id if server_obj else uuid.uuid4(),
                            server_name=alert["server_name"],
                            tool_name=alert.get("tool_name", ""),
                            agent_id=alert.get("agent_id", ""),
                            risk_level=alert["risk_level"],
                            message=alert["message"],
                            is_acknowledged=alert["is_acknowledged"],
                        ))
                        alert["_persisted"] = True

                await db.commit()
        except Exception:
            logger.warning("Failed to persist MCP discovery to DB", exc_info=True)


# ── Singleton ────────────────────────────────────────────────────────────

_discovery_service: MCPDiscoveryService | None = None


def get_mcp_discovery_service(session_factory=None) -> MCPDiscoveryService:
    """Get or create the singleton MCP discovery service."""
    global _discovery_service
    if _discovery_service is None:
        _discovery_service = MCPDiscoveryService(session_factory=session_factory)
    return _discovery_service


def reset_mcp_discovery_service() -> None:
    """Reset for testing."""
    global _discovery_service
    _discovery_service = None
