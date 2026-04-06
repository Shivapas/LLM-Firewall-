"""Sprint 15: MCP Server Discovery & Risk Scoring.

Add mcp_servers, mcp_capabilities, and mcp_risk_alerts tables.

Revision ID: 012
Revises: 011
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # MCP server inventory
    op.create_table(
        "mcp_servers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("server_name", sa.String(256), unique=True, index=True, nullable=False),
        sa.Column("url", sa.String(512), nullable=False, server_default=""),
        sa.Column("protocol_version", sa.String(32), nullable=False, server_default="1.0"),
        sa.Column("connected_agents", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("capabilities_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("aggregate_risk_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="low"),
        sa.Column("is_reviewed", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # MCP capabilities (tools) per server
    op.create_table(
        "mcp_capabilities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("server_id", UUID(as_uuid=True), index=True, nullable=False),
        sa.Column("tool_name", sa.String(256), index=True, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("parameter_schema_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("required_permissions", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("capability_category", sa.String(32), nullable=False, server_default="read"),
        sa.Column("data_access_scope", sa.String(64), nullable=False, server_default="none"),
        sa.Column("has_external_network_access", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_destructive", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="low"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # MCP risk alerts
    op.create_table(
        "mcp_risk_alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_type", sa.String(64), index=True, nullable=False),
        sa.Column("server_id", UUID(as_uuid=True), index=True, nullable=False),
        sa.Column("server_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("capability_id", UUID(as_uuid=True), nullable=True),
        sa.Column("tool_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("agent_id", sa.String(256), nullable=False, server_default=""),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="high"),
        sa.Column("message", sa.Text, nullable=False, server_default=""),
        sa.Column("is_acknowledged", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("acknowledged_by", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("mcp_risk_alerts")
    op.drop_table("mcp_capabilities")
    op.drop_table("mcp_servers")
