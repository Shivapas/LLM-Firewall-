"""Sprint 17: MCP Guardrails Dashboard & Compliance Tagging.

Add mcp_tool_call_audits and agent_risk_scores tables.

Revision ID: 014
Revises: 013
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # MCP tool call audit log
    op.create_table(
        "mcp_tool_call_audits",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.String(256), index=True, nullable=False),
        sa.Column("tool_name", sa.String(256), index=True, nullable=False),
        sa.Column("mcp_server", sa.String(256), index=True, nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("output_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("action", sa.String(32), nullable=False, server_default="allowed"),
        sa.Column("compliance_tags", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("latency_ms", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("request_size_bytes", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("response_size_bytes", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("metadata_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Agent risk score snapshots
    op.create_table(
        "agent_risk_scores",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.String(256), index=True, nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="low"),
        sa.Column("tool_risk_component", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("violation_component", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("scope_breadth_component", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("connected_tools_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("violation_count_24h", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("total_violations", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("contributing_factors", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("agent_risk_scores")
    op.drop_table("mcp_tool_call_audits")
