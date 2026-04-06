"""Sprint 16: Per-Agent Scope Enforcement.

Add agent_service_accounts and agent_scope_violations tables.

Revision ID: 013
Revises: 012
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Agent service accounts
    op.create_table(
        "agent_service_accounts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.String(256), unique=True, index=True, nullable=False),
        sa.Column("display_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("allowed_mcp_servers", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("allowed_tools", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("context_scope", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("redact_fields", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Agent scope violation log
    op.create_table(
        "agent_scope_violations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.String(256), index=True, nullable=False),
        sa.Column("violation_type", sa.String(64), index=True, nullable=False),
        sa.Column("tool_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("mcp_server", sa.String(256), nullable=False, server_default=""),
        sa.Column("resource_id", sa.String(256), nullable=False, server_default=""),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("agent_scope_violations")
    op.drop_table("agent_service_accounts")
