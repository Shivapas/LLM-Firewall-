"""Sprint 11: Sensitivity-Based Routing & Budget Downgrade

Revision ID: 009
Revises: 008
Create Date: 2026-04-06
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "routing_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("description", sa.String(512), server_default=""),
        sa.Column("priority", sa.Integer, server_default="100"),
        sa.Column("condition_type", sa.String(64), server_default="sensitivity"),
        sa.Column("condition_json", sa.Text, server_default="{}"),
        sa.Column("target_model", sa.String(128), server_default=""),
        sa.Column("target_provider", sa.String(64), server_default=""),
        sa.Column("action", sa.String(32), server_default="route"),
        sa.Column("tenant_id", sa.String(64), index=True, server_default="*"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "budget_tiers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("model_name", sa.String(128), index=True, nullable=False),
        sa.Column("tier_name", sa.String(64), server_default="standard"),
        sa.Column("token_budget", sa.Integer, server_default="1000000"),
        sa.Column("downgrade_model", sa.String(128), server_default=""),
        sa.Column("budget_window_seconds", sa.Integer, server_default="3600"),
        sa.Column("tenant_id", sa.String(64), index=True, server_default="*"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("budget_tiers")
    op.drop_table("routing_rules")
