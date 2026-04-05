"""Sprint 4: security_rules table for threat detection

Revision ID: 004
Revises: 003
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, index=True),
        sa.Column("description", sa.String(512), server_default=""),
        sa.Column("category", sa.String(64), server_default="prompt_injection"),
        sa.Column("severity", sa.String(16), server_default="medium"),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("action", sa.String(16), server_default="block"),
        sa.Column("rewrite_template", sa.String(512), nullable=True),
        sa.Column("tags_json", sa.String(1024), server_default="[]"),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true")),
        sa.Column("stage", sa.String(32), server_default="input"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("security_rules")
