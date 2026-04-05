"""Sprint 8: vector collection policies for vector DB proxy & namespace isolation

Revision ID: 006
Revises: 005
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vector_collection_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("collection_name", sa.String(256), nullable=False, unique=True, index=True),
        sa.Column("provider", sa.String(64), server_default="chromadb"),
        sa.Column("default_action", sa.String(16), server_default="deny"),
        sa.Column("allowed_operations", postgresql.ARRAY(sa.String()), server_default="{}"),
        sa.Column("sensitive_fields", postgresql.ARRAY(sa.String()), server_default="{}"),
        sa.Column("namespace_field", sa.String(128), server_default="tenant_id"),
        sa.Column("max_results", sa.Integer(), server_default="10"),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true")),
        sa.Column("tenant_id", sa.String(64), server_default="*", index=True),
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
    op.drop_table("vector_collection_policies")
