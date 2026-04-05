"""Sprint 7: policy version snapshots for versioning, diff, and rollback

Revision ID: 005
Revises: 004
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_version_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(512), server_default=""),
        sa.Column("policy_type", sa.String(64), nullable=False),
        sa.Column("rules_json", sa.Text(), server_default="{}"),
        sa.Column("created_by", sa.String(128), server_default="system"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # Composite unique constraint: one version number per policy
    op.create_unique_constraint(
        "uq_policy_version_snapshots_policy_version",
        "policy_version_snapshots",
        ["policy_id", "version"],
    )


def downgrade() -> None:
    op.drop_table("policy_version_snapshots")
