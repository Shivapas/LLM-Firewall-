"""Sprint 6 — Gateway/Proxy Integration Mode: route_classification_configs table.

Revision ID: 025
Revises: 024
Create Date: 2026-04-10

Adds the ``route_classification_configs`` table that persists per-application
(route-level) Thoth classification configuration (S6-T2 / FR-CFG-02).

Schema additions:
- ``route_classification_configs`` table — stores per-application Thoth config

Index additions:
- ``ix_route_cfg_application_id`` — fast lookup by application_id (primary key).
- ``ix_route_cfg_policy_group_id`` — lookup by policy group for group-scoped queries.
"""

from alembic import op
import sqlalchemy as sa

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "route_classification_configs",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column(
            "application_id",
            sa.String(length=255),
            nullable=False,
            comment="Application/project ID — maps to project_id in audit records",
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default="true",
            comment="Whether Thoth classification is active for this route",
        ),
        sa.Column(
            "timeout_ms",
            sa.Integer(),
            nullable=True,
            comment="Per-route Thoth API timeout override (null = global default)",
        ),
        sa.Column(
            "fail_closed",
            sa.Boolean(),
            nullable=True,
            comment="Per-route FAIL_CLOSED mode override (null = global default)",
        ),
        sa.Column(
            "policy_group_id",
            sa.String(length=255),
            nullable=True,
            comment="Optional policy group label for scoped rule evaluation",
        ),
        sa.Column(
            "vendor_hint",
            sa.String(length=64),
            nullable=True,
            server_default="auto",
            comment="Expected LLM vendor hint: openai|anthropic|azure_openai|bedrock|oss|auto",
        ),
        sa.Column(
            "created_at",
            sa.Float(),
            nullable=False,
            server_default="0",
            comment="Unix timestamp of creation",
        ),
        sa.Column(
            "updated_at",
            sa.Float(),
            nullable=False,
            server_default="0",
            comment="Unix timestamp of last update",
        ),
        sa.Column(
            "created_by",
            sa.String(length=255),
            nullable=True,
            comment="Admin user who created this config",
        ),
        sa.UniqueConstraint("application_id", name="uq_route_cfg_application_id"),
    )

    op.create_index(
        "ix_route_cfg_application_id",
        "route_classification_configs",
        ["application_id"],
        unique=True,
    )
    op.create_index(
        "ix_route_cfg_policy_group_id",
        "route_classification_configs",
        ["policy_group_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_route_cfg_policy_group_id", table_name="route_classification_configs")
    op.drop_index("ix_route_cfg_application_id", table_name="route_classification_configs")
    op.drop_table("route_classification_configs")
