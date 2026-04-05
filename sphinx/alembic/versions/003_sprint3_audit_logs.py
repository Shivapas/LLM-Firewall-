"""Sprint 3 — audit logs table for enforcement event tracking

Revision ID: 003
Revises: 002
Create Date: 2026-04-05

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("request_hash", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), index=True, nullable=False, server_default=""),
        sa.Column("project_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("api_key_id", sa.String(64), index=True, nullable=False, server_default=""),
        sa.Column("model", sa.String(128), nullable=False, server_default=""),
        sa.Column("provider", sa.String(64), nullable=False, server_default=""),
        sa.Column("action", sa.String(32), nullable=False, server_default="allowed"),
        sa.Column("policy_version", sa.String(64), nullable=False, server_default=""),
        sa.Column("status_code", sa.Integer, nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("prompt_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.String(4096), nullable=False, server_default="{}"),
        sa.Column("event_timestamp", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Index for time-range queries on audit logs
    op.create_index("ix_audit_logs_event_timestamp", "audit_logs", ["event_timestamp"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_event_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")
