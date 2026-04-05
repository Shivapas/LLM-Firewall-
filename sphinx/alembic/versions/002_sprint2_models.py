"""Sprint 2 — kill switches, token usage, policy rules

Revision ID: 002
Revises: 001
Create Date: 2026-04-05

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "kill_switches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("model_name", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("action", sa.String(16), default="block", nullable=False),
        sa.Column("fallback_model", sa.String(128), nullable=True),
        sa.Column("activated_by", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(512), default="", nullable=False),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "token_usage",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("api_key_id", UUID(as_uuid=True), index=True, nullable=False),
        sa.Column("model", sa.String(128), default="", nullable=False),
        sa.Column("prompt_tokens", sa.Integer, default=0, nullable=False),
        sa.Column("completion_tokens", sa.Integer, default=0, nullable=False),
        sa.Column("total_tokens", sa.Integer, default=0, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "policy_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("description", sa.String(512), default="", nullable=False),
        sa.Column("policy_type", sa.String(64), nullable=False),
        sa.Column("rules_json", sa.String(4096), default="{}", nullable=False),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("version", sa.Integer, default=1, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("policy_rules")
    op.drop_table("token_usage")
    op.drop_table("kill_switches")
