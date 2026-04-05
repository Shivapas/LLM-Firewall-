"""Initial schema - API keys and provider credentials

Revision ID: 001
Revises: None
Create Date: 2026-04-05

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("key_hash", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("key_prefix", sa.String(8), nullable=False),
        sa.Column("tenant_id", sa.String(64), index=True, nullable=False),
        sa.Column("project_id", sa.String(64), index=True, nullable=False),
        sa.Column("allowed_models", ARRAY(sa.String), default=[]),
        sa.Column("tpm_limit", sa.Integer, default=100000, nullable=False),
        sa.Column("risk_score", sa.Float, default=0.0, nullable=False),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "provider_credentials",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider_name", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("encrypted_api_key", sa.String(512), nullable=False),
        sa.Column("base_url", sa.String(256), nullable=False),
        sa.Column("is_enabled", sa.Boolean, default=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("provider_credentials")
    op.drop_table("api_keys")
