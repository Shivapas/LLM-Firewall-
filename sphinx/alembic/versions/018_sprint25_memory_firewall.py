"""Sprint 25 — Agent Memory Store Firewall: Write Interception.

Revision ID: 018
Revises: 017
Create Date: 2026-04-07

Tables:
- memory_write_audit: per-write audit records with hash chain
- memory_write_policies: per-agent write policy configuration
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "memory_write_audit",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("request_id", sa.String(64), nullable=False, index=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("session_id", sa.String(128), nullable=False, default=""),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("content_key", sa.String(256), nullable=False, default=""),
        sa.Column("backend", sa.String(32), nullable=False, default="redis"),
        sa.Column("framework", sa.String(32), nullable=False, default="langchain"),
        sa.Column("namespace", sa.String(128), nullable=False, default=""),
        sa.Column("scanner_verdict", sa.String(16), nullable=False, default="clean"),
        sa.Column("scanner_score", sa.Float, nullable=False, default=0.0),
        sa.Column("matched_patterns", sa.Text, nullable=False, default="[]"),
        sa.Column("action_taken", sa.String(32), nullable=False, index=True),
        sa.Column("reason", sa.Text, nullable=False, default=""),
        sa.Column("enforcement_duration_ms", sa.Float, nullable=False, default=0.0),
        sa.Column("previous_hash", sa.String(64), nullable=False, default=""),
        sa.Column("record_hash", sa.String(64), nullable=False, default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "memory_write_policies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.String(128), nullable=False, unique=True, index=True),
        sa.Column("policy", sa.String(32), nullable=False, default="scan_and_block"),
        sa.Column("allowed_backends", sa.Text, nullable=False, default="[]"),
        sa.Column("allowed_namespaces", sa.Text, nullable=False, default="[]"),
        sa.Column("max_content_length", sa.Integer, nullable=False, default=0),
        sa.Column("custom_threshold", sa.Float, nullable=False, default=0.0),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("memory_write_policies")
    op.drop_table("memory_write_audit")
