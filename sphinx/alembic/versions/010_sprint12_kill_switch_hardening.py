"""Sprint 12: Kill-switch production hardening.

Add kill_switch_audit_logs table (immutable), error_message to kill_switches.

Revision ID: 010
Revises: 009
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add error_message column to kill_switches
    op.add_column(
        "kill_switches",
        sa.Column("error_message", sa.String(512), server_default="Model temporarily unavailable", nullable=False),
    )

    # Create immutable kill-switch audit log table
    op.create_table(
        "kill_switch_audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("model_name", sa.String(128), index=True, nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("fallback_model", sa.String(128), nullable=True),
        sa.Column("activated_by", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(512), server_default="", nullable=False),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("kill_switch_audit_logs")
    op.drop_column("kill_switches", "error_message")
