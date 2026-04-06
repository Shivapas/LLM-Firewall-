"""Sprint 18: Audit Trail Hardening & Compliance Reports.

Add risk_score, action_taken, enforcement_duration_ms, previous_hash,
record_hash, chain_sequence columns to audit_logs table.

Revision ID: 015
Revises: 014
"""

from alembic import op
import sqlalchemy as sa

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add Sprint 18 columns to audit_logs
    op.add_column("audit_logs", sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"))
    op.add_column("audit_logs", sa.Column("action_taken", sa.String(32), nullable=False, server_default=""))
    op.add_column("audit_logs", sa.Column("enforcement_duration_ms", sa.Float, nullable=False, server_default="0.0"))
    op.add_column("audit_logs", sa.Column("previous_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("audit_logs", sa.Column("record_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("audit_logs", sa.Column("chain_sequence", sa.Integer, nullable=False, server_default="0"))

    # Index on record_hash for chain verification lookups
    op.create_index("ix_audit_logs_record_hash", "audit_logs", ["record_hash"])
    # Index on chain_sequence for ordered chain traversal
    op.create_index("ix_audit_logs_chain_sequence", "audit_logs", ["chain_sequence"])
    # Composite index for common query patterns (tenant + timestamp)
    op.create_index("ix_audit_logs_tenant_timestamp", "audit_logs", ["tenant_id", "event_timestamp"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_tenant_timestamp")
    op.drop_index("ix_audit_logs_chain_sequence")
    op.drop_index("ix_audit_logs_record_hash")
    op.drop_column("audit_logs", "chain_sequence")
    op.drop_column("audit_logs", "record_hash")
    op.drop_column("audit_logs", "previous_hash")
    op.drop_column("audit_logs", "enforcement_duration_ms")
    op.drop_column("audit_logs", "action_taken")
    op.drop_column("audit_logs", "risk_score")
