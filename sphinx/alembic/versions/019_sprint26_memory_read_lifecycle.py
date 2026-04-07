"""Sprint 26 — Agent Memory Store Firewall: Read Controls + Lifecycle.

Revision ID: 019
Revises: 018
Create Date: 2026-04-07

Tables:
- memory_read_anomalies: Read anomaly alert records
- memory_lifecycle_entries: Per-agent memory entries for lifecycle tracking
- memory_lifecycle_evictions: Eviction event log
- memory_integrity_records: Hash-chain integrity records for stored memory
- memory_integrity_alerts: Integrity verification failure alerts
- memory_isolation_permissions: Cross-agent read permission grants
- memory_isolation_audit: Cross-agent isolation check audit log
"""

from alembic import op
import sqlalchemy as sa

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Read Anomaly Alerts ─────────────────────────────────────────────
    op.create_table(
        "memory_read_anomalies",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(64), unique=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("reader_agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("content_key", sa.String(256), nullable=False),
        sa.Column("anomaly_type", sa.String(32), nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("details", sa.Text, nullable=True),
        sa.Column("writer_agent_id", sa.String(128), nullable=True),
        sa.Column("namespace", sa.String(128), nullable=True),
        sa.Column("chunk_age_days", sa.Float, nullable=True),
        sa.Column("days_since_last_access", sa.Float, nullable=True),
        sa.Column("blocked", sa.Boolean, default=False),
    )

    # ── Lifecycle Entries ───────────────────────────────────────────────
    op.create_table(
        "memory_lifecycle_entries",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("entry_id", sa.String(64), unique=True, nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("content_key", sa.String(256), nullable=False),
        sa.Column("namespace", sa.String(128), nullable=True),
        sa.Column("token_count", sa.Integer, nullable=False, default=0),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Lifecycle Evictions ─────────────────────────────────────────────
    op.create_table(
        "memory_lifecycle_evictions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(64), unique=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("evicted_entry_id", sa.String(64), nullable=False),
        sa.Column("evicted_content_key", sa.String(256), nullable=False),
        sa.Column("evicted_token_count", sa.Integer, nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("tokens_before", sa.Integer, nullable=True),
        sa.Column("tokens_after", sa.Integer, nullable=True),
    )

    # ── Integrity Records ───────────────────────────────────────────────
    op.create_table(
        "memory_integrity_records",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("record_id", sa.String(64), unique=True, nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("content_key", sa.String(256), nullable=False),
        sa.Column("namespace", sa.String(128), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
    )

    # ── Integrity Alerts ────────────────────────────────────────────────
    op.create_table(
        "memory_integrity_alerts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(64), unique=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("record_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("content_key", sa.String(256), nullable=True),
        sa.Column("failure_type", sa.String(32), nullable=False),
        sa.Column("expected_hash", sa.String(64), nullable=True),
        sa.Column("actual_hash", sa.String(64), nullable=True),
        sa.Column("details", sa.Text, nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, default="critical"),
    )

    # ── Cross-Agent Isolation Permissions ───────────────────────────────
    op.create_table(
        "memory_isolation_permissions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("permission_id", sa.String(64), unique=True, nullable=False),
        sa.Column("reader_agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("writer_agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("namespaces", sa.Text, nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("granted_by", sa.String(128), nullable=True),
    )

    # ── Isolation Audit ─────────────────────────────────────────────────
    op.create_table(
        "memory_isolation_audit",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("request_id", sa.String(64), unique=True, nullable=False),
        sa.Column("reader_agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("writer_agent_id", sa.String(128), nullable=False),
        sa.Column("content_key", sa.String(256), nullable=True),
        sa.Column("namespace", sa.String(128), nullable=True),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("memory_isolation_audit")
    op.drop_table("memory_isolation_permissions")
    op.drop_table("memory_integrity_alerts")
    op.drop_table("memory_integrity_records")
    op.drop_table("memory_lifecycle_evictions")
    op.drop_table("memory_lifecycle_entries")
    op.drop_table("memory_read_anomalies")
