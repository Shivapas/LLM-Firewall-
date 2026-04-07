"""Sprint 30 — Secure Semantic Caching + Phase 8 Hardening & v2.0 Release.

Revision ID: 023
Revises: 022
Create Date: 2026-04-07

Tables:
- semantic_cache_entries: Tenant-scoped semantic cache with embeddings
- cache_audit_log: Audit trail for cache hits and misses
- cache_poison_events: Cache poisoning detection events
- release_checklist_items: v2.0 release checklist items
- performance_benchmarks: Performance regression test results
"""

from alembic import op
import sqlalchemy as sa

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Semantic Cache Entries ────────────────────────────────────────────
    op.create_table(
        "semantic_cache_entries",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("entry_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("query_hash", sa.String(32), nullable=False, index=True),
        sa.Column("query_text", sa.Text, nullable=False),
        sa.Column("response_text", sa.Text, nullable=False),
        sa.Column("model", sa.String(128), default=""),
        sa.Column("policy_version", sa.String(64), default="", index=True),
        sa.Column("embedding_json", sa.Text, nullable=True),
        sa.Column("similarity_threshold", sa.Float, default=0.95),
        sa.Column("hit_count", sa.Integer, default=0),
        sa.Column("metadata_json", sa.Text, nullable=True, default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── Cache Audit Log ──────────────────────────────────────────────────
    op.create_table(
        "cache_audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("query_hash", sa.String(32), default=""),
        sa.Column("response_source", sa.String(16), default="model", index=True),
        sa.Column("cache_key", sa.String(64), default=""),
        sa.Column("similarity_score", sa.Float, default=0.0),
        sa.Column("policy_version", sa.String(64), default=""),
        sa.Column("model", sa.String(128), default=""),
        sa.Column("lookup_time_ms", sa.Float, default=0.0),
        sa.Column("metadata_json", sa.Text, nullable=True, default="{}"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )

    # ── Cache Poison Events ──────────────────────────────────────────────
    op.create_table(
        "cache_poison_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("entry_id", sa.String(64), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("patterns_matched_json", sa.Text, nullable=True, default="[]"),
        sa.Column("categories_json", sa.Text, nullable=True, default="[]"),
        sa.Column("severity", sa.String(16), default="none"),
        sa.Column("details_json", sa.Text, nullable=True, default="{}"),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Release Checklist Items ──────────────────────────────────────────
    op.create_table(
        "release_checklist_items",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("item_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("category", sa.String(32), nullable=False, index=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True, default=""),
        sa.Column("status", sa.String(16), default="pending", index=True),
        sa.Column("assigned_to", sa.String(64), default=""),
        sa.Column("evidence", sa.Text, nullable=True, default=""),
        sa.Column("checked_by", sa.String(128), default=""),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Performance Benchmarks ───────────────────────────────────────────
    op.create_table(
        "performance_benchmarks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("benchmark_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("check_name", sa.String(128), nullable=False, index=True),
        sa.Column("p50_ms", sa.Float, default=0.0),
        sa.Column("p95_ms", sa.Float, default=0.0),
        sa.Column("p99_ms", sa.Float, default=0.0),
        sa.Column("max_ms", sa.Float, default=0.0),
        sa.Column("sample_count", sa.Integer, default=0),
        sa.Column("passes_threshold", sa.Boolean, default=True),
        sa.Column("threshold_ms", sa.Float, default=50.0),
        sa.Column("measured_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("performance_benchmarks")
    op.drop_table("release_checklist_items")
    op.drop_table("cache_poison_events")
    op.drop_table("cache_audit_log")
    op.drop_table("semantic_cache_entries")
