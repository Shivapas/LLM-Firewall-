"""Sprint 29 — ML Model Scanning + Multi-Turn Security + AI-SPM Integration.

Revision ID: 022
Revises: 021
Create Date: 2026-04-07

Tables:
- model_scan_results: Model artifact scan results and findings
- model_provenance_registry: Approved model hashes for deployment gating
- session_contexts: Multi-turn conversation session contexts
- session_turns: Individual turn records within sessions
- cross_turn_escalations: Escalation events from cross-turn risk accumulation
- ai_spm_assets: AI asset inventory (governed + ungoverned)
- ai_spm_enrollments: Enrollment requests for ungoverned assets
"""

from alembic import op
import sqlalchemy as sa

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Model Scan Results ───────────────────────────────────────────────
    op.create_table(
        "model_scan_results",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("filename", sa.String(256), nullable=False, default=""),
        sa.Column("file_hash", sa.String(64), nullable=False, index=True),
        sa.Column("file_size", sa.Integer, default=0),
        sa.Column("model_format", sa.String(32), default="unknown"),
        sa.Column("verdict", sa.String(16), default="safe", index=True),
        sa.Column("findings_json", sa.Text, nullable=True, default="[]"),
        sa.Column("scan_duration_ms", sa.Float, default=0.0),
        sa.Column("scanned_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Model Provenance Registry ────────────────────────────────────────
    op.create_table(
        "model_provenance_registry",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("registration_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("model_name", sa.String(256), nullable=False, index=True),
        sa.Column("model_version", sa.String(64), nullable=False),
        sa.Column("file_hash", sa.String(64), nullable=False, index=True),
        sa.Column("file_size", sa.Integer, default=0),
        sa.Column("model_format", sa.String(32), default=""),
        sa.Column("source", sa.String(128), default=""),
        sa.Column("registered_by", sa.String(128), default="system"),
        sa.Column("scan_id", sa.String(64), default=""),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("metadata_json", sa.Text, nullable=True, default="{}"),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Session Contexts ─────────────────────────────────────────────────
    op.create_table(
        "session_contexts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("agent_id", sa.String(128), default=""),
        sa.Column("cumulative_risk_score", sa.Float, default=0.0),
        sa.Column("max_risk_level", sa.String(16), default="none"),
        sa.Column("turn_count", sa.Integer, default=0),
        sa.Column("is_escalated", sa.Boolean, default=False),
        sa.Column("escalation_reason", sa.Text, nullable=True, default=""),
        sa.Column("expired", sa.Boolean, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Session Turns ────────────────────────────────────────────────────
    op.create_table(
        "session_turns",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("turn_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("session_id", sa.String(128), nullable=False, index=True),
        sa.Column("turn_number", sa.Integer, default=0),
        sa.Column("risk_score", sa.Float, default=0.0),
        sa.Column("risk_level", sa.String(16), default="none"),
        sa.Column("matched_patterns_json", sa.Text, nullable=True, default="[]"),
        sa.Column("action_taken", sa.String(32), default="allowed"),
        sa.Column("input_preview", sa.String(256), default=""),
        sa.Column("metadata_json", sa.Text, nullable=True, default="{}"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )

    # ── Cross-Turn Escalations ───────────────────────────────────────────
    op.create_table(
        "cross_turn_escalations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("session_id", sa.String(128), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("agent_id", sa.String(128), default=""),
        sa.Column("cumulative_risk_score", sa.Float, default=0.0),
        sa.Column("threshold", sa.Float, default=0.0),
        sa.Column("turn_count", sa.Integer, default=0),
        sa.Column("escalation_action", sa.String(32), default="block"),
        sa.Column("trigger_turn_number", sa.Integer, default=0),
        sa.Column("risk_trajectory_json", sa.Text, nullable=True, default="[]"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )

    # ── AI-SPM Assets ────────────────────────────────────────────────────
    op.create_table(
        "ai_spm_assets",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("asset_type", sa.String(32), default="llm_api"),
        sa.Column("provider", sa.String(128), default=""),
        sa.Column("endpoint", sa.String(512), default=""),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("team", sa.String(128), default=""),
        sa.Column("status", sa.String(32), default="ungoverned", index=True),
        sa.Column("risk_level", sa.String(16), default="medium"),
        sa.Column("discovery_source", sa.String(64), default=""),
        sa.Column("metadata_json", sa.Text, nullable=True, default="{}"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── AI-SPM Enrollments ───────────────────────────────────────────────
    op.create_table(
        "ai_spm_enrollments",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("request_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("asset_id", sa.String(64), nullable=False, index=True),
        sa.Column("requested_by", sa.String(128), default="system"),
        sa.Column("routing_policy", sa.String(128), default="default"),
        sa.Column("status", sa.String(16), default="pending", index=True),
        sa.Column("resolution_note", sa.Text, nullable=True, default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("ai_spm_enrollments")
    op.drop_table("ai_spm_assets")
    op.drop_table("cross_turn_escalations")
    op.drop_table("session_turns")
    op.drop_table("session_contexts")
    op.drop_table("model_provenance_registry")
    op.drop_table("model_scan_results")
