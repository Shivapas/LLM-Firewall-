"""Sprint 28 — HITL Enforcement Checkpoints + Cascading Failure Detection.

Revision ID: 021
Revises: 020
Create Date: 2026-04-07

Tables:
- approval_requests: HITL approval workflow for policy-triggered human review
- agent_behavioral_baselines: Per-agent behavioral baseline (7-day observation)
- agent_behavioral_events: Individual agent behavioral events for baseline computation
- cascading_failure_events: Anomaly events from cascading failure detector
"""

from alembic import op
import sqlalchemy as sa

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Approval Requests ─────────────────────────────────────────────
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("action_description", sa.Text, nullable=True, default=""),
        sa.Column("risk_context", sa.Text, nullable=True, default="{}"),
        sa.Column("risk_level", sa.String(16), default="high"),
        sa.Column("risk_score", sa.Float, default=0.0),
        sa.Column("matched_patterns", sa.Text, nullable=True, default="[]"),
        sa.Column("status", sa.String(16), default="pending", index=True),
        sa.Column("fallback_action", sa.String(16), default="block"),
        sa.Column("timeout_seconds", sa.Integer, default=300),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decision_reason", sa.Text, nullable=True),
        sa.Column("notification_channels", sa.Text, nullable=True, default='["slack"]'),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    # ── Agent Behavioral Baselines ────────────────────────────────────
    op.create_table(
        "agent_behavioral_baselines",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("observation_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_baseline_ready", sa.Boolean, default=False),
        sa.Column("tool_call_sequence_patterns", sa.Text, nullable=True, default="{}"),
        sa.Column("avg_output_volume", sa.Float, default=0.0),
        sa.Column("std_output_volume", sa.Float, default=0.0),
        sa.Column("avg_api_call_frequency", sa.Float, default=0.0),
        sa.Column("std_api_call_frequency", sa.Float, default=0.0),
        sa.Column("total_observations", sa.Integer, default=0),
        sa.Column("baseline_json", sa.Text, nullable=True, default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Agent Behavioral Events ───────────────────────────────────────
    op.create_table(
        "agent_behavioral_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("event_type", sa.String(64), nullable=False, index=True),
        sa.Column("tool_name", sa.String(128), nullable=True),
        sa.Column("output_tokens", sa.Integer, default=0),
        sa.Column("metadata_json", sa.Text, nullable=True, default="{}"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )

    # ── Cascading Failure Events ──────────────────────────────────────
    op.create_table(
        "cascading_failure_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("anomaly_type", sa.String(64), nullable=False),
        sa.Column("deviation_score", sa.Float, default=0.0),
        sa.Column("circuit_breaker_state", sa.String(16), default="closed"),
        sa.Column("details_json", sa.Text, nullable=True, default="{}"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("cascading_failure_events")
    op.drop_table("agent_behavioral_events")
    op.drop_table("agent_behavioral_baselines")
    op.drop_table("approval_requests")
