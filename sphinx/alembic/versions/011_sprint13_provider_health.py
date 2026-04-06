"""Sprint 13: Provider health monitoring, circuit breaker, and cost tracking.

Add provider_health_checks, circuit_breaker_states, provider_cost_records,
and failover_policies tables.

Revision ID: 011
Revises: 010
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Provider health check records
    op.create_table(
        "provider_health_checks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider_name", sa.String(64), index=True, nullable=False),
        sa.Column("is_healthy", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("latency_ms", sa.Float, nullable=False, server_default="0"),
        sa.Column("status_code", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.String(512), server_default="", nullable=False),
        sa.Column("error_rate", sa.Float, nullable=False, server_default="0"),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Circuit breaker state per provider
    op.create_table(
        "circuit_breaker_states",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider_name", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="closed"),  # closed, open, half_open
        sa.Column("failure_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("success_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("half_open_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_threshold", sa.Integer, nullable=False, server_default="5"),
        sa.Column("recovery_timeout_seconds", sa.Integer, nullable=False, server_default="60"),
        sa.Column("half_open_max_requests", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Provider cost tracking records
    op.create_table(
        "provider_cost_records",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider_name", sa.String(64), index=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), index=True, nullable=False),
        sa.Column("model", sa.String(128), index=True, nullable=False),
        sa.Column("prompt_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("estimated_cost_usd", sa.Float, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Failover policy configuration
    op.create_table(
        "failover_policies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider_name", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("error_rate_threshold", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("latency_threshold_ms", sa.Float, nullable=False, server_default="5000"),
        sa.Column("evaluation_window_seconds", sa.Integer, nullable=False, server_default="60"),
        sa.Column("fallback_provider", sa.String(64), nullable=False, server_default=""),
        sa.Column("auto_failover", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("require_confirmation", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("failover_policies")
    op.drop_table("provider_cost_records")
    op.drop_table("circuit_breaker_states")
    op.drop_table("provider_health_checks")
