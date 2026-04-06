"""Sprint 19: Enterprise Dashboard & Alerting.

New tables: alert_rules, alert_events, security_incidents, onboarding_progress.

Revision ID: 016
Revises: 015
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Alert rules
    op.create_table(
        "alert_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), unique=True, index=True, nullable=False),
        sa.Column("description", sa.String(512), server_default=""),
        sa.Column("condition_type", sa.String(64), index=True, nullable=False),
        sa.Column("condition_config_json", sa.Text, server_default="{}"),
        sa.Column("delivery_channel", sa.String(32), server_default="webhook"),
        sa.Column("delivery_target", sa.String(512), server_default=""),
        sa.Column("cooldown_seconds", sa.Integer, server_default="300"),
        sa.Column("last_fired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", sa.String(64), index=True, server_default="*"),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Alert events
    op.create_table(
        "alert_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_rule_id", UUID(as_uuid=True), index=True, nullable=False),
        sa.Column("alert_rule_name", sa.String(256), server_default=""),
        sa.Column("condition_type", sa.String(64), server_default=""),
        sa.Column("severity", sa.String(16), server_default="high"),
        sa.Column("message", sa.Text, server_default=""),
        sa.Column("delivery_channel", sa.String(32), server_default=""),
        sa.Column("delivery_target", sa.String(512), server_default=""),
        sa.Column("delivery_status", sa.String(16), server_default="pending"),
        sa.Column("tenant_id", sa.String(64), index=True, server_default=""),
        sa.Column("metadata_json", sa.Text, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Security incidents
    op.create_table(
        "security_incidents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_type", sa.String(64), index=True, nullable=False),
        sa.Column("severity", sa.String(16), server_default="high"),
        sa.Column("title", sa.String(512), server_default=""),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("tenant_id", sa.String(64), index=True, server_default=""),
        sa.Column("source_event_id", sa.String(64), server_default=""),
        sa.Column("status", sa.String(32), index=True, server_default="open"),
        sa.Column("assigned_to", sa.String(128), server_default=""),
        sa.Column("resolution_notes", sa.Text, server_default=""),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.Text, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Onboarding progress
    op.create_table(
        "onboarding_progress",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("step_register_model", sa.Boolean, server_default=sa.text("false")),
        sa.Column("step_issue_api_key", sa.Boolean, server_default=sa.text("false")),
        sa.Column("step_send_test_request", sa.Boolean, server_default=sa.text("false")),
        sa.Column("step_verify_audit_log", sa.Boolean, server_default=sa.text("false")),
        sa.Column("completed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("onboarding_progress")
    op.drop_table("security_incidents")
    op.drop_table("alert_events")
    op.drop_table("alert_rules")
