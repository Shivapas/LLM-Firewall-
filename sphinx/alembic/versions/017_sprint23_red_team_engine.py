"""Sprint 23: Red Teaming Engine — Attack Probe Library.

New tables: red_team_campaigns, red_team_probe_results.

Revision ID: 017
Revises: 016
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Red team campaigns
    op.create_table(
        "red_team_campaigns",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False, index=True),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("target_url", sa.String(1024), nullable=False),
        sa.Column("probe_categories_json", sa.Text, server_default='["injection","jailbreak","pii_extraction"]'),
        sa.Column("concurrency", sa.Integer, server_default="10"),
        sa.Column("timeout_seconds", sa.Integer, server_default="30"),
        sa.Column("status", sa.String(32), index=True, server_default="pending"),
        sa.Column("total_probes", sa.Integer, server_default="0"),
        sa.Column("probes_executed", sa.Integer, server_default="0"),
        sa.Column("error_message", sa.Text, server_default=""),
        sa.Column("created_by", sa.String(128), server_default="admin"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Red team probe results
    op.create_table(
        "red_team_probe_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", UUID(as_uuid=True), index=True, nullable=False),
        sa.Column("probe_id", sa.String(32), index=True, nullable=False),
        sa.Column("probe_name", sa.String(256), server_default=""),
        sa.Column("category", sa.String(64), index=True, server_default=""),
        sa.Column("technique", sa.String(128), server_default=""),
        sa.Column("severity", sa.String(16), index=True, server_default="medium"),
        sa.Column("detected", sa.Boolean, server_default=sa.text("false")),
        sa.Column("risk_score", sa.Float, server_default="0.0"),
        sa.Column("response_snippet", sa.Text, server_default=""),
        sa.Column("bypass_technique", sa.String(256), server_default=""),
        sa.Column("latency_ms", sa.Float, server_default="0.0"),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("red_team_probe_results")
    op.drop_table("red_team_campaigns")
