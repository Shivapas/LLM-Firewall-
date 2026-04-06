"""Sprint 10: Vector DB Firewall Hardening & Observability

Adds collection_audit_logs table for per-collection query audit trail.
Extends vector_collection_policies with Milvus partition isolation config.

Revision ID: 008
Revises: 007
Create Date: 2026-04-06
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Collection audit log table
    op.create_table(
        "collection_audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("audit_id", sa.String(64), index=True),
        sa.Column("timestamp", sa.Float(), default=0.0),
        sa.Column("collection_name", sa.String(256), index=True),
        sa.Column("tenant_id", sa.String(64), index=True),
        sa.Column("operation", sa.String(32)),
        sa.Column("query_hash", sa.String(64), index=True),
        sa.Column("namespace_field", sa.String(128), server_default=""),
        sa.Column("namespace_value", sa.String(128), server_default=""),
        sa.Column("namespace_injected", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("chunks_returned", sa.Integer(), server_default="0"),
        sa.Column("chunks_blocked", sa.Integer(), server_default="0"),
        sa.Column("results_capped", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("original_top_k", sa.Integer(), server_default="0"),
        sa.Column("enforced_top_k", sa.Integer(), server_default="0"),
        sa.Column("injection_blocks", sa.Integer(), server_default="0"),
        sa.Column("sensitive_field_blocks", sa.Integer(), server_default="0"),
        sa.Column("anomaly_score", sa.Float(), server_default="0.0"),
        sa.Column("anomaly_detected", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("compliance_tags_json", sa.Text(), server_default="{}"),
        sa.Column("requires_private_model", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("latency_ms", sa.Float(), server_default="0.0"),
        sa.Column("provider", sa.String(64), server_default=""),
        sa.Column("action", sa.String(32), server_default="allowed"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # Extend vector_collection_policies with Sprint 10 fields
    op.add_column(
        "vector_collection_policies",
        sa.Column("use_partition_isolation", sa.Boolean(), server_default=sa.text("false")),
    )
    op.add_column(
        "vector_collection_policies",
        sa.Column("partition_prefix", sa.String(64), server_default="tenant_"),
    )
    op.add_column(
        "vector_collection_policies",
        sa.Column("compliance_tagging_enabled", sa.Boolean(), server_default=sa.text("true")),
    )


def downgrade() -> None:
    op.drop_column("vector_collection_policies", "compliance_tagging_enabled")
    op.drop_column("vector_collection_policies", "partition_prefix")
    op.drop_column("vector_collection_policies", "use_partition_isolation")
    op.drop_table("collection_audit_logs")
