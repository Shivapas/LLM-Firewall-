"""Sprint 9: chunk scanning & indirect injection prevention

Adds Incident table for recording injection incidents in retrieved chunks.
Extends vector_collection_policies with chunk scanning and anomaly detection fields.

Revision ID: 007
Revises: 006
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Incident table for indirect injection logging
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_type", sa.String(64), server_default="indirect_injection", index=True),
        sa.Column("tenant_id", sa.String(64), server_default="", index=True),
        sa.Column("collection_name", sa.String(256), server_default="", index=True),
        sa.Column("chunk_content_hash", sa.String(64), server_default=""),
        sa.Column("chunk_id", sa.String(256), server_default=""),
        sa.Column("matched_patterns", sa.Text(), server_default="[]"),
        sa.Column("risk_level", sa.String(16), server_default="high"),
        sa.Column("score", sa.Float(), server_default="0.0"),
        sa.Column("action_taken", sa.String(32), server_default="blocked"),
        sa.Column("metadata_json", sa.Text(), server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # Extend vector_collection_policies with Sprint 9 fields
    op.add_column(
        "vector_collection_policies",
        sa.Column("block_sensitive_documents", sa.Boolean(), server_default=sa.text("false")),
    )
    op.add_column(
        "vector_collection_policies",
        sa.Column("sensitive_field_patterns", postgresql.ARRAY(sa.String()), server_default="{}"),
    )
    op.add_column(
        "vector_collection_policies",
        sa.Column("anomaly_distance_threshold", sa.Float(), server_default="0.0"),
    )
    op.add_column(
        "vector_collection_policies",
        sa.Column("scan_chunks_for_injection", sa.Boolean(), server_default=sa.text("true")),
    )
    op.add_column(
        "vector_collection_policies",
        sa.Column("max_tokens_per_chunk", sa.Integer(), server_default="512"),
    )


def downgrade() -> None:
    op.drop_column("vector_collection_policies", "max_tokens_per_chunk")
    op.drop_column("vector_collection_policies", "scan_chunks_for_injection")
    op.drop_column("vector_collection_policies", "anomaly_distance_threshold")
    op.drop_column("vector_collection_policies", "sensitive_field_patterns")
    op.drop_column("vector_collection_policies", "block_sensitive_documents")
    op.drop_table("incidents")
