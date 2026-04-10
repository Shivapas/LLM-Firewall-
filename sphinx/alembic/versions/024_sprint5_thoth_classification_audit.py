"""Sprint 5 — Thoth Classification Audit Schema v2 & Observability Dashboard.

Add Thoth semantic classification metadata as first-class columns on
audit_logs, enabling efficient dashboard aggregation queries (S5-T1, S5-T2).

All new columns are nullable so existing rows without classification data
remain valid — fully backward-compatible migration (FR-AUD-01, FR-AUD-02).

Indexes added:
- classification_intent: intent category breakdown queries (S5-T3)
- classification_risk_level: risk heatmap queries (S5-T4)
- classification_pii_detected: PII frequency queries (S5-T6)
- Composite (tenant_id, classification_risk_level, event_timestamp): heatmap

Revision ID: 024
Revises: 023
Create Date: 2026-04-10
"""

from alembic import op
import sqlalchemy as sa

revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Classification metadata columns (S5-T1) ──────────────────────────────
    # All nullable: pre-Sprint-5 audit rows lack classification data; that is
    # a valid, expected state — not a data integrity violation.
    op.add_column(
        "audit_logs",
        sa.Column("classification_intent", sa.String(128), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("classification_risk_level", sa.String(16), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("classification_confidence", sa.Float, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("classification_pii_detected", sa.Boolean, nullable=True),
    )
    # JSON-encoded list of PII type strings (e.g. '["AADHAAR","EMAIL"]')
    op.add_column(
        "audit_logs",
        sa.Column("classification_pii_types", sa.String(512), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("classification_latency_ms", sa.Integer, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("classification_model_version", sa.String(64), nullable=True),
    )
    # "thoth" | "structural_fallback"
    op.add_column(
        "audit_logs",
        sa.Column("classification_source", sa.String(32), nullable=True),
    )

    # ── Indexes for dashboard queries (S5-T3 to S5-T7) ──────────────────────
    # Intent breakdown (S5-T3): GROUP BY classification_intent
    op.create_index(
        "ix_audit_logs_classification_intent",
        "audit_logs",
        ["classification_intent"],
    )
    # Risk heatmap (S5-T4): GROUP BY classification_risk_level + time bucket
    op.create_index(
        "ix_audit_logs_classification_risk_level",
        "audit_logs",
        ["classification_risk_level"],
    )
    # PII frequency (S5-T6): WHERE classification_pii_detected = true
    op.create_index(
        "ix_audit_logs_classification_pii_detected",
        "audit_logs",
        ["classification_pii_detected"],
    )
    # Heatmap + PII trend composite: tenant × risk_level × timestamp
    op.create_index(
        "ix_audit_logs_tenant_risk_timestamp",
        "audit_logs",
        ["tenant_id", "classification_risk_level", "event_timestamp"],
    )
    # Latency percentile queries (S5-T7): WHERE classification_source = 'thoth'
    op.create_index(
        "ix_audit_logs_classification_source",
        "audit_logs",
        ["classification_source"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_classification_source", table_name="audit_logs")
    op.drop_index("ix_audit_logs_tenant_risk_timestamp", table_name="audit_logs")
    op.drop_index("ix_audit_logs_classification_pii_detected", table_name="audit_logs")
    op.drop_index("ix_audit_logs_classification_risk_level", table_name="audit_logs")
    op.drop_index("ix_audit_logs_classification_intent", table_name="audit_logs")
    op.drop_column("audit_logs", "classification_source")
    op.drop_column("audit_logs", "classification_model_version")
    op.drop_column("audit_logs", "classification_latency_ms")
    op.drop_column("audit_logs", "classification_pii_types")
    op.drop_column("audit_logs", "classification_pii_detected")
    op.drop_column("audit_logs", "classification_confidence")
    op.drop_column("audit_logs", "classification_risk_level")
    op.drop_column("audit_logs", "classification_intent")
