"""Sprint 7 — Indian Regulatory Compliance Mode (DPDPA / CERT-In).

Revision ID: 026
Revises: 025
Create Date: 2026-04-10

Adds tables for data residency configuration, DPDPA policy rule templates,
and CERT-In incident tracking to support Indian regulatory requirements.

Schema additions:
- ``residency_configs`` — per-application Thoth endpoint residency configuration
- ``dpdpa_policy_templates`` — pre-built DPDPA-sensitive routing/block rules
- ``certin_incidents`` — CERT-In 6-hour reportable incident tracking
- ``pii_hash_audit`` — audit trail for PII hashing operations

Index additions:
- ``ix_residency_app_id`` — fast lookup by application_id
- ``ix_residency_zone`` — lookup by data_residency_zone
- ``ix_certin_reported`` — filter unreported incidents
- ``ix_certin_detected_at`` — time-windowed queries for 6-hour reporting
"""

from alembic import op
import sqlalchemy as sa

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── S7-T1: Residency configuration table ────────────────────────────
    op.create_table(
        "residency_configs",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column(
            "config_id",
            sa.String(length=255),
            nullable=False,
            comment="Unique config identifier",
        ),
        sa.Column(
            "application_id",
            sa.String(length=255),
            nullable=False,
            server_default="*",
            comment="Application scope — '*' for global default",
        ),
        sa.Column(
            "region",
            sa.String(length=64),
            nullable=True,
            comment="Geographic region code (e.g. in-mum-1)",
        ),
        sa.Column(
            "deployment_mode",
            sa.String(length=32),
            nullable=False,
            server_default="saas",
            comment="saas | vpc | on_prem",
        ),
        sa.Column(
            "data_residency_zone",
            sa.String(length=32),
            nullable=False,
            server_default="GLOBAL",
            comment="Regulatory zone: INDIA | EU | US | GLOBAL",
        ),
        sa.Column(
            "endpoint_url_override",
            sa.String(length=1024),
            nullable=True,
            comment="Thoth API URL override for this deployment",
        ),
        sa.Column(
            "regulatory_tags",
            sa.Text(),
            nullable=True,
            comment="JSON array of regulatory compliance tags",
        ),
        sa.Column(
            "require_on_prem",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="Block classification if local endpoint unavailable",
        ),
        sa.Column(
            "created_at",
            sa.Float(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "updated_at",
            sa.Float(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("config_id", name="uq_residency_config_id"),
    )

    op.create_index(
        "ix_residency_app_id",
        "residency_configs",
        ["application_id"],
        unique=False,
    )
    op.create_index(
        "ix_residency_zone",
        "residency_configs",
        ["data_residency_zone"],
        unique=False,
    )

    # ── S7-T2: DPDPA policy rule templates table ────────────────────────
    op.create_table(
        "dpdpa_policy_templates",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column(
            "rule_id",
            sa.String(length=255),
            nullable=False,
            comment="Template rule identifier (e.g. dpdpa_aadhaar_routing)",
        ),
        sa.Column(
            "name",
            sa.String(length=512),
            nullable=False,
            comment="Human-readable rule name",
        ),
        sa.Column(
            "rule_json",
            sa.Text(),
            nullable=False,
            comment="Full rule definition as JSON",
        ),
        sa.Column(
            "pii_type",
            sa.String(length=64),
            nullable=True,
            comment="Primary PII type targeted (AADHAAR, PAN, BANK_ACCOUNT)",
        ),
        sa.Column(
            "action",
            sa.String(length=64),
            nullable=False,
            comment="Rule action: route | block | queue_for_review",
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column(
            "created_at",
            sa.Float(),
            nullable=False,
            server_default="0",
        ),
        sa.UniqueConstraint("rule_id", name="uq_dpdpa_rule_id"),
    )

    # ── S7-T4: CERT-In incident tracking table ─────────────────────────
    op.create_table(
        "certin_incidents",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=255),
            nullable=False,
            comment="Unique incident identifier (UUID)",
        ),
        sa.Column(
            "detected_at",
            sa.Float(),
            nullable=False,
            comment="Unix timestamp of incident detection",
        ),
        sa.Column(
            "incident_type",
            sa.String(length=128),
            nullable=False,
            comment="Incident category (pii_exfiltration, data_breach, etc.)",
        ),
        sa.Column(
            "severity",
            sa.String(length=32),
            nullable=False,
            server_default="HIGH",
            comment="CRITICAL | HIGH | MEDIUM | LOW",
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "affected_pii_types",
            sa.Text(),
            nullable=True,
            comment="JSON array of affected PII types",
        ),
        sa.Column(
            "tenant_id",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "audit_event_ids",
            sa.Text(),
            nullable=True,
            comment="JSON array of related Sphinx audit event IDs",
        ),
        sa.Column(
            "reported",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="Whether this incident has been reported to CERT-In",
        ),
        sa.Column(
            "reported_at",
            sa.Float(),
            nullable=True,
            comment="Unix timestamp when marked as reported",
        ),
        sa.Column(
            "reporting_deadline",
            sa.Float(),
            nullable=False,
            comment="Unix timestamp of 6-hour reporting deadline",
        ),
        sa.Column(
            "regulatory_tags",
            sa.Text(),
            nullable=True,
            comment="JSON array of regulatory tags",
        ),
        sa.Column(
            "metadata_json",
            sa.Text(),
            nullable=True,
        ),
        sa.UniqueConstraint("incident_id", name="uq_certin_incident_id"),
    )

    op.create_index(
        "ix_certin_reported",
        "certin_incidents",
        ["reported"],
        unique=False,
    )
    op.create_index(
        "ix_certin_detected_at",
        "certin_incidents",
        ["detected_at"],
        unique=False,
    )

    # ── S7-T3: PII hash audit table ────────────────────────────────────
    op.create_table(
        "pii_hash_audit",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column(
            "request_id",
            sa.String(length=255),
            nullable=False,
            comment="Sphinx trace/request ID",
        ),
        sa.Column(
            "tenant_id",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "fields_hashed",
            sa.Integer(),
            nullable=False,
            server_default="0",
            comment="Number of PII fields hashed in this request",
        ),
        sa.Column(
            "pii_types_found",
            sa.Text(),
            nullable=True,
            comment="JSON array of PII types found and hashed",
        ),
        sa.Column(
            "hash_manifest",
            sa.Text(),
            nullable=True,
            comment="JSON array of hash manifest entries",
        ),
        sa.Column(
            "created_at",
            sa.Float(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_table("pii_hash_audit")
    op.drop_index("ix_certin_detected_at", table_name="certin_incidents")
    op.drop_index("ix_certin_reported", table_name="certin_incidents")
    op.drop_table("certin_incidents")
    op.drop_table("dpdpa_policy_templates")
    op.drop_index("ix_residency_zone", table_name="residency_configs")
    op.drop_index("ix_residency_app_id", table_name="residency_configs")
    op.drop_table("residency_configs")
