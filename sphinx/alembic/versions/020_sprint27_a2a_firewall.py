"""Sprint 27 — Inter-Agent A2A Protocol Firewall.

Revision ID: 020
Revises: 019
Create Date: 2026-04-07

Tables:
- a2a_registered_agents: Agent service accounts for A2A communication
- a2a_issued_tokens: JWT tokens issued to agents
- a2a_revoked_tokens: Revoked token JTIs
- a2a_agent_certificates: mTLS certificates per agent
- a2a_mtls_policies: mTLS enforcement policies per workflow
- a2a_audit_log: Per-message A2A audit records with hash chain
- a2a_nonce_log: Used nonces for replay attack prevention
"""

from alembic import op
import sqlalchemy as sa

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Registered Agents ──────────────────────────────────────────────
    op.create_table(
        "a2a_registered_agents",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("allowed_downstream", sa.Text, nullable=True, default="[]"),
        sa.Column("permission_scope", sa.Text, nullable=True, default='["read","write"]'),
        sa.Column("signing_secret_hash", sa.String(128), nullable=False),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("token_ttl_seconds", sa.Integer, default=3600),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Issued Tokens ──────────────────────────────────────────────────
    op.create_table(
        "a2a_issued_tokens",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("jti", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean, default=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── Agent Certificates ─────────────────────────────────────────────
    op.create_table(
        "a2a_agent_certificates",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("cert_fingerprint", sa.String(128), unique=True, nullable=False),
        sa.Column("spiffe_id", sa.String(256), nullable=True),
        sa.Column("serial_number", sa.String(64), unique=True, nullable=False),
        sa.Column("issuer", sa.String(128), default="sphinx-ca"),
        sa.Column("status", sa.String(16), default="active", index=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── mTLS Policies ──────────────────────────────────────────────────
    op.create_table(
        "a2a_mtls_policies",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("policy_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("workflow_id", sa.String(128), nullable=False, index=True),
        sa.Column("agent_pairs", sa.Text, nullable=True, default="[]"),
        sa.Column("framework", sa.String(32), default="langgraph"),
        sa.Column("required", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── A2A Audit Log ──────────────────────────────────────────────────
    op.create_table(
        "a2a_audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("record_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("message_id", sa.String(64), nullable=False, index=True),
        sa.Column("sender_agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("receiver_agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("message_type", sa.String(32), nullable=True),
        sa.Column("framework", sa.String(32), nullable=True),
        sa.Column("session_id", sa.String(128), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("signature_verified", sa.Boolean, default=False),
        sa.Column("token_valid", sa.Boolean, default=False),
        sa.Column("nonce_valid", sa.Boolean, default=True),
        sa.Column("mtls_verified", sa.Boolean, default=False),
        sa.Column("action_taken", sa.String(64), nullable=False, index=True),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("enforcement_duration_ms", sa.Float, default=0.0),
        sa.Column("previous_hash", sa.String(64), nullable=True),
        sa.Column("record_hash", sa.String(64), nullable=True),
    )

    # ── Nonce Log ──────────────────────────────────────────────────────
    op.create_table(
        "a2a_nonce_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("nonce", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("agent_id", sa.String(128), nullable=False, index=True),
        sa.Column("used_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("a2a_nonce_log")
    op.drop_table("a2a_audit_log")
    op.drop_table("a2a_mtls_policies")
    op.drop_table("a2a_agent_certificates")
    op.drop_table("a2a_issued_tokens")
    op.drop_table("a2a_registered_agents")
