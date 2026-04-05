import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, Float, DateTime, Boolean, Text, func
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(8))
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    allowed_models: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    tpm_limit: Mapped[int] = mapped_column(Integer, default=100000)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class KillSwitch(Base):
    __tablename__ = "kill_switches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    model_name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    action: Mapped[str] = mapped_column(String(16), default="block")  # block | reroute
    fallback_model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    activated_by: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(512), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TokenUsage(Base):
    __tablename__ = "token_usage"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    api_key_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    model: Mapped[str] = mapped_column(String(128), default="")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    policy_type: Mapped[str] = mapped_column(String(64))  # rate_limit, access_control, kill_switch, etc.
    rules_json: Mapped[str] = mapped_column(String(4096), default="{}")  # compiled policy as JSON
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuditLog(Base):
    """Audit log for all gateway enforcement events."""
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    request_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    project_id: Mapped[str] = mapped_column(String(64), default="")
    api_key_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    provider: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(32), default="allowed")  # allowed, blocked, rerouted, rate_limited
    policy_version: Mapped[str] = mapped_column(String(64), default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[str] = mapped_column(String(4096), default="{}")
    event_timestamp: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SecurityRule(Base):
    """Security rule for threat detection — configurable per-tenant patterns."""
    __tablename__ = "security_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    category: Mapped[str] = mapped_column(
        String(64), default="prompt_injection"
    )  # prompt_injection, jailbreak, data_extraction, etc.
    severity: Mapped[str] = mapped_column(
        String(16), default="medium"
    )  # critical, high, medium, low
    pattern: Mapped[str] = mapped_column(Text)  # regex pattern
    action: Mapped[str] = mapped_column(
        String(16), default="block"
    )  # allow, block, rewrite, downgrade
    rewrite_template: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    tags_json: Mapped[str] = mapped_column(String(1024), default="[]")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    stage: Mapped[str] = mapped_column(
        String(32), default="input"
    )  # input, output, rag
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RAGPolicyConfig(Base):
    """Per-stage policy configuration for RAG pipelines."""
    __tablename__ = "rag_policy_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    # Stage-specific enforcement toggles
    query_stage_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    retrieval_stage_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    generator_stage_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Query stage config
    query_threat_detection: Mapped[bool] = mapped_column(Boolean, default=True)
    query_pii_redaction: Mapped[bool] = mapped_column(Boolean, default=True)
    query_intent_classification: Mapped[bool] = mapped_column(Boolean, default=True)
    block_high_risk_intents: Mapped[bool] = mapped_column(Boolean, default=False)
    # Retrieval stage config
    max_chunks: Mapped[int] = mapped_column(Integer, default=10)
    max_tokens_per_chunk: Mapped[int] = mapped_column(Integer, default=512)
    scan_retrieved_chunks: Mapped[bool] = mapped_column(Boolean, default=True)
    # Generator stage config
    generator_pii_redaction: Mapped[bool] = mapped_column(Boolean, default=True)
    generator_threat_detection: Mapped[bool] = mapped_column(Boolean, default=True)
    # Metadata
    rules_json: Mapped[str] = mapped_column(Text, default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="*")  # * = global
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class PolicyVersionSnapshot(Base):
    """Versioned snapshot of a policy for audit trail, diff, and rollback."""
    __tablename__ = "policy_version_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    version: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(512), default="")
    policy_type: Mapped[str] = mapped_column(String(64))
    rules_json: Mapped[str] = mapped_column(Text, default="{}")
    created_by: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ProviderCredential(Base):
    __tablename__ = "provider_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider_name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_api_key: Mapped[str] = mapped_column(String(512))
    base_url: Mapped[str] = mapped_column(String(256))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
