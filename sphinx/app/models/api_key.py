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
    error_message: Mapped[str] = mapped_column(String(512), default="Model temporarily unavailable")
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
    """Audit log for all gateway enforcement events.

    Sprint 18: adds risk_score, action_taken, enforcement_duration_ms,
    previous_hash, record_hash for tamper-evident hash chaining.
    """
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
    # Sprint 18: audit trail hardening fields
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    action_taken: Mapped[str] = mapped_column(String(32), default="")
    enforcement_duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    # Sprint 18: tamper-evident hash chain
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    record_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    chain_sequence: Mapped[int] = mapped_column(Integer, default=0)
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


class VectorCollectionPolicy(Base):
    """Per-collection access policy for vector DB proxy enforcement."""
    __tablename__ = "vector_collection_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    collection_name: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    provider: Mapped[str] = mapped_column(
        String(64), default="chromadb"
    )  # chromadb, pinecone, milvus
    default_action: Mapped[str] = mapped_column(
        String(16), default="deny"
    )  # deny, allow, monitor
    allowed_operations: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list
    )  # query, insert, update, delete
    sensitive_fields: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list
    )
    namespace_field: Mapped[str] = mapped_column(String(128), default="tenant_id")
    max_results: Mapped[int] = mapped_column(Integer, default=10)
    block_sensitive_documents: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_field_patterns: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list
    )  # regex patterns for sensitive field matching
    anomaly_distance_threshold: Mapped[float] = mapped_column(Float, default=0.0)  # 0 = disabled
    scan_chunks_for_injection: Mapped[bool] = mapped_column(Boolean, default=True)
    max_tokens_per_chunk: Mapped[int] = mapped_column(Integer, default=512)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="*")  # * = global
    # Sprint 10 fields
    use_partition_isolation: Mapped[bool] = mapped_column(Boolean, default=False)
    partition_prefix: Mapped[str] = mapped_column(String(64), default="tenant_")
    compliance_tagging_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Incident(Base):
    """Incident record for indirect injection detection in retrieved chunks."""
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_type: Mapped[str] = mapped_column(
        String(64), index=True, default="indirect_injection"
    )  # indirect_injection, sensitive_field_block, embedding_anomaly
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    collection_name: Mapped[str] = mapped_column(String(256), index=True, default="")
    chunk_content_hash: Mapped[str] = mapped_column(String(64), default="")
    chunk_id: Mapped[str] = mapped_column(String(256), default="")
    matched_patterns: Mapped[str] = mapped_column(Text, default="[]")  # JSON array of pattern IDs
    risk_level: Mapped[str] = mapped_column(String(16), default="high")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    action_taken: Mapped[str] = mapped_column(String(32), default="blocked")  # blocked, alerted
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CollectionAuditLogRecord(Base):
    """Per-collection audit log for every governed vector DB query (Sprint 10)."""
    __tablename__ = "collection_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    audit_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    timestamp: Mapped[float] = mapped_column(Float, default=0.0)
    collection_name: Mapped[str] = mapped_column(String(256), index=True, default="")
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    operation: Mapped[str] = mapped_column(String(32), default="")
    query_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    namespace_field: Mapped[str] = mapped_column(String(128), default="")
    namespace_value: Mapped[str] = mapped_column(String(128), default="")
    namespace_injected: Mapped[bool] = mapped_column(Boolean, default=False)
    chunks_returned: Mapped[int] = mapped_column(Integer, default=0)
    chunks_blocked: Mapped[int] = mapped_column(Integer, default=0)
    results_capped: Mapped[bool] = mapped_column(Boolean, default=False)
    original_top_k: Mapped[int] = mapped_column(Integer, default=0)
    enforced_top_k: Mapped[int] = mapped_column(Integer, default=0)
    injection_blocks: Mapped[int] = mapped_column(Integer, default=0)
    sensitive_field_blocks: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    compliance_tags_json: Mapped[str] = mapped_column(Text, default="{}")
    requires_private_model: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    provider: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(32), default="allowed")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RoutingRule(Base):
    """Configurable routing rule for sensitivity-based model routing.

    Rules are evaluated in priority order (lower number = higher priority).
    First matching rule wins; unmatched requests fall through to default routing.
    """
    __tablename__ = "routing_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    priority: Mapped[int] = mapped_column(Integer, default=100)  # lower = higher priority
    # Condition fields
    condition_type: Mapped[str] = mapped_column(
        String(64), default="sensitivity"
    )  # sensitivity, budget, compliance_tag, kill_switch, composite
    condition_json: Mapped[str] = mapped_column(
        Text, default="{}"
    )  # e.g. {"tags": ["PII","PHI"], "operator": "any"} or {"budget_exceeded": true}
    # Action fields
    target_model: Mapped[str] = mapped_column(String(128), default="")
    target_provider: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(
        String(32), default="route"
    )  # route, downgrade, block
    # Scope
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="*")  # * = global
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class BudgetTier(Base):
    """Budget tier configuration for model downgrade chains.

    Defines token budget thresholds and downgrade targets per model.
    """
    __tablename__ = "budget_tiers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    model_name: Mapped[str] = mapped_column(String(128), index=True)
    tier_name: Mapped[str] = mapped_column(String(64), default="standard")  # premium, standard, economy
    token_budget: Mapped[int] = mapped_column(Integer, default=1000000)  # tokens per budget window
    downgrade_model: Mapped[str] = mapped_column(String(128), default="")  # model to downgrade to when budget exceeded
    budget_window_seconds: Mapped[int] = mapped_column(Integer, default=3600)  # 1 hour default
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="*")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
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


class KillSwitchAuditLog(Base):
    """Immutable audit log for kill-switch activations/deactivations.

    Records cannot be deleted via API — ensures compliance traceability.
    """
    __tablename__ = "kill_switch_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    model_name: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(16))  # block | reroute
    fallback_model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    activated_by: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(512), default="")
    event_type: Mapped[str] = mapped_column(String(16))  # activated | deactivated
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ── Sprint 13: Provider Health Monitoring & Failover ────────────────────


class ProviderHealthCheck(Base):
    """Health check record for a provider probe."""
    __tablename__ = "provider_health_checks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider_name: Mapped[str] = mapped_column(String(64), index=True)
    is_healthy: Mapped[bool] = mapped_column(Boolean, default=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(String(512), default="")
    error_rate: Mapped[float] = mapped_column(Float, default=0.0)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CircuitBreakerState(Base):
    """Per-provider circuit breaker state."""
    __tablename__ = "circuit_breaker_states"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider_name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    state: Mapped[str] = mapped_column(String(16), default="closed")  # closed, open, half_open
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    last_failure_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    opened_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    half_open_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_threshold: Mapped[int] = mapped_column(Integer, default=5)
    recovery_timeout_seconds: Mapped[int] = mapped_column(Integer, default=60)
    half_open_max_requests: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ProviderCostRecord(Base):
    """Token consumption and estimated cost per provider per tenant."""
    __tablename__ = "provider_cost_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider_name: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    model: Mapped[str] = mapped_column(String(128), index=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class FailoverPolicy(Base):
    """Configurable failover policy per provider."""
    __tablename__ = "failover_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider_name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    error_rate_threshold: Mapped[float] = mapped_column(Float, default=0.5)
    latency_threshold_ms: Mapped[float] = mapped_column(Float, default=5000.0)
    evaluation_window_seconds: Mapped[int] = mapped_column(Integer, default=60)
    fallback_provider: Mapped[str] = mapped_column(String(64), default="")
    auto_failover: Mapped[bool] = mapped_column(Boolean, default=True)
    require_confirmation: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Sprint 15: MCP Server Discovery & Risk Scoring ──────────────────────


class MCPServer(Base):
    """Inventory record for a connected MCP server."""
    __tablename__ = "mcp_servers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    server_name: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    url: Mapped[str] = mapped_column(String(512), default="")
    protocol_version: Mapped[str] = mapped_column(String(32), default="1.0")
    connected_agents: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    aggregate_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")  # critical, high, medium, low
    is_reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class MCPCapability(Base):
    """Discovered capability (tool) from an MCP server."""
    __tablename__ = "mcp_capabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    tool_name: Mapped[str] = mapped_column(String(256), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    parameter_schema_json: Mapped[str] = mapped_column(Text, default="{}")
    required_permissions: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Risk classification
    capability_category: Mapped[str] = mapped_column(
        String(32), default="read"
    )  # read, write, outbound, delete, admin
    data_access_scope: Mapped[str] = mapped_column(
        String(64), default="none"
    )  # none, local, sensitive, external
    has_external_network_access: Mapped[bool] = mapped_column(Boolean, default=False)
    is_destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")  # critical, high, medium, low
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ── Sprint 16: Per-Agent Scope Enforcement ────────────────────────────────


class AgentServiceAccount(Base):
    """Service account for an AI agent with scope enforcement.

    Each agent authenticates via a dedicated service account that carries:
    - allowed MCP servers
    - allowed tool names
    - context scope (document tags/namespaces the agent may access)
    - field-level redaction policy (sensitive fields to strip before agent sees content)
    """
    __tablename__ = "agent_service_accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(String(512), default="")
    # Scope: allowed MCP servers (by server_name)
    allowed_mcp_servers: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Scope: allowed tool names (fully qualified)
    allowed_tools: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Context scope: document tags/namespaces the agent may access
    context_scope: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Field-level redaction: fields to strip from context before agent sees it
    redact_fields: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AgentScopeViolation(Base):
    """Log of scope enforcement violations by agents."""
    __tablename__ = "agent_scope_violations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(256), index=True)
    violation_type: Mapped[str] = mapped_column(
        String(64), index=True
    )  # tool_blocked, context_filtered, field_redacted
    tool_name: Mapped[str] = mapped_column(String(256), default="")
    mcp_server: Mapped[str] = mapped_column(String(256), default="")
    resource_id: Mapped[str] = mapped_column(String(256), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MCPRiskAlert(Base):
    """Alert generated for MCP risk events."""
    __tablename__ = "mcp_risk_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_type: Mapped[str] = mapped_column(
        String(64), index=True
    )  # new_server, critical_capability, unreviewed_connection
    server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    server_name: Mapped[str] = mapped_column(String(256), default="")
    capability_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(256), default="")
    agent_id: Mapped[str] = mapped_column(String(256), default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="high")
    message: Mapped[str] = mapped_column(Text, default="")
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ── Sprint 17: MCP Guardrails Dashboard & Compliance Tagging ────────────


class MCPToolCallAudit(Base):
    """Audit record for every MCP tool call.

    Per-call audit: agent ID, tool name, MCP server, input hash,
    output hash, action taken, compliance tags, timestamp.
    """
    __tablename__ = "mcp_tool_call_audits"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(256), index=True)
    tool_name: Mapped[str] = mapped_column(String(256), index=True)
    mcp_server: Mapped[str] = mapped_column(String(256), index=True)
    input_hash: Mapped[str] = mapped_column(String(64), default="")
    output_hash: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(
        String(32), default="allowed"
    )  # allowed, blocked, filtered, redacted
    compliance_tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    request_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    response_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AgentRiskScoreRecord(Base):
    """Persisted agent risk score snapshot.

    Aggregate risk score per agent based on: connected tool risk scores,
    violation history, scope breadth.
    """
    __tablename__ = "agent_risk_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(256), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    tool_risk_component: Mapped[float] = mapped_column(Float, default=0.0)
    violation_component: Mapped[float] = mapped_column(Float, default=0.0)
    scope_breadth_component: Mapped[float] = mapped_column(Float, default=0.0)
    connected_tools_count: Mapped[int] = mapped_column(Integer, default=0)
    violation_count_24h: Mapped[int] = mapped_column(Integer, default=0)
    total_violations: Mapped[int] = mapped_column(Integer, default=0)
    contributing_factors: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ── Sprint 19: Enterprise Dashboard & Alerting ───────────────────────────


class AlertRule(Base):
    """Configurable alert rule for the real-time alert engine.

    Supports conditions: block_rate_spike, budget_exhaustion,
    new_critical_mcp_tool, kill_switch_activation, anomaly_score_breach.
    Delivery: email, webhook.
    """
    __tablename__ = "alert_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    condition_type: Mapped[str] = mapped_column(
        String(64), index=True
    )  # block_rate_spike, budget_exhaustion, new_critical_mcp_tool, kill_switch_activation, anomaly_score_breach
    condition_config_json: Mapped[str] = mapped_column(Text, default="{}")
    # Delivery
    delivery_channel: Mapped[str] = mapped_column(
        String(32), default="webhook"
    )  # email, webhook
    delivery_target: Mapped[str] = mapped_column(String(512), default="")  # email address or webhook URL
    # Cooldown to prevent alert storms
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300)
    last_fired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Scope
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="*")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AlertEvent(Base):
    """Fired alert event record."""
    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    alert_rule_name: Mapped[str] = mapped_column(String(256), default="")
    condition_type: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="high")  # critical, high, medium, low
    message: Mapped[str] = mapped_column(Text, default="")
    delivery_channel: Mapped[str] = mapped_column(String(32), default="")
    delivery_target: Mapped[str] = mapped_column(String(512), default="")
    delivery_status: Mapped[str] = mapped_column(
        String(16), default="pending"
    )  # pending, sent, failed
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SecurityIncident(Base):
    """Incident record for critical security events.

    Types: critical_threat, namespace_breach, kill_switch_activation, tier2_finding.
    """
    __tablename__ = "security_incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_type: Mapped[str] = mapped_column(
        String(64), index=True
    )  # critical_threat, namespace_breach, kill_switch_activation, tier2_finding
    severity: Mapped[str] = mapped_column(String(16), default="high")  # critical, high, medium, low
    title: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    source_event_id: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(
        String(32), default="open", index=True
    )  # open, investigating, resolved, dismissed
    assigned_to: Mapped[str] = mapped_column(String(128), default="")
    resolution_notes: Mapped[str] = mapped_column(Text, default="")
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class OnboardingProgress(Base):
    """Tracks onboarding wizard progress per tenant."""
    __tablename__ = "onboarding_progress"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Step completion flags
    step_register_model: Mapped[bool] = mapped_column(Boolean, default=False)
    step_issue_api_key: Mapped[bool] = mapped_column(Boolean, default=False)
    step_send_test_request: Mapped[bool] = mapped_column(Boolean, default=False)
    step_verify_audit_log: Mapped[bool] = mapped_column(Boolean, default=False)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RedTeamCampaign(Base):
    """A red team attack simulation campaign."""
    __tablename__ = "red_team_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(256), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    target_url: Mapped[str] = mapped_column(String(1024))
    probe_categories_json: Mapped[str] = mapped_column(
        Text, default='["injection","jailbreak","pii_extraction"]'
    )
    concurrency: Mapped[int] = mapped_column(Integer, default=10)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    total_probes: Mapped[int] = mapped_column(Integer, default=0)
    probes_executed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(128), default="admin")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RedTeamProbeResult(Base):
    """Result of a single probe execution within a campaign."""
    __tablename__ = "red_team_probe_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    probe_id: Mapped[str] = mapped_column(String(32), index=True)
    probe_name: Mapped[str] = mapped_column(String(256), default="")
    category: Mapped[str] = mapped_column(String(64), default="", index=True)
    technique: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    detected: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    response_snippet: Mapped[str] = mapped_column(Text, default="")
    bypass_technique: Mapped[str] = mapped_column(String(256), default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Sprint 24B — Red Team Policy Recommendations, Scheduling & CI/CD API
# ---------------------------------------------------------------------------


class RedTeamPolicyRecommendation(Base):
    """Policy rule recommendation generated from red team probe findings."""
    __tablename__ = "red_team_policy_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    priority: Mapped[str] = mapped_column(String(16), default="high")
    rule_name: Mapped[str] = mapped_column(String(256))
    rule_type: Mapped[str] = mapped_column(String(64), default="block")
    pattern: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    stage: Mapped[str] = mapped_column(String(64), default="input")
    imported: Mapped[bool] = mapped_column(Boolean, default=False)
    imported_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    imported_rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_probe_ids: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RedTeamSchedule(Base):
    """Recurring red team campaign schedule."""
    __tablename__ = "red_team_schedules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(256), index=True)
    target_url: Mapped[str] = mapped_column(String(1024))
    probe_categories_json: Mapped[str] = mapped_column(
        Text, default='["injection","jailbreak","pii_extraction"]'
    )
    concurrency: Mapped[int] = mapped_column(Integer, default=10)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    frequency: Mapped[str] = mapped_column(String(16), default="daily")  # daily, weekly
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_campaign_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), default="admin")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RedTeamRegressionAlert(Base):
    """Alert raised when a scheduled campaign detects a new vulnerability."""
    __tablename__ = "red_team_regression_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    schedule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    current_campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    previous_campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    new_vulnerability_probe_ids: Mapped[str] = mapped_column(Text, default="[]")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    message: Mapped[str] = mapped_column(Text, default="")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ── Sprint 27: A2A Protocol Firewall ────────────────────────────────────


class A2ARegisteredAgent(Base):
    """Registered agent service account for A2A communication."""
    __tablename__ = "a2a_registered_agents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    allowed_downstream: Mapped[str] = mapped_column(Text, default="[]")
    permission_scope: Mapped[str] = mapped_column(Text, default='["read","write"]')
    signing_secret_hash: Mapped[str] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    token_ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class A2AIssuedToken(Base):
    """JWT token issued to an agent."""
    __tablename__ = "a2a_issued_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class A2AAgentCertificate(Base):
    """mTLS certificate for an agent."""
    __tablename__ = "a2a_agent_certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    cert_fingerprint: Mapped[str] = mapped_column(String(128), unique=True)
    spiffe_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    serial_number: Mapped[str] = mapped_column(String(64), unique=True)
    issuer: Mapped[str] = mapped_column(String(128), default="sphinx-ca")
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class A2AMTLSPolicy(Base):
    """mTLS enforcement policy for agent workflows."""
    __tablename__ = "a2a_mtls_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    workflow_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_pairs: Mapped[str] = mapped_column(Text, default="[]")
    framework: Mapped[str] = mapped_column(String(32), default="langgraph")
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class A2AAuditLogEntry(Base):
    """Immutable A2A message audit log entry."""
    __tablename__ = "a2a_audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    record_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    message_id: Mapped[str] = mapped_column(String(64), index=True)
    sender_agent_id: Mapped[str] = mapped_column(String(128), index=True)
    receiver_agent_id: Mapped[str] = mapped_column(String(128), index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    message_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    framework: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    token_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    nonce_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    mtls_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    action_taken: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enforcement_duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class A2ANonceLog(Base):
    """Used nonces for replay attack prevention."""
    __tablename__ = "a2a_nonce_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    nonce: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# ── Sprint 28: HITL Enforcement Checkpoints + Cascading Failure Detection ──


class ApprovalRequest(Base):
    """Human-in-the-loop approval request created when policy triggers require_approval."""
    __tablename__ = "approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    action_description: Mapped[str] = mapped_column(Text, default="")
    risk_context: Mapped[str] = mapped_column(Text, default="{}")
    risk_level: Mapped[str] = mapped_column(String(16), default="high")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    matched_patterns: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(
        String(16), default="pending", index=True
    )  # pending, approved, rejected, expired
    fallback_action: Mapped[str] = mapped_column(String(16), default="block")  # auto-approve | block
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    decided_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    decision_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notification_channels: Mapped[str] = mapped_column(Text, default='["slack"]')
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AgentBehavioralBaseline(Base):
    """Per-agent behavioral baseline built over observation period."""
    __tablename__ = "agent_behavioral_baselines"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    observation_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observation_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_baseline_ready: Mapped[bool] = mapped_column(Boolean, default=False)
    tool_call_sequence_patterns: Mapped[str] = mapped_column(Text, default="{}")
    avg_output_volume: Mapped[float] = mapped_column(Float, default=0.0)
    std_output_volume: Mapped[float] = mapped_column(Float, default=0.0)
    avg_api_call_frequency: Mapped[float] = mapped_column(Float, default=0.0)
    std_api_call_frequency: Mapped[float] = mapped_column(Float, default=0.0)
    total_observations: Mapped[int] = mapped_column(Integer, default=0)
    baseline_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AgentBehavioralEvent(Base):
    """Individual agent behavioral event for baseline computation."""
    __tablename__ = "agent_behavioral_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)  # tool_call, api_call, output
    tool_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class CascadingFailureEvent(Base):
    """Recorded anomaly event from cascading failure detector."""
    __tablename__ = "cascading_failure_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    anomaly_type: Mapped[str] = mapped_column(String(64))  # volume_spike, frequency_spike, pattern_deviation
    deviation_score: Mapped[float] = mapped_column(Float, default=0.0)
    circuit_breaker_state: Mapped[str] = mapped_column(
        String(16), default="closed"
    )  # closed, open, half_open
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
