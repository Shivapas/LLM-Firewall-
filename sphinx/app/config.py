from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = ""
    redis_url: str = "redis://localhost:6379/0"
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8000
    credential_encryption_key: str = ""
    default_provider_url: str = "http://localhost:9000"
    kafka_bootstrap_servers: str = "localhost:9092"
    admin_api_token: str = ""
    allowed_provider_hosts: str = ""  # Comma-separated allowlist of provider hostnames

    # Thoth Semantic Classification Integration (Sprint 1)
    thoth_enabled: bool = False
    thoth_api_url: str = ""
    thoth_api_key: str = ""
    thoth_timeout_ms: int = 150  # Per FR-PRE-06: default 150ms timeout
    thoth_max_retries: int = 1   # Retries before timeout fallback

    # Thoth Circuit Breaker (Sprint 2 / S2-T2 — FR-CFG-03)
    # Sustained error rate above threshold disables Thoth calls and
    # activates structural-only enforcement mode.
    thoth_circuit_breaker_enabled: bool = True
    thoth_circuit_breaker_error_threshold: int = 5   # Consecutive failures to open
    thoth_circuit_breaker_recovery_timeout_s: float = 30.0  # Seconds before half-open probe

    # Thoth FAIL_CLOSED mode (Sprint 2 / S2-T3 — FR-PRE-07)
    # When enabled and Thoth is unavailable, block requests whose structural
    # risk level matches thoth_fail_closed_risk_levels (comma-separated).
    thoth_fail_closed_enabled: bool = False  # Default: allow on unavailability
    thoth_fail_closed_risk_levels: str = "HIGH,CRITICAL"  # Structural risk levels triggering block

    # Thoth Post-Inference Async Classification (Sprint 4 / S4-T1 — FR-POST-01)
    # Timeout is longer than the pre-inference 150ms since post-inference runs
    # asynchronously and does not add to the end-to-end request latency.
    thoth_post_inference_enabled: bool = True   # Enable async response classification
    thoth_post_inference_timeout_ms: int = 5000  # 5 s timeout for response classification

    # SIEM / Data Lake Export (Sprint 4 / S4-T5 — FR-POST-05)
    siem_export_enabled: bool = False
    siem_export_url: str = ""
    siem_export_api_key: str = ""
    siem_export_format: str = "webhook"      # webhook | splunk_hec | datadog
    siem_export_timeout_ms: int = 5000
    siem_export_batch_size: int = 50
    siem_export_flush_interval_s: float = 5.0

    # Thoth Gateway / Proxy Integration Mode (Sprint 6)
    # Per-application (route-level) classification configuration.
    # S6-T1: Proxy plugin — Thoth callable from reverse proxy intercept layer.
    thoth_proxy_plugin_enabled: bool = True   # Enable ThothProxyPlugin in the proxy layer
    # S6-T2: Per-application classification enablement via RouteConfigRegistry.
    # JSON string or path to a file containing per-route config list.
    # Format: '[{"application_id": "app1", "enabled": true, "timeout_ms": 200}]'
    # Empty string means no per-route overrides; all routes use global thoth_enabled.
    thoth_route_configs_json: str = ""
    # S6-T3: Cross-vendor parity — vendor detection is always active when
    # thoth_proxy_plugin_enabled is True; no additional flag needed.

    # Indian Regulatory Compliance Mode — Sprint 7 (DPDPA / CERT-In)
    # S7-T1: On-prem / VPC Thoth endpoint support with residency tagging.
    # JSON string containing residency config list.
    # Format: '[{"application_id": "*", "region": "in-mum-1",
    #   "deployment_mode": "on_prem", "data_residency_zone": "INDIA",
    #   "endpoint_url_override": "https://thoth.internal.in:8443",
    #   "regulatory_tags": ["DPDPA_COMPLIANT"], "require_on_prem": true}]'
    thoth_residency_configs_json: str = ""

    # S7-T3: PII content hashing before Thoth transmission (DPDPA data minimisation).
    thoth_pii_hashing_enabled: bool = False
    thoth_pii_hashing_salt: str = ""       # HMAC salt — MUST be set in production
    thoth_pii_hashing_types: str = "AADHAAR,PAN,BANK_ACCOUNT"  # PII types to hash

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @field_validator("database_url")
    @classmethod
    def database_url_must_be_set(cls, v: str) -> str:
        if not v:
            raise ValueError(
                "DATABASE_URL must be set. "
                "Example: postgresql+asyncpg://user:pass@host:5432/dbname"
            )
        return v

    @field_validator("credential_encryption_key")
    @classmethod
    def encryption_key_must_be_set(cls, v: str) -> str:
        if not v:
            raise ValueError(
                "CREDENTIAL_ENCRYPTION_KEY must be set. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
