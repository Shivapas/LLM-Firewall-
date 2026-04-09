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
