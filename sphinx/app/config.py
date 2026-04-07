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
