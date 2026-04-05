from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://sphinx:sphinx_secret@localhost:5432/sphinx"
    redis_url: str = "redis://localhost:6379/0"
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8000
    credential_encryption_key: str = ""
    default_provider_url: str = "http://localhost:9000"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
