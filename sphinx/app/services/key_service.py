import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey
from app.services.redis_client import get_redis

CACHE_TTL = 300  # 5 minutes


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> str:
    return f"spx-{secrets.token_urlsafe(32)}"


def _serialize_key_data(key: APIKey) -> dict:
    return {
        "id": str(key.id),
        "tenant_id": key.tenant_id,
        "project_id": key.project_id,
        "allowed_models": key.allowed_models or [],
        "tpm_limit": key.tpm_limit,
        "risk_score": key.risk_score,
        "is_active": key.is_active,
        "expires_at": key.expires_at.isoformat() if key.expires_at else None,
    }


async def validate_api_key(raw_key: str) -> Optional[dict]:
    """Validate an API key. Checks Redis cache first, falls back to DB."""
    key_hash_val = hash_key(raw_key)
    r = await get_redis()

    # Check Redis cache
    cached = await r.get(f"apikey:{key_hash_val}")
    if cached:
        data = json.loads(cached)
        if not data["is_active"]:
            return None
        if data["expires_at"]:
            if datetime.fromisoformat(data["expires_at"]) < datetime.now(timezone.utc):
                return None
        return data

    return None  # DB lookup handled at service layer


async def validate_api_key_from_db(raw_key: str, db: AsyncSession) -> Optional[dict]:
    """Validate API key from database and populate cache."""
    key_hash_val = hash_key(raw_key)
    result = await db.execute(select(APIKey).where(APIKey.key_hash == key_hash_val))
    key = result.scalar_one_or_none()

    if key is None:
        return None

    if not key.is_active:
        return None

    if key.expires_at and key.expires_at < datetime.now(timezone.utc):
        return None

    data = _serialize_key_data(key)

    # Cache in Redis
    r = await get_redis()
    await r.setex(f"apikey:{key_hash_val}", CACHE_TTL, json.dumps(data))

    return data


async def create_api_key(
    db: AsyncSession,
    tenant_id: str,
    project_id: str,
    allowed_models: list[str] | None = None,
    tpm_limit: int = 100000,
    expires_at: datetime | None = None,
) -> tuple[str, APIKey]:
    """Create a new API key. Returns (raw_key, api_key_record)."""
    raw_key = generate_api_key()
    key_hash_val = hash_key(raw_key)

    api_key = APIKey(
        id=uuid.uuid4(),
        key_hash=key_hash_val,
        key_prefix=raw_key[:8],
        tenant_id=tenant_id,
        project_id=project_id,
        allowed_models=allowed_models or [],
        tpm_limit=tpm_limit,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    # Pre-populate cache
    r = await get_redis()
    await r.setex(
        f"apikey:{key_hash_val}", CACHE_TTL, json.dumps(_serialize_key_data(api_key))
    )

    return raw_key, api_key


async def revoke_api_key(db: AsyncSession, key_id: uuid.UUID) -> bool:
    """Revoke an API key by ID."""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    key = result.scalar_one_or_none()
    if key is None:
        return False

    key.is_active = False
    await db.commit()

    # Invalidate cache
    r = await get_redis()
    await r.delete(f"apikey:{key.key_hash}")

    return True
