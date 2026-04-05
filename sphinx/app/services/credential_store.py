import uuid
from typing import Optional

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.api_key import ProviderCredential


def _get_cipher() -> Fernet:
    key = get_settings().credential_encryption_key
    if not key:
        raise ValueError("CREDENTIAL_ENCRYPTION_KEY not configured")
    return Fernet(key.encode())


def encrypt_credential(plaintext: str) -> str:
    return _get_cipher().encrypt(plaintext.encode()).decode()


def decrypt_credential(ciphertext: str) -> str:
    return _get_cipher().decrypt(ciphertext.encode()).decode()


async def store_provider_credential(
    db: AsyncSession,
    provider_name: str,
    api_key: str,
    base_url: str,
    is_enabled: bool = True,
) -> ProviderCredential:
    """Store an encrypted provider credential."""
    encrypted = encrypt_credential(api_key)

    # Upsert
    result = await db.execute(
        select(ProviderCredential).where(
            ProviderCredential.provider_name == provider_name
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.encrypted_api_key = encrypted
        existing.base_url = base_url
        existing.is_enabled = is_enabled
    else:
        existing = ProviderCredential(
            id=uuid.uuid4(),
            provider_name=provider_name,
            encrypted_api_key=encrypted,
            base_url=base_url,
            is_enabled=is_enabled,
        )
        db.add(existing)

    await db.commit()
    await db.refresh(existing)
    return existing


async def get_provider_credential(
    db: AsyncSession, provider_name: str
) -> Optional[dict]:
    """Retrieve and decrypt a provider credential."""
    result = await db.execute(
        select(ProviderCredential).where(
            ProviderCredential.provider_name == provider_name
        )
    )
    cred = result.scalar_one_or_none()
    if cred is None or not cred.is_enabled:
        return None

    return {
        "provider_name": cred.provider_name,
        "api_key": decrypt_credential(cred.encrypted_api_key),
        "base_url": cred.base_url,
        "is_enabled": cred.is_enabled,
    }


async def list_providers(db: AsyncSession) -> list[dict]:
    """List all providers (without decrypted keys)."""
    result = await db.execute(select(ProviderCredential))
    return [
        {
            "id": str(c.id),
            "provider_name": c.provider_name,
            "base_url": c.base_url,
            "is_enabled": c.is_enabled,
        }
        for c in result.scalars().all()
    ]
