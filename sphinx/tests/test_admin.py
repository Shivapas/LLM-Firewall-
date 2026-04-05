from unittest.mock import patch, AsyncMock, MagicMock
import uuid
from datetime import datetime, timezone

from app.main import app
from app.services.database import get_db


def test_create_key_endpoint(client):
    """Test creating an API key via admin endpoint."""
    key_id = uuid.uuid4()
    mock_key = MagicMock()
    mock_key.id = key_id
    mock_key.key_prefix = "spx-abcd"
    mock_key.tenant_id = "tenant-1"
    mock_key.project_id = "project-1"

    with patch("app.routers.admin.create_api_key") as mock_create:
        mock_create.return_value = ("spx-abcdefghijklmnop", mock_key)

        response = client.post(
            "/admin/keys",
            json={
                "tenant_id": "tenant-1",
                "project_id": "project-1",
                "allowed_models": ["gpt-4"],
                "tpm_limit": 50000,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == "tenant-1"
        assert data["raw_key"].startswith("spx-")


def test_list_keys_endpoint(client):
    """Test listing API keys."""
    mock_key = MagicMock()
    mock_key.id = uuid.uuid4()
    mock_key.key_prefix = "spx-test"
    mock_key.tenant_id = "tenant-1"
    mock_key.project_id = "project-1"
    mock_key.allowed_models = ["gpt-4"]
    mock_key.tpm_limit = 100000
    mock_key.risk_score = 0.0
    mock_key.is_active = True
    mock_key.expires_at = None
    mock_key.created_at = datetime.now(timezone.utc)

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_key]
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.get("/admin/keys")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["tenant_id"] == "tenant-1"
    finally:
        app.dependency_overrides.clear()


def test_delete_key_endpoint(client):
    """Test revoking an API key."""
    key_id = uuid.uuid4()

    with patch("app.routers.admin.revoke_api_key") as mock_revoke:
        mock_revoke.return_value = True

        response = client.delete(f"/admin/keys/{key_id}")
        assert response.status_code == 200
        assert response.json()["status"] == "revoked"


def test_delete_nonexistent_key(client):
    """Test revoking a nonexistent key returns 404."""
    key_id = uuid.uuid4()

    with patch("app.routers.admin.revoke_api_key") as mock_revoke:
        mock_revoke.return_value = False

        response = client.delete(f"/admin/keys/{key_id}")
        assert response.status_code == 404
