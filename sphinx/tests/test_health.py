from unittest.mock import patch, AsyncMock


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_all_up(client, mock_redis):
    mock_engine = AsyncMock()
    with patch("app.routers.health.get_redis", return_value=mock_redis):
        with patch("app.routers.health.engine") as engine_mock:
            # Mock the async context manager for engine.connect()
            conn_mock = AsyncMock()
            conn_mock.execute = AsyncMock()
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=conn_mock)
            ctx.__aexit__ = AsyncMock(return_value=False)
            engine_mock.connect.return_value = ctx

            response = client.get("/ready")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ready"
            assert data["checks"]["redis"] is True
            assert data["checks"]["postgres"] is True


def test_readiness_redis_down(client):
    failing_redis = AsyncMock()
    failing_redis.ping = AsyncMock(side_effect=ConnectionError("Redis down"))
    with patch("app.routers.health.get_redis", return_value=failing_redis):
        with patch("app.routers.health.engine") as engine_mock:
            conn_mock = AsyncMock()
            conn_mock.execute = AsyncMock()
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=conn_mock)
            ctx.__aexit__ = AsyncMock(return_value=False)
            engine_mock.connect.return_value = ctx

            response = client.get("/ready")
            assert response.status_code == 503
            data = response.json()
            assert data["checks"]["redis"] is False
