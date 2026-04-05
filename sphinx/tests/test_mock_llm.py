from fastapi.testclient import TestClient
from mock_llm.server import app


def test_mock_chat_completions():
    client = TestClient(app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "mock-model",
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "choices" in data
    assert data["choices"][0]["message"]["content"].startswith("Mock response to:")


def test_mock_chat_completions_streaming():
    client = TestClient(app)
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "mock-model",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": True,
        },
    )
    assert response.status_code == 200
    content = response.text
    assert "data:" in content
    assert "[DONE]" in content


def test_mock_list_models():
    client = TestClient(app)
    response = client.get("/v1/models")
    assert response.status_code == 200
    data = response.json()
    assert data["object"] == "list"
    assert len(data["data"]) == 2
