import pytest
from app.services.key_service import hash_key, generate_api_key


def test_hash_key_deterministic():
    key = "spx-test-key-12345"
    assert hash_key(key) == hash_key(key)


def test_hash_key_unique():
    assert hash_key("key-a") != hash_key("key-b")


def test_generate_api_key_format():
    key = generate_api_key()
    assert key.startswith("spx-")
    assert len(key) > 20


def test_generate_api_key_unique():
    keys = {generate_api_key() for _ in range(100)}
    assert len(keys) == 100
