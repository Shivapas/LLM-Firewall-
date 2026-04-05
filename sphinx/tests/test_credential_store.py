import pytest
from unittest.mock import patch
from cryptography.fernet import Fernet

from app.services.credential_store import encrypt_credential, decrypt_credential


@pytest.fixture(autouse=True)
def mock_encryption_key():
    key = Fernet.generate_key().decode()
    with patch("app.services.credential_store.get_settings") as mock_settings:
        mock_settings.return_value.credential_encryption_key = key
        yield key


def test_encrypt_decrypt_roundtrip():
    plaintext = "sk-test-openai-key-12345"
    encrypted = encrypt_credential(plaintext)
    assert encrypted != plaintext
    decrypted = decrypt_credential(encrypted)
    assert decrypted == plaintext


def test_different_encryptions_differ():
    plaintext = "sk-test-key"
    enc1 = encrypt_credential(plaintext)
    enc2 = encrypt_credential(plaintext)
    # Fernet uses random IV, so encryptions should differ
    assert enc1 != enc2
    # But both decrypt to the same value
    assert decrypt_credential(enc1) == decrypt_credential(enc2) == plaintext
