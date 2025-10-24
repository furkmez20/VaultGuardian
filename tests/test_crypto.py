import os
import importlib
import base64
import pytest

crypto_mod = importlib.import_module("src.crypto")
CryptoManager = getattr(crypto_mod, "CryptoManager")

def test_encrypt_decrypt_with_provided_key():
    mgr = CryptoManager()
    key = mgr.generate_key()  # Fernet key (urlsafe base64 bytes)
    plaintext = "vault-guardian-🔐"
    token = mgr.encrypt_data(plaintext, key=key)
    # should be URL-safe base64 string
    base64.urlsafe_b64decode(token.encode())
    result = mgr.decrypt_data(token, key=key)
    assert result == plaintext

def test_encrypt_decrypt_with_master_password():
    mgr = CryptoManager(master_password="S3cret!@#")
    plaintext = "top-secret-cookie"
    token = mgr.encrypt_data(plaintext)  # derives key from password, prepends salt
    # token is base64(salt(16 bytes) + encrypted)
    decoded = base64.urlsafe_b64decode(token.encode())
    assert len(decoded) > 16
    result = mgr.decrypt_data(token)     # derives same key from embedded salt
    assert result == plaintext

def test_decrypt_bad_token_raises():
    mgr = CryptoManager(master_password="S3cret!@#")
    with pytest.raises(ValueError):
        mgr.decrypt_data("not-a-valid-token")
