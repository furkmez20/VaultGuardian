import importlib
import base64
import pytest

crypto_mod = importlib.import_module("src.crypto")
CryptoManager = getattr(crypto_mod, "CryptoManager")

def test_encrypt_decrypt_with_provided_key():
    mgr = CryptoManager()
    key = mgr.generate_key()
    pt = "vault-guardian-🔐"
    token = mgr.encrypt_data(pt, key=key)
    base64.urlsafe_b64decode(token.encode())  # is valid base64
    rt = mgr.decrypt_data(token, key=key)
    assert rt == pt

def test_encrypt_decrypt_with_master_password():
    mgr = CryptoManager(master_password="S3cret!@#")
    pt = "top-secret-cookie"
    token = mgr.encrypt_data(pt)
    decoded = base64.urlsafe_b64decode(token.encode())
    assert len(decoded) > 16  # salt + ciphertext
    rt = mgr.decrypt_data(token)
    assert rt == pt

def test_decrypt_bad_token_raises():
    mgr = CryptoManager(master_password="S3cret!@#")
    with pytest.raises(ValueError):
        mgr.decrypt_data("not-a-valid-token")
