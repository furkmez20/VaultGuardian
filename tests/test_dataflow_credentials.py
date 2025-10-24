# tests/test_dataflow_credentials.py
import json
import importlib
import pyotp

def test_add_and_view_credential_roundtrip(client, app, monkeypatch):
    app_mod = importlib.import_module("src.app")

    # Make CryptoManager no-op for this test (focus on data flow, not crypto)
    from src.crypto import CryptoManager
    monkeypatch.setattr(CryptoManager, "encrypt_data", lambda self, s, key=None: s)
    monkeypatch.setattr(CryptoManager, "decrypt_data", lambda self, s, key=None: s)

    # Register a user (CSRF disabled in tests via conftest)
    r = client.post("/register", data={
        "username": "eve",
        "password": "P@ssw0rd!",
        "confirm_password": "P@ssw0rd!",
        "email": "eve@example.com",
    }, follow_redirects=False)
    assert r.status_code in (302, 303)

    # Complete MFA so protected routes work
    user = app_mod.data_store.get_user("eve")
    code = pyotp.TOTP(user.mfa_secret).now()
    with client.session_transaction() as s:
        s["username"] = "eve"
    r = client.post("/mfa", data={"otp_code": code}, follow_redirects=False)
    assert r.status_code in (302, 303)

    # Submit the Add Credential form (frontend -> server)
    form = {
        "title": "GitHub",
        "username": "eve-gh",
        "password": "token123",
        "url": "https://github.com",
        "notes": "personal",
        "credential_id": "",  # new
    }
    r = client.post("/add_credential", data=form, follow_redirects=True)
    assert r.status_code in (200, 302)

    # Verify it was persisted (server -> database)
    creds = app_mod.data_store.get_credentials("eve")
    assert len(creds) == 1
    cred = creds[0]
    assert cred.title == "GitHub"
    assert cred.encrypted_data  # stored (even though we patched crypto)

    # Read it back via the view endpoint (database -> server -> frontend/json)
    r = client.get(f"/view_credential/{cred.id}")
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["title"] == "GitHub"
    assert payload["username"] == "eve-gh"
    assert payload["password"] == "token123"
    assert payload["url"] == "https://github.com"
    assert payload["notes"] == "personal"
