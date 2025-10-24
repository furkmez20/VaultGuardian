import pyotp
from src.models import User

def _get_user(app, username):
    # access the swapped data_store in src.app
    import src.app as app_mod
    return app_mod.data_store.get_user(username)

def test_register_then_totp_verify_then_dashboard(client, app):
    # 1) Register (CSRF off in tests, see conftest)
    r = client.post("/register", data={
        "username": "alice",
        "password": "P@ssw0rd!",
        "confirm_password": "P@ssw0rd!",
        "email": "alice@example.com"
    }, follow_redirects=False)
    # Should redirect to setup MFA
    assert r.status_code in (302, 303)

    # Grab the generated MFA secret from the JSON store
    user = _get_user(app, "alice")
    assert isinstance(user, User)
    secret = user.mfa_secret
    code = pyotp.TOTP(secret).now()

    # 2) Simulate the login step that sets session['username'] (normally via /login)
    with client.session_transaction() as sess:
        sess["username"] = "alice"

    # 3) POST TOTP to /mfa to complete MFA
    r2 = client.post("/mfa", data={"otp_code": code}, follow_redirects=False)
    assert r2.status_code in (302, 303)

    # 4) Access dashboard (now requires username + mfa_verified)
    r3 = client.get("/dashboard")
    assert r3.status_code == 200

def test_dashboard_requires_auth(client):
    r = client.get("/dashboard")
    assert r.status_code in (302, 401, 403)
