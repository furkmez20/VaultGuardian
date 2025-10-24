# tests/test_auth.py
import importlib
import pytest

def test_health_or_home(client):
    # Try a few common routes; accept 200/302/401/403 depending on auth config
    for path in ("/", "/login", "/health", "/status"):
        resp = client.get(path)
        if resp.status_code != 404:
            assert resp.status_code in (200, 302, 401, 403)
            return
    pytest.skip("No common public route found. Add the correct route to the test.")

def test_protected_like_dashboard_requires_auth(client):
    # If your app redirects unauthenticated users, 302 is fine; 401/403 also fine.
    resp = client.get("/dashboard")
    assert resp.status_code in (302, 401, 403)
