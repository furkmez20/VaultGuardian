import pytest

def test_app_responds_somewhere(client):
    # Accept any non-404 response from a common route
    for path in ("/", "/login", "/dashboard", "/health", "/status"):
        r = client.get(path)
        if r.status_code != 404:
            assert r.status_code in (200, 302, 401, 403)
            return
    pytest.skip("No common route found; adjust to an existing route.")
