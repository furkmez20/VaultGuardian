# tests/conftest.py
import os, tempfile, importlib, types, pytest
from pathlib import Path

@pytest.fixture(scope="session")
def app():
    app_mod = importlib.import_module("src.app")
    app = app_mod.app

    # test-mode config
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # point datastore at a temp file (isolated)
    tmp = tempfile.NamedTemporaryFile(prefix="vault_", suffix=".json", delete=False)
    tmp_path = Path(tmp.name); tmp.close()
    from src.models import JSONDataStore
    app_mod.data_store = JSONDataStore(json_path=str(tmp_path))

    # --- rebind managers to the NEW store/mail ---
    from src.auth import AuthManager
    from src.mfa import MFAManager

    # fake mail so /send_email_otp doesn't touch SMTP
    class FakeMail:
        default_sender = "noreply@test.local"
        def send(self, msg): pass

    app_mod.mail = FakeMail()
    app_mod.auth_manager = AuthManager(app_mod.data_store)
    app_mod.mfa_manager  = MFAManager(app_mod.mail)
    # ---------------------------------------------

    yield app

    try: tmp_path.unlink(missing_ok=True)
    except Exception: pass

@pytest.fixture()
def client(app):
    return app.test_client()
