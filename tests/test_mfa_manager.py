import base64
import time
import importlib
import pyotp

mfa_mod = importlib.import_module("src.mfa")
MFAManager = getattr(mfa_mod, "MFAManager")

def test_totp_roundtrip_with_class():
    mgr = MFAManager()
    secret = mgr.generate_secret()
    code = pyotp.TOTP(secret).now()
    assert mgr.verify_totp(secret, code) is True

def test_email_otp_generate_verify_and_reuse_blocked():
    mgr = MFAManager(mail_app=None)  # no SMTP
    email = "user@example.com"
    otp = mgr.generate_email_otp(email)
    assert len(otp) == 6 and otp.isdigit()
    assert mgr.verify_email_otp(email, otp) is True
    assert mgr.verify_email_otp(email, otp) is False  # cannot reuse

def test_email_otp_expiry():
    mgr = MFAManager(mail_app=None)
    email = "exp@example.com"
    _ = mgr.generate_email_otp(email)
    mgr.email_otp_cache[email]["timestamp"] = time.time() - 400  # > 300s
    assert mgr.verify_email_otp(email, mgr.email_otp_cache[email]["otp"]) is False

def test_qr_code_is_base64_png():
    mgr = MFAManager()
    secret = mgr.generate_secret()
    b64_png = mgr.generate_qr_code("user@example.com", secret, issuer_name="Vault Guardian")
    raw = base64.b64decode(b64_png)
    assert raw.startswith(b"\x89PNG")
