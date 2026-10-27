# VaultGuardian

VaultGuardian is a Flask credential manager with account registration, login, multi-factor verification, and a dashboard for saving and managing encrypted credentials. It uses SQLite by default and can send one-time codes by email when SMTP settings are configured.

> This repository is a learning project. It has not been documented or tested here as a production password manager.

## Features

- Register and sign in with password hashing and temporary lockout after repeated failed attempts.
- Set up TOTP-based MFA with a QR code, or use email OTP when mail is configured.
- Add, edit, and delete saved credentials.
- Encrypt credential data with Fernet using a key derived from the master password.
- Persist application records through Flask-SQLAlchemy; SQLite is the default database.

## Stack

Python, Flask, Flask-WTF, WTForms, Flask-SQLAlchemy, SQLite, `cryptography`, `pyotp`, `qrcode`, and optional Flask-Mail SMTP delivery.

## Architecture

```text
Browser forms and templates
          |
Flask routes, sessions, and CSRF protection
          |
Authentication / MFA / credential services
          |
Flask-SQLAlchemy -> SQLite by default
```

The Flask app creates its database tables at startup. Set `DATABASE_URL` to use a different SQLAlchemy-supported database.

## Run locally

### Requirements

- Python 3.11 or newer
- pip

Create and activate a virtual environment, then install the pinned dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

Generate local keys:

```bash
python generate_keys.py
```

The helper prints keys and writes them to `.env.example`. Copy the generated `SECRET_KEY` and `ENCRYPTION_KEY` into a local `.env` file, then keep generated secrets out of Git. The app also accepts `DATABASE_URL`. For email OTP, set `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, and `MAIL_PASSWORD` in `.env`.

Start the app from the repository root:

```bash
python run.py
```

Open `http://127.0.0.1:5000` in a browser. Without explicit key configuration, the source falls back to development-only key values; do not use those defaults for real credentials.

## Tests

Run the included tests with:

```bash
python -m pytest
```

## Demo

No public demo URL is listed.

## Repository

[furkmez20/VaultGuardian](https://github.com/furkmez20/VaultGuardian)
