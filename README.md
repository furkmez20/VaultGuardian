# VaultGuardian
VaultGuardian is a secure Flask-based password manager that encrypts credentials, supports multi-factor authentication (TOTP &amp; email OTP), and provides a clean dashboard for adding, editing, and managing sensitive data. Built with Flask, WTForms, and Bootstrap for a modern, user-friendly experience.

# Testing

Run the VaultGuardian test suite locally with a virtual environment. These tests use a temporary JSON file as the datastore and stub email sending, so they won’t touch real data or SMTP.

Prerequisites
Python 3.11+ (3.13 works too)
git, pip

Quick start
from the repo root
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest pytest-cov pyotp "qrcode[pil]" pillow cryptography python-dotenv

Run tests
full suite with coverage summary
python -m pytest --cov=src --cov-report=term-missing
