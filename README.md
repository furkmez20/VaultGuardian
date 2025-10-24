# VaultGuardian
VaultGuardian is a secure Flask-based password manager that encrypts credentials, supports multi-factor authentication (TOTP &amp; email OTP), and provides a clean dashboard for adding, editing, and managing sensitive data. Built with Flask, WTForms, and Bootstrap for a modern, user-friendly experience.

Quick start
from the repo root
# Create virtual enviroment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Download python
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest pytest-cov pyotp "qrcode[pil]" pillow cryptography python-dotenv

# Generate Keys
python generate_keys.py

# Set up .env folder
Paste keys from generate_keys here 
Create a .env file in the project root:
SECRET_KEY=your-super-secret-key
ENCRYPTION_KEY=your-32-byte-base64-encoded-encryption-key
# Setting up email otp
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password #get it from your Google MFA password


# Run the database
1. Run python3 "migrate_data.py" 
2. Run **sqlite3 data/vault.db ** to see what information is stored in the database currently. Potential commands to test out include SELECT * FROM users;

# Run the App
python app.py

# Testing

Run the VaultGuardian test suite locally with a virtual environment. These tests use a temporary JSON file as the datastore and stub email sending, so they won’t touch real data or SMTP.

Prerequisites
Python 3.11+ (3.13 works too)
git, pip

Run tests
full suite with coverage summary
python -m pytest --cov=src --cov-report=term-missing

# Future code
1. Connect the database to the login-page
2. Connect the stored credentials to password manager 
