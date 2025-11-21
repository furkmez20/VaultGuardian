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
In the root directory of Vault Guardian, find the generate_keys.py file
Run the script: python generate_keys.py

The script will output two keys:
- SECRET_KEY= (a random string)
- ENCRYPTION_KEY= (a 32-byte base64-encoded key)
copy both keys

# Set up .env folder
In the root directory of Vault Guardian, create a file named .env
If .env already exists, open it for editing

Paste keys from generate_keys here: 

SECRET_KEY=your-super-secret-key
ENCRYPTION_KEY=your-32-byte-base64-encoded-encryption-key

# Setting up email otp
Email OTP allows users to receive a 6-digit code via email. This is configured using Gmail's SMTP server.

Enabling 2-Factor Authentication on Your Gmail Account:
1. Create or Use Your Gmail Account
2. Go to https://myaccount.google.com/
3. Click on "Security" in the left sidebar
4. Scroll down to "How you sign in to Google"
5. Click on "2-Step Verification"
6. Follow the prompts to set up 2FA using your phone
   - You'll need to verify with a code sent to your phone or authenticator app
7. Once complete, you should see "2-Step Verification is on"

Generating a Gmail App Password:
1. Go back to https://myaccount.google.com/
2. Click on "Security" in the left sidebar
3. Scroll down to find "App passwords" or search for it in search bar
   - If you don't see "App passwords," make sure 2FA is fully set up first
4. In the "App passwords" section:
   - Select "Mail" from the first dropdown
   - Select "Windows Computer" (or your device type) from the second dropdown
5. Click "Generate"
6. Google will show you a 16-character password (example: raff iefa ctds zhoj)
7. Copy this password - you'll need it in the next step

Adding Configuration Variables in .env File:

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password #get it from your Google MFA password

So your entire .env file should look like this;
SECRET_KEY=your-secret-key-from-generate-keys.py
ENCRYPTION_KEY=your-encryption-key-from-generate-keys.py
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-16-char-app-password
DATABASE_URL=sqlite:///./data/vault.db


# Run the database
1. Navigate to /Users/aaryaamoharir/repos/VaultGuardian/src and Run python3 "migrate_data.py" 
2. Navigate to /Users/aaryaamoharir/repos/VaultGuardian and run **sqlite3 data/vault.db ** to see what information is stored in the database currently. Potential commands to test out include SELECT * FROM users;

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
