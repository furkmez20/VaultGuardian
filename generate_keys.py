# generate_keys.py - Run this to generate secure keys
import secrets
import base64
from cryptography.fernet import Fernet

print("🔐 Generating secure keys for Vault Guardian...")
print("=" * 50)

# Generate Flask SECRET_KEY
secret_key = secrets.token_urlsafe(32)
print(f"SECRET_KEY={secret_key}")

# Generate encryption key
encryption_key = Fernet.generate_key().decode()
print(f"ENCRYPTION_KEY={encryption_key}")

print("=" * 50)
print("📋 Copy these values to your .env file!")
print("⚠️  Keep these keys secret and secure!")

# Create a sample .env file
env_content = f"""# Vault Guardian Environment Variables
SECRET_KEY={secret_key}
ENCRYPTION_KEY={encryption_key}

# Email Configuration (Optional - for email OTP)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
"""

with open('.env.example', 'w') as f:
    f.write(env_content)

print("📁 Created .env.example file - rename it to .env and update email settings if needed!")