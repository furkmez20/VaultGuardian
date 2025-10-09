import time
import pyotp
import qrcode
import io
import base64
import random
import string
from flask_mail import Mail, Message
from PIL import Image

class MFAManager:
    def __init__(self, mail_app=None):
        self.mail = mail_app
        self.email_otp_cache = {}  # In production, use Redis or database
    
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, username: str, secret: str, issuer_name: str = "Vault Guardian") -> str:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer_name
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 string
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception:
            return False
    
    def generate_email_otp(self, email: str) -> str:
        """Generate and cache email OTP"""
        otp = ''.join(random.choices(string.digits, k=6))
        self.email_otp_cache[email] = {
            'otp': otp,
            'timestamp': time.time()
        }
        return otp
    
    def send_email_otp(self, email: str) -> bool:
        """Send OTP via email"""
        if not self.mail:
            return False
        
        try:
            otp = self.generate_email_otp(email)
            msg = Message(
                'Your Vault Guardian OTP',
                sender=self.mail.default_sender,
                #sender='noreply@vaultguardian.com',
                recipients=[email]
            )
            msg.body = f'Your one-time password is: {otp}\n\nThis code will expire in 5 minutes.'
            self.mail.send(msg)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send OTP email: {e}")
            return False
    
    def verify_email_otp(self, email: str, otp: str) -> bool:
        """Verify email OTP"""
        cached = self.email_otp_cache.get(email)
        if not cached:
            return False
        
        # Check if OTP has expired (5 minutes)
        if time.time() - cached['timestamp'] > 300:
            del self.email_otp_cache[email]
            return False
        
        if cached['otp'] == otp:
            del self.email_otp_cache[email]
            return True
        
        return False