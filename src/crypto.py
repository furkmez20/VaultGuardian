
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self, master_password: str = None):
        self.master_password = master_password
        
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def encrypt_data(self, plaintext: str, key: bytes = None) -> str:
        """Encrypt data using Fernet (AES-256)"""
        if key is None:
            if not self.master_password:
                raise ValueError("No key or master password provided")
            key, salt = self.derive_key_from_password(self.master_password)
            # Prepend salt to encrypted data
            fernet = Fernet(key)
            encrypted = fernet.encrypt(plaintext.encode())
            return base64.urlsafe_b64encode(salt + encrypted).decode()
        
        fernet = Fernet(key)
        encrypted = fernet.encrypt(plaintext.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_data(self, ciphertext: str, key: bytes = None) -> str:
        """Decrypt data using Fernet (AES-256)"""
        try:
            encrypted_data = base64.urlsafe_b64decode(ciphertext.encode())
            
            if key is None:
                if not self.master_password:
                    raise ValueError("No key or master password provided")
                # Extract salt from the beginning
                salt = encrypted_data[:16]
                encrypted_data = encrypted_data[16:]
                key, _ = self.derive_key_from_password(self.master_password, salt)
            
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
