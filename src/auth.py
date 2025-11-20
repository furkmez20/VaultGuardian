import bcrypt
import time
from typing import Optional

from .models import User, JSONDataStore



class AuthManager:
    def __init__(self, data_store: JSONDataStore):
        self.data_store = data_store
        self.max_failed_attempts = 5
        self.lockout_duration = 900  # 15 minutes in seconds
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def register_user(self, username: str, password: str, mfa_secret: str, email: str = None) -> bool:
        """Register a new user"""
        # Check if user already exists
        if self.data_store.get_user(username):
            return False
        
        # Create new user
        user = User(
            username=username,
            password_hash=self.hash_password(password),
            mfa_secret=mfa_secret,
            email=email
        )
        
        return self.data_store.save_user(user)
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        user = self.data_store.get_user(username)
        if not user:
            return None
        
        # Check if user is locked out
        if user.locked_until and time.time() < user.locked_until:
            return None
        
        # Verify password
        if self.verify_password(password, user.password_hash):
            # Reset failed attempts on successful login
            if user.failed_attempts > 0:
                user.failed_attempts = 0
                user.locked_until = None
                self.data_store.update_user(user)
            return user
        else:
            # Increment failed attempts
            user.failed_attempts += 1
            if user.failed_attempts >= self.max_failed_attempts:
                user.locked_until = time.time() + self.lockout_duration
            self.data_store.update_user(user)
            return None
    
    def is_user_locked(self, username: str) -> bool:
        """Check if user is currently locked out"""
        user = self.data_store.get_user(username)
        if not user or not user.locked_until:
            return False
        
        if time.time() >= user.locked_until:
            # Lock has expired, clear it
            user.locked_until = None
            user.failed_attempts = 0
            self.data_store.update_user(user)
            return False
        
        return True
