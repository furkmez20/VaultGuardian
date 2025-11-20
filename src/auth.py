import bcrypt
import time
from typing import Optional
from database import db, User

from .models import User, JSONDataStore



class AuthManager:
    def __init__(self):
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
        """Register a new user using the database"""
        # Check if user already exists
        existing = User.query.filter_by(username=username).first()
        if existing:
            return False
        user = User(
            username=username,
            password_hash=self.hash_password(password),
            mfa_secret=mfa_secret,
            email=email
        )
        db.session.add(user)
        db.session.commit()
        return True
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password using DB"""
        user = User.query.filter_by(username=username).first()
        if not user:
            return None
        if user.locked_until and time.time() < user.locked_until:
            return None
        if self.verify_password(password, user.password_hash):
            if user.failed_attempts > 0:
                user.failed_attempts = 0
                user.locked_until = None
                db.session.commit()
            return user
        else:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= self.max_failed_attempts:
                user.locked_until = time.time() + self.lockout_duration
            db.session.commit()
            return None
    
    def is_user_locked(self, username: str) -> bool:
        """Check if user is currently locked out using DB"""
        user = User.query.filter_by(username=username).first()
        if not user or not user.locked_until:
            return False
        if time.time() >= user.locked_until:
            user.locked_until = None
            user.failed_attempts = 0
            db.session.commit()
            return False
        return True
