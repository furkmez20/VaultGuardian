from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Text, DateTime, Integer, String, Float
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    #create a table users 
    __tablename__ = 'users'
    
    #store the same info that was originally in the json file and also track failed attempts 
    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(String(128), nullable=False)
    mfa_secret = db.Column(String(32), nullable=False)
    email = db.Column(String(120), nullable=True)
    failed_attempts = db.Column(Integer, default=0)
    locked_until = db.Column(Float, nullable=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # relationship to credentials so one user can have multiple credentials (we can change this information later if we need to)
    #if user is deleted, delete all their credentials too
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')


class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(String(100), nullable=False)
    encrypted_data = db.Column(Text, nullable=False)  # JSON blob of encrypted credential data
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Credential {self.title} for user {self.user_id}>'
