from database import db, User, Credential
from crypto import CryptoManager
from typing import List, Optional, Dict
import json
from sqlalchemy.exc import IntegrityError

class DatabaseManager:
    def __init__(self):
        self.crypto = CryptoManager()
    
    def create_user(self, username: str, password_hash: str, mfa_secret: str, email: str = None) -> bool:
        """Create a new user"""
        try:
            user = User(
                username=username,
                password_hash=password_hash,
                mfa_secret=mfa_secret,
                email=email
            )
            db.session.add(user)
            db.session.commit()
            return True
        except IntegrityError:
            db.session.rollback()
            return False
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        #get user by their username 
        return User.query.filter_by(username=username).first()
    
    def update_user(self, user: User) -> bool:
        #update user infov
        try:
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False
    
    def save_credential(self, user: User, title: str, credential_data: Dict, master_password: str) -> bool:
        """Save encrypted credential for user"""
        try:
            # Encrypt credential data
            encrypted_data = self.crypto.encrypt_credential_data(credential_data, master_password)
            
            credential = Credential(
                user_id=user.id,
                title=title,
                encrypted_data=encrypted_data
            )
            
            db.session.add(credential)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Error saving credential: {e}")
            return False
    
    def get_user_credentials(self, user: User, master_password: str) -> List[Dict]:
        """Get all credentials for user (decrypted)"""
        credentials = Credential.query.filter_by(user_id=user.id).all()
        decrypted_creds = []
        
        for cred in credentials:
            try:
                decrypted_data = self.crypto.decrypt_credential_data(cred.encrypted_data, master_password)
                decrypted_creds.append({
                    'id': cred.id,
                    'title': cred.title,
                    'data': decrypted_data,
                    'created_at': cred.created_at,
                    'updated_at': cred.updated_at
                })
            except Exception as e:
                print(f"Failed to decrypt credential {cred.id}: {e}")
                continue
        
        return decrypted_creds
    
    def delete_credential(self, credential_id: int, user_id: int) -> bool:
        """Delete a credential (with user ownership check)"""
        try:
            credential = Credential.query.filter_by(id=credential_id, user_id=user_id).first()
            if credential:
                db.session.delete(credential)
                db.session.commit()
                return True
            return False
        except Exception:
            db.session.rollback()
            return False
