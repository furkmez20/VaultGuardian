import json
from app import app
from database import db, User, Credential
from crypto import CryptoManager
import bcrypt

#this file is made to migrate the json code to the database (praying it works LOL)

def migrate_json_to_database():
    
    with app.app_context():
        #loads data 
        with open('data/vault.json', 'r') as f:
            data = json.load(f)
        
        crypto = CryptoManager()
        
        # moves users 
        for username, user_data in data.get('users', {}).items():
            existing_user = User.query.filter_by(username=username).first()
            if not existing_user:
                user = User(
                    username=user_data['username'],
                    password_hash=user_data['password_hash'],
                    mfa_secret=user_data['mfa_secret'],
                    email=user_data.get('email'),
                    failed_attempts=user_data.get('failed_attempts', 0),
                    locked_until=user_data.get('locked_until')
                )
                db.session.add(user)
        
        db.session.commit()
        print("user migration completed")
        
        # moves the existing credentials 
        for username, creds in data.get('credentials', {}).items():
            user = User.query.filter_by(username=username).first()
            if user and creds:
                for cred_data in creds:
                    # do i need to reencrypt the crendentials again since i'm moving them? 
                    print(f"⚠️  Manual re-encryption needed for {username}'s credentials")
        
        print("migration done")

if __name__ == '__main__':
    migrate_json_to_database()
