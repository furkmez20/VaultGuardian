
import json
import sys
import os

# added this path cause it wasn't migrating to database without it 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import db, User, Credential

def migrate_json_to_database():
    #migrate data from vault.json to database
    
    with app.app_context():
        print("starting migration")
        
        # changed path to see if that was the issue 
        json_path = os.path.join(os.path.dirname(__file__), "data", "vault.json")
        print(json_path)
        
        if not os.path.exists(json_path):
            print(f"json file doenst exist: {json_path}")
            return False
        
        try:
            # Load JSON data
            with open(json_path, 'r') as f:
                data = json.load(f)
            print(f"loaded json data from: {json_path}")
            
            # migrate 
            users_migrated = 0
            for username, user_data in data.get('users', {}).items():
                # check if exists 
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
                    users_migrated += 1
                    print(f"✅ Added user: {username}")
                else:
                    print(f"⏭️  User already exists: {username}")
            
            # commit users first 
            db.session.commit()
            print(f"👥 Users migration completed: {users_migrated} users added")
            
            # migrate credentials
            credentials_migrated = 0
            for username, creds in data.get('credentials', {}).items():
                user = User.query.filter_by(username=username).first()
                if user and creds:
                    for cred_data in creds:
                        existing_cred = Credential.query.filter_by(
                            user_id=user.id, 
                            title=cred_data.get('title', 'Untitled')
                        ).first()
                        
                        if not existing_cred:
                            credential = Credential(
                                user_id=user.id,
                                title=cred_data.get('title', 'Untitled'),
                                encrypted_data=cred_data.get('encrypted_data', '')
                            )
                            db.session.add(credential)
                            credentials_migrated += 1
                            print(f"added credential: {cred_data.get('title', 'Untitled')} for {username}")
                        else:
                            print(f"credential already exists: {cred_data.get('title', 'Untitled')}")
            
            # Commit credentials
            db.session.commit()
    
            # Verify migration
            total_users = User.query.count()
            total_creds = Credential.query.count()
       
            return True
            
        except Exception as e:
            print(f"error during migration: {str(e)}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = migrate_json_to_database()
