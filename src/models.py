
import json
import os
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class User:
    username: str
    password_hash: str
    mfa_secret: str
    email: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[float] = None


@dataclass
class Credential:
    title: str
    encrypted_data: str
    id: Optional[str] = None


class JSONDataStore:
    def __init__(self, json_path: str = 'data/vault.json'):
        self.json_path = json_path
        self.data_dir = os.path.dirname(json_path)
        if self.data_dir and not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        """Ensure the JSON file exists with proper structure."""
        if not os.path.exists(self.json_path):
            initial_data = {
                "users": {},
                "credentials": {}
            }
            with open(self.json_path, 'w') as f:
                json.dump(initial_data, f, indent=2)

    def _load_data(self) -> Dict:
        """Load data from JSON file."""
        try:
            with open(self.json_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {"users": {}, "credentials": {}}

    def _save_data(self, data: Dict) -> bool:
        """Save data to JSON file."""
        try:
            with open(self.json_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def save_user(self, user: User) -> bool:
        """Save user to JSON storage."""
        data = self._load_data()
        data['users'][user.username] = asdict(user)
        return self._save_data(data)

    def get_user(self, username: str) -> Optional[User]:
        """Get user from JSON storage."""
        data = self._load_data()
        user_data = data.get('users', {}).get(username)
        if user_data:
            return User(**user_data)
        return None

    def update_user(self, user: User) -> bool:
        """Update existing user in JSON storage."""
        return self.save_user(user)

    def save_credential(self, username: str, credential: Credential) -> bool:
        """
        Save credential for a user.

        - If credential.id is None ⇒ treat as NEW and:
            * check for duplicates (same title for this user)
            * if duplicate exists, return False (do NOT insert)
        - If credential.id is set ⇒ treat as UPDATE of existing record.
        """
        data = self._load_data()
        if 'credentials' not in data:
            data['credentials'] = {}

        if username not in data['credentials']:
            data['credentials'][username] = []

        user_creds = data['credentials'][username]

        # Duplicate check for new credentials
        if not credential.id:
    
            for existing in user_creds:
                if existing.get('title') == credential.title:
                    # Duplicate found – do not insert
                    return False

            # No duplicate found, generate new ID
            credential.id = str(int(time.time() * 1000))

            # append new credential
            user_creds.append(asdict(credential))

        else:
            # Update existing credential by ID
            existing_index = None
            for i, cred in enumerate(user_creds):
                if cred.get('id') == credential.id:
                    existing_index = i
                    break

            if existing_index is not None:
                user_creds[existing_index] = asdict(credential)
            else:
                # If the ID does not exist, treat it as new
                user_creds.append(asdict(credential))

        data['credentials'][username] = user_creds
        return self._save_data(data)

    def get_credentials(self, username: str) -> List[Credential]:
        """Get all credentials for a user."""
        data = self._load_data()
        creds_data = data.get('credentials', {}).get(username, [])
        return [Credential(**cred) for cred in creds_data]

    def delete_credential(self, username: str, credential_id: str) -> bool:
        """Delete a specific credential."""
        data = self._load_data()
        if username in data.get('credentials', {}):
            data['credentials'][username] = [
                cred for cred in data['credentials'][username]
                if cred.get('id') != credential_id
            ]
            return self._save_data(data)
        return False
