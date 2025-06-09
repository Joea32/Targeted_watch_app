# auth.py

import bcrypt
from extensions import db
from models import User
from utils import update_trust_level

def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()

#def check_password(stored_hash: str, candidate_password: str) -> bool:
#    return bcrypt.checkpw(candidate_password.encode(), stored_hash.encode())

def check_password(candidate_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(candidate_password.encode(), stored_hash.encode())

def register_user(username, password, **kwargs):
    """
    Register a new user, hash their password, save to DB, and update trust level.
    kwargs can include other user fields like name, bio, etc.
    """
    hashed_password = hash_password(password)
    new_user = User(username=username, password=hashed_password, **kwargs)

    db.session.add(new_user)
    db.session.commit()

    update_trust_level(new_user)

    return new_user