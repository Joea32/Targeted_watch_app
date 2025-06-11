from yourapp import db
from yourapp.models import User, UserTypeEnum, VerificationStatusEnum
from werkzeug.security import generate_password_hash
import getpass

def create_admin():
    password = getpass.getpass("Enter admin password (input hidden): ")
    hashed_password = generate_password_hash(password)
    
    admin = User(
        name="Admin User",
        username="Atueman31",
        email=None,
        password=hashed_password,
        is_admin=True,
        badge="New/Unverified",
        trust_level="New/Unverified",
        user_type=UserTypeEnum.VICTIM.value,
        verification_status=VerificationStatusEnum.UNVERIFIED.value,
        verified=False,
    )
    
    db.session.add(admin)
    db.session.commit()
    print("Admin user created!")

if __name__ == "__main__":
    create_admin()
