import os
import sys
import argparse
from sqlalchemy.orm import Session

# Ensure project root is in sys.path
sys.path.insert(0, os.getcwd())

from backend.app.core.security import get_password_hash, validate_password_strength
from backend.app.db.session import SessionLocal
from backend.app.models.user import User
from backend.app.models.enums import UserRole

def bootstrap_admin(username: str, email: str | None, password: str, display_name: str = "System Administrator") -> None:
    """Create an administrator account cleanly without printing plaintext passwords."""
    try:
        validate_password_strength(password)
    except ValueError as err:
        print(f"[ERROR] Password validation failed: {err}")
        sys.exit(1)

    db: Session = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"[INFO] User '{username}' already exists. Updating role to ADMIN.")
            existing.role = UserRole.ADMIN
            existing.is_active = True
            existing.password_hash = get_password_hash(password)
            db.commit()
            print(f"[SUCCESS] Updated administrator '{username}' successfully.")
            return

        password_hash = get_password_hash(password)
        admin = User(
            username=username,
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"[SUCCESS] Created new administrator '{username}' successfully.")
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Failed to bootstrap administrator: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyberwolf SIEM Admin Bootstrap CLI")
    parser.add_argument("--username", default=os.getenv("ADMIN_USERNAME", "admin"), help="Admin username")
    parser.add_argument("--email", default=os.getenv("ADMIN_EMAIL", "admin@cyberwolf.local"), help="Admin email")
    parser.add_argument("--password", default=os.getenv("ADMIN_PASSWORD"), help="Admin password (min 12 chars)")
    parser.add_argument("--display-name", default="System Administrator", help="Admin display name")

    args = parser.parse_args()

    if not args.password:
        print("[ERROR] Password is required. Set ADMIN_PASSWORD environment variable or pass --password argument.")
        sys.exit(1)

    bootstrap_admin(
        username=args.username,
        email=args.email,
        password=args.password,
        display_name=args.display_name,
    )
