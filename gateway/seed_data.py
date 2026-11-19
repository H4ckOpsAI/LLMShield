import os
import hashlib
import secrets
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .database import SessionLocal, InternalUser

def hash_password(password: str, salt_hex: str = None) -> tuple[str, str]:
    """
    Hashes a password using standard PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (password_hash, salt_hex).
    """
    if not salt_hex:
        salt_hex = secrets.token_hex(32)
    salt_bytes = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        100000
    ).hex()
    return pwd_hash, salt_hex

# ==============================================================================
# DEMO ORGANIZATIONAL USER ACCOUNTS (DEVELOPMENT ONLY)
# Seeded safely with PBKDF2-HMAC-SHA256 password hashing and random salt.
# In production, set ENABLE_DEMO_ACCOUNTS=false.
# ==============================================================================
DEMO_ACCOUNTS = [
    {
        "username": "alice.smith",
        "full_name": "Alice Smith",
        "department": "Executive",
        "role": "EMPLOYEE",
        "password": os.getenv("DEMO_EMPLOYEE_PASSWORD", "Alice@Corp2026!")
    },
    {
        "username": "bob.johnson",
        "full_name": "Bob Johnson",
        "department": "IT Support",
        "role": "IT_ADMIN",
        "password": os.getenv("DEMO_ADMIN_PASSWORD", "Bob@Corp2026!")
    },
    {
        "username": "carol.white",
        "full_name": "Carol White",
        "department": "Finance",
        "role": "EMPLOYEE",
        "password": os.getenv("DEMO_FINANCE_PASSWORD", "Carol@Corp2026!")
    },
    {
        "username": "david.brown",
        "full_name": "David Brown",
        "department": "Engineering",
        "role": "EMPLOYEE",
        "password": os.getenv("DEMO_ENGINEER_PASSWORD", "David@Corp2026!")
    },
    {
        "username": "soc.admin",
        "full_name": "SOC Administrator",
        "department": "Security Operations",
        "role": "SOC_ANALYST",
        "password": os.getenv("DEMO_SOC_PASSWORD", "Admin@SOC2026!")
    }
]

def seed_demo_users(db: Session) -> int:
    """
    Seeds development-only demo user accounts with hashed credentials.
    Prevents duplicates on application restart.
    """
    enable_demo = os.getenv("ENABLE_DEMO_ACCOUNTS", "false").lower() in ("true", "1", "yes")
    if not enable_demo:
        return 0

    count = 0
    for acc in DEMO_ACCOUNTS:
        existing = db.query(InternalUser).filter_by(username=acc["username"]).first()
        if not existing:
            pwd_hash, salt = hash_password(acc["password"])
            user = InternalUser(
                username=acc["username"],
                full_name=acc["full_name"],
                department=acc["department"],
                role=acc["role"],
                password_hash=pwd_hash,
                salt=salt,
                is_active=True,
                is_demo=True,
                created_at=datetime.now(timezone.utc).replace(tzinfo=None)
            )
            db.add(user)
            count += 1
    db.commit()
    return count

def seed_all(db: Session = None) -> dict:
    """
    Executes full database seeding workflow.
    """
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True
    try:
        user_count = seed_demo_users(db)
        total_users = db.query(InternalUser).count()
        return {
            "users_newly_inserted": user_count,
            "total_internal_users": total_users
        }
    finally:
        if should_close:
            db.close()

if __name__ == "__main__":
    result = seed_all()
    print("Database seeding completed successfully:", result)
