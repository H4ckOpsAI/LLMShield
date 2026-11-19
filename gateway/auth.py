import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .database import SessionLocal, InternalUser, UserSession

def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

security_bearer = HTTPBearer(auto_error=False)

# Configuration
SESSION_TTL_HOURS = 8
IP_FAIL_THRESHOLD = 10
IP_WINDOW_SECONDS = 300
IP_LOCKOUT_SECONDS = 900 # 15 minutes

# In-memory tracking for source IP rate limiting:
# ip -> {"failed_attempts": [timestamp, ...], "locked_until": timestamp | None}
_ip_attempt_cache: dict[str, dict] = {}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def resolve_client_ip(request: Request) -> str:
    """
    Safely resolves the client IP address.
    Does NOT blindly trust X-Forwarded-For unless TRUSTED_PROXIES is configured.
    """
    trusted_proxies = os.getenv("TRUSTED_PROXIES", "").split(",")
    trusted_proxies = [p.strip() for p in trusted_proxies if p.strip()]

    client_host = request.client.host if request.client else "127.0.0.1"

    if trusted_proxies and client_host in trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Rightmost untrusted IP
            parts = [p.strip() for p in forwarded.split(",")]
            for ip in reversed(parts):
                if ip not in trusted_proxies:
                    return ip

    return client_host

def check_ip_throttled(client_ip: str) -> Tuple[bool, int]:
    """
    Checks if client IP is throttled due to >= 10 failed login attempts within 300s.
    Returns (is_throttled, seconds_remaining).
    """
    now = utc_now()
    record = _ip_attempt_cache.get(client_ip)
    if not record:
        return False, 0

    locked_until = record.get("locked_until")
    if locked_until and now < locked_until:
        remaining = int((locked_until - now).total_seconds())
        return True, max(remaining, 1)

    # Filter out attempts older than window
    cutoff = now - timedelta(seconds=IP_WINDOW_SECONDS)
    valid_attempts = [t for t in record.get("failed_attempts", []) if t >= cutoff]
    record["failed_attempts"] = valid_attempts

    if len(valid_attempts) >= IP_FAIL_THRESHOLD:
        record["locked_until"] = now + timedelta(seconds=IP_LOCKOUT_SECONDS)
        return True, IP_LOCKOUT_SECONDS

    return False, 0

def record_failed_login_attempt(client_ip: str):
    """
    Records a failed login attempt for an IP.
    """
    now = utc_now()
    if client_ip not in _ip_attempt_cache:
        _ip_attempt_cache[client_ip] = {"failed_attempts": [], "locked_until": None}

    record = _ip_attempt_cache[client_ip]
    record["failed_attempts"].append(now)

    cutoff = now - timedelta(seconds=IP_WINDOW_SECONDS)
    record["failed_attempts"] = [t for t in record["failed_attempts"] if t >= cutoff]

    if len(record["failed_attempts"]) >= IP_FAIL_THRESHOLD:
        record["locked_until"] = now + timedelta(seconds=IP_LOCKOUT_SECONDS)

def record_successful_login(client_ip: str):
    """
    Resets failed login attempt counter for clean IP.
    """
    if client_ip in _ip_attempt_cache:
        _ip_attempt_cache[client_ip]["failed_attempts"] = []
        _ip_attempt_cache[client_ip]["locked_until"] = None

def hash_token(raw_token: str) -> str:
    """
    Computes SHA-256 hash of a raw session token.
    Only the hash is persisted in the database.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def verify_password(plain_password: str, password_hash: str, salt_hex: str) -> bool:
    """
    Verifies password using PBKDF2-HMAC-SHA256 and constant-time comparison.
    """
    salt_bytes = bytes.fromhex(salt_hex)
    computed_hash = hashlib.pbkdf2_hmac(
        "sha256",
        plain_password.encode("utf-8"),
        salt_bytes,
        100000
    ).hex()
    return secrets.compare_digest(computed_hash, password_hash)

def create_user_session(db: Session, user: InternalUser, client_ip: str, user_agent: Optional[str] = None) -> Tuple[str, UserSession]:
    """
    Creates a new user session with a cryptographically random bearer token.
    Returns (raw_bearer_token, UserSession).
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    expires_at = utc_now() + timedelta(hours=SESSION_TTL_HOURS)

    session = UserSession(
        user_id=user.id,
        session_token_hash=token_hash,
        client_ip=client_ip,
        user_agent=user_agent[:250] if user_agent else None,
        created_at=utc_now(),
        expires_at=expires_at,
        is_revoked=False
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return raw_token, session

def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> Optional[Tuple[InternalUser, UserSession]]:
    """
    Dependency that resolves the authenticated user if an Authorization header is provided.
    - If NO Authorization header is provided: returns None.
    - If Authorization header IS provided: validates it strictly.
      If token is invalid, expired, or revoked, raises HTTP 401 Unauthorized.
    """
    # Check if header is present
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization credentials format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )

    raw_token = credentials.credentials.strip()
    token_hash = hash_token(raw_token)

    session = db.query(UserSession).filter_by(session_token_hash=token_hash).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token invalid or not found.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if session.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if session.expires_at < utc_now():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(InternalUser).filter_by(id=session.user_id, is_active=True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or no longer exists.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user, session

def get_current_user(
    auth_context: Optional[Tuple[InternalUser, UserSession]] = Depends(get_optional_user)
) -> Tuple[InternalUser, UserSession]:
    """
    Requires an authenticated user. Raises 401 if unauthenticated.
    """
    if not auth_context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return auth_context

def require_roles(allowed_roles: list[str]):
    """
    RBAC dependency factory. Derives role directly from database user.
    """
    def role_checker(auth_context: Tuple[InternalUser, UserSession] = Depends(get_current_user)):
        user, session = auth_context
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Access restricted. Role '{user.role}' not permitted."
            )
        return user, session
    return role_checker
