# pyrefly: ignore [missing-import]
import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, event
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.engine import Engine
from datetime import datetime, timezone

def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

# Absolute path anchor to llmshield/llmshield.db regardless of process working directory
current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.abspath(os.path.join(current_dir, "..", "llmshield.db"))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_path}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Enable SQLite foreign-key constraint enforcement on every connection
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# ==============================================================================
# EXISTING UNTOUCHED TABLE: request_logs
# Preserves all 26 existing columns, indexes, types, and operational semantics.
# ==============================================================================
class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now)
    input_text = Column(String)
    normalized_input = Column(String, nullable=True)
    decision = Column(String)
    risk = Column(String)
    attack_type = Column(String)
    detection_layer = Column(String)
    matched_rules = Column(String, nullable=True)
    semantic_verdict = Column(String, nullable=True)
    semantic_confidence = Column(Float, nullable=True)
    security_reason = Column(String, nullable=True)
    latency_ms = Column(Float)
    groq_calls = Column(Integer) # Legacy column
    security_groq_calls = Column(Integer, default=0)
    target_groq_calls = Column(Integer, default=0)
    total_groq_calls = Column(Integer, default=0)
    user_classification = Column(String, nullable=True)
    classification_reason = Column(String, nullable=True)
    structured_prompt_used = Column(Boolean, nullable=True)
    prompt_structure = Column(String, nullable=True)
    output_validation_verdict = Column(String, nullable=True)
    output_validation_confidence = Column(Float, nullable=True)
    output_validation_reason = Column(String, nullable=True)
    output_validation_groq_calls = Column(Integer, default=0)
    enforcement_action = Column(String, nullable=True)

    # Decoupled relationship to user_request_links
    user_links = relationship("UserRequestLink", back_populates="request_log", cascade="all, delete-orphan")
    conversation_message = relationship("ConversationMessage", back_populates="request_log", uselist=False, cascade="all, delete-orphan")


# ==============================================================================
# NEW TABLE 1: internal_users
# Stores corporate user identities, departments, roles, and hashed credentials.
# ==============================================================================
class InternalUser(Base):
    __tablename__ = "internal_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    department = Column(String(50), nullable=False, index=True)
    role = Column(String(30), nullable=False, index=True, default="EMPLOYEE")
    password_hash = Column(String(128), nullable=False)
    salt = Column(String(64), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    request_links = relationship("UserRequestLink", back_populates="user", cascade="all, delete-orphan")


# ==============================================================================
# TABLE 2: user_sessions
# Tracks active bearer sessions with cryptographic token hashing and 8-hour TTL.
# ==============================================================================
class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("internal_users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_token_hash = Column(String(64), unique=True, index=True, nullable=False)
    client_ip = Column(String(45), nullable=False, index=True)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)

    # Relationships
    user = relationship("InternalUser", back_populates="sessions")
    request_links = relationship("UserRequestLink", back_populates="session")


# ==============================================================================
# TABLE 3: user_request_links
# Relational link between authenticated users and unaltered request_logs records.
# ==============================================================================
class UserRequestLink(Base):
    __tablename__ = "user_request_links"

    id = Column(Integer, primary_key=True, index=True)
    request_log_id = Column(Integer, ForeignKey("request_logs.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("internal_users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(Integer, ForeignKey("user_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    # Relationships
    request_log = relationship("RequestLog", back_populates="user_links")
    user = relationship("InternalUser", back_populates="request_links")
    session = relationship("UserSession", back_populates="request_links")


# ==============================================================================
# TABLE 4: conversation_messages
# Tracks multi-turn conversations, advanced obfuscation & multilingual injection
# ==============================================================================
class ConversationMessage(Base):
    __tablename__ = "conversation_messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(String(100), nullable=False, index=True)
    request_log_id = Column(Integer, ForeignKey("request_logs.id", ondelete="CASCADE"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("internal_users.id", ondelete="SET NULL"), nullable=True, index=True)
    turn_index = Column(Integer, nullable=False, default=1)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    raw_message = Column(Text, nullable=False)
    normalized_message = Column(Text, nullable=True)
    detected_language = Column(String(20), default="en")
    detected_techniques_json = Column(Text, default="[]")
    indicators_json = Column(Text, default="{}")
    individual_risk = Column(String(20), default="LOW")
    individual_risk_score = Column(Float, default=0.0)
    cumulative_risk = Column(String(20), default="LOW")
    cumulative_risk_score = Column(Float, default=0.0)
    decision = Column(String(20), nullable=False, default="ALLOWED")
    enforcement_action = Column(String(30), default="ALLOW")
    detection_reason = Column(Text, nullable=True)
    detection_layer = Column(String(50), default="BASELINE")
    is_attack_turn = Column(Boolean, default=False)

    # Relationships
    request_log = relationship("RequestLog", back_populates="conversation_message")
    user = relationship("InternalUser")


# Create all tables if they do not already exist
Base.metadata.create_all(bind=engine)
