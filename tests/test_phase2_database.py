import pytest
import sys
import os
import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import inspect, text

# Add llmshield directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from gateway.database import (
    engine,
    SessionLocal,
    RequestLog,
    InternalUser,
    UserSession,
    UserRequestLink,
    ConversationMessage
)
from gateway.seed_data import seed_all, DEMO_ACCOUNTS, hash_password

def test_sqlite_foreign_key_pragma():
    """
    Verifies that SQLite foreign key constraint enforcement is enabled on connection.
    """
    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA foreign_keys;")).scalar()
        assert result == 1, "SQLite foreign key enforcement is NOT enabled! PRAGMA foreign_keys must be 1."

def test_request_logs_schema_unmodified():
    """
    Verifies that the existing request_logs table schema is 100% untouched (26 columns).
    """
    inspector = inspect(engine)
    columns = {col["name"]: col for col in inspector.get_columns("request_logs")}
    
    expected_columns = [
        "id", "timestamp", "input_text", "normalized_input", "decision", "risk",
        "attack_type", "detection_layer", "matched_rules", "semantic_verdict",
        "semantic_confidence", "security_reason", "latency_ms", "groq_calls",
        "security_groq_calls", "target_groq_calls", "total_groq_calls",
        "user_classification", "classification_reason", "structured_prompt_used",
        "prompt_structure", "output_validation_verdict", "output_validation_confidence",
        "output_validation_reason", "output_validation_groq_calls", "enforcement_action"
    ]
    
    assert len(expected_columns) == 26
    for col_name in expected_columns:
        assert col_name in columns, f"Expected column '{col_name}' missing from request_logs!"

def test_database_tables_exist():
    """
    Verifies that all required core security and identity tables exist in SQLite.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    required_tables = {
        "request_logs",
        "internal_users",
        "user_sessions",
        "user_request_links",
        "conversation_messages"
    }
    missing = required_tables - existing_tables
    assert not missing, f"Missing required database tables: {missing}"

def test_seeding_idempotence_and_counts():
    """
    Verifies that seed_all populates demo accounts without duplicating records on re-execution.
    """
    db = SessionLocal()
    try:
        res1 = seed_all(db)
        users_count = db.query(InternalUser).count()
        assert users_count >= 5, f"Expected at least 5 demo users, found {users_count}"
        
        # Verify idempotence on second run
        res2 = seed_all(db)
        assert res2["users_newly_inserted"] == 0
    finally:
        db.close()

def test_demo_user_credentials_hashed():
    """
    Verifies that all demo user accounts have non-plaintext, cryptographic hashes and salts.
    """
    db = SessionLocal()
    try:
        demo_usernames = ["alice.smith", "bob.johnson", "carol.white", "david.brown", "soc.admin"]
        for username in demo_usernames:
            user = db.query(InternalUser).filter_by(username=username).first()
            assert user is not None, f"Demo user {username} not found!"
            assert user.is_demo is True
            assert len(user.password_hash) == 64
            assert len(user.salt) == 64
            assert not user.password_hash.startswith("Alice")
            assert not user.password_hash.startswith("Admin")
            
            for acc in DEMO_ACCOUNTS:
                if acc["username"] == username:
                    computed_hash, _ = hash_password(acc["password"], user.salt)
                    assert computed_hash == user.password_hash
    finally:
        db.close()

def test_relational_integrity_and_foreign_keys():
    """
    Tests foreign key constraints, cascade rules, and user_request_links.
    """
    db = SessionLocal()
    try:
        test_user = InternalUser(
            username="temp_test_user_phase2",
            full_name="Temporary Test User",
            department="QA",
            role="EMPLOYEE",
            password_hash="testhash123",
            salt="testsalt123",
            is_active=True,
            is_demo=False
        )
        db.add(test_user)
        db.commit()
        
        test_session = UserSession(
            user_id=test_user.id,
            session_token_hash="dummy_session_hash_phase2",
            client_ip="127.0.0.1",
            user_agent="pytest-client",
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=8),
            is_revoked=False
        )
        db.add(test_session)
        db.commit()
        
        dummy_log = RequestLog(
            input_text="Hello, target assistant",
            decision="ALLOWED",
            risk="LOW",
            attack_type="NONE",
            detection_layer="BASELINE",
            latency_ms=12.5,
            groq_calls=1,
            total_groq_calls=1
        )
        db.add(dummy_log)
        db.commit()
        
        link = UserRequestLink(
            request_log_id=dummy_log.id,
            user_id=test_user.id,
            session_id=test_session.id
        )
        db.add(link)
        db.commit()
        
        # Verify relationships
        assert len(test_user.sessions) >= 1
        assert len(test_user.request_links) >= 1
        assert link.request_log.id == dummy_log.id
        
        # Test Cascading Behavior: Delete test user
        user_id = test_user.id
        log_id = dummy_log.id
        
        db.delete(test_user)
        db.commit()
        
        # Session and request link should be deleted via CASCADE
        assert db.query(UserSession).filter_by(user_id=user_id).first() is None
        assert db.query(UserRequestLink).filter_by(user_id=user_id).first() is None
        
        # request_log should remain intact
        reloaded_log = db.query(RequestLog).filter_by(id=log_id).first()
        assert reloaded_log is not None
        
        db.delete(reloaded_log)
        db.commit()
    finally:
        db.close()
