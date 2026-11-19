import os
import json
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from .database import (
    SessionLocal,
    InternalUser,
    UserSession,
    RequestLog,
    UserRequestLink,
    ConversationMessage
)
from .auth import (
    get_db,
    resolve_client_ip,
    check_ip_throttled,
    record_failed_login_attempt,
    record_successful_login,
    verify_password,
    create_user_session,
    get_current_user,
    get_optional_user,
    require_roles
)
from .security_models import (
    LoginRequest,
    DemoLoginRequest,
    AuthResponse,
    UserProfile,
    PublicUserProfile,
    LLMSOCSummaryResponse
)

router = APIRouter(prefix="/api", tags=["Security & Monitoring"])

# ==============================================================================
# AUTHENTICATION ENDPOINTS
# ==============================================================================

@router.post("/auth/login", response_model=AuthResponse)
def login(login_req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = resolve_client_ip(request)

    # 1. Source IP Throttling Check
    is_throttled, retry_after = check_ip_throttled(client_ip)
    if is_throttled:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts from this source. Access blocked for {retry_after} seconds."
        )

    # 2. Query user by username
    user = db.query(InternalUser).filter_by(username=login_req.username.strip().lower()).first()
    
    invalid_cred_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password.",
        headers={"WWW-Authenticate": "Bearer"}
    )

    if not user or not user.is_active:
        record_failed_login_attempt(client_ip)
        raise invalid_cred_error

    # 3. Verify PBKDF2 Password Hash
    if not verify_password(login_req.password, user.password_hash, user.salt):
        record_failed_login_attempt(client_ip)
        raise invalid_cred_error

    # 4. Authentication Succeeded
    record_successful_login(client_ip)
    user_agent = request.headers.get("User-Agent")
    raw_token, session = create_user_session(db, user, client_ip, user_agent)

    user_profile = UserProfile(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        department=user.department,
        role=user.role,
        is_demo=user.is_demo,
        created_at=user.created_at
    )
    return AuthResponse(token=raw_token, user=user_profile)

@router.post("/auth/demo-login", response_model=AuthResponse)
def demo_login(
    payload: DemoLoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Development-only passwordless demo login.
    Disabled when ENABLE_DEMO_ACCOUNTS=false.
    """
    enable_demo = os.getenv("ENABLE_DEMO_ACCOUNTS", "false").lower() in ("true", "1", "yes")
    if not enable_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo authentication is disabled in this environment."
        )

    client_ip = resolve_client_ip(request)
    user = db.query(InternalUser).filter_by(username=payload.username.strip().lower(), is_active=True).first()
    if not user:
        raise HTTPException(status_code=404, detail="Demo account not found or inactive.")

    user_agent = request.headers.get("User-Agent")
    raw_token, session = create_user_session(db, user, client_ip, user_agent)

    user_profile = UserProfile(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        department=user.department,
        role=user.role,
        is_demo=user.is_demo,
        created_at=user.created_at
    )
    return AuthResponse(token=raw_token, user=user_profile)

@router.post("/auth/demo-login/{username}", response_model=AuthResponse)
def demo_login_path(
    username: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Convenience URL-based demo login for local development testing."""
    return demo_login(DemoLoginRequest(username=username), request, db)

@router.post("/auth/logout")
def logout(
    auth_context=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, session = auth_context
    session.is_revoked = True
    db.commit()
    return {"status": "ok", "message": "Session successfully revoked."}

@router.get("/auth/me", response_model=UserProfile)
def get_me(auth_context=Depends(get_current_user)):
    user, _ = auth_context
    return UserProfile(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        department=user.department,
        role=user.role,
        is_demo=user.is_demo,
        created_at=user.created_at
    )

@router.get("/auth/demo-users", response_model=List[PublicUserProfile])
def list_demo_users(db: Session = Depends(get_db)):
    """
    Lists available organizational accounts for demonstration selection.
    Returns empty list when ENABLE_DEMO_ACCOUNTS=false.
    """
    enable_demo = os.getenv("ENABLE_DEMO_ACCOUNTS", "false").lower() in ("true", "1", "yes")
    if not enable_demo:
        return []
    users = db.query(InternalUser).filter_by(is_active=True, is_demo=True).all()
    return [
        PublicUserProfile(
            username=u.username,
            full_name=u.full_name,
            department=u.department,
            role=u.role
        )
        for u in users
    ]

# ==============================================================================
# SOC & CONVERSATION ANALYTICS (MONITORING EXTERNAL & INTERNAL TRAFFIC)
# ==============================================================================

@router.get("/soc/summary", response_model=LLMSOCSummaryResponse)
def get_soc_summary(
    auth_context=Depends(require_roles(["SOC_ANALYST", "ADMIN"])),
    db: Session = Depends(get_db)
):
    """Unified SOC overview for monitoring LLM perimeter defense activity."""
    total_reqs = db.query(RequestLog).count()
    blocked_reqs = db.query(RequestLog).filter(RequestLog.decision == "BLOCKED").count()
    allowed_reqs = db.query(RequestLog).filter(RequestLog.decision == "ALLOWED").count()
    internal_reqs = db.query(UserRequestLink).count()
    external_reqs = max(0, total_reqs - internal_reqs)
    
    # Conversations count
    total_convs = db.query(func.count(func.distinct(ConversationMessage.conversation_id))).scalar() or 0
    suspicious_convs = db.query(func.count(func.distinct(ConversationMessage.conversation_id)))\
        .filter(ConversationMessage.cumulative_risk.in_(["MEDIUM", "HIGH", "CRITICAL"])).scalar() or 0

    return LLMSOCSummaryResponse(
        total_requests=total_reqs,
        blocked_requests=blocked_reqs,
        allowed_requests=allowed_reqs,
        internal_requests=internal_reqs,
        external_requests=external_reqs,
        total_conversations=total_convs,
        suspicious_conversations=suspicious_convs
    )

@router.get("/conversations/analytics")
def get_conversations_analytics(
    auth_context=Depends(require_roles(["SOC_ANALYST", "ADMIN"])),
    db: Session = Depends(get_db)
):
    """
    Returns aggregated metrics for Advanced Prompt Injection Detection:
    - Obfuscation attempts
    - Multilingual attempts
    - Multi-turn attacks
    - Cumulative conversation risk distribution
    - Technique breakdowns and timeline trends
    """
    all_messages = db.query(ConversationMessage).order_by(ConversationMessage.timestamp.asc()).all()
    total_messages_analyzed = len(all_messages)
    
    total_blocked_requests = sum(1 for m in all_messages if m.decision == "BLOCKED")
    total_allowed_requests = sum(1 for m in all_messages if m.decision == "ALLOWED")
    
    obfuscated_count = 0
    multilingual_count = 0
    multi_turn_count = 0
    technique_counts = {
        "Keyword & Rewritten Evasion": 0,
        "Unicode & Homoglyph Evasion": 0,
        "Special-Char & Spaced Obfuscation": 0,
        "Emoji-Based Obfuscation": 0,
        "Multilingual Semantic Injection": 0,
        "Multi-Turn Context Evasion": 0
    }
    
    # Group by conversation
    conv_map = {}
    for m in all_messages:
        cid = m.conversation_id
        if cid not in conv_map:
            conv_map[cid] = []
        conv_map[cid].append(m)
        
        # Parse indicators
        try:
            ind = json.loads(m.indicators_json) if m.indicators_json else {}
        except Exception:
            ind = {}
            
        if ind.get("has_unicode_homoglyphs") or ind.get("has_scrambled_spaced_text") or ind.get("has_emoji_obfuscation"):
            obfuscated_count += 1
        if ind.get("is_multilingual"):
            multilingual_count += 1
            
        # Parse techniques
        try:
            techs = json.loads(m.detected_techniques_json) if m.detected_techniques_json else []
        except Exception:
            techs = []
            
        for t in techs:
            if "Keyword" in t:
                technique_counts["Keyword & Rewritten Evasion"] += 1
            elif "Unicode" in t or "Homoglyph" in t:
                technique_counts["Unicode & Homoglyph Evasion"] += 1
            elif "Special" in t or "Spaced" in t:
                technique_counts["Special-Char & Spaced Obfuscation"] += 1
            elif "Emoji" in t:
                technique_counts["Emoji-Based Obfuscation"] += 1
            elif "Multilingual" in t:
                technique_counts["Multilingual Semantic Injection"] += 1
            elif "Multi-Turn" in t:
                technique_counts["Multi-Turn Context Evasion"] += 1
                multi_turn_count += 1

    total_conversations = len(conv_map)
    suspicious_conversations = 0
    conversation_risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    
    for cid, msgs in conv_map.items():
        last_turn = max(msgs, key=lambda x: x.turn_index)
        c_risk = last_turn.cumulative_risk or "LOW"
        conversation_risk_dist[c_risk] = conversation_risk_dist.get(c_risk, 0) + 1
        if c_risk in ["MEDIUM", "HIGH", "CRITICAL"] or any(m.decision == "BLOCKED" for m in msgs):
            suspicious_conversations += 1

    # Detection trends over time (by date)
    date_trends = {}
    for m in all_messages:
        d_str = m.timestamp.strftime("%Y-%m-%d")
        if d_str not in date_trends:
            date_trends[d_str] = {"date": d_str, "allowed": 0, "blocked": 0, "multilingual": 0, "obfuscated": 0}
        if m.decision == "BLOCKED":
            date_trends[d_str]["blocked"] += 1
        else:
            date_trends[d_str]["allowed"] += 1
            
        try:
            ind = json.loads(m.indicators_json) if m.indicators_json else {}
            if ind.get("is_multilingual"):
                date_trends[d_str]["multilingual"] += 1
            if ind.get("has_unicode_homoglyphs") or ind.get("has_scrambled_spaced_text"):
                date_trends[d_str]["obfuscated"] += 1
        except Exception:
            pass

    timeline_data = sorted(date_trends.values(), key=lambda x: x["date"])

    return {
        "overview": {
            "total_requests_analyzed": total_messages_analyzed,
            "total_obfuscated_attempts": obfuscated_count,
            "total_multilingual_attempts": multilingual_count,
            "total_multi_turn_attacks": multi_turn_count,
            "total_blocked_requests": total_blocked_requests,
            "total_requests_blocked": total_blocked_requests,
            "total_allowed_requests": total_allowed_requests,
            "total_requests_allowed": total_allowed_requests,
            "total_conversations": total_conversations,
            "suspicious_conversations": suspicious_conversations,
            "total_suspicious_conversations": suspicious_conversations,
            "conversation_risk_distribution": conversation_risk_dist
        },
        "technique_breakdown": [
            {"technique": k, "count": v} for k, v in technique_counts.items()
        ],
        "risk_comparison": {
            "conversation_risk": conversation_risk_dist,
            "individual_risk": {
                "LOW": sum(1 for m in all_messages if m.individual_risk == "LOW"),
                "MEDIUM": sum(1 for m in all_messages if m.individual_risk == "MEDIUM"),
                "HIGH": sum(1 for m in all_messages if m.individual_risk in ["HIGH", "CRITICAL"])
            }
        },
        "timeline_data": timeline_data
    }

@router.get("/conversations")
def list_conversations(
    auth_context=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists recorded conversation summaries.
    - Regular employees: view only their own conversations.
    - SOC Analysts and Admins: view all external and internal conversation audits.
    """
    user, _ = auth_context
    query = db.query(ConversationMessage)
    if user.role not in ["SOC_ANALYST", "ADMIN"]:
        query = query.filter(ConversationMessage.user_id == user.id)
        
    messages = query.order_by(ConversationMessage.timestamp.desc()).all()
    
    conversations = {}
    for m in messages:
        cid = m.conversation_id
        if cid not in conversations:
            conversations[cid] = {
                "conversation_id": cid,
                "user_id": m.user_id,
                "username": m.user.username if m.user else "Unauthenticated",
                "department": m.user.department if m.user else "N/A",
                "message_count": 0,
                "messages": [],
                "latest_timestamp": m.timestamp,
                "final_decision": "ALLOWED",
                "final_cumulative_risk": "LOW",
                "final_cumulative_score": 0.0,
                "detection_reason": m.detection_reason,
                "detection_layer": m.detection_layer,
                "has_attack": False,
                "attack_turn_index": None
            }
        conv = conversations[cid]
        conv["message_count"] += 1
        conv["messages"].append(m)
        if m.decision == "BLOCKED":
            conv["has_attack"] = True
            conv["final_decision"] = "BLOCKED"
            if conv["attack_turn_index"] is None or m.turn_index < conv["attack_turn_index"]:
                conv["attack_turn_index"] = m.turn_index

    result = []
    for cid, conv in conversations.items():
        sorted_msgs = sorted(conv["messages"], key=lambda x: x.turn_index)
        last_msg = sorted_msgs[-1]
        
        u = last_msg.user
        if u:
            u_type = "INTERNAL_USER"
            auth_status = "AUTHENTICATED"
            authz_status = "NOT_EVALUATED"
            ident_label = "INTERNAL USER – AUTHENTICATED EMPLOYEE"
            role = u.role
            dept = u.department
            uname = u.username
        else:
            u_type = "EXTERNAL_USER"
            auth_status = "UNAUTHENTICATED"
            authz_status = "UNAUTHORIZED"
            ident_label = "EXTERNAL USER – UNAUTHORIZED"
            role = "N/A"
            dept = "N/A"
            uname = "Unauthenticated"
            
        conv["user_type"] = u_type
        conv["authentication_status"] = auth_status
        conv["authorization_status"] = authz_status
        conv["user_identity_label"] = ident_label
        conv["role"] = role
        conv["department"] = dept
        conv["username"] = uname
        conv["final_cumulative_risk"] = last_msg.cumulative_risk
        conv["final_cumulative_score"] = last_msg.cumulative_risk_score
        conv["detection_reason"] = last_msg.detection_reason
        conv["detection_layer"] = last_msg.detection_layer
        del conv["messages"]
        result.append(conv)
        
    result.sort(key=lambda x: x["latest_timestamp"], reverse=True)
    return result

@router.get("/conversations/{conversation_id}")
def get_conversation_details(
    conversation_id: str,
    auth_context=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns full chronological audit trail and forensic breakdown for a single conversation.
    """
    user, _ = auth_context
    query = db.query(ConversationMessage).filter(ConversationMessage.conversation_id == conversation_id)
    if user.role not in ["SOC_ANALYST", "ADMIN"]:
        query = query.filter(ConversationMessage.user_id == user.id)
        
    messages = query.order_by(ConversationMessage.turn_index.asc()).all()
    if not messages:
        # Check if conversation exists under another identity to enforce object-level authorization (IDOR protection)
        any_conv = db.query(ConversationMessage).filter(ConversationMessage.conversation_id == conversation_id).first()
        if any_conv:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view another user's conversation."
            )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found.")
        
    timeline = []
    for m in messages:
        try:
            indicators = json.loads(m.indicators_json) if m.indicators_json else {}
        except Exception:
            indicators = {}
            
        try:
            techniques = json.loads(m.detected_techniques_json) if m.detected_techniques_json else []
        except Exception:
            techniques = []

        msg_user = m.user
        if msg_user:
            m_u_type = "INTERNAL_USER"
            m_auth_status = "AUTHENTICATED"
            m_authz_status = "NOT_EVALUATED"
            m_ident_label = "INTERNAL USER – AUTHENTICATED EMPLOYEE"
            m_uname = msg_user.username
            m_dept = msg_user.department
            m_role = msg_user.role
        else:
            m_u_type = "EXTERNAL_USER"
            m_auth_status = "UNAUTHENTICATED"
            m_authz_status = "UNAUTHORIZED"
            m_ident_label = "EXTERNAL USER – UNAUTHORIZED"
            m_uname = "Unauthenticated"
            m_dept = "N/A"
            m_role = "N/A"

        timeline.append({
            "id": m.id,
            "turn_index": m.turn_index,
            "request_log_id": m.request_log_id,
            "timestamp": m.timestamp,
            "raw_message": m.raw_message,
            "normalized_message": m.normalized_message,
            "detected_language": m.detected_language,
            "detected_techniques": techniques,
            "indicators": indicators,
            "individual_risk": m.individual_risk,
            "individual_risk_score": m.individual_risk_score,
            "cumulative_risk": m.cumulative_risk,
            "cumulative_risk_score": m.cumulative_risk_score,
            "decision": m.decision,
            "enforcement_action": m.enforcement_action,
            "detection_reason": m.detection_reason,
            "detection_layer": m.detection_layer,
            "is_attack_turn": m.is_attack_turn,
            "user_type": m_u_type,
            "authentication_status": m_auth_status,
            "authorization_status": m_authz_status,
            "user_identity_label": m_ident_label,
            "username": m_uname,
            "department": m_dept,
            "role": m_role
        })
        
    last_msg = messages[-1]
    last_user = last_msg.user
    if last_user:
        u_type = "INTERNAL_USER"
        auth_status = "AUTHENTICATED"
        authz_status = "NOT_EVALUATED"
        ident_label = "INTERNAL USER – AUTHENTICATED EMPLOYEE"
        username = last_user.username
        full_name = last_user.full_name
        dept = last_user.department
        role = last_user.role
    else:
        u_type = "EXTERNAL_USER"
        auth_status = "UNAUTHENTICATED"
        authz_status = "UNAUTHORIZED"
        ident_label = "EXTERNAL USER – UNAUTHORIZED"
        username = "Unauthenticated"
        full_name = "N/A"
        dept = "N/A"
        role = "N/A"

    return {
        "conversation_id": conversation_id,
        "user_id": last_msg.user_id,
        "username": username,
        "full_name": full_name,
        "department": dept,
        "role": role,
        "user_type": u_type,
        "authentication_status": auth_status,
        "authorization_status": authz_status,
        "user_identity_label": ident_label,
        "total_turns": len(messages),
        "final_decision": "BLOCKED" if any(m.decision == "BLOCKED" for m in messages) else "ALLOWED",
        "final_cumulative_risk": last_msg.cumulative_risk,
        "final_cumulative_score": last_msg.cumulative_risk_score,
        "timeline": timeline
    }
