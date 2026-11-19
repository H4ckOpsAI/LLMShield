# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException, Depends
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional, Tuple
import requests
import time
import json
import uuid
from .models import ChatRequest, ChatResponse
from .database import SessionLocal, RequestLog, UserRequestLink, ConversationMessage
from .normalization import normalize_text
from .rules import rule_detect, is_suspicious
from .semantic_detector import semantic_detect
from .output_validator import validate_output
from .auth import get_optional_user
from .seed_data import seed_all
from .security_routes import router as security_router
from .obfuscation_detector import analyze_obfuscation
from .conversation_engine import analyze_conversation_turn
import os

SYSTEM_PROMPT = ""
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_path = os.path.join(current_dir, "..", "target_app", "system_prompt.txt")
    with open(prompt_path, "r") as f:
        SYSTEM_PROMPT = f.read()
except FileNotFoundError:
    SYSTEM_PROMPT = "You are a helpful assistant."

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        seed_all()
    except Exception as e:
        print(f"[STARTUP SEEDING ERROR] {e}")
    yield

app = FastAPI(title="LLMShield Security Gateway", lifespan=lifespan)

# Mount security, authentication & conversation analytics routes
app.include_router(security_router)

# CORS setup for Next.js Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_APP_URL = "http://localhost:8001/chat"

# Dependency to get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "gateway"}

@app.get("/events")
def get_events(
    auth_context=Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Security Audit Logs:
    - SOC Analysts & Admins: Full global access across all external and internal security events.
    - Corporate Employees: Isolated access strictly to their own past requests.
    - Unauthenticated Users: Denied access (returns empty list) to prevent information leakage.
    """
    if not auth_context:
        return []

    user, _ = auth_context
    if user.role in ["SOC_ANALYST", "ADMIN"]:
        logs = db.query(RequestLog).order_by(RequestLog.timestamp.desc()).limit(50).all()
    else:
        logs = (
            db.query(RequestLog)
            .join(UserRequestLink, RequestLog.id == UserRequestLink.request_log_id)
            .filter(UserRequestLink.user_id == user.id)
            .order_by(RequestLog.timestamp.desc())
            .limit(50)
            .all()
        )

    events_data = []
    for l in logs:
        linked_user = l.user_links[0].user if (l.user_links and len(l.user_links) > 0 and l.user_links[0].user) else None
        if linked_user:
            u_type = "INTERNAL_USER"
            auth_status = "AUTHENTICATED"
            authz_status = "NOT_EVALUATED"
            ident_label = "INTERNAL USER – AUTHENTICATED EMPLOYEE"
            username = linked_user.username
            dept = linked_user.department
            role = linked_user.role
        else:
            u_type = "EXTERNAL_USER"
            auth_status = "UNAUTHENTICATED"
            authz_status = "UNAUTHORIZED"
            ident_label = "EXTERNAL USER – UNAUTHORIZED"
            username = "Unauthenticated"
            dept = "N/A"
            role = "N/A"
            
        events_data.append({
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "input_text": l.input_text,
            "decision": l.decision,
            "risk": l.risk,
            "attack_type": l.attack_type,
            "detection_layer": l.detection_layer,
            "latency_ms": l.latency_ms,
            "user_classification": l.user_classification,
            "classification_reason": l.classification_reason,
            "enforcement_action": l.enforcement_action,
            "matched_rules": l.matched_rules,
            "semantic_verdict": l.semantic_verdict,
            "user_type": u_type,
            "authentication_status": auth_status,
            "authorization_status": authz_status,
            "user_identity_label": ident_label,
            "username": username,
            "department": dept,
            "role": role
        })
    return events_data

@app.post("/chat", response_model=ChatResponse)
def chat(
    request: ChatRequest,
    db: Session = Depends(get_db),
    auth_context=Depends(get_optional_user)
):
    start_time = time.time()
    
    # 1. Advanced Obfuscation Analysis & Multilingual Canonical Mapping
    obf_info = analyze_obfuscation(request.message)
    canonical_text = obf_info.get("normalized_canonical") or request.message
    
    # Standard normalization on canonical text
    normalized_input = normalize_text(canonical_text)
    
    # Primary rule-based check on normalized input
    is_attack, severity, rule_id, category = rule_detect(normalized_input)
    
    # Fallback rule-based check on raw message normalized if canonical was different
    if not is_attack:
        raw_norm = normalize_text(request.message)
        if raw_norm != normalized_input:
            is_att_raw, sev_raw, r_id_raw, cat_raw = rule_detect(raw_norm)
            if is_att_raw:
                is_attack, severity, rule_id, category = is_att_raw, sev_raw, r_id_raw, cat_raw

    # Initialize trackers
    security_groq_calls = 0
    target_groq_calls = 0
    semantic_verdict = None
    semantic_confidence = None
    security_reason = None
    output_validation_verdict = None
    output_validation_confidence = None
    output_validation_reason = None
    output_validation_groq_calls = 0
    enforcement_action = None
    
    if is_attack:
        decision = "BLOCKED"
        risk = severity
        attack_type = category
        detection_layer = "RULE_ENGINE"
        matched_rules = rule_id
        response_text = f"Security Violation: Your request was blocked because it triggered rule {rule_id} ({category})."
        
        user_classification = "POTENTIAL_ATTACKER"
        classification_reason = f"Matched {rule_id} {category} signature."
        
        structured_prompt_used = False
        prompt_structure = "— NOT REACHED"
        enforcement_action = "BLOCK_INPUT"
    else:
        matched_rules = None
        suspicion = is_suspicious(normalized_input) or (obf_info.get("obfuscation_score", 0) >= 0.25)
        
        is_semantic_attack = False
        if suspicion:
            semantic_res = semantic_detect(normalized_input)
            security_groq_calls = 1
            
            is_semantic_attack = semantic_res.get("is_attack", False)
            semantic_verdict = "ATTACK" if is_semantic_attack else "SAFE"
            semantic_confidence = semantic_res.get("confidence")
            security_reason = semantic_res.get("reason")
            
            if is_semantic_attack:
                decision = "BLOCKED"
                risk = semantic_res.get("risk", "HIGH")
                attack_type = semantic_res.get("attack_type", "SEMANTIC_ANALYSIS_UNAVAILABLE")
                detection_layer = "SEMANTIC_DETECTOR"
                response_text = f"Security Violation: Your request was blocked by the semantic engine."
                
                if attack_type == "SEMANTIC_ANALYSIS_UNAVAILABLE":
                    user_classification = "GENUINE_USER"
                    classification_reason = "No attack evidence; request blocked due to analysis failure."
                else:
                    user_classification = "POTENTIAL_ATTACKER"
                    classification_reason = f"Semantic analysis identified: {security_reason}"
                    
                structured_prompt_used = False
                prompt_structure = "— NOT REACHED"
                enforcement_action = "BLOCK_INPUT"

        if not is_attack and not is_semantic_attack:
            decision = "ALLOWED"
            risk = "LOW"
            attack_type = "NONE"
            detection_layer = "BASELINE"
            user_classification = "GENUINE_USER"
            classification_reason = "No prompt-injection indicators detected."
            
            try:
                # Forward to target app
                target_resp = requests.post(TARGET_APP_URL, json={"message": request.message})
                target_resp.raise_for_status()
                target_data = target_resp.json()
                
                target_response_text = target_data.get("response", "Error getting response")
                target_groq_calls = target_data.get("groq_calls", 1)
                structured_prompt_used = target_data.get("structured_prompt_used", False)
                prompt_structure = target_data.get("prompt_structure", "")
                
                # Output Validation / LLM-as-Critic
                critic_res = validate_output(SYSTEM_PROMPT, request.message, target_response_text)
                output_validation_groq_calls = 1
                
                output_validation_verdict = critic_res.get("verdict", "UNSAFE")
                output_validation_confidence = critic_res.get("confidence")
                output_validation_reason = critic_res.get("reason")
                
                if output_validation_verdict == "UNSAFE":
                    decision = "BLOCKED"
                    risk = "HIGH"
                    attack_type = "UNSAFE_OUTPUT"
                    detection_layer = "OUTPUT_VALIDATOR"
                    response_text = "Response blocked by the LLMShield output security layer."
                    user_classification = "POTENTIAL_ATTACKER"
                    classification_reason = f"Output validation failed: {output_validation_reason}"
                    
                    if "Failing closed due to output validation error" in output_validation_reason:
                        enforcement_action = "BLOCK_VALIDATION_FAILURE"
                    else:
                        enforcement_action = "BLOCK_OUTPUT"
                else:
                    response_text = target_response_text
                    enforcement_action = "ALLOW"
                    
            except requests.RequestException as e:
                response_text = f"Target Application Error: {str(e)}"
                target_groq_calls = 0
                structured_prompt_used = False
                prompt_structure = ""
                enforcement_action = "BLOCK_VALIDATION_FAILURE"

    # Multi-turn Conversation & Context Tracking with Verified User Classification
    if auth_context:
        user, session = auth_context
        user_type = "INTERNAL_USER"
        authentication_status = "AUTHENTICATED"
        authorization_status = "NOT_EVALUATED"
        user_identity_label = "INTERNAL USER – AUTHENTICATED EMPLOYEE"
        user_id = user.id
        session_id = session.id if session else None
        authenticated_user_dict = {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "department": user.department
        }
    else:
        user_type = "EXTERNAL_USER"
        authentication_status = "UNAUTHENTICATED"
        authorization_status = "UNAUTHORIZED"
        user_identity_label = "EXTERNAL USER – UNAUTHORIZED"
        user_id = None
        session_id = None
        authenticated_user_dict = None

    # Embed verified user classification into indicators
    obf_info["user_type"] = user_type
    obf_info["authentication_status"] = authentication_status
    obf_info["authorization_status"] = authorization_status
    obf_info["user_identity_label"] = user_identity_label
    if authenticated_user_dict:
        obf_info["authenticated_user"] = authenticated_user_dict

    # Derive conversation ID: if not supplied in request, keep requests isolated per unique conversation/request
    conversation_id = request.conversation_id
    if not conversation_id:
        conversation_id = f"conv-req-{uuid.uuid4().hex[:12]}"

    individual_score = 0.95 if decision == "BLOCKED" and risk in ["HIGH", "CRITICAL"] else (0.50 if risk == "MEDIUM" else 0.05)
    
    conv_analysis = analyze_conversation_turn(
        db=db,
        conversation_id=conversation_id,
        user_id=user_id,
        current_raw_message=request.message,
        current_canonical_message=canonical_text,
        individual_attack_detected=(decision == "BLOCKED"),
        individual_risk=risk,
        individual_score=individual_score,
        indicators=obf_info
    )

    # If multi-turn analysis intercepted a progressive attack
    if conv_analysis["is_multi_turn_attack"] and decision == "ALLOWED":
        decision = "BLOCKED"
        risk = "HIGH"
        attack_type = "MULTI_TURN_INJECTION"
        detection_layer = "MULTI_TURN_ANALYZER"
        response_text = f"Security Violation: Cumulative conversation context analysis flagged progressive injection: {conv_analysis['multi_turn_reason']}"
        user_classification = "POTENTIAL_ATTACKER"
        classification_reason = conv_analysis["multi_turn_reason"]
        enforcement_action = "BLOCK_INPUT"

    end_time = time.time()
    latency_ms = round((end_time - start_time) * 1000, 2)
    total_groq_calls = security_groq_calls + target_groq_calls + output_validation_groq_calls
    
    # Log to SQLite
    log_entry = RequestLog(
        input_text=request.message,
        normalized_input=normalized_input,
        decision=decision,
        risk=risk,
        attack_type=attack_type,
        detection_layer=detection_layer,
        matched_rules=matched_rules,
        semantic_verdict=semantic_verdict,
        semantic_confidence=semantic_confidence,
        security_reason=security_reason,
        latency_ms=latency_ms,
        groq_calls=total_groq_calls, # Legacy
        security_groq_calls=security_groq_calls,
        target_groq_calls=target_groq_calls,
        total_groq_calls=total_groq_calls,
        user_classification=user_classification,
        classification_reason=classification_reason,
        structured_prompt_used=structured_prompt_used,
        prompt_structure=prompt_structure,
        output_validation_verdict=output_validation_verdict,
        output_validation_confidence=output_validation_confidence,
        output_validation_reason=output_validation_reason,
        output_validation_groq_calls=output_validation_groq_calls,
        enforcement_action=enforcement_action
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # Optional authenticated internal user link (preserves request_logs schema)
    if auth_context:
        try:
            link = UserRequestLink(
                request_log_id=log_entry.id,
                user_id=user_id,
                session_id=session_id,
                created_at=datetime.now(timezone.utc).replace(tzinfo=None)
            )
            db.add(link)
            db.commit()
        except Exception as e:
            print(f"[USER_REQUEST_LINK ERROR] {e}")

    # Persist ConversationMessage
    try:
        conv_msg = ConversationMessage(
            conversation_id=conversation_id,
            request_log_id=log_entry.id,
            user_id=user_id,
            turn_index=conv_analysis["turn_index"],
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            raw_message=request.message,
            normalized_message=canonical_text,
            detected_language=obf_info.get("detected_language", "en"),
            detected_techniques_json=json.dumps(conv_analysis["detected_techniques"]),
            indicators_json=json.dumps(obf_info),
            individual_risk=risk,
            individual_risk_score=individual_score,
            cumulative_risk=conv_analysis["cumulative_risk"],
            cumulative_risk_score=conv_analysis["cumulative_risk_score"],
            decision=decision,
            enforcement_action=enforcement_action,
            detection_reason=classification_reason,
            detection_layer=detection_layer,
            is_attack_turn=(decision == "BLOCKED")
        )
        db.add(conv_msg)
        db.commit()
    except Exception as e:
        print(f"[CONVERSATION_MESSAGE ERROR] {e}")
    
    return ChatResponse(
        response=response_text,
        decision=decision,
        risk=risk,
        attack_type=attack_type,
        detection_layer=detection_layer,
        latency_ms=latency_ms,
        total_groq_calls=total_groq_calls,
        security_groq_calls=security_groq_calls,
        target_groq_calls=target_groq_calls,
        matched_rules=matched_rules,
        semantic_verdict=semantic_verdict,
        semantic_confidence=semantic_confidence,
        normalized_input=normalized_input,
        user_classification=user_classification,
        classification_reason=classification_reason,
        structured_prompt_used=structured_prompt_used,
        prompt_structure=prompt_structure,
        output_validation_verdict=output_validation_verdict,
        output_validation_confidence=output_validation_confidence,
        output_validation_reason=output_validation_reason,
        output_validation_groq_calls=output_validation_groq_calls,
        enforcement_action=enforcement_action,
        conversation_id=conversation_id,
        turn_index=conv_analysis["turn_index"],
        cumulative_risk=conv_analysis["cumulative_risk"],
        cumulative_risk_score=conv_analysis["cumulative_risk_score"],
        detected_techniques=conv_analysis["detected_techniques"],
        detected_language=obf_info.get("detected_language", "en"),
        obfuscation_indicators=obf_info,
        user_type=user_type,
        authentication_status=authentication_status,
        authorization_status=authorization_status,
        user_identity_label=user_identity_label,
        authenticated_user=authenticated_user_dict
    )
