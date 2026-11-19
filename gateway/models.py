# pyrefly: ignore [missing-import]
from pydantic import BaseModel

class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None

class ChatResponse(BaseModel):
    response: str
    decision: str
    risk: str
    attack_type: str
    detection_layer: str
    latency_ms: float
    total_groq_calls: int
    security_groq_calls: int
    target_groq_calls: int
    matched_rules: str | None = None
    semantic_verdict: str | None = None
    semantic_confidence: float | None = None
    normalized_input: str | None = None
    user_classification: str | None = None
    classification_reason: str | None = None
    structured_prompt_used: bool | None = None
    prompt_structure: str | None = None
    output_validation_verdict: str | None = None
    output_validation_confidence: float | None = None
    output_validation_reason: str | None = None
    output_validation_groq_calls: int = 0
    enforcement_action: str | None = None
    conversation_id: str | None = None
    turn_index: int | None = None
    cumulative_risk: str | None = None
    cumulative_risk_score: float | None = None
    detected_techniques: list[str] = []
    detected_language: str | None = None
    obfuscation_indicators: dict | None = None
    user_type: str | None = None
    authentication_status: str | None = None
    authorization_status: str | None = None
    user_identity_label: str | None = None
    authenticated_user: dict | None = None
