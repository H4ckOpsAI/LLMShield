from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from datetime import datetime
from .database import ConversationMessage

# Indicators that suggest multi-turn context priming or progressive jailbreaking
CONTEXT_PRIMING_KEYWORDS = [
    "remember this", "in our previous context", "for our game", "hypothetically",
    "let's roleplay", "continue the story", "as agreed before", "step 2", "next step",
    "unlock mode", "now that we are aligned", "as the character we created"
]

EXTRACTION_GOAL_KEYWORDS = [
    "reveal", "print", "disclose", "system prompt", "secret", "credentials",
    "instructions", "ignore rules", "override", "bypass"
]

def analyze_conversation_turn(
    db: Session,
    conversation_id: str,
    user_id: int | None,
    current_raw_message: str,
    current_canonical_message: str,
    individual_attack_detected: bool,
    individual_risk: str,
    individual_score: float,
    indicators: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates cumulative risk across the chronological history of a conversation.
    Identifies multi-turn progressive prompt injection attacks:
    - Turn 1: Benign setup / hypothetical frame / persona definition
    - Turn 2+: Step-by-step constraint relaxation / rule probing
    - Turn N: Payload execution or instruction override
    """
    # Fetch previous messages in this conversation ordered by turn_index
    history = db.query(ConversationMessage).filter(
        ConversationMessage.conversation_id == conversation_id
    ).order_by(ConversationMessage.turn_index.asc()).all()

    turn_index = len(history) + 1
    
    # Calculate cumulative factors
    prev_turns_count = len(history)
    cumulative_score = individual_score
    multi_turn_attack_detected = False
    multi_turn_reason = None
    detected_techniques = []

    # Check techniques on current turn
    if indicators.get("has_unicode_homoglyphs"):
        detected_techniques.append("Unicode / Homoglyph Evasion")
    if indicators.get("has_scrambled_spaced_text"):
        detected_techniques.append("Special-Character / Spaced Obfuscation")
    if indicators.get("has_emoji_obfuscation"):
        detected_techniques.append("Emoji-Based Obfuscation")
    if indicators.get("is_multilingual"):
        detected_techniques.append("Multilingual Semantic Injection")

    # If already an individual attack
    if individual_attack_detected:
        detected_techniques.append("Direct / Rewritten Keyword Evasion")

    # Multi-turn correlation logic
    if prev_turns_count > 0:
        # Check historical context for priming
        has_historical_priming = any(
            any(k in m.normalized_message.lower() for k in CONTEXT_PRIMING_KEYWORDS)
            for m in history if m.normalized_message
        )
        
        # Check historical warnings / suspicious turns
        historical_suspicious_count = sum(
            1 for m in history if m.individual_risk in ["MEDIUM", "HIGH", "CRITICAL"] or m.is_attack_turn
        )

        curr_has_goal = any(k in current_canonical_message.lower() for k in EXTRACTION_GOAL_KEYWORDS)
        curr_has_priming = any(k in current_canonical_message.lower() for k in CONTEXT_PRIMING_KEYWORDS)

        # Pattern 1: Progressive Escalation (priming earlier + goal now)
        if has_historical_priming and curr_has_goal:
            multi_turn_attack_detected = True
            multi_turn_reason = f"Multi-turn progressive attack: Conversation established framing in turns 1-{prev_turns_count} and triggered goal extraction in turn {turn_index}."
            cumulative_score = max(cumulative_score, 0.88)
            detected_techniques.append("Multi-Turn Context Evasion")

        # Pattern 2: Repeated Probing / Incremental boundary pushing
        elif historical_suspicious_count >= 1 and (curr_has_goal or curr_has_priming or individual_attack_detected):
            multi_turn_attack_detected = True
            multi_turn_reason = f"Cumulative risk threshold exceeded: {historical_suspicious_count} prior probing turns culminated in turn {turn_index} attack payload."
            cumulative_score = max(cumulative_score, 0.92)
            detected_techniques.append("Multi-Turn Context Evasion")

        # Cumulative score compounding
        for m in history:
            cumulative_score += (m.individual_risk_score * 0.25)
        cumulative_score = round(min(1.0, cumulative_score), 2)
    
    # Final cumulative risk label
    if cumulative_score >= 0.80 or multi_turn_attack_detected or individual_risk in ["HIGH", "CRITICAL"]:
        cumulative_risk = "HIGH"
    elif cumulative_score >= 0.50 or individual_risk == "MEDIUM":
        cumulative_risk = "MEDIUM"
    else:
        cumulative_risk = "LOW"

    # Multi-turn override decision
    final_decision = "BLOCKED" if (individual_attack_detected or multi_turn_attack_detected or cumulative_risk == "HIGH") else "ALLOWED"
    final_enforcement = "BLOCK_INPUT" if final_decision == "BLOCKED" else "ALLOW"

    return {
        "turn_index": turn_index,
        "detected_techniques": list(set(detected_techniques)),
        "is_multi_turn_attack": multi_turn_attack_detected,
        "multi_turn_reason": multi_turn_reason,
        "cumulative_risk": cumulative_risk,
        "cumulative_risk_score": cumulative_score,
        "decision": final_decision,
        "enforcement_action": final_enforcement,
        "history_length": prev_turns_count
    }
