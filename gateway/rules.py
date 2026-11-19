import re
from typing import Tuple, List, Optional

RULES = [
    {
        "id": "R001",
        "category": "INSTRUCTION_OVERRIDE",
        "pattern": r"\b(ignore|disregard|forget|bypass)\s+(your\s+)?(all\s+)?(previous\s+)?(instructions|directions|rules)\b.*\b(reveal|print|disclose|provide|expose|show|return|output)\b",
        "severity": "HIGH",
        "description": "Attempt to override system instructions with an unauthorized action."
    },
    {
        "id": "R002",
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "pattern": r"\b(repeat|print|show|output|reveal|disclose|expose)\s+(your\s+)?(complete\s+|all\s+)?(the\s+)?(words\s+above|system prompt|instructions)\b",
        "severity": "HIGH",
        "description": "Attempt to extract the system prompt."
    },
    {
        "id": "R003",
        "category": "ROLE_MANIPULATION",
        "pattern": r"\b(you are now|act as|pretend to be)\b.*\b(reveal|print|disclose|provide|expose|show|return|output)\b",
        "severity": "HIGH",
        "description": "Attempt to change the AI's role coupled with an action."
    },
    {
        "id": "R004",
        "category": "SECURITY_RULE_BYPASS",
        "pattern": r"\b(developer mode|jailbreak|dan|do anything now)\b",
        "severity": "HIGH",
        "description": "Attempt to bypass security rules using known jailbreak terms."
    },
    {
        "id": "R005",
        "category": "SENSITIVE_DATA_REQUEST",
        "pattern": r"\b(aws_access_key|aws_secret_key|stripe_sk|ssn|social security number|database credentials?)\b",
        "severity": "HIGH",
        "description": "Direct request for known sensitive data keywords."
    }
]

def rule_detect(text: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    Implements rule-based / signature detection.
    Returns (is_attack, risk_level, matched_rule_id, matched_category).
    """
    for rule in RULES:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            return True, rule["severity"], rule["id"], rule["category"]
            
    return False, "LOW", None, None

def is_suspicious(text: str) -> bool:
    """
    Lightweight deterministic check to see if semantic Groq analysis is required.
    Does NOT do semantic understanding. Just looks for suspicious keywords or fragments.
    """
    suspicion_patterns = [
        r"\b(ignore|disregard|forget|bypass)\b",
        r"\b(instructions|directions|rules|system prompt)\b",
        r"\b(you are now|act as|pretend to be)\b",
        r"\b(developer mode|jailbreak|dan|do anything now)\b",
        r"\b(aws_access_key|aws_secret_key|stripe_sk|ssn|social security number|database credentials?|salary|role)\b",
        r"\b(reveal|print|disclose|provide|expose|show|return|output)\b"
    ]
    
    # We will trigger suspicion if any of these highly correlated words appear.
    # It doesn't mean it's an attack, just that we need the semantic layer to look closer.
    for pattern in suspicion_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
            
    return False
