from pydantic import BaseModel
from typing import Optional, Any, List
from datetime import datetime

# ==============================================================================
# AUTHENTICATION SCHEMAS
# ==============================================================================
class LoginRequest(BaseModel):
    username: str
    password: str

class DemoLoginRequest(BaseModel):
    username: str

class PublicUserProfile(BaseModel):
    username: str
    full_name: str
    department: str
    role: str

class UserProfile(BaseModel):
    id: int
    username: str
    full_name: str
    department: str
    role: str
    is_demo: bool
    created_at: datetime

class AuthResponse(BaseModel):
    token: str
    user: UserProfile

# ==============================================================================
# SOC SUMMARY & CONVERSATION SCHEMAS
# ==============================================================================
class LLMSOCSummaryResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    allowed_requests: int
    internal_requests: int
    external_requests: int
    total_conversations: int
    suspicious_conversations: int = 0
