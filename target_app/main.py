# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
import os
# pyrefly: ignore [missing-import]
import json
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
from groq import Groq

# Load .env from the project root
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, '..', '.env')
load_dotenv(dotenv_path=env_path)

app = FastAPI(title="Target LLM Application")

# CORS setup: Restrict to internal gateway and dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Groq client
api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key) if api_key else None

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    decision: str
    risk: str
    attack_type: str
    detection_layer: str
    latency_ms: float
    groq_calls: int
    structured_prompt_used: bool = False
    prompt_structure: str = ""

# Load system prompt
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_path = os.path.join(current_dir, "system_prompt.txt")
    with open(prompt_path, "r") as f:
        SYSTEM_PROMPT = f.read()
except FileNotFoundError:
    SYSTEM_PROMPT = "You are a helpful assistant."

# Load company data context
try:
    data_path = os.path.join(current_dir, "data", "company_data.json")
    with open(data_path, "r") as f:
        company_data_json = json.load(f)
        COMPANY_CONTEXT = f"Trusted Company Data:\n{json.dumps(company_data_json, indent=2)}"
except Exception as e:
    COMPANY_CONTEXT = "Trusted Company Data:\n{}"
    print(f"Failed to load company data: {e}")

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "target_app"}

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    global client
    if not client:
        # Try to re-initialize if it was missing during startup
        api_key = os.getenv("GROQ_API_KEY")
        if api_key:
            client = Groq(api_key=api_key)
        else:
            raise HTTPException(status_code=500, detail="Groq API key is missing or client is not initialized.")
    
    try:
        # We only return the target response. Latency/decision are filled by gateway usually,
        # but the schema requires them. Target app can return defaults or just the response.
        # Let's return defaults for the security fields, the gateway will overwrite them.
        
        # Create the message array for the LLM
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": COMPANY_CONTEXT},
            {"role": "user", "content": request.message}
        ]
        
        # Forward messages to Groq LLM
        chat_completion = client.chat.completions.create(
            messages=messages,
            model="openai/gpt-oss-20b", # Supported free tier fast model
        )
        
        response_content = chat_completion.choices[0].message.content
        
        return ChatResponse(
            response=response_content,
            decision="ALLOWED",
            risk="LOW",
            attack_type="NONE",
            detection_layer="TARGET_APP_NATIVE",
            latency_ms=0.0,
            groq_calls=1,
            structured_prompt_used=True,
            prompt_structure="system + trusted_context + user"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
