@echo off
title LLMShield Security Platform Launcher
echo ==============================================================================
echo                      LLMShield Guardrail Framework
echo ==============================================================================

if not exist .env (
    echo [WARNING] .env file not found!
    echo Creating .env from .env.example...
    copy .env.example .env
    echo Please configure your GROQ_API_KEY inside .env before continuing.
    echo.
)

echo [1/3] Starting Target LLM Application (Port 8001)...
start "LLMShield - Target LLM (:8001)" cmd /k "if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) else if exist ..\venv\Scripts\activate.bat (call ..\venv\Scripts\activate.bat) & python -m uvicorn target_app.main:app --host 127.0.0.1 --port 8001 --reload"

echo [2/3] Starting Security Proxy Gateway (Port 8000)...
start "LLMShield - Security Gateway (:8000)" cmd /k "if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) else if exist ..\venv\Scripts\activate.bat (call ..\venv\Scripts\activate.bat) & python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --reload"

echo [3/3] Starting Unified SOC Dashboard (Port 3000)...
start "LLMShield - SOC Dashboard (:3000)" cmd /k "cd dashboard && npm run dev"

echo.
echo ==============================================================================
echo All LLMShield services are launching:
echo   - Target LLM Service:      http://127.0.0.1:8001/health
echo   - Security Proxy Gateway:  http://127.0.0.1:8000/health
echo   - Unified SOC Dashboard:   http://localhost:3000
echo ==============================================================================
