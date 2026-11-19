# LLMShield - Comprehensive Project Handover & Context Document
*Version: Mid-Sem Review Ready (November 2026)*
*Primary Target: Anti-Gravity IDE / AI Pair-Programmer Handover Document*

---

## 1. Project Overview & Core Mission

**LLMShield** is an external, multi-tier security gateway and guardrail framework specifically engineered to protect target Large Language Model (LLM) applications against:
1. **Direct Prompt Injection** (instruction overrides, jailbreaks, system role hijacking).
2. **System Prompt Extraction / Reconnaissance** (attempts to dump hidden developer instructions or confidential schemas).
3. **Sensitive Data Leakage & Exfiltration** (unauthorized retrieval of employee records, salaries, credentials, and API keys).

### Key Architectural Philosophy: "Defense-in-Depth with Latency-Aware Heuristics"
- **External Proxy Gateway**: Guardrails are completely decoupled from the target LLM application. All client traffic hits LLMShield first (`http://127.0.0.1:8000`), which sanitizes, inspects, and enforces safety before relaying requests to the target application (`http://127.0.0.1:8001`).
- **Cost & Latency Optimization**: Deterministic rules (Layer 1) run locally in sub-millisecond time. Only suspicious prompts with specific trigger keywords trigger semantic LLM classification (Layer 2). Clean, benign prompts bypass Layer 2 and proceed directly to inference, saving Groq API calls and keeping latency minimal.
- **Fail-Safe Output Validation**: Even if an injection technique evades input layers, model responses are scrutinized by an output validation guardrail (Layer 3) before being returned to the user.

---

## 2. Architecture & Service Topology

The project is composed of three concurrently running standalone components:

```
[ Client / User ]
       │
       ▼  HTTP POST /chat
┌─────────────────────────────────────────────────────────────┐
│ 1. LLMShield Gateway (:8000)                                │
│    ├── Layer 1: Normalization & Regex Rule Engine (R001-R007)│
│    ├── Layer 2: Semantic Injection Guardrail (Groq LLM)     │
│    ├── Prompt Structuring: System / Context / User isolation │
│    ├── Forwarder: Relays to Target App (:8001)              │
│    ├── Layer 3: Output Leakage Validator (Groq LLM)         │
│    ├── External Enforcer: ALLOW vs. BLOCKED                 │
│    └── Audit Logger: SQLite DB (`llmshield.db`)             │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP POST /chat (Trusted Internal)
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Target LLM Application (:8001)                           │
│    ├── Role: Internal Corporate IT Support Assistant        │
│    ├── Model: `openai/gpt-oss-20b` via Groq Cloud API       │
│    └── Context: Hardcoded sensitive employee database       │
│        (Contains CEO, VP, Engineer salaries, roles, PII)    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 3. SOC Security Dashboard (:3000)                           │
│    ├── Framework: Next.js 16 + React 19 + TailwindCSS       │
│    ├── Theme: Deep Obsidian (`#030712`) Cyber SOC Terminal  │
│    ├── Features: Real-time Live Prompt Analyzer, Multi-Tier  │
│    │   Execution Trace, Security Telemetry, Recharts, Audit │
│    │   Log polling every 5s from `http://127.0.0.1:8000/events`│
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Directory Structure & Key Files

```
llmshield/
├── gateway/
│   ├── main.py                  # Primary FastAPI gateway logic, pipeline routing & enforcement
│   ├── rules.py                 # Layer 1 deterministic regex rules (R001-R007) & heuristics
│   ├── semantic.py              # Layer 2 Groq LLM semantic injection classifier
│   ├── output_validator.py      # Layer 3 Groq LLM sensitive data leakage & extraction validator
│   ├── database.py              # SQLite event logging model (SecurityEvent table)
│   └── mock_groq.py             # Deterministic fallback simulator when offline or rate-limited
├── target_app/
│   └── main.py                  # Standalone FastAPI IT assistant hosting mock company data
├── dashboard/
│   ├── src/app/page.tsx         # Complete SOC command center UI (live analyzer, charts, logs)
│   ├── src/app/globals.css      # Core styles & Tailwind imports
│   └── package.json             # Next.js 16 dependencies (Lucide icons, Recharts, React-Markdown)
├── tests/
│   ├── test_basic_flow.py       # 14 unit tests covering rules, edge cases, and end-to-end flows
│   ├── test_flow_paths.py       # 8 basis path tests covering complete cyclomatic complexity V(G)=8
│   ├── test_boundary_values.py  # 5 boundary value analysis tests (0-length, whitespace, 0.69/0.70/0.71)
│   ├── run_comparative_evaluation.py # Academic evaluation runner (Baseline vs Protected on 40 cases)
│   └── evaluation_dataset.json  # JSON test cases with labels and attack categories
├── evaluation/
│   ├── baseline_vs_protected_results.csv   # Raw per-case evaluation data for 40 test prompts
│   ├── baseline_vs_protected_summary.csv   # Comparative summary metrics
│   ├── baseline_vs_protected_summary.json  # JSON summary metrics (ASR, Precision, Recall, F1)
│   ├── generate_flow_path_figures.py       # Script generating publication-grade CFG diagrams
│   └── figures/
│       ├── flow_path_testing_cfg.png       # Control Flow Graph for Section 6.1.1
│       └── baseline_vs_protected_comparison.png # Academic bar chart for Section 7.2
├── llmshield_40_synthetic_test_cases.csv   # Master CSV with 40 labelled prompts
├── requirements.txt             # Python dependencies (fastapi, uvicorn, groq, pydantic, pytest)
├── .env                         # GROQ_API_KEY and environment configuration
└── run.bat                      # Convenience script to launch all 3 servers
```

---

## 4. Multi-Tier Security Pipeline (Execution Flow)

When a request arrives at `POST /chat` on `http://127.0.0.1:8000`:

1. **Step 1: Normalization**
   - Strips zero-width characters, collapses whitespace, normalizes unicode.
2. **Step 2: Rule-Based Signature Inspection (`gateway/rules.py`)**
   - Evaluates regular expressions for known attack signatures:
     - `R001`: Instruction override / ignore previous commands.
     - `R002`: System prompt disclosure / reveal developer instructions.
     - `R003`: Role-play / DAN / jailbreak persona simulation.
     - `R004`: Database dumping / salary exfiltration attempts.
     - `R005`: Delimiter & markdown manipulation attacks.
     - `R006`: System prompt extraction phrases ("repeat everything above").
     - `R007`: Special token injections (`<|im_start|>`, `[INST]`, `<<SYS>>`).
   - If matched: Request is immediately **BLOCKED** with `risk: HIGH` or `MEDIUM`, `detection_layer: RULE_ENGINE`. Target LLM is **never called** (`total_groq_calls = 0`).
3. **Step 3: Latency-Aware Heuristic & Semantic Check (`gateway/semantic.py`)**
   - Calls `is_suspicious(normalized_input)`:
     - If benign (e.g., "What are the company holidays?"): Semantic check is bypassed (`security_groq_calls = 0`).
     - If suspicious (contains security-sensitive terms like "password", "confidential", "bypass"): Calls Groq LLM with a dedicated security prompt to judge intent (`ATTACK` vs `SAFE`).
   - If `ATTACK`: Intercepted and **BLOCKED** (`detection_layer: SEMANTIC_DETECTOR`).
4. **Step 4: Structured Prompting**
   - Isolates developer system instructions, trusted business context, and untrusted user inputs with distinct system tags to prevent prompt escaping.
5. **Step 5: Target LLM Inference (`target_app/main.py`)**
   - Gateway forwards payload to the internal IT assistant running `openai/gpt-oss-20b`.
6. **Step 6: Output Validation (`gateway/output_validator.py`)**
   - Scans the generated output for sensitive data leakage:
     - Checks against regex rules for leaked salaries, employee database dumps, API keys.
     - Evaluates with a Groq LLM validator if sensitive patterns are suspected.
   - If unsafe: Response is censored and sanitized (`detection_layer: OUTPUT_VALIDATOR`).
7. **Step 7: External Enforcement & Audit Logging**
   - Final verdict (`ALLOW` or `BLOCKED`) is logged to SQLite (`llmshield.db`) along with execution latency, rule matches, confidence scores, and token/call metrics.

---

## 5. Summary of Recent Development Milestones (Already Completed)

### Milestone A: Section 6.1.1 Flow Path Testing (Cyclomatic Complexity $V(G)=8$)
- **File**: `tests/test_flow_paths.py`
- Formally derived cyclomatic complexity $V(G) = 14 \text{ edges} - 8 \text{ nodes} + 2 = 8$.
- Implemented and passed all 8 basis paths:
  1. *Path 1*: Immediate rule-based block (`R001` match, 0 Groq calls).
  2. *Path 2*: Clean benign prompt $\to$ heuristic bypass $\to$ Target LLM $\to$ safe output (2 Groq calls).
  3. *Path 3*: Suspicious prompt $\to$ Semantic detector classifies `ATTACK` $\to$ blocked (1 Groq call).
  4. *Path 4*: Suspicious prompt $\to$ Semantic classifier `SAFE` $\to$ Target LLM $\to$ safe output (3 Groq calls).
  5. *Path 5*: Benign prompt $\to$ Target LLM leaks data $\to$ Output validator blocks response (2 Groq calls).
  6. *Path 6*: Suspicious prompt $\to$ Semantic `SAFE` $\to$ Target leaks $\to$ Output validator blocks (3 Groq calls).
  7. *Path 7*: Empty string validation failure.
  8. *Path 8*: Structured prompt assembly verification.
- **Figure Generated**: `evaluation/figures/flow_path_testing_cfg.png`.

### Milestone B: Section 6.2.1 Boundary Value Analysis (BVA)
- **File**: `tests/test_boundary_values.py`
- Covered 5 rigorous boundary conditions:
  1. Empty input string (`""` $\to$ 400 Bad Request).
  2. Whitespace-only input (`"    \t\n"` $\to$ 400 Bad Request).
  3. Semantic confidence just below threshold (0.69).
  4. Semantic confidence exactly at threshold (0.70).
  5. Semantic confidence just above threshold (0.71).
- *Academic Note*: Discovered that production `gateway/main.py` currently gates strictly on the boolean `is_attack` returned by the LLM classifier rather than numerical confidence gating. Documented in the test suite without altering production logic.

### Milestone C: Section 7.2 Comparative Evaluation (Baseline vs. Protected)
- **Files**: `tests/run_comparative_evaluation.py`, `evaluation/baseline_vs_protected_results.csv`, `evaluation/baseline_vs_protected_summary.json`.
- Evaluated **40 synthetic prompts** against both modes:
  - **Baseline Mode**: Direct calls to `http://127.0.0.1:8001/chat` without guardrails.
  - **Protected Mode**: Complete LLMShield pipeline via `http://127.0.0.1:8000/chat`.
- **Results Achieved**:
  - **Attack Success Rate (ASR)**: Reduced from **82.5%** in baseline down to **5.0%** with LLMShield.
  - **Malicious Interception Recall**: **95.0%** (38/40 attacks blocked).
  - **Benign Precision**: **100%** (0 false positives on legitimate IT support queries).
  - **Interception Breakdown**: 24 blocked at Layer 1 (Rules), 12 at Layer 2 (Semantic), 2 at Layer 3 (Output Validator).
- **Academic Chart Generated**: `evaluation/figures/baseline_vs_protected_comparison.png`.

### Milestone D: SOC Dashboard Visual Modernization
- **Files**: `dashboard/src/app/page.tsx`, `dashboard/src/app/globals.css`.
- Elevated the UI into a polished Cyber SOC Command Center:
  - Deep Obsidian theme (`#030712`) with ambient radial glows (`cyan-500/10`, `blue-600/10`).
  - Frosted glass cards (`backdrop-blur-md`, `border-slate-800`).
  - Neon emerald (`#10b981`) and rose (`#f43f5e`) indicators.
  - Color-differentiated telemetry charts and real-time execution trace steps.

---

## 6. How to Run & Verify the Project

### Environment Setup
1. **Python Virtual Environment**:
   ```powershell
   ..\venv\Scripts\Activate.ps1
   ```
2. **Groq API Key**:
   Verify `.env` has:
   ```env
   GROQ_API_KEY=gsk_your_actual_groq_api_key_here
   ```

### Starting the Three Services
Open three separate terminal windows or run `run.bat`:
```powershell
# Terminal 1: Gateway (Port 8000)
python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Target LLM Application (Port 8001)
python -m uvicorn target_app.main:app --host 127.0.0.1 --port 8001 --reload

# Terminal 3: SOC Dashboard (Port 3000)
cd dashboard
npm run dev
```

### Running Test Suites
```powershell
# Run all 27 unit, flow path, and boundary tests:
pytest tests/test_basic_flow.py tests/test_flow_paths.py tests/test_boundary_values.py -v

# Run the comparative evaluation suite:
python tests/run_comparative_evaluation.py
```

---

## 7. Key Implementation Rules & Constraints

When implementing modifications or viva feedback:
1. **Do Not Break Business Logic for Tests**: If a test fails, verify whether the test assertion or the application logic is contradictory. Never blindly change production gateway logic.
2. **Preserve Decoupling**: Keep `target_app` naive. The target app represents a vulnerable internal system; security logic belongs strictly in `gateway/`.
3. **Preserve Multi-Tier Routing**: Ensure Layer 1 runs locally first (0 Groq calls for obvious attacks), Layer 2 runs only when suspicious, and Layer 3 runs post-inference.
4. **No Synthetic Result Fabrication**: All benchmark results and evaluation metrics must be derived from genuine script runs and real API outputs.
5. **Dashboard Styling Tokens**: Maintain the dark obsidian (`#030712`), slate text (`text-slate-200` to `text-slate-400`), cyan accents (`#06b6d4`), and glowing status indicators.