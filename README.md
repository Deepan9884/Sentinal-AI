# SENTINEL-AI: Evidence-Based Multi-Agent Threat Modeling & Automated Security Validation

**Prototype Implementation for TECHgium / L&T Cybersecurity Track**

SENTINEL-AI transforms embedded architecture diagrams, documents, and specifications into verifiable threat models, proving or rejecting each threat through isolated sandbox execution.

---

## Architecture Overview

```
                      Engineering Design Docs / Specs
                                     │
                         [Sentinel Orchestrator]  <── Shared State (Graph & Evidence Store),
                                     │                Retry Caps (2), Human Approval Gate
                                     │
   ┌─────────────────────────────────┴─────────────────────────────────┐
   │                                                                   │
1. Analyzer ──> Reviewer ──> 2. Investigator ──> Reviewer ──> 3. Planner ──> Reviewer
                   │                             │                          │
                   └─[Reject & Retry Loop]───────┴─[Reject & Retry Loop]────┘
                                     │
                              [Human-in-the-Loop]
                                     │ (Approved)
                                     ▼
                        4. Executor ──> Reviewer ──> Final Certified Security Report
                              │            │
                              └─[Reject]───┘
```

---

## Agent Contracts & Roles

| Agent | Input | Output | Core Tools / Implementation |
| :--- | :--- | :--- | :--- |
| **Analyzer** | Diagrams, specs, configs | Structured JSON: components, interfaces, data flows, trust boundaries, confidence scores | Pydantic model parser, vision extractor |
| **Investigator** | Security Knowledge Graph | Prioritized threats with graph evidence, EMB3D / CWE / CAPEC IDs, ranked attack paths | **Rule engine + graph traversal** (NetworkX) + explanatory synthesis |
| **Planner** | Investigator threat report | Prioritized mitigation plan with projected risk reductions and config patches | MITRE EMB3D-M series catalog mapping |
| **Executor** | Approved mitigation plan | Baseline exploit run, patch applied to emulated copy, verification test re-run, before/after delta | Isolated QEMU/CAN sandbox emulator |
| **Reviewer** | Any agent's output | `PASS` or `REJECT` with granular rule violations | **Strict non-LLM hard checks** (schemas, catalog lookups, graph node verification) |

---

## Key Architectural Highlights

1. **Rule-Driven Investigator**:
   - The Investigator does **not** rely on a hallucinating LLM to guess threats.
   - Threats are discovered deterministically via graph rules: unauthenticated trust boundary crossings (`EMB3D-T-0012`, `CWE-306`) and reachability to safety-critical ECUs (`CAPEC-272` to ASIL-D Brake Controller).
   - The synthesis component formats structured graph evidence and technical explanations.

2. **Deterministic State Machine (Sentinel Orchestrator)**:
   - Workflow controller enforcing strict transitions, retry counting, evidence archiving, and human approval checkpoints.

3. **Strict Non-LLM Reviewer**:
   - Hard checks:
     - Pydantic schema validation.
     - MITRE catalog lookups (validates that EMB3D, CAPEC, and CWE IDs actually exist in authoritative datasets).
     - Graph grounding & topological path connectivity (confirms every cited node exists and consecutive hops form directed edges).
     - Unique identifier checks (no duplicate threat or mitigation IDs).
     - Referential integrity (data flows reference registered components; mitigations reference valid threats).
     - Test reproducibility & availability (confirms baseline exploit reproduced, post-patch attack blocked, and legitimate traffic preserved).

4. **Power-Limited Executor & Sandbox Verification**:
   - Runs tests and applies patches **only to an isolated emulated sandbox copy**.
   - Before-and-after proof:
     - Baseline Exploit: Unauthenticated MQTT payload breaches Gateway and forces Brake ECU deceleration (`Status 200 - Vulnerable`).
     - Patch Applied: `mTLS (TLS 1.3)` + `HMAC` enabled.
     - Verification Pass: Identical spoofing payload dropped at perimeter (`Status 401 - Blocked`).
     - Legitimate Operations Verification: Authorized telematics telemetry processes cleanly (`Status 200 - Operational`).
     - Empirical Risk Delta: **8.2 (CRITICAL) ➔ 3.1 (LOW)** (Risk Reduction: **62.2%**).

5. **Rejection Feedback Loops & Human Escalation**:
   - If Reviewer rejects an agent's output, specific violation feedback routes back to that agent for self-correction.
   - Retries capped at **2**; further failures escalate to the lead engineer.

---

## Quickstart & Execution

### 0. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 1. Run Automated Unit Tests (100% Pass)
```powershell
python tests/test_sentinel.py
```

### 2. Run Interactive CLI Demonstration
```powershell
python demo.py
```
Or run specific demo modes directly:
- **Full End-to-End Demo:** `python demo.py --mode=1`
- **Reviewer Rejection & Self-Correction:** `python demo.py --mode=2`
- **Human Approval Guardrail:** `python demo.py --mode=3`

### 3. Launch Web Applications
- **Streamlit Interactive Dashboard:**
```powershell
streamlit run web/app.py
```
  Access at `http://localhost:8501`.

- **Standalone Cyber-Console:**
```powershell
python run_web.py
```

---

## Project Structure

```
.
├── sentinel_core/
│   ├── catalogs/              # Ground-truth EMB3D, CAPEC, CWE datasets
│   ├── models/                # Strict Pydantic v2 data schemas
│   ├── graph/                 # NetworkX-based Security Knowledge Graph
│   ├── harness/               # Isolated Emulated Subsystem (Gateway + Brake ECU)
│   ├── agents/
│   │   ├── analyzer.py        # Architecture extractor
│   │   ├── investigator.py    # Rule-driven graph threat engine
│   │   ├── planner.py         # Mitigation planner
│   │   ├── executor.py        # Sandboxed test & verification runner
│   │   └── reviewer.py        # Independent non-LLM strict gate
│   ├── orchestrator/
│   │   ├── state.py           # Shared state & evidence store
│   │   ├── state_machine.py   # Deterministic StateGraph engine
│   │   └── sentinel.py        # Central Sentinel Orchestrator
│   └── report.py              # ISO/SAE 21434 & IEC 62443 compliance report generator
├── web/
│   ├── app.py                 # Streamlit Interactive Web Dashboard
│   ├── index.html             # Standalone Cyber-Console interface
│   ├── demo_player.html       # Visual playback console
│   └── dist/
│       └── audit_report.html  # Sample ISO/SAE 21434 Audit Report
├── tests/
│   └── test_sentinel.py       # 16 automated test cases (100% passing)
├── demo.py                    # Rich interactive terminal demonstration
├── run_web.py                 # Multi-mode web launcher
├── run_dashboard.ps1          # 1-click dashboard launcher
├── run_demo.ps1               # 1-click CLI demo launcher
└── requirements.txt           # Python dependencies
```
