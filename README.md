# Unified Autonomous Cloud Intelligence - Srijan 2026 Project

**Unified Autonomous Cloud Intelligence (UACI) — Multi-Generational Evolution**

> Enterprise-grade GCP Cloud Security, Operations, and FinOps platform powered by Gemini 2.5 / 2.0 models  
> *Submission for Srijan 2026 Hackathon — Problem 7 + Problem 14*

---
## 👥 Meet the Team

This project was designed and developed by team **Yuti** under **Srijan 2026 Hackthon - BY Atos Global IT Solutions and Services**.
Feel free to connect with us and explore our work!

### 👤 Ankita Patil  

[![Email](https://img.shields.io/badge/Email-95ankita.s.patil%40gmail.com-red?style=flat&logo=gmail)](mailto:95ankita.s.patil@gmail.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ankita%20Patil-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/ankita-patil-10b0732ab/)

---

### 👤 Mithilesh Kolhapurkar  

[![Email](https://img.shields.io/badge/Email-m.kolhapurkar3529%40gmail.com-red?style=flat&logo=gmail)](mailto:m.kolhapurkar3529@gmail.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mithilesh%20Kolhapurkar-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/mithilesh-kolhapurkar-258001214)

---

## 🔗 Website / Demo Links
- **V1 Demo:** https://storage.googleapis.com/cloudops-frontend-123/index.html
- **V2 Demo:** https://gen-lang-client-0591533880.web.app/

---

## 📋 Table of Contents

1. [Executive Overview](#executive-overview)
2. [Architecture Comparison: V1 vs V2](#architecture-comparison-v1-vs-v2)
3. [V1: CloudOps AI Copilot MVP](#v1-cloudops-ai-copilot-mvp)
4. [V2: UACI Multi-Project Platform](#v2-uaci-multi-project-platform)
5. [Quick Start](#quick-start)
6. [Deployment](#deployment)
7. [API Reference](#api-reference)
8. [Security & Compliance](#security--compliance)

---

## Executive Overview

### What It Does

CloudOps AI Copilot is a **unified autonomous cloud intelligence platform** that:

- **Detects security misconfigurations** across GCP services (Cloud Storage, Compute Engine, Cloud SQL, IAM, VPC Firewall, GKE)
- **Scores and prioritizes risk** using RPN (Risk Priority Number) analysis with business context multipliers
- **Quantifies cost waste** from misconfigured and idle resources
- **Orchestrates remediation** across three execution tiers (Auto / Suggest / IaC) with human-in-the-loop approval
- **Provides GenAI insights** via Gemini 2.5 Flash / 2.0 Flash explaining findings and generating fix commands
- **Manages multi-project portfolios** with isolated permissions and team attribution

### Why Two Versions?

| Aspect | V1 | V2 |
|--------|----|----|
| **Scope** | Single GCP project | Multi-project enterprise portfolio |
| **AI Model** | Gemini 2.5 Flash (main), Gemini 2.5 Pro (fallback) | Gemini 2.0 Flash with structured outputs |
| **Architecture** | Monolithic FastAPI + Vanilla JS | Microservices with agent orchestration |
| **Agents** | Single `llm_analyzer` | 3 specialist agents: SRE, Security, FinOps |
| **Automation** | Manual execution | Saga pattern with approval workflow |
| **Frontend** | Vanilla HTML/CSS/JS | React 18 + TypeScript + Vite + TailwindCSS |
| **Database** | In-memory JSON config | Firestore (production) / JSON (MVP) |
| **Output** | Risk score + findings | Structured JSON events (OCSF), billing (FOCUS), RPN scores |

---

## Architecture Comparison: V1 vs V2

### V1: Simplified Flow

**[Image Generation Prompt]**

Create a flowchart diagram showing:
1. GCP Project box with "cloud_config.json (static snapshot)" label
2. Rules Engine box containing "5 simple rule sets (GCS, GCE, SQL, IAM, Firewall)" with analyze_resource() function
3. Arrow down labeled "JSON findings"
4. FastAPI box showing endpoints: /api/scan, /api/chat with functions: Load config, Apply security rules, Calculate risk scores (simple), Chat with Gemini 2.5 Flash
5. Arrow down labeled "Findings + Explanations"
6. Vanilla JS Frontend box showing: Display findings by severity, Ask Copilot questions, Show gcloud fix commands
7. Connect boxes vertically with labeled arrows
8. Use professional blue and gray color scheme
9. Add title: "V1 CloudOps AI Copilot - Simplified Architecture"

### V2: Advanced Orchestration Flow

**[Image Generation Prompt]**

Create a comprehensive enterprise architecture diagram showing:

**Top Level:** Multi-Project Container box containing:
1. Three GCP Projects (Proj 1, Proj 2, Proj N) with downward arrows
2. Data Collection Layer (async) with components: Cloud Asset API, Cloud Monitoring, BigQuery (events + billing)
3. Orchestrator Agent (Master Router) box with functions:
   - Natural language query → JSON routing
   - Conflict detection
   - Parallel agent invocation

**Middle Level:** Three specialist agent boxes arranged horizontally:
1. SRE Agent with outputs: RCA + Tier1 Actions
2. Security Agent with outputs: IaC Patches + RPN Scores
3. FinOps Agent with outputs: Cost Analysis + Optimization

**Lower Level:** 
4. Saga Engine box showing 3-phase flow: pre_check → execute → health (with compensation path)
5. Action Register box (Firestore or JSON file)
6. HITL Approval Queue (Tier2/Tier3 only)

**Bottom Level:**
7. React Frontend Dashboard (Real-time project insights)

Use professional enterprise blue color scheme, include all connecting arrows with labels, add component descriptions, type: systems architecture diagram

---

## V1: CloudOps AI Copilot MVP

### Purpose

Single-project security scanner with GenAI-powered explanations for GCP misconfigurations. Ideal for:
- Quick security audits
- Learning security best practices
- On-demand vulnerability scanning

### Technical Stack

| Layer | Technology |
|-------|-----------|
| **AI/LLM** | Gemini 2.5 Flash (primary), Gemini 2.5 Pro (fallback) |
| **Backend** | Python 3.10+, FastAPI, Uvicorn |
| **Frontend** | Vanilla HTML5, CSS3, Fetch API |
| **Configuration** | Static JSON (`cloud_config.json`) |
| **Deployment** | Docker-ready (see `Dockerfile` in V2 for reference) |

### Project Structure

```
UCAI_MVP.V1/
├── backend/
│   ├── main.py                 # FastAPI entry point
│   ├── rules.py                # Security rule engine
│   ├── requirements.txt        # Python dependencies
│   └── data/
│       └── cloud_config.json   # GCP resource snapshot
└── frontend/
    └── index.html              # Standalone UI
```

### Key Components

#### 1. **rules.py** — Security Rules Engine

Defines rules for 6 GCP services:

- **Cloud Storage Bucket** (GCS-001 to GCS-004)
  - Public access detection
  - Uniform bucket-level access verification
  - CMEK configuration checks
  - Versioning enablement
  
- **Compute Engine VM** (GCE-001 to GCE-005)
  - SSH exposure (0.0.0.0/0)
  - OS Login enablement
  - Serial port access
  - Metadata SSH key management
  - Shielded VM verification

- **Cloud SQL** (SQL-001 to SQL-005)
  - Public IP exposure
  - SSL enforcement
  - Authorized networks
  - Point-in-time recovery
  - Backup retention

- **IAM Service Account** (IAM-001 to IAM-003)
  - Owner role assignments
  - Key rotation policies
  - User-managed key usage

- **VPC Firewall** (FW-001 to FW-002)
  - Unrestricted ingress (0.0.0.0/0)
  - Multi-port allow rules

#### 2. **main.py** — FastAPI Backend

```python
# Endpoints:
GET  /                    # Health check
GET  /api/scan           # Scan GCP project → findings + risk score
POST /api/chat           # Chat with Gemini 2.5 Copilot
GET  /api/models         # List available models
```

**Key Functions:**
- `analyze_resource()` — Apply rules to resource
- `calculate_risk_score()` — Aggregate risk across all findings
- `calculate_cost_waste()` — Quantify misconfiguration costs
- `call_gemini()` — Fallback logic (2.5-flash → 2.5-pro)

#### 3. **index.html** — Frontend

Single-page application with:
- **Scan Results Panel** — findings grouped by severity (CRITICAL → LOW)
- **Risk Gauge** — 0–100 score visualization
- **Cost Waste Calculator** — estimated monthly savings
- **Copilot Chat** — natural language Q&A with gcloud command generation

### Setup (5 minutes)

#### Step 1: Get Gemini API Key

```bash
# Visit: https://makersuite.google.com/app/apikey
# Create new API key → copy to clipboard
```

#### Step 2: Configure Backend

```bash
cd UCAI_MVP.V1/backend

# Create .env file
echo 'GEMINI_API_KEY=your_key_here' > .env

# Install dependencies
pip install -r requirements.txt
```

#### Step 3: Add Your GCP Resources

Edit `data/cloud_config.json`:

```json
{
  "project_name": "My GCP Project",
  "project_id": "my-gcp-project-123",
  "resources": [
    {
      "id": "gcs-bucket-1",
      "name": "backup-bucket",
      "type": "Cloud Storage Bucket",
      "region": "us-central1",
      "cost_per_month": 45.00,
      "public_access": true,
      "uniform_bucket_level_access": false,
      "cmek_enabled": false,
      "versioning": false
    },
    {
      "id": "gce-vm-1",
      "name": "web-server-prod",
      "type": "Compute Engine VM",
      "region": "us-east1-b",
      "cost_per_month": 120.00,
      "firewall_ssh_open": true,
      "os_login_enabled": false,
      "serial_port_access": true,
      "ssh_keys_in_metadata": true,
      "shielded_vm": false
    }
  ]
}
```

#### Step 4: Start Backend

```bash
cd UCAI_MVP.V1/backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

#### Step 5: Open Frontend

```bash
# Option A: Double-click frontend/index.html
# Option B: python -m http.server 8080 (from frontend dir) → http://localhost:8080
```

### API Response Example

**GET /api/scan**

```json
{
  "project_name": "My GCP Project",
  "project_id": "my-gcp-project-123",
  "risk_score": 82,
  "cost_waste_per_month": 340.50,
  "severity_counts": {
    "CRITICAL": 3,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 0
  },
  "resources": [
    {
      "id": "gcs-bucket-1",
      "name": "backup-bucket",
      "type": "Cloud Storage Bucket",
      "region": "us-central1",
      "cost_per_month": 45.00,
      "finding_count": 4,
      "critical_count": 1,
      "high_count": 3,
      "findings": [
        {
          "severity": "CRITICAL",
          "rule": "GCS-001",
          "title": "Cloud Storage bucket is publicly accessible",
          "description": "Bucket is exposed to the internet...",
          "remediation": "Go to Cloud Console → Storage → Bucket → Permissions...",
          "gcp_doc": "https://cloud.google.com/storage/docs/access-control/making-data-public",
          "cost_waste": 0
        }
      ]
    }
  ]
}
```

**POST /api/chat**

```json
{
  "message": "What should I fix first?",
  "context": { "project_id": "my-gcp-project-123" }
}
```

**Response:**
```json
{
  "response": "Focus on fixing the 3 CRITICAL findings first:\n\n1. **Public S3 Bucket Access** (backup-bucket) — Immediate exposure risk...",
  "model_used": "gemini-2.5-flash",
  "recommendations": [
    "gcloud storage buckets update gs://backup-bucket --uniform-bucket-level-access",
    "gcloud storage buckets update gs://backup-bucket --remove-public-access"
  ]
}
```

### Limitations

- ⚠️ Static configuration — requires manual JSON editing
- ⚠️ Single project scope
- ⚠️ No execution engine — recommendations are read-only
- ⚠️ No approval workflow
- ⚠️ No compliance mapping

---

## V2: UACI Multi-Project Platform

### Purpose

Enterprise-grade autonomous cloud intelligence platform with:
- Multi-project portfolio management
- Specialist AI agents for SRE, Security, and FinOps domains
- Autonomous remediation with human oversight (Saga pattern)
- Comprehensive audit trails and compliance evidence
- Real-time project health dashboards

### Technical Stack

| Layer | Technology |
|-------|-----------|
| **AI/LLM** | Gemini 2.0 Flash with structured outputs or system instructions |
| **Backend** | Python 3.10+, FastAPI, Uvicorn |
| **Async** | asyncio, concurrent agent execution |
| **Frontend** | React 18, TypeScript, Vite, TailwindCSS, Tailwind Merge |
| **Database** | Firestore (production), JSON files (MVP) |
| **GCP SDKs** | Cloud Asset, Monitoring, BigQuery, Billing, Pub/Sub, Storage |
| **Event Standards** | OCSF (security events), FOCUS (billing) |
| **Infrastructure** | Docker, Kubernetes-ready, Cloud Run compatible |

### Project Structure

```
UCAI_MVP.V2/
├── backend/
│   ├── main.py                      # FastAPI entry point (production-hardened)
│   ├── requirements.txt             # Dependencies (18 packages)
│   ├── Dockerfile                   # Multi-stage build
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base_agent.py            # (Gemini calls + rate limiting + JSON parsing)
│   │   ├── orchestrator.py          # Master router (async, context-aware)
│   │   ├── sre_agent.py             # Incident RCA + Tier-1 auto-actions
│   │   ├── security_agent.py        # CNAPP CSPM + IaC patch generation
│   │   └── finops_agent.py          # Cost anomaly detection + optimization
│   ├── data/
│   │   ├── __init__.py
│   │   ├── schemas.py               # OCSF, FOCUS, RiskScore, ActionRegister, etc.
│   │   ├── project_store.py         # Multi-project persistence (JSON/Firestore)
│   │   ├── credentials/             # GCP service account files (git-ignored)
│   │   └── projects.json            # Project metadata (generated)
│   ├── engines/
│   │   ├── __init__.py
│   │   ├── saga_engine.py           # 3-phase execution (pre-check → execute → health)
│   │   └── rpn_scorer.py            # Risk Priority Number: likelihood×impact×(1/detectability)×multipliers
│   ├── functions/
│   │   ├── anomaly_detector/        # Identifies cost spikes and resource anomalies
│   │   ├── normalizer/              # OCSF/FOCUS event normalization
│   │   ├── rpn_calculator/          # Distributed RPN scoring
│   │   └── saga_executor/           # Cloud Function for async action execution
│   └── routers/
│       ├── __init__.py
│       ├── chat.py                  # Natural language Q&A + streaming responses
│       ├── approvals.py             # HITL approval queue
│       ├── actions.py               # Action submission + execution state
│       ├── health.py                # Liveness/readiness probes (K8s)
│       ├── projects.py              # Multi-project CRUD
│       └── reports.py               # Audit reports + compliance evidence export
├── frontend/
│   ├── src/
│   │   ├── App.tsx                  # Root component + routing
│   │   ├── AuthContext.tsx          # Firebase auth state management
│   │   ├── firebase.ts              # Firebase SDK config
│   │   ├── main.tsx                 # React entry point
│   │   ├── index.css                # Tailwind imports
│   │   ├── components/
│   │   │   ├── Sidebar.tsx          # Navigation (7 main routes)
│   │   │   ├── Topbar.tsx           # User menu + notifications
│   │   │   └── ApprovalPanel.tsx    # Real-time approval workflow
│   │   └── pages/
│   │       ├── Dashboard.tsx        # Overall portfolio health
│   │       ├── Projects.tsx         # Project list + add new
│   │       ├── ProjectDetail.tsx    # Single project deep dive
│   │       ├── CommandCenter.tsx    # Chat interface with agent
│   │       ├── Incidents.tsx        # SRE incidents + RCA
│   │       ├── FinOps.tsx           # Cost analysis + optimization
│   │       ├── Profile.tsx          # User settings
│   │       ├── Auth.tsx             # Firebase login/signup
│   │       └── Landing.tsx          # Hero page
│   ├── vite.config.ts              # Build config
│   ├── tailwind.config.js          # TailwindCSS theme
│   ├── tsconfig.json               # TypeScript settings
│   ├── package.json                # Frontend dependencies
│   ├── firebase.json               # Firebase project settings
│   ├── .firebaserc                 # Firebase CLI config
│   └── index.html                  # HTML template
├── data-gen/
│   └── generate_all.py             # Mock data generator for testing
├── infra/
│   ├── bigquery_schema.sql         # OCSF + FOCUS + RiskScore tables
│   └── setup.sh                    # Infrastructure provisioning
└── .env.example                    # Template for environment variables
```

### Core Architecture

#### 1. **Base Agent** (`agents/base_agent.py`)

All agents inherit from this foundation:

```python
class BaseAgent:
    - async generate(prompt: str) → str
      • Calls Gemini 2.0 Flash
      • Exponential backoff on rate limits (3 retries × 2^n seconds)
      • Keeps within 14 RPM free tier limit
    
    - async generate_json(prompt: str) → dict
      • Forces structured JSON output
      • Strips markdown fences
      • Extracts JSON from prose
      • Fallback error dict (never raises)
    
    - Configurable generation_config (2048 tokens, 0.1 temperature)
    - System instruction per agent for role-specific behavior
```

#### 2. **Orchestrator Agent** (`agents/orchestrator.py`)

Master router that:

1. **Analyzes user query** → natural language classification
2. **Routes to specialists** — SRE, Security, FinOps (or combinations)
3. **Checks conflicts** — e.g., Security wants to block ★ but FinOps wants to delete (cost-saving)
4. **Runs agents in parallel** — `asyncio.gather()` for independent agents
5. **Synthesizes response** — combines results + prioritizes actions
6. **Sanitizes context** — never leaks credentials to LLM

```python
# Example flow:
User Query: "Why is my API latency spiking and costing more?"
            ↓
        [Routing Decision]
            ↓
      SRE (incident) + FinOps (cost)
            ↓
    [Parallel Execution]
            ↓
  SRE: "Memory leak in payment-svc"
  FinOps: "GPU cluster running 24/7"
            ↓
     [Conflict Check: None]
            ↓
  [Synthesize + Rank Actions]
            ↓
  User Response: "Fix memory leak (TIER_1_AUTO), then terminate idle GPU (TIER_2_SUGGEST)"
```

#### 3. **Specialist Agents**

##### SRE Agent (`agents/sre_agent.py`)

**Input:** Incident metadata + BigQuery telemetry + dependency graph  
**Output:** Root cause analysis (RCA) with confidence scores

**Capabilities:**
- Identifies root causes (not symptoms) from event logs
- Searches vector-embedded runbook database for similar incidents
- Recommends tiered actions:
  - TIER_1_AUTO: Pod restart, cache flush (~2 min recovery)
  - TIER_2_SUGGEST: Config rollback (needs 1-click approval)
  - TIER_3_IAC: Architecture changes (full IaC review)
- Generates post-mortem drafts

**Example RCA Output:**
```json
{
  "root_cause": "Memory leak in payment-service@v1.2.3 event listener",
  "root_cause_evidence": ["Memory usage > 2GB", "Go runtime metric", "GC collection fails"],
  "affected_components": ["payments-api-prod", "order-processor"],
  "confidence": 92,
  "causal_chain": "Deploy v1.2.3 → New event listener attached → Forgot defer close() → Memory accumulates → GC can't keep up → Pod OOMKilled",
  "recommended_actions": [
    {
      "action": "pod_restart",
      "target_resource": "payments-api-prod-us-central1-abcd1234",
      "tier": "TIER_1_AUTO",
      "rationale": "Restart will clear leaked memory. Pod is stateless.",
      "rollback_plan": "Revert to previous pod if health check fails after 60s",
      "estimated_recovery_time_minutes": 2
    },
    {
      "action": "deploy",
      "target_resource": "payments-api-prod",
      "tier": "TIER_3_IAC",
      "rationale": "Deploy bugfix v1.2.4 which adds defer close()",
      "rollback_plan": "Rollback to v1.2.2 via Cloud Deploy",
      "estimated_recovery_time_minutes": 8
    }
  ],
  "runbook_reference": "RB-MEM-LEAK-001",
  "post_mortem_draft": "## Incident Summary\n..."
}
```

##### Security Agent (`agents/security_agent.py`)

**Input:** OCSF security findings + resource graph  
**Output:** Business-impact explanations + Terraform patches + compliance mapping

**Capabilities:**
- Translates technical findings into CEO-friendly risk language
- Calculates RPN scores with multipliers:
  - Internet-exposed resources: ×3.0
  - PII-adjacent data: ×2.0
  - Business-critical apps: ×2.0
  - AI/ML workloads: ×1.5
- Identifies **toxic combinations** — multi-hop attack paths
- Generates valid, deployable Terraform patches with:
  - Inline rollback instructions
  - Compliance control IDs (NIST AI RMF, SOC 2, GDPR, ISO 42001)
- NEVER auto-applies security changes → always TIER_2_SUGGEST or TIER_3_IAC

**Example Response:**
```json
{
  "business_impact": "If exploited, attacker gains admin access to all GCP resources and can exfiltrate customer payment data (PII). Estimated 30-day exposure window.",
  "likelihood_of_exploitation": "High — public IAM policy exposed to Google workspace. Common malware scanning technique.",
  "blast_radius": "All 15 APIs, payment database, 5M customer records, compliance violations (SOC 2, GDPR)",
  "rpn_score": 78.5,
  "compliance_controls": ["NIST-AI-RMF-MS-2.5", "SOC2-CC6.1", "GDPR-Article-32"],
  "remediation_summary": "Remove 'allUsers' from Cloud Storage IAM binding. Enable uniform bucket-level access.",
  "tier": "TIER_3_IAC",
  "terraform_patch": "# Remediation for PUBLIC_BUCKET_ACCESS\n# ROLLBACK: gcloud ... iam bindings restore ...\n# COMPLIANCE: SOC2-CC6.1, GDPR-Article-32\nresource \"google_storage_bucket_iam_member\" \"remove_public\" {\n  action = \"google.storage.buckets.removeIamBinding\"\n  member = \"allUsers\"\n  ...\n}"
}
```

##### FinOps Agent (`agents/finops_agent.py`)

**Input:** FOCUS billing records + resource metrics  
**Output:** Cost anomaly detection + optimization recommendations

**Capabilities:**
- Detects spike patterns (e.g., GPU cluster running 24/7 unexpectedly)
- Attributes spend to teams via tags
- Cross-checks with SRE/Security before recommending termination
- Tiered recommendations:
  - TIER_1_AUTO: Auto-pause idle resources
  - TIER_2_SUGGEST: Rightsizing proposals
  - TIER_3_IAC: Reserved instance switches

**Example Output:**
```json
{
  "anomaly_detected": true,
  "attributed_team": "ml-platform",
  "explanation": "GPU cluster (n1-standard-4 × 10 with NVIDIA T4) running continuously for 45 days. Estimated cost drift: +$3,200/month.",
  "recommended_action": "Query if training job completed. If yes → terminate cluster.",
  "potential_savings": 3200,
  "security_check": "Cluster is internal VPC. No PII. SRE confirms no workload running.",
  "finops_check": "Cost vs benefit: GPU training $3.2K/mo, storage $0.5K/mo. If job complete → terminate."
}
```

#### 4. **Saga Engine** (`engines/saga_engine.py`)

Implements the **Saga pattern** for safe autonomous remediation:

**[Image Generation Prompt]**

Create a Saga Pattern flowchart diagram showing:

**Phase 1 - PRE_CHECK (Top Box):**
- Verify resource exists
- Check if action preconditions met
- Take snapshot of current state
- Success arrow pointing down to Phase 2

**Phase 2 - EXECUTE (Middle Box):**
- Run actual remediation command
- Examples: kubectl delete pod, gcloud instances delete, etc
- Log action in ActionRegister
- Success arrow pointing down to Phase 3

**Phase 3 - HEALTH_CHECK (Bottom Box):**
- Service comes back? Pod restarted? CPU usage normal?
- 3-way split:
  - "Healthy" path → SUCCESS (green checkmark)
  - "Unhealthy" path → COMPENSATING TRANSACTION box (orange/red)
  - "Timeout" path → COMPENSATING TRANSACTION box

**Compensating Transaction (Rollback) Box:**
- Restore pre_state_snapshot
- Log rollback reason
- Alert SRE team

Use green for success paths, red/orange for rollback, show all connections with labeled arrows, type: process flow diagram

**Action Document Lifecycle:**

```json
{
  "action_id": "a1b2c3d4-e5f6-47g8-h9i0-j1k2l3m4n5o6",
  "agent_name": "sre_agent",
  "action_type": "pod_restart",
  "resource_id": "payments-prod-us-east1",
  "tier": "TIER_1_AUTO",
  "status": "completed",  // pending → pre_check_passed → executed → health_check_passed → completed
  "pre_state_snapshot": { "pod_status": "CrashLoopBackOff", "memory_pct": 94 },
  "post_state_snapshot": { "pod_status": "Running", "memory_pct": 42 },
  "saga_steps": [
    { "step": "pre_check", "status": "passed", "data": {...} },
    { "step": "execute", "status": "completed", "data": {...} },
    { "step": "health_check", "status": "passed", "data": {...} }
  ],
  "rollback_executed": false,
  "compliance_evidence": {
    "audit_log_id": "...",
    "actor": "uaci_sre_agent",
    "reason": "Automated incident remediation (RPN=45)",
    "change_ticket": "INC-12345"
  },
  "created_at": "2024-04-13T14:23:45Z",
  "updated_at": "2024-04-13T14:25:12Z"
}
```

#### 5. **RPN Scorer** (`engines/rpn_scorer.py`)

Calculates **Risk Priority Number** (FMEA-inspired):

$$
\text{RPN} = \text{Likelihood} \times \text{Impact} \times \frac{1}{\text{Detectability}} \times \text{Multipliers}
$$

**Multipliers:**
- Internet-exposed: ×3.0 (directly hackable)
- PII-adjacent: ×2.0 (compliance violation)
- Business-critical: ×2.0 (revenue impact)
- AI/ML workload: ×1.5 (AI-SPM considerations)

**Example Calculation:**
```
Finding: Public S3 bucket with payment data

Base: Likelihood=3 × Impact=5 × (1/2) = 7.5
Multiplier: internet_exposed=3.0 × pii_adjacent=2.0 × business_critical=2.0 = 12.0
RPN = 7.5 × 12.0 = 90.0 → TIER_3_IAC (high risk, manual review required)
```

**Tier Classification:**
- TIER_1_AUTO: RPN 0–15 (auto-execute immediately)
- TIER_2_SUGGEST: RPN 15–35 (suggest with 1-click approval)
- TIER_3_IAC: RPN 35+ (IaC patch only, full review cycle)

#### 6. **Data Schemas** (`data/schemas.py`)

**OCSF Event** — Standardized security event

```python
class OCSFEvent:
  event_uid: str                    # Unique event ID
  time: datetime                    # Event timestamp
  severity_id: int                  # 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
  class_uid: int                    # OCSF class (e.g., 3005=Detection Finding)
  activity_id: int                  # 1=Create, 2=Read, 3=Update, 4=Delete
  cloud_account_id: str             # GCP project
  resource_name: str                # "payments-bucket" or "payments-db-prod"
  resource_type: str                # "S3Bucket", "EC2Instance", "Database"
  finding_type: str                 # "PubliclyAccessibleStorage", "OverprivilegedRole"
  finding_desc: str
  remediation_hint: Optional[str]
  tags: dict                        # {team: "payments", env: "prod", criticality: "P1"}
```

**FOCUS Billing Record** — Standardized cost data

```python
class FOCSBillingRecord:
  billing_period_start: datetime
  provider_name: str                # "Google Cloud"
  account_id: str                   # GCP project ID
  resource_id: str                  # "projects/my-proj/zones/us-central1"
  resource_type: str                # "Compute", "Storage", "Networking"
  service_name: str                 # "Cloud SQL", "Compute Engine"
  region: str
  billed_cost: float
  usage_quantity: float
  usage_unit: str                   # "Hours", "GB", "Requests"
  tags: dict                        # MUST include team, environment, project
```

**Risk Score** — Multi-factor risk assessment

```python
class RiskScore:
  rpn_score: float                  # Computed from RPN formula
  likelihood: float                 # 1-5
  impact: float                     # 1-5
  detectability: float              # 1-5 (higher = less risky)
  internet_exposed: bool            # ×3.0 multiplier
  pii_adjacent: bool                # ×2.0 multiplier
  business_critical: bool           # ×2.0 multiplier
  ai_workload: bool                 # ×1.5 multiplier
  remediation_type: str             # "TIER_1_AUTO", "TIER_2_SUGGEST", "TIER_3_IAC"
  compliance_controls: List[str]    # ["NIST-AI-RMF-MS-2.5", "SOC2-CC6.1"]
```

**Action Register** — Audit trail for remediation

```python
class ActionRegister:
  action_id: str                    # UUID
  agent_name: str                   # "sre_agent", "security_agent", "finops_agent"
  action_type: str                  # "pod_restart", "apply_iac_patch"
  tier: str                         # "TIER_1_AUTO", "TIER_2_SUGGEST", "TIER_3_IAC"
  status: str                       # pending → approved → executed → rolled_back
  pre_state_snapshot: dict          # Before state
  post_state_snapshot: dict         # After state
  saga_steps: List[dict]            # pre_check, execute, health_check results
  rollback_executed: bool
  compliance_evidence: dict         # Audit trail for regulators
```

#### 7. **Frontend** (React 18 + TypeScript + Vite)

**Pages:**

- **Dashboard** — Portfolio health scorecard
  - Total risk score across all projects
  - Cost drift YoY
  - Action queue status
  - SLA compliance

- **Projects** — Multi-project management
  - Create/connect GCP projects
  - Health status per project (color-coded)
  - Team attribution
  - Cost per project

- **ProjectDetail** — Deep dive into single project
  - Real-time metrics (CPU, memory, disk)
  - Security findings by severity
  - Incident timeline
  - Cost breakdown

- **CommandCenter** — Natural language chatbot
  - Ask orchestrator questions
  - Real-time `EventSource` streaming
  - "What should I fix first?"
  - "Why is my bill spiking?"

- **Incidents** — SRE incident management
  - Open incidents + RCA progress
  - Runbook links
  - Action recommendations
  - Post-mortems

- **FinOps** — Cost analysis
  - Cost anomalies
  - Team attribution
  - Reserved instance recommendations
  - Commitment discount optimizer

- **Profile** — User settings
  - API key management
  - Notification preferences
  - Team membership

**Components:**

- **Sidebar** — Navigation (all routes)
- **Topbar** — User menu + notifications + project selector
- **ApprovalPanel** — Real-time HITL workflow
  - Shows pending approvals
  - Risk level + RPN score
  - One-click approve/reject
  - Reason text (required for reject)

#### 8. **API Endpoints** (`routers/`)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/chat` | Natural language → orchestrator → agent routing (streaming) |
| POST | `/api/chat/rca` | Full RCA on incident (SRE-specific) |
| GET | `/api/approvals` | List pending approvals |
| POST | `/api/approvals/{id}/approve` | Human approval |
| POST | `/api/approvals/{id}/reject` | Reject + provide reason |
| GET | `/api/actions` | List all actions (with state filters) |
| POST | `/api/actions/execute` | Submit action to Saga engine |
| GET | `/api/projects` | List projects |
| POST | `/api/projects` | Add new GCP project |
| GET | `/api/projects/{id}` | Project metrics + findings |
| PUT | `/api/projects/{id}` | Update project metadata |
| DELETE | `/api/projects/{id}` | Deregister project |
| GET | `/api/reports` | Audit reports + compliance export |
| GET | `/health` | Liveness probe (K8s) |
| GET | `/ready` | Readiness probe (checks Gemini key) |

### Setup (Production)

#### Step 1: Prerequisites

```bash
# GCP Project
gcloud projects create my-uaci-project --name="UACI Platform"
gcloud config set project my-uaci-project

# Enable APIs
gcloud services enable run.googleapis.com \
  firestore.googleapis.com \
  bigquery.googleapis.com \
  cloudasset.googleapis.com \
  monitoring.googleapis.com \
  cloudkms.googleapis.com \
  secretmanager.googleapis.com

# Create service account
gcloud iam service-accounts create uaci-backend \
  --display-name="UACI Backend Service"

# Grant roles
gcloud projects add-iam-policy-binding my-uaci-project \
  --member=serviceAccount:uaci-backend@my-uaci-project.iam.gserviceaccount.com \
  --role=roles/editor  # Adjust to least-privilege in production
```

#### Step 2: Configure Environment

```bash
cd UCAI_MVP.V2/backend

# Copy .env template
cp ../.env.example .env

# Edit .env:
cat >> .env << EOF
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.0-flash
GCP_PROJECT_ID=my-uaci-project
FIRESTORE_DATABASE=projects-db
ALLOWED_ORIGINS=https://yourdomain.com
CHANGE_FREEZE=false
EOF
```

#### Step 3: Setup Firestore (Production)

```bash
# Create Firestore database
gcloud firestore databases create \
  --location=us-central1 \
  --type=firestore-native

# Deploy BigQuery schema
cd infra
gcloud config set project my-uaci-project
bq mk --dataset uaci_data
bq mk --table uaci_data.ocsf_events < bigquery_schema.sql
```

#### Step 4: Build & Deploy

```bash
# Option A: Cloud Run
cd UCAI_MVP.V2/backend
gcloud run deploy uaci-backend \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY="$(gcloud secrets versions access latest --secret=gemini-key)"

# Option B: Docker locally
docker build -t gcr.io/my-uaci-project/uaci-backend:latest .
docker run -p 8000:8000 \
  -e GEMINI_API_KEY="..." \
  gcr.io/my-uaci-project/uaci-backend:latest

# Option C: Kubernetes
kubectl apply -f - << EOF
apiVersion: v1
kind: Deployment
metadata:
  name: uaci-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: uaci-backend
  template:
    metadata:
      labels:
        app: uaci-backend
    spec:
      containers:
      - name: backend
        image: gcr.io/my-uaci-project/uaci-backend:latest
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
EOF
```

#### Step 5: Deploy Frontend

```bash
cd UCAI_MVP.V2/frontend

# Install dependencies
npm install

# Build
npm run build

# Deploy to Firebase Hosting
firebase deploy
```

#### Step 6: Configure BigQuery Event Streaming

```bash
# Setup Pub/Sub for OCSF events
gcloud pubsub topics create ocsf-events
gcloud pubsub subscriptions create ocsf-to-bq \
  --topic=ocsf-events \
  --ack-deadline=300

# Enable Cloud Asset to stream to Pub/Sub
# (Setup in Cloud Asset API UI or via IaC)
```

---

## Quick Start

### For V1 (Single Project Scanner)

**Live Demo:** https://storage.googleapis.com/cloudops-frontend-123/index.html

**Local Development:**
```bash
# Backend
cd UCAI_MVP.V1/backend
export GEMINI_API_KEY=sk-...
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend (in new terminal)
cd UCAI_MVP.V1/frontend
# Then visit: https://storage.googleapis.com/cloudops-frontend-123/index.html
# Or run locally:
python -m http.server 8080
```

### For V2 (Multi-Project Platform)

**Live Demo:** https://gen-lang-client-0591533880.web.app/

**Local Development:**
```bash
# Backend
cd UCAI_MVP.V2/backend
export GEMINI_API_KEY=sk-...
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend (in new terminal)
cd UCAI_MVP.V2/frontend
npm install
npm run dev
```

---

## Deployment

### V1 Deployment

| Target | Method | Live Link |
|--------|--------|----------|
| **Production** | Google Cloud Storage Static Hosting | https://storage.googleapis.com/cloudops-frontend-123/index.html |
| **Local Dev** | `uvicorn main:app --reload` | http://localhost:8000 |
| **Docker** | `docker build -t cloudops-v1 . && docker run -p 8000:8000 cloudops-v1` | http://localhost:8000 |
| **Cloud Run** | `gcloud run deploy cloudops-v1 --source .` | Auto-generated URL |
| **Kubernetes** | `kubectl apply -f deployment.yaml` | External IP |

### V2 Deployment

| Target | Method | Live Link |
|--------|--------|----------|
| **Production** | Firebase Hosting | https://gen-lang-client-0591533880.web.app/ |
| **Local Dev** | `uvicorn main:app --reload` + `npm run dev` | http://localhost:5173 |
| **Docker Compose** | `docker-compose up` | http://localhost:3000 |
| **Cloud Run** | Backend: `gcloud run deploy`, Frontend: `firebase deploy` | Auto-generated URLs |
| **GKE** | `kubectl apply -f manifests/` | Load Balancer IP |
| **App Engine** | `gcloud app deploy` | Project App Engine URL |

---

## API Reference

### V1

#### GET /api/scan

```bash
curl http://localhost:8000/api/scan
```

**Response:** `{"project_name": "", "risk_score": 82, "findings": [...]}`

#### POST /api/chat

```bash
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What should I fix first?", "context": {"project_id": "my-project"}}'
```

### V2

#### POST /api/chat

Streaming endpoint (Server-Sent Events):

```bash
curl -N -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Why is latency spiking?", "context": {"project_id": "prod-api"}}'
```

**Stream:** `data: {"type": "thinking", "content": "..."}`  
`data: {"type": "result", "content": {...}}`

#### POST /api/approvals/{id}/approve

```bash
curl -X POST http://localhost:8000/api/approvals/a1b2c3d4/approve
```

**Response:** `{"status": "approved", "action_id": "...", "executor_triggered": true}`

#### GET /api/projects

```bash
curl http://localhost:8000/api/projects
```

**Response:** `[{"project_id": "prod-api", "health_score": 78, ...}, ...]`

#### POST /api/projects

```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"project_id": "new-project", "cred_path": "/path/to/credentials.json"}'
```

---

## Security & Compliance

### Architecture Security

- **🔐 Credential Isolation** — Credentials never leave the backend; never sent to Gemini
- **🔒 CORS Locked** — Frontend restricted to whitelisted origins
- **⏱️ Rate Limiting** — Gemini calls capped at 14 RPM (stays under 15 RPM free tier)
- **📝 Audit Trail** — Every action logged to ActionRegister with actor + reason
- **🔄 Saga Pattern** — Automatic rollback on health check failure
- **🚫 No Auto-Security** — Security agents NEVER auto-execute (always TIER_2_SUGGEST/3_IAC)

### Compliance Mappings

| Standard | Coverage |
|----------|----------|
| **NIST AI RMF** | AI-SPM, model card specs, RPN scoring |
| **SOC 2** | Audit logs, change management, incident response |
| **GDPR** | PII-adjacent multiplier, consent tracking |
| **ISO 42001** | Risk assessment, governance |
| **CIS Benchmarks** | GCS, GCE, SQL rules aligned |

### Data Privacy

- ✅ No PII storage — only anonymized metrics
- ✅ Credentials encrypted (GCP Secret Manager)
- ✅ BigQuery data retention policies
- ✅ Audit log exports to Cloud Logging
- ✅ Option to run on-premises via Kubernetes

---

### Future Enhancements

- [ ] **Multi-Cloud** — AWS (Security Hub + Cost Explorer), Azure (Defender + Cost Management)
- [ ] **Vector Search** — Runbook RAG with text-embedding-004
- [ ] **Custom Rules Engine** — YAML-based rule definitions
- [ ] **Advanced Analytics** — Trend forecasting, anomaly prediction
- [ ] **ChatOps Integration** — Slack/Teams bots for approvals + notifications
- [ ] **Custom Remediation** — User-defined automation workflows
- [ ] **Policy as Code** — OPA/Rego for compliance policies

---

## Troubleshooting

### V1 Issues

| Issue | Solution |
|-------|----------|
| `GEMINI_API_KEY missing!` | Set env var or .env file |
| `cloud_config.json not found` | Create `data/cloud_config.json` with sample resources |
| CORS errors | Ensure frontend served from `localhost:8080` or update CORS in main.py |
| Gemini rate limit | Wait 60 seconds; code decreases retry window automatically |

### V2 Issues

| Issue | Solution |
|-------|----------|
| Firestore connection failed | Run locally with JSON fallback or ensure `GOOGLE_APPLICATION_CREDENTIALS` set |
| Action hangs in "pending_approval" | Check `/api/approvals` — approve/reject manually |
| RCA agent returns empty | Ensure BigQuery tables exist; SREAgent searches with mock data in MVP |
| Frontend can't reach backend | Check CORS: add frontend URL to `ALLOWED_ORIGINS` env var |

---

## Contributing

### Code Style

- **Python** — Black formatting, type hints via Pydantic
- **TypeScript/React** — ESLint + Prettier
- **SQL** — BigQuery standard SQL with partitioning + clustering

### Testing

```bash
# Backend
pytest tests/

# Frontend
npm test
```

### Pull Requests

1. Fork repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Commit with clear messages: `git commit -m "Add XYZ capability"`
4. Push to fork: `git push origin feature/my-feature`
5. Open PR with description + testing evidence

---

## License

This project is submitted for the CloudSentinel AI Hackathon. See LICENSE file for terms.

---

## Contact & Support

- **Issues** — File GitHub issues with detailed reproduction steps
- **Questions** — Start a discussion thread
- **Hackathon Submission** — See SUBMISSION.md for submission details

---

## Acknowledgments

- **Gemini Models** — Google Generative AI API
- **Frameworks** — FastAPI, React, Vite, TailwindCSS
- **Standards** — OCSF, FOCUS, NIST AI RMF
- **Community** — Open-source contributors

---

**Last Updated:** April 13, 2024  
**Version:** 2.0.0 (Multi-Project Enterprise Edition)
