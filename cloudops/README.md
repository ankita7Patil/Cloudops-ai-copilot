# CloudOps AI Copilot 🛡️

**GCP Cloud Security & Operations Intelligence powered by Gemini 2.5**

Submission for CloudSentinel AI Hackathon — Problem 7 + Problem 14

---

## What It Does

CloudOps AI Copilot scans your GCP project configuration and:
- Detects **security misconfigurations** across Cloud Storage, Compute Engine, Cloud SQL, IAM, VPC Firewall, and GKE
- **Scores your project risk** from 0–100
- **Quantifies cost waste** from misconfigured resources
- Provides a **GenAI Copilot** (Gemini 2.5 Flash) that explains every finding in plain English and gives exact gcloud commands to fix them

---

## Tech Stack

| Layer | Technology |
|---|---|
| AI Model | **Gemini 2.5 Flash** (fallback: Gemini 2.5 Pro) |
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Frontend | Vanilla HTML/CSS/JS (no build step needed) |
| Cloud Platform | **GCP** (Cloud Storage, Compute Engine, Cloud SQL, IAM, VPC, GKE) |

---

## Setup (5 minutes)

### 1. Get a Gemini API Key
Go to: https://makersuite.google.com/app/apikey
Create a new key → copy it

### 2. Add your key to .env
```
cd backend
# Edit .env file:
GEMINI_API_KEY=your_actual_key_here
```

### 3. Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 4. Start the backend
```bash
uvicorn main:app --reload
```
Backend runs at: http://localhost:8000

### 5. Open the frontend
Simply open `frontend/index.html` in your browser (double-click it).

---

## Usage

1. Click **"Run GCP Security Scan"**
2. View findings, risk score, and cost waste
3. Click any finding to expand the remediation steps
4. Ask the **Gemini 2.5 Copilot** anything:
   - *"What should I fix first?"*
   - *"Give me gcloud commands to fix all CRITICAL findings"*
   - *"Explain the GKE cluster risks"*

---

## Project Structure

```
cloudops-ai-copilot/
├── backend/
│   ├── main.py              # FastAPI app + Gemini 2.5 integration
│   ├── rules.py             # GCP security rule engine (50+ rules)
│   ├── requirements.txt     # Python dependencies
│   ├── .env                 # GEMINI_API_KEY goes here
│   └── data/
│       └── cloud_config.json  # GCP resource configurations to scan
├── frontend/
│   └── index.html           # Complete dashboard (no install needed)
└── README.md
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Health check + model info |
| `/api/scan` | GET | Scan all GCP resources |
| `/api/chat` | POST | Chat with Gemini 2.5 Copilot |
| `/api/models` | GET | List available Gemini 2.x models |

---

## Models Used

- **Primary:** `gemini-2.5-flash` — Fast responses, optimized for production
- **Fallback:** `gemini-2.5-pro` — More powerful, used if flash is unavailable

---

## Security Rules Covered

| GCP Service | Rules |
|---|---|
| Cloud Storage | Public access, CMEK, uniform bucket-level access, versioning |
| Compute Engine | SSH exposure, OS Login, serial port, Shielded VM |
| Cloud SQL | Public IP, SSL enforcement, authorized networks, backups |
| IAM Service Account | Owner role, key rotation, user-managed keys |
| VPC Firewall | 0.0.0.0/0 ingress, all-ports-open rules |
| GKE Cluster | Legacy ABAC, network policy, private cluster, Workload Identity |
