import json
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from rules import analyze_resource, calculate_risk_score, calculate_cost_waste
from google import genai
from google.genai import types
from flask_cors import CORS
CORS(app)

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY missing in .env file!")

client = genai.Client(api_key=GEMINI_API_KEY)

# Try these models in order
MODEL_OPTIONS = [
    "gemini-2.5-flash-preview-04-17",
    "gemini-2.5-pro-preview-03-25",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-1.5-flash",
]

def call_gemini(prompt: str):
    last_error = ""
    for model_name in MODEL_OPTIONS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=800,
                    temperature=0.4,
                )
            )
            return response.text, model_name
        except Exception as e:
            last_error = f"{model_name}: {str(e)}"
            continue
    raise HTTPException(
        status_code=500,
        detail=f"All Gemini models failed. Error: {last_error}"
    )

# ── FastAPI ───────────────────────────────────────────────────
app = FastAPI(title="CloudOps AI Copilot", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_config():
    path = os.path.join(os.path.dirname(__file__), "data", "cloud_config.json")
    with open(path) as f:
        return json.load(f)

# ── Routes ────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "running", "app": "CloudOps AI Copilot", "cloud": "GCP"}


@app.get("/api/scan")
def scan():
    try:
        config = load_config()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="cloud_config.json not found")

    all_findings = []
    resources    = []

    for r in config["resources"]:
        f = analyze_resource(r)
        all_findings.extend(f)
        resources.append({
            "id":             r.get("id", r["name"]),
            "name":           r["name"],
            "type":           r["type"],
            "region":         r.get("region", "us-central1"),
            "cost_per_month": r.get("cost_per_month", r.get("cost", 0)),
            "findings":       f,
            "finding_count":  len(f),
            "critical_count": sum(1 for x in f if x["severity"] == "CRITICAL"),
            "high_count":     sum(1 for x in f if x["severity"] == "HIGH"),
        })

    severity_counts = {
        "CRITICAL": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "HIGH":     sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "MEDIUM":   sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "LOW":      sum(1 for f in all_findings if f["severity"] == "LOW"),
    }

    return {
        "project_name":            config.get("project_name", "GCP Project"),
        "project_id":              config.get("project_id", "my-gcp-project"),
        "resources_scanned":       len(resources),
        "total_findings":          len(all_findings),
        "risk_score":              calculate_risk_score(all_findings),
        "estimated_monthly_waste": calculate_cost_waste(all_findings),
        "severity_counts":         severity_counts,
        "resources":               resources,
    }


class ChatRequest(BaseModel):
    message:      str
    scan_context: dict = {}


@app.post("/api/chat")
def chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    ctx = req.scan_context
    if ctx and ctx.get("total_findings") is not None:
        summary = f"""
GCP Project : {ctx.get('project_name','Unknown')} ({ctx.get('project_id','')})
Risk Score  : {ctx.get('risk_score','N/A')} / 100
Findings    : {ctx.get('total_findings',0)} total
  Critical  : {ctx.get('severity_counts',{}).get('CRITICAL',0)}
  High      : {ctx.get('severity_counts',{}).get('HIGH',0)}
  Medium    : {ctx.get('severity_counts',{}).get('MEDIUM',0)}
  Low       : {ctx.get('severity_counts',{}).get('LOW',0)}
Cost Waste  : ${ctx.get('estimated_monthly_waste',0)}

Resources & Findings:
{json.dumps(ctx.get('resources',[]), indent=2)}
"""
    else:
        summary = "No scan data yet — ask the user to run a scan first."

    system_prompt = f"""You are CloudOps AI Copilot — a friendly expert GCP cloud security assistant.

Current GCP scan data:
{summary}

Rules:
- Be warm and friendly. If someone says hi/hello, greet them back naturally.
- Use simple language and emojis to make responses readable.
- For security questions: prioritize CRITICAL first, then HIGH, MEDIUM, LOW.
- Give exact gcloud CLI commands or Console steps to fix issues.
- Keep responses focused and helpful."""

    text, model_used = call_gemini(f"{system_prompt}\n\nUser: {req.message}")
    return {"response": text, "model_used": model_used}
