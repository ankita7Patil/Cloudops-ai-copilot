import json
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from rules import analyze_resource, calculate_risk_score, calculate_cost_waste


from google import genai
from google.genai import types


load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY missing!")

client = genai.Client(api_key=GEMINI_API_KEY)

MODEL_OPTIONS = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
]

def call_gemini(prompt: str):
    for model_name in MODEL_OPTIONS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt
            )

          
            if response.candidates:
                content = response.candidates[0].content.parts[0].text
                return content, model_name

            return "⚠️ No response from Gemini", model_name

        except Exception as e:
            print(f"Gemini error with {model_name}: {e}")
            continue

    return "❌ Gemini failed. Check API key or model.", "none"

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
    resources = []

    for r in config["resources"]:
        f = analyze_resource(r)
        all_findings.extend(f)
        resources.append({
            "id": r.get("id", r["name"]),
            "name": r["name"],
            "type": r["type"],
            "region": r.get("region", "us-central1"),
            "cost_per_month": r.get("cost_per_month", r.get("cost", 0)),
            "findings": f,
            "finding_count": len(f),
            "critical_count": sum(1 for x in f if x["severity"] == "CRITICAL"),
            "high_count": sum(1 for x in f if x["severity"] == "HIGH"),
        })

    severity_counts = {
        "CRITICAL": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "HIGH": sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "MEDIUM": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "LOW": sum(1 for f in all_findings if f["severity"] == "LOW"),
    }

    return {
        "project_name": config.get("project_name", "GCP Project"),
        "project_id": config.get("project_id", "my-gcp-project"),
        "resources_scanned": len(resources),
        "total_findings": len(all_findings),
        "risk_score": calculate_risk_score(all_findings),
        "estimated_monthly_waste": calculate_cost_waste(all_findings),
        "severity_counts": severity_counts,
        "resources": resources,
    }

class ChatRequest(BaseModel):
    message: str
    scan_context: dict = {}

@app.post("/api/chat")
def chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Empty message")

    ctx = req.scan_context

    summary = "No scan data yet."
    if ctx and ctx.get("total_findings") is not None:
        summary = f"""
Project: {ctx.get('project_name')}
Risk: {ctx.get('risk_score')}
Findings: {ctx.get('total_findings')}
"""

    prompt = f"""
You are a GCP cloud expert.

Context:
{summary}

User: {req.message}
"""

    text, model_used = call_gemini(prompt)
    return {"response": text, "model_used": model_used}
