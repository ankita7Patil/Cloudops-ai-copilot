
import json
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import google.generativeai as genai
from dotenv import load_dotenv
from rules import analyze_resource, calculate_risk_score, calculate_cost_waste

load_dotenv()

# ── Gemini setup ─────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY not found in .env file")

genai.configure(api_key=GEMINI_API_KEY)

# Primary model: gemini-2.5-flash (fast + capable)
# Fallback model: gemini-2.5-pro  (more powerful, use if flash unavailable)
PRIMARY_MODEL   = "gemini-2.5-flash"
FALLBACK_MODEL  = "gemini-2.5-pro"

def get_gemini_model():
    try:
        return genai.GenerativeModel(PRIMARY_MODEL)
    except Exception:
        return genai.GenerativeModel(FALLBACK_MODEL)

# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(
    title="CloudOps AI Copilot",
    description="GCP Security & Operations Intelligence powered by Gemini 2.5",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ───────────────────────────────────────────────────
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "data", "cloud_config.json")
    with open(config_path) as f:
        return json.load(f)

# ── Routes ────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "status": "running",
        "app": "CloudOps AI Copilot",
        "model": PRIMARY_MODEL,
        "cloud": "GCP"
    }


@app.get("/api/scan")
def scan():
    """Scan all GCP resources and return findings + risk score."""
    try:
        config = load_config()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="cloud_config.json not found in data/ folder")

    all_findings = []
    resource_results = []

    for resource in config["resources"]:
        findings = analyze_resource(resource)
        all_findings.extend(findings)
        resource_results.append({
            "id":             resource["id"],
            "name":           resource["name"],
            "type":           resource["type"],
            "region":         resource.get("region", "global"),
            "cost_per_month": resource.get("cost_per_month", 0),
            "findings":       findings,
            "finding_count":  len(findings),
            "critical_count": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high_count":     len([f for f in findings if f["severity"] == "HIGH"]),
        })

    risk_score   = calculate_risk_score(all_findings)
    cost_waste   = calculate_cost_waste(all_findings)

    severity_counts = {
        "CRITICAL": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
        "HIGH":     len([f for f in all_findings if f["severity"] == "HIGH"]),
        "MEDIUM":   len([f for f in all_findings if f["severity"] == "MEDIUM"]),
        "LOW":      len([f for f in all_findings if f["severity"] == "LOW"]),
    }

    return {
        "project_id":              config.get("project_id", "unknown"),
        "project_name":            config.get("project_name", "GCP Project"),
        "risk_score":              risk_score,
        "total_findings":          len(all_findings),
        "severity_counts":         severity_counts,
        "estimated_monthly_waste": cost_waste,
        "resources_scanned":       len(resource_results),
        "resources":               resource_results,
        "model_used":              PRIMARY_MODEL,
    }


class ChatRequest(BaseModel):
    message: str
    scan_context: dict = {}


@app.post("/api/chat")
def chat(req: ChatRequest):
    """Send a question to Gemini 2.5 with the scan context as background."""
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    context_str = json.dumps(req.scan_context, indent=2) if req.scan_context else "No scan data yet."

    system_prompt = f"""You are CloudOps AI Copilot — a senior GCP cloud security and operations expert.

You are analyzing the following GCP project scan results:
{context_str}

Your role:
- Explain GCP security findings clearly in plain English
- Give specific, GCP-native remediation steps (gcloud commands, Console navigation, or Terraform)
- Quantify business risk and potential cost impact
- Reference official GCP documentation where helpful
- Be concise, practical, and actionable
- Use bullet points for remediation steps
- Prioritize fixes by severity: CRITICAL first, then HIGH, MEDIUM, LOW

Always respond as a helpful, expert GCP security advisor."""

    try:
        model    = get_gemini_model()
        response = model.generate_content(
            f"{system_prompt}\n\nUser question: {req.message}",
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=800,
                temperature=0.3,
            )
        )
        answer = response.text
    except Exception as e:
        # Try fallback model
        try:
            model    = genai.GenerativeModel(FALLBACK_MODEL)
            response = model.generate_content(
                f"{system_prompt}\n\nUser question: {req.message}",
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=800,
                    temperature=0.3,
                )
            )
            answer = response.text
        except Exception as e2:
            raise HTTPException(status_code=500, detail=f"Gemini API error: {str(e2)}")

    return {
        "response":   answer,
        "model_used": PRIMARY_MODEL,
    }


@app.get("/api/models")
def list_models():
    """List available Gemini models."""
    try:
        models = [m.name for m in genai.list_models()
                  if "generateContent" in m.supported_generation_methods
                  and "gemini-2" in m.name]
        return {"available_gemini_2x_models": models}
    except Exception as e:
        return {"error": str(e), "note": "Models configured: gemini-2.5-flash, gemini-2.5-pro"}
