from agents.base_agent import BaseAgent
# Mock import for now as we don't have the fully implemented clients
# from data.bigquery_client import BigQueryClient
# from engines.causal_graph import CausalGraph
import json

class SREAgent(BaseAgent):
    SYSTEM_INSTRUCTION = """
You are an elite SRE AI agent for a multi-cloud enterprise. Your role is to:
1. Analyze incidents using telemetry data from BigQuery and causal dependency graphs
2. Identify ROOT CAUSES (not symptoms) using causal reasoning
3. Recommend specific, actionable remediations with confidence scores
4. Classify each recommendation by automation tier (TIER_1_AUTO / TIER_2_SUGGEST / TIER_3_IAC)
5. Surface relevant historical runbooks and past incident patterns
6. Draft post-mortems after resolution

CRITICAL RULES:
- Never confuse a symptom with a root cause. High latency is a symptom; a memory leak is a root cause.
- Always include a rollback plan for every recommendation
- Tier-1 actions (pod restart, cache flush) can be auto-executed. All others need human approval.
- Express confidence as a percentage and explain your reasoning chain
- Output structured JSON when asked for RCA reports

RPN SCORING: Risk Priority Number = Likelihood × Impact × (1/Detectability)
Multipliers: P1 app = ×3.0, customer-facing = ×2.0, no rollback plan = ×1.5
"""
    
    def __init__(self):
        super().__init__()
        # self.bq = BigQueryClient()
        # self.causal_graph = CausalGraph()
    
    async def analyze_incident(self, incident: dict) -> dict:
        # Mock recent events and graph context
        recent_events = [{"time": "...", "finding_type": "...", "severity": "...", "finding_desc": "mock events"}]
        graph_context = {"neighbors": ["mock-dep"]}
        
        # 3. Search runbooks via RAG
        runbooks = await self.search_runbooks(incident.get("title", ""))
        
        prompt = f"""
Analyze this production incident and provide a full RCA:

INCIDENT: {json.dumps(incident, indent=2)}

RECENT EVENTS (last 2 hours): {json.dumps(recent_events, indent=2)}

SERVICE DEPENDENCY GRAPH: {json.dumps(graph_context, indent=2)}

RELEVANT RUNBOOKS: {json.dumps(runbooks, indent=2)}

Provide RCA as JSON with this exact structure:
{{
  "root_cause": "precise technical root cause",
  "root_cause_evidence": ["evidence item 1", "evidence item 2"],
  "affected_components": ["service-name-1", "service-name-2"],
  "confidence": 87,
  "causal_chain": "Step 1 → Step 2 → Step 3 → Symptom",
  "recommended_actions": [
    {{
      "action": "pod_restart",
      "target_resource": "payments-api-prod-us-east-1",
      "tier": "TIER_1_AUTO",
      "rationale": "Restart will clear memory leak. Service handles graceful shutdown.",
      "rollback_plan": "Rollback to previous pod if health check fails after 60s",
      "estimated_recovery_time_minutes": 2
    }}
  ],
  "runbook_reference": "RB-001",
  "post_mortem_draft": "## Incident Summary\\n..."
}}
"""
        return await self.generate_json(prompt, "RCAReport schema")
    
    async def search_runbooks(self, query: str) -> list:
        """RAG: embed query → search Firestore runbooks by vector similarity."""
        import google.generativeai as genai
        try:
            embedding = genai.embed_content(
                model="models/text-embedding-004",
                content=query
            )["embedding"]
        except Exception:
            pass
        # Query Firestore for nearest runbooks (implement cosine similarity)
        # For MVP: return top 3 by keyword match as fallback
        return [{"id": "RB-001", "title": "Memory Leak Investigation", "resolution": "Pod restart restores service."}]
    
    async def execute_tier1_action(self, action: dict) -> dict:
        """Execute auto-approved Tier-1 actions (simulated for MVP)."""
        # In production: kubectl, AWS SDK, etc.
        # For MVP: update Firestore resource state + log to action_register
        result = {
            "action": action.get("action", "unknown"),
            "resource": action.get("target_resource", "unknown"),
            "status": "executed",
            "pre_state": {"status": "degraded", "memory_pct": 94},
            "post_state": {"status": "healthy", "memory_pct": 45},
            "health_check_passed": True,
        }
        return result
