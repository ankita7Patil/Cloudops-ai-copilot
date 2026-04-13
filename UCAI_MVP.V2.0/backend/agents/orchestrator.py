"""
Orchestrator Agent — production hardened.
Fixes:
 - Context isolation: always passes project_id to sub-agents
 - Agents called in parallel where independent (asyncio.gather)
 - Fallback if routing JSON is malformed
 - Never exposes raw credentials in prompts
"""
from agents.base_agent import BaseAgent
from agents.sre_agent import SREAgent
from agents.security_agent import SecurityAgent
from agents.finops_agent import FinOpsAgent
import json, asyncio, logging

logger = logging.getLogger("uaci.orchestrator")


class OrchestratorAgent(BaseAgent):
    SYSTEM_INSTRUCTION = """
You are the master orchestrator for UACI — Unified Autonomous Cloud Intelligence.
You receive natural language queries about GCP cloud operations and route them to
specialist agents: SRE (incidents/performance), Security (CSPM/risk), FinOps (costs).

Rules:
1. Always analyse ONLY the project in context — never generalise across projects.
2. Classify every recommended action by tier: TIER_1_AUTO / TIER_2_SUGGEST / TIER_3_IAC.
3. Flag any FinOps-Security conflicts before routing.
4. Return ONLY valid JSON — no markdown, no prose outside JSON.
"""

    def __init__(self):
        super().__init__()
        self.sre = SREAgent()
        self.security = SecurityAgent()
        self.finops = FinOpsAgent()

    async def handle_query(self, query: str, context: dict = {}) -> dict:
        project_id = context.get("project_id") or context.get("project", {}).get("project_id", "unknown")

        # ── Step 1: routing decision ──────────────────────────────────────────
        routing_prompt = f"""
User query: "{query}"
Project context (ID: {project_id}):
{json.dumps({k: v for k, v in context.items() if k != "cred_path"}, indent=2)}

Which specialist agents should handle this query?
Return ONLY this JSON (no other text):
{{"agents": ["sre"|"security"|"finops"], "rationale": "...", "conflict_check_needed": true|false}}
"""
        routing = await self.generate_json(routing_prompt)
        logger.info(f"[{project_id}] Routing decision: {routing}")

        if "error" in routing:
            # Fallback: run all agents if routing fails
            routing = {"agents": ["sre", "security", "finops"]}

        agents_to_run = routing.get("agents", [])

        # ── Step 2: run agents in parallel ────────────────────────────────────
        safe_ctx = {k: v for k, v in context.items() if k != "cred_path"}
        safe_ctx["project_id"] = project_id
        safe_ctx["user_query"] = query

        tasks = {}
        if "sre" in agents_to_run:
            tasks["sre"] = self.sre.analyze_incident(safe_ctx)
        if "security" in agents_to_run:
            tasks["security"] = self.security.explain_finding(safe_ctx)
        if "finops" in agents_to_run:
            tasks["finops"] = self.finops.analyze_costs(safe_ctx)

        if tasks:
            results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
            results = {}
            for key, res in zip(tasks.keys(), results_list):
                if isinstance(res, Exception):
                    logger.error(f"[{project_id}] {key} agent failed: {res}")
                    results[key] = {"error": str(res)}
                else:
                    results[key] = res
        else:
            results = {}

        # ── Step 3: synthesize ────────────────────────────────────────────────
        synthesis_prompt = f"""
Project: {project_id}
Original query: "{query}"
Agent results: {json.dumps(results, indent=2)}

Synthesize a response that:
1. Directly answers the query for project "{project_id}" only
2. Flags any cross-domain conflicts
3. Lists recommended actions in priority order with their tier
4. Stays concise and actionable (cloud ops manager audience)

Return ONLY this JSON:
{{
  "summary": "...",
  "project_id": "{project_id}",
  "conflicts_detected": [],
  "recommended_actions": [{{"action_type": "...", "tier": "...", "resource_id": "...", "rationale": "..."}}],
  "audit_note": "..."
}}
"""
        final = await self.generate_json(synthesis_prompt)
        final["project_id"] = project_id  # guarantee it's always set
        return final
