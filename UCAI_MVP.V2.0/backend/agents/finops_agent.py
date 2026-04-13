from agents.base_agent import BaseAgent
import json

class FinOpsAgent(BaseAgent):
    SYSTEM_INSTRUCTION = """
You are a Cloud FinOps AI agent.
Your responsibilities:
1. Detect cost anomalies and analyze FOCUS billing data.
2. Attribute spend to teams using tags.
3. Recommend rightsizing or termination for idle resources.
4. Always check for security or SRE implications before recommending cost-saving actions!
"""
    
    async def analyze_costs(self, context: dict) -> dict:
        prompt = f"""
Analyze these cost figures and provide a FinOps perspective:

CONTEXT: {json.dumps(context, indent=2)}

Return JSON:
{{
    "anomaly_detected": true,
    "attributed_team": "ml",
    "explanation": "GPU cluster running continuously",
    "recommended_action": "terminate cluster",
    "potential_savings": 500
}}
"""
        return await self.generate_json(prompt)
