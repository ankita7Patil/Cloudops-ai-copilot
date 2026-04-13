from agents.base_agent import BaseAgent
import json

class SecurityAgent(BaseAgent):
    SYSTEM_INSTRUCTION = """
You are an expert cloud security AI agent specializing in CNAPP (Cloud-Native Application Protection Platform).
Your responsibilities:
1. Analyze OCSF-normalized security findings and explain them in business context
2. Score risk using RPN (Risk Priority Number) = Likelihood × Impact × (1/Detectability)
   Apply multipliers: internet_exposed=×3.0, pii_adjacent=×2.0, business_critical=×2.0, ai_workload=×1.5
3. Identify toxic combinations: multi-hop attack paths (public IP → over-privileged role → PII data)
4. Generate valid Terraform HCL patches for misconfigurations
5. Map findings to compliance frameworks: NIST AI RMF, ISO 42001, SOC 2, GDPR
6. Classify remediation tier: TIER_2_SUGGEST (policy changes) or TIER_3_IAC (network/IAM changes)

NEVER auto-apply security changes. Always route to TIER_2_SUGGEST or TIER_3_IAC.
ALWAYS include rollback instructions in every IaC patch as comments.
"""
    
    async def generate_iac_patch(self, finding: dict) -> str:
        prompt = f"""
Generate a Terraform HCL patch to remediate this security finding:

FINDING: {json.dumps(finding, indent=2)}

Requirements:
1. Valid, deployable Terraform HCL
2. Include # ROLLBACK: comment explaining how to revert
3. Include # COMPLIANCE: comment listing controls addressed (NIST AI RMF, SOC 2 control IDs)
4. Be minimal — only change what's needed to fix the finding
5. Include resource lookups using data sources where needed

Return ONLY the Terraform HCL code, no explanation.
"""
        return await self.generate(prompt)
    
    async def explain_finding(self, finding: dict) -> dict:
        prompt = f"""
Explain this cloud security finding for a business audience:

FINDING: {json.dumps(finding, indent=2)}

Return JSON:
{{
  "business_impact": "plain English description of what could happen if exploited",
  "likelihood_of_exploitation": "Low/Medium/High with reasoning",
  "blast_radius": "what systems/data could be affected",
  "rpn_score": 0.0,
  "compliance_controls": ["NIST-AI-RMF-MS-2.5", "SOC2-CC6.1"],
  "remediation_summary": "one sentence fix description",
  "tier": "TIER_2_SUGGEST or TIER_3_IAC"
}}
"""
        return await self.generate_json(prompt)
    
    async def find_toxic_combinations(self, graph_data: dict) -> list:
        prompt = f"""
Analyze this cloud resource relationship graph and identify "toxic combinations":
Multi-hop attack paths where an attacker could pivot from internet exposure to sensitive data.

GRAPH DATA: {json.dumps(graph_data, indent=2)}

Return JSON array of toxic paths:
[{{
  "path": ["public-load-balancer", "over-privileged-ec2-role", "prod-payments-s3"],
  "path_description": "Public internet → EC2 with admin IAM role → Payment PII data",
  "severity": "Critical",
  "attack_steps": ["1. Exploit public endpoint", "2. Use admin role to pivot", "3. Exfiltrate PII"],
  "rpn_score": 87.5
}}]
"""
        return await self.generate_json(prompt)
