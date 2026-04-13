from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class OCSFEvent(BaseModel):
    event_uid: str                    # unique event ID
    time: datetime                    # event timestamp
    severity_id: int                  # 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
    severity: str
    class_uid: int                    # OCSF class (e.g., 3005=Detection Finding)
    class_name: str
    activity_id: int                  # 1=Create, 2=Read, 3=Update, 4=Delete
    activity_name: str
    category_uid: int                 # OCSF category
    category_name: str
    cloud_account_id: str             # mock account ID
    cloud_provider: str               # "AWS" | "Azure" | "GCP"
    resource_name: str                # e.g., "payments-api-prod-us-east-1"
    resource_type: str                # e.g., "S3Bucket", "EC2Instance", "IAMRole"
    finding_type: str                 # e.g., "PubliclyAccessibleStorage", "OverprivilegedRole"
    finding_desc: str
    remediation_hint: Optional[str]
    raw_data: dict                    # full original event
    tags: dict                        # resource tags (team, env, criticality)


class FOCUSBillingRecord(BaseModel):
    billing_period_start: datetime
    billing_period_end: datetime
    charge_period_start: datetime
    charge_period_end: datetime
    provider_name: str               # "Amazon Web Services" | "Microsoft Azure" | "Google Cloud"
    account_id: str
    account_name: str
    resource_id: str
    resource_name: str
    resource_type: str
    service_category: str            # "Compute", "Storage", "AI/ML", "Networking"
    service_name: str
    region: str
    billed_cost: float
    effective_cost: float
    list_cost: float
    usage_quantity: float
    usage_unit: str                  # "Hours", "GB", "Requests"
    billing_currency: str            # "USD"
    tags: dict                       # MUST include "team", "environment", "project"


class RiskScore(BaseModel):
    resource_id: str
    resource_name: str
    account_id: str
    cloud_provider: str
    likelihood: float                # 1-5 scale
    impact: float                    # 1-5 scale
    detectability: float             # 1-5 scale (higher = more detectable = LOWER risk)
    internet_exposed: bool           # multiplier 3.0x if True
    pii_adjacent: bool               # multiplier 2.0x if True
    business_critical: bool          # multiplier 2.0x if True
    ai_workload: bool                # multiplier 1.5x if True (AI-SPM)
    rpn_score: float                 # computed: likelihood * impact * (1/detectability) * multipliers
    finding_type: str
    finding_desc: str
    remediation_type: str            # "TIER_1_AUTO" | "TIER_2_SUGGEST" | "TIER_3_IAC"
    compliance_controls: List[str]   # e.g., ["NIST-AI-RMF-MS-2.5", "SOC2-CC6.1"]
    calculated_at: datetime


class ActionRegister(BaseModel):
    action_id: str                   # UUID
    agent_name: str                  # "sre_agent" | "security_agent" | "finops_agent"
    action_type: str                 # e.g., "pod_restart", "iac_patch_generate"
    resource_id: str
    resource_name: str
    tier: str                        # "TIER_1_AUTO" | "TIER_2_SUGGEST" | "TIER_3_IAC"
    pre_state_snapshot: dict         # resource state BEFORE action
    post_state_snapshot: Optional[dict]
    status: str                      # "pending" | "approved" | "rejected" | "executed" | "rolled_back"
    approver_id: Optional[str]
    approval_timestamp: Optional[datetime]
    saga_steps: List[dict]           # pre_check, execute, health_check results
    rollback_executed: bool
    rollback_reason: Optional[str]
    compliance_evidence: dict        # audit evidence for regulators
    created_at: datetime
    updated_at: datetime


class Approval(BaseModel):
    approval_id: str                 # UUID
    action_id: str                   # links to ActionRegister
    action_summary: str              # human-readable: "Restart payments-api-prod pod"
    risk_level: str                  # "LOW" | "MEDIUM" | "HIGH"
    rpn_score: float
    proposed_by: str                 # agent name
    iac_patch_url: Optional[str]     # Cloud Storage URL for Terraform patch
    status: str                      # "pending" | "approved" | "rejected" | "expired"
    expires_at: datetime             # auto-expires after 15 minutes
    created_at: datetime
