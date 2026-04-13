"""
Run: python generate_all.py
Outputs: JSON files in ./output/ directory
Then: load to BigQuery and Firestore
"""

import json, random, uuid
from datetime import datetime, timedelta
from faker import Faker
fake = Faker()

# === MOCK CLOUD ACCOUNTS ===
ACCOUNTS = [
    {"id": "aws-prod-001", "name": "Production AWS", "provider": "AWS", "env": "production"},
    {"id": "azure-dev-002", "name": "Dev Azure", "provider": "Azure", "env": "development"},
    {"id": "gcp-staging-003", "name": "Staging GCP", "provider": "GCP", "env": "staging"},
]

# === REALISTIC RESOURCE NAMES (not generic!) ===
SERVICES = [
    "payments-api", "user-auth-service", "order-processor", "inventory-sync",
    "notification-hub", "ml-training-pipeline", "recommendation-engine",
    "fraud-detection-svc", "api-gateway", "data-warehouse-etl",
    "customer-portal-frontend", "internal-admin-panel", "event-streaming-broker",
    "cdn-edge-cache", "metrics-aggregator"
]
ENVS = ["prod", "staging", "dev"]
REGIONS = {"AWS": ["us-east-1", "eu-west-1"], "Azure": ["eastus", "westeurope"], "GCP": ["us-central1", "europe-west1"]}

def resource_name(service, provider, env="prod"):
    region = random.choice(REGIONS.get(provider, ["us-central1"]))
    return f"{service}-{env}-{region}"

# === SEEDED CRITICAL MISCONFIGURATIONS (judges must see these as top-3) ===
CRITICAL_MISCONFIGS = [
    {
        "resource_name": "payments-api-data-store-prod-us-east-1",
        "resource_type": "S3Bucket",
        "finding_type": "PubliclyAccessibleStorageWithPIIData",
        "finding_desc": "S3 bucket containing PII customer payment records is publicly accessible via ACL. No encryption at rest.",
        "severity": "Critical",
        "internet_exposed": True,
        "pii_adjacent": True,
        "business_critical": True,
        "likelihood": 5, "impact": 5, "detectability": 1,  # RPN = 75 * multipliers = 900
    },
    {
        "resource_name": "user-auth-service-iam-role-prod",
        "resource_type": "IAMRole",
        "finding_type": "WildcardAdminPolicyOnProductionRole",
        "finding_desc": "IAM role attached to user-auth-service has AdministratorAccess policy. Can read/write all resources including production databases.",
        "severity": "Critical",
        "internet_exposed": False,
        "pii_adjacent": True,
        "business_critical": True,
        "likelihood": 4, "impact": 5, "detectability": 2,  # RPN = 50
    },
    {
        "resource_name": "ml-training-pipeline-gpu-cluster-dev",
        "resource_type": "ComputeInstance",
        "finding_type": "ShadowAIUnauthorizedModelEndpoint",
        "finding_desc": "Unauthorized Bedrock/OpenAI API endpoint detected on dev cluster. No data classification, no encryption, no AI-BOM. Possible Shadow AI deployment processing customer data.",
        "severity": "High",
        "internet_exposed": True,
        "pii_adjacent": True,
        "business_critical": False,
        "ai_workload": True,
        "likelihood": 4, "impact": 4, "detectability": 2,
    },
]

# === GENERATE 30 DAYS OF OCSF EVENTS ===
def generate_ocsf_events(n=500):
    events = []
    finding_types = [
        "OpenSecurityGroup", "MFANotEnabled", "UnencryptedStorage",
        "OverprivilegedRole", "PublicRDSInstance", "InsecureTLSConfig",
        "MissingCloudTrailLogging", "ExcessiveIAMPermissions",
    ]
    for _ in range(n):
        account = random.choice(ACCOUNTS)
        service = random.choice(SERVICES)
        provider = account["provider"]
        days_ago = random.randint(0, 30)
        events.append({
            "event_uid": str(uuid.uuid4()),
            "time": (datetime.utcnow() - timedelta(days=days_ago, hours=random.randint(0,23))).isoformat(),
            "severity_id": random.choice([2, 3, 4, 5]),
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "class_uid": 3005,
            "class_name": "Detection Finding",
            "cloud_account_id": account["id"],
            "cloud_provider": provider,
            "resource_name": resource_name(service, provider, random.choice(ENVS)),
            "resource_type": random.choice(["EC2Instance", "S3Bucket", "IAMRole", "RDSInstance", "LambdaFunction"]),
            "finding_type": random.choice(finding_types),
            "finding_desc": f"Automated scanner detected {random.choice(finding_types)} on resource.",
            "tags": {"team": random.choice(["payments","ml","platform","frontend","data"]), "env": account["env"]},
        })
    # Inject the critical seeded misconfigs
    for crit in CRITICAL_MISCONFIGS:
        events.append({**crit, "event_uid": str(uuid.uuid4()),
                        "time": datetime.utcnow().isoformat(),
                        "class_uid": 3005, "class_name": "Detection Finding",
                        "cloud_account_id": "aws-prod-001", "cloud_provider": "AWS"})
    return events

# === GENERATE FOCUS BILLING (30 days, 3 accounts) ===
def generate_focus_billing(n=300):
    records = []
    services = [
        ("Compute", "Amazon EC2", 2.5, "Hours"),
        ("Storage", "Amazon S3", 0.023, "GB"),
        ("AI/ML", "Amazon Bedrock", 0.008, "Tokens"),
        ("Compute", "Azure Virtual Machines", 1.8, "Hours"),
        ("AI/ML", "Azure OpenAI", 0.01, "Tokens"),
        ("Compute", "Google Compute Engine", 1.2, "Hours"),
    ]
    teams = ["payments", "ml", "platform", "frontend", "data"]
    for _ in range(n):
        account = random.choice(ACCOUNTS)
        svc_cat, svc_name, unit_price, unit = random.choice(services)
        usage = random.uniform(10, 500)
        days_ago = random.randint(0, 30)
        start = datetime.utcnow() - timedelta(days=days_ago)
        records.append({
            "billing_period_start": start.isoformat(),
            "billing_period_end": (start + timedelta(days=1)).isoformat(),
            "provider_name": account["provider"],
            "account_id": account["id"],
            "resource_id": str(uuid.uuid4()),
            "resource_name": resource_name(random.choice(SERVICES), account["provider"]),
            "service_category": svc_cat,
            "service_name": svc_name,
            "region": random.choice(REGIONS.get(account["provider"], ["us-central1"])),
            "billed_cost": round(usage * unit_price, 4),
            "usage_quantity": round(usage, 2),
            "usage_unit": unit,
            "billing_currency": "USD",
            "tags": {"team": random.choice(teams), "environment": account["env"], "project": "uaci-demo"},
        })
    # Inject cost spike: ml-team GPU cluster (will be detected by anomaly engine)
    for day in range(3):
        records.append({
            "billing_period_start": (datetime.utcnow() - timedelta(days=day)).isoformat(),
            "billing_period_end": (datetime.utcnow() - timedelta(days=day-1)).isoformat(),
            "provider_name": "Amazon Web Services", "account_id": "aws-prod-001",
            "resource_id": "gpu-cluster-ml-001",
            "resource_name": "ml-training-pipeline-gpu-cluster-dev",
            "service_category": "AI/ML", "service_name": "Amazon EC2 P4d",
            "region": "us-east-1",
            "billed_cost": 847.32,  # spike: normally $12/day, now $847
            "usage_quantity": 72, "usage_unit": "Hours",
            "billing_currency": "USD",
            "tags": {"team": "ml", "environment": "development", "project": "uaci-demo"},
        })
    return records

# === SEEDED INCIDENTS (for PS1 demo) ===
SEEDED_INCIDENTS = [
    {
        "incident_id": "INC-001",
        "title": "Memory leak in payments-api-prod causing latency spike",
        "description": "P99 latency for /api/checkout endpoint spiked from 120ms to 4800ms. OOM errors in logs.",
        "severity": "Critical",
        "status": "open",
        "affected_service": "payments-api-prod-us-east-1",
        "account_id": "aws-prod-001",
        "root_cause": None,  # Gemini will discover: payments-service v2.3.1 memory leak
        "rca_summary": None,
        "rpn_score": 87.5,
        "created_at": datetime.utcnow().isoformat(),
    }
]

# === SRE RUNBOOKS (for RAG) ===
RUNBOOKS = [
    {"id": "RB-001", "title": "Memory Leak Investigation", "service": "generic",
     "symptoms": ["high memory usage", "OOM errors", "increasing latency"],
     "steps": ["1. Check pod memory with kubectl top pods", "2. Capture heap dump", "3. Check recent deployments", "4. If version rollback resolves: mark as regression", "5. Restart pod to restore service: kubectl rollout restart"],
     "resolution": "Pod restart restores service. File ticket for dev team to fix memory leak in identified version."},
    {"id": "RB-002", "title": "Database Connection Pool Exhaustion", "service": "generic",
     "symptoms": ["connection timeout errors", "slow queries", "5xx errors"],
     "steps": ["1. Check active DB connections", "2. Identify connection leaks in logs", "3. Increase pool size temporarily", "4. Restart application instances"],
     "resolution": "Connection pool exhaustion usually caused by connection leak in application code."},
    # ... add 48 more realistic runbooks
]

if __name__ == "__main__":
    import os
    os.makedirs("output", exist_ok=True)
    
    ocsf = generate_ocsf_events(500)
    focus = generate_focus_billing(300)
    
    with open("output/ocsf_events.json", "w") as f:
        json.dump(ocsf, f, indent=2)
    with open("output/focus_billing.json", "w") as f:
        json.dump(focus, f, indent=2)
    with open("output/incidents.json", "w") as f:
        json.dump(SEEDED_INCIDENTS, f, indent=2)
    with open("output/runbooks.json", "w") as f:
        json.dump(RUNBOOKS, f, indent=2)
    
    print(f"Generated: {len(ocsf)} OCSF events, {len(focus)} billing records")
    print("Load to BigQuery: bq load --source_format=NEWLINE_DELIMITED_JSON ...")
