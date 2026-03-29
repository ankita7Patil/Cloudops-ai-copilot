def analyze_resource(resource):
    findings = []
    r = resource
    rtype = r.get("type", "")

    # ── Cloud Storage Bucket ─────────────────────────────────
    if rtype == "Cloud Storage Bucket":
        if r.get("public_access"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "GCS-001",
                "title": "Cloud Storage bucket is publicly accessible",
                "description": "Bucket is exposed to the internet. Any unauthenticated user can read or download objects.",
                "remediation": "Go to Cloud Console → Storage → Bucket → Permissions. Remove 'allUsers' and 'allAuthenticatedUsers'. Enable 'Prevent public access' at the bucket level.",
                "gcp_doc": "https://cloud.google.com/storage/docs/access-control/making-data-public",
                "cost_waste": 0
            })
        if not r.get("uniform_bucket_level_access"):
            findings.append({
                "severity": "HIGH",
                "rule": "GCS-002",
                "title": "Uniform bucket-level access not enabled",
                "description": "Fine-grained ACLs allow inconsistent permission management, increasing risk of misconfiguration.",
                "remediation": "Enable 'Uniform bucket-level access' in Bucket Settings → Permissions. This enforces IAM-only access.",
                "gcp_doc": "https://cloud.google.com/storage/docs/uniform-bucket-level-access",
                "cost_waste": 0
            })
        if not r.get("cmek_enabled"):
            findings.append({
                "severity": "HIGH",
                "rule": "GCS-003",
                "title": "Customer-managed encryption key (CMEK) not configured",
                "description": "Bucket uses Google-managed keys. CMEK gives you full control over encryption key lifecycle.",
                "remediation": "Create a Cloud KMS key ring and key, then configure the bucket to use it as the default encryption key.",
                "gcp_doc": "https://cloud.google.com/storage/docs/encryption/using-customer-managed-keys",
                "cost_waste": 0
            })
        if not r.get("versioning"):
            findings.append({
                "severity": "MEDIUM",
                "rule": "GCS-004",
                "title": "Object versioning not enabled",
                "description": "Accidental deletions or overwrites cannot be recovered without versioning.",
                "remediation": "Enable versioning: gsutil versioning set on gs://BUCKET_NAME",
                "gcp_doc": "https://cloud.google.com/storage/docs/object-versioning",
                "cost_waste": 0
            })

    # ── Compute Engine VM ────────────────────────────────────
    if rtype == "Compute Engine VM":
        if r.get("firewall_ssh_open"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "GCE-001",
                "title": "SSH port 22 open to 0.0.0.0/0",
                "description": "SSH is accessible from the entire internet. This is a direct brute-force attack vector.",
                "remediation": "Delete the default-allow-ssh firewall rule. Use Identity-Aware Proxy (IAP) for SSH: gcloud compute ssh --tunnel-through-iap",
                "gcp_doc": "https://cloud.google.com/iap/docs/using-tcp-forwarding",
                "cost_waste": 0
            })
        if not r.get("os_login_enabled"):
            findings.append({
                "severity": "HIGH",
                "rule": "GCE-002",
                "title": "OS Login not enabled",
                "description": "Without OS Login, SSH keys are stored in instance metadata and not centrally managed.",
                "remediation": "Set metadata: enable-oslogin=TRUE on the instance or project level.",
                "gcp_doc": "https://cloud.google.com/compute/docs/oslogin/set-up-oslogin",
                "cost_waste": 0
            })
        if r.get("serial_port_access"):
            findings.append({
                "severity": "HIGH",
                "rule": "GCE-003",
                "title": "Interactive serial port access enabled",
                "description": "Serial port access allows unauthenticated console access to the VM, bypassing normal auth.",
                "remediation": "Disable serial port: set metadata serial-port-enable=false on the instance.",
                "gcp_doc": "https://cloud.google.com/compute/docs/instances/interacting-with-serial-console",
                "cost_waste": 0
            })
        if r.get("ssh_keys_in_metadata"):
            findings.append({
                "severity": "MEDIUM",
                "rule": "GCE-004",
                "title": "SSH keys stored in project metadata",
                "description": "Project-wide SSH keys apply to all instances — compromising one key grants access everywhere.",
                "remediation": "Remove project-level SSH keys. Use OS Login for centralized IAM-based SSH key management.",
                "gcp_doc": "https://cloud.google.com/compute/docs/connect/add-ssh-keys",
                "cost_waste": 0
            })
        if not r.get("shielded_vm"):
            findings.append({
                "severity": "MEDIUM",
                "rule": "GCE-005",
                "title": "Shielded VM not enabled",
                "description": "Without Shielded VM, the instance is vulnerable to boot-level and kernel-level attacks.",
                "remediation": "Recreate the instance with Shielded VM options: Secure Boot, vTPM, and Integrity Monitoring enabled.",
                "gcp_doc": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",
                "cost_waste": 0
            })

    # ── Cloud SQL ────────────────────────────────────────────
    if rtype == "Cloud SQL Instance":
        if r.get("public_ip_enabled"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "SQL-001",
                "title": "Cloud SQL has a public IP address",
                "description": "Database is reachable from the internet. Even with a password, it is exposed to brute force and credential stuffing.",
                "remediation": "Disable public IP. Use Cloud SQL Auth Proxy or Private IP for all connections.",
                "gcp_doc": "https://cloud.google.com/sql/docs/postgres/configure-private-ip",
                "cost_waste": 0
            })
        if not r.get("ssl_required"):
            findings.append({
                "severity": "HIGH",
                "rule": "SQL-002",
                "title": "SSL/TLS not required for Cloud SQL connections",
                "description": "Database connections can be made without encryption — credentials and data transmitted in plaintext.",
                "remediation": "In Cloud SQL settings → Connections → SSL, set SSL Mode to 'Require SSL'.",
                "gcp_doc": "https://cloud.google.com/sql/docs/postgres/configure-ssl-instance",
                "cost_waste": 0
            })
        if r.get("authorized_networks_all"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "SQL-003",
                "title": "Cloud SQL authorized networks set to 0.0.0.0/0",
                "description": "All IP addresses are whitelisted — any machine on the internet can attempt to connect.",
                "remediation": "Remove the 0.0.0.0/0 authorized network. Add only specific known IP ranges or remove all and use Cloud SQL Auth Proxy.",
                "gcp_doc": "https://cloud.google.com/sql/docs/postgres/authorize-networks",
                "cost_waste": 0
            })
        if not r.get("automated_backups"):
            findings.append({
                "severity": "HIGH",
                "rule": "SQL-004",
                "title": "Automated backups disabled for Cloud SQL",
                "description": "Without automated backups, data loss is permanent if the instance is corrupted or deleted.",
                "remediation": "Enable automated backups in Cloud SQL → Edit → Backups. Set retention to at least 7 days.",
                "gcp_doc": "https://cloud.google.com/sql/docs/postgres/backup-recovery/backups",
                "cost_waste": 0
            })

    # ── IAM Service Account ──────────────────────────────────
    if rtype == "IAM Service Account":
        if r.get("has_owner_role"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "IAM-001",
                "title": "Service account has roles/owner (full project access)",
                "description": "Owner role grants unrestricted access to all GCP resources in the project — severe violation of least privilege.",
                "remediation": "Remove roles/owner. Create a custom IAM role with only the minimum permissions this service account needs.",
                "gcp_doc": "https://cloud.google.com/iam/docs/understanding-roles",
                "cost_waste": 0
            })
        if r.get("key_rotation_days", 0) > 90:
            findings.append({
                "severity": "HIGH",
                "rule": "IAM-002",
                "title": "Service account keys not rotated in over 90 days",
                "description": f"Keys are {r.get('key_rotation_days')} days old. Stale keys are a credential compromise risk.",
                "remediation": "Delete old keys and create new ones. Set up automated key rotation using Cloud Scheduler + Cloud Functions.",
                "gcp_doc": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
                "cost_waste": 0
            })
        if r.get("user_managed_keys", 0) > 1:
            findings.append({
                "severity": "MEDIUM",
                "rule": "IAM-003",
                "title": f"Service account has {r.get('user_managed_keys')} user-managed keys",
                "description": "Multiple long-lived keys increase the attack surface. Prefer Workload Identity Federation.",
                "remediation": "Delete unused keys. Use Workload Identity Federation instead of service account keys where possible.",
                "gcp_doc": "https://cloud.google.com/iam/docs/workload-identity-federation",
                "cost_waste": 0
            })

    # ── VPC Firewall Rule ────────────────────────────────────
    if rtype == "VPC Firewall Rule":
        if "0.0.0.0/0" in r.get("source_ranges", []):
            findings.append({
                "severity": "CRITICAL",
                "rule": "FW-001",
                "title": "Firewall rule allows ingress from 0.0.0.0/0",
                "description": "All internet traffic is permitted into the VPC. This exposes every VM behind this rule.",
                "remediation": "Delete this rule. Create targeted firewall rules with specific source IP ranges or use service account-based rules.",
                "gcp_doc": "https://cloud.google.com/vpc/docs/firewalls",
                "cost_waste": 0
            })
        if r.get("all_ports_open"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "FW-002",
                "title": "Firewall rule opens all ports",
                "description": "Every TCP/UDP port is accessible — every service on every VM is potentially reachable.",
                "remediation": "Replace with specific port rules: allow only 80/443 for web, 8080 for internal APIs, etc.",
                "gcp_doc": "https://cloud.google.com/vpc/docs/using-firewalls",
                "cost_waste": 0
            })

    # ── GKE Cluster ──────────────────────────────────────────
    if rtype == "GKE Cluster":
        if r.get("legacy_abac_enabled"):
            findings.append({
                "severity": "CRITICAL",
                "rule": "GKE-001",
                "title": "Legacy ABAC authorization enabled on GKE cluster",
                "description": "Legacy ABAC bypasses Kubernetes RBAC, granting all service accounts full cluster access.",
                "remediation": "Disable legacy ABAC: gcloud container clusters update CLUSTER --no-enable-legacy-authorization",
                "gcp_doc": "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster",
                "cost_waste": 0
            })
        if not r.get("network_policy_enabled"):
            findings.append({
                "severity": "HIGH",
                "rule": "GKE-002",
                "title": "Kubernetes Network Policy not enabled",
                "description": "Without network policies, any pod can communicate with any other pod — lateral movement risk.",
                "remediation": "Enable network policy on creation or use GKE Dataplane V2 which includes Cilium network policies.",
                "gcp_doc": "https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy",
                "cost_waste": 0
            })
        if not r.get("private_cluster"):
            findings.append({
                "severity": "HIGH",
                "rule": "GKE-003",
                "title": "GKE cluster nodes have public IP addresses",
                "description": "Public node IPs expose the cluster control plane and nodes directly to the internet.",
                "remediation": "Migrate to a private GKE cluster where nodes use internal IPs only.",
                "gcp_doc": "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters",
                "cost_waste": 0
            })
        if not r.get("workload_identity"):
            findings.append({
                "severity": "MEDIUM",
                "rule": "GKE-004",
                "title": "Workload Identity not enabled",
                "description": "Without Workload Identity, pods use the node service account — overly broad permissions shared across all pods.",
                "remediation": "Enable Workload Identity Federation for GKE to bind Kubernetes service accounts to GCP IAM.",
                "gcp_doc": "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
                "cost_waste": 0
            })
        if not r.get("auto_upgrade"):
            findings.append({
                "severity": "MEDIUM",
                "rule": "GKE-005",
                "title": "GKE auto-upgrade disabled",
                "description": "Cluster may be running outdated Kubernetes versions with known CVEs.",
                "remediation": "Enable auto-upgrade for node pools to receive automatic security patches.",
                "gcp_doc": "https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-upgrades",
                "cost_waste": r.get("cost_per_month", 0) * 0.1
            })

    return findings


def calculate_risk_score(all_findings):
    score = 100
    for f in all_findings:
        if f["severity"] == "CRITICAL":
            score -= 18
        elif f["severity"] == "HIGH":
            score -= 9
        elif f["severity"] == "MEDIUM":
            score -= 4
        elif f["severity"] == "LOW":
            score -= 2
    return max(0, score)


def calculate_cost_waste(all_findings):
    return round(sum(f.get("cost_waste", 0) for f in all_findings), 2)
