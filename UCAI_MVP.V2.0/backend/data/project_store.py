"""
Project Store — JSON file-based persistence for MVP.
Stores project metadata + credentials path.
Production migration path: GCP Secret Manager + Firestore.
"""
import json, os, datetime, random

STORE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "projects.json")
CREDENTIALS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "credentials")

os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
os.makedirs(CREDENTIALS_DIR, exist_ok=True)


def _load() -> dict:
    if not os.path.exists(STORE_PATH):
        return {}
    with open(STORE_PATH) as f:
        return json.load(f)


def _save(data: dict):
    with open(STORE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def list_projects() -> list:
    return list(_load().values())


def get_project(project_id: str) -> dict | None:
    return _load().get(project_id)


def upsert_project(project_id: str, name: str, cred_path: str) -> dict:
    store = _load()
    existing = store.get(project_id, {})
    store[project_id] = {
        "project_id": project_id,
        "project_name": name or project_id,
        "cred_path": cred_path,
        "connection_status": "connected",
        "added_at": existing.get("added_at", datetime.datetime.utcnow().isoformat()),
        "last_sync": datetime.datetime.utcnow().isoformat(),
        # Simulated metrics — replaced by real Cloud Monitoring calls per project
        "health_score": existing.get("health_score", random.randint(72, 98)),
        "alerts_count": existing.get("alerts_count", random.randint(0, 8)),
        "risk_level": existing.get("risk_level", random.choice(["Low", "Medium", "High"])),
        "cpu_usage": existing.get("cpu_usage", f"{random.randint(30,80)}%"),
        "memory_usage": existing.get("memory_usage", f"{random.randint(40,85)}%"),
        "monthly_cost": existing.get("monthly_cost", round(random.uniform(400, 5000), 2)),
        "cost_drift": existing.get("cost_drift", f"+{random.randint(2,25)}%"),
    }
    _save(store)
    return store[project_id]


def refresh_project_metrics(project_id: str) -> dict | None:
    """Simulate metric refresh — in production this calls Cloud Monitoring API."""
    store = _load()
    if project_id not in store:
        return None
    p = store[project_id]
    p["last_sync"] = datetime.datetime.utcnow().isoformat()
    p["health_score"] = max(0, min(100, p["health_score"] + random.randint(-3, 3)))
    p["cpu_usage"] = f"{random.randint(30,80)}%"
    p["memory_usage"] = f"{random.randint(40,85)}%"
    p["alerts_count"] = max(0, p["alerts_count"] + random.randint(-1, 1))
    p["risk_level"] = "Critical" if p["health_score"] < 60 else "Medium" if p["health_score"] < 80 else "Low"
    _save(store)
    return p


def delete_project(project_id: str) -> bool:
    store = _load()
    if project_id not in store:
        return False
    # Remove credentials file
    cred = store[project_id].get("cred_path", "")
    if cred and os.path.exists(cred):
        os.remove(cred)
    del store[project_id]
    _save(store)
    return True
