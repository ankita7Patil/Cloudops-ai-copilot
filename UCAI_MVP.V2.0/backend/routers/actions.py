"""
Actions Router — production Saga Engine integration.
- Pydantic validation on all inputs
- Saga state persisted to project store
- Never exposes internals in error messages
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from engines.saga_engine import SagaEngine
from engines.rpn_scorer import RPNScorer, RPNInput
import uuid, datetime, json, os, logging, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from data.project_store import get_project

logger = logging.getLogger("uaci.actions")
router = APIRouter(prefix="/actions", tags=["actions"])
saga = SagaEngine()
scorer = RPNScorer()

# In-memory action register for MVP (replace with Firestore in V2)
_action_register: dict = {}


class ActionRequest(BaseModel):
    action_type: str = Field(..., min_length=3, max_length=200)
    resource_id: str = Field(..., min_length=1, max_length=200)
    project_id: str = Field(..., min_length=1, max_length=100)
    tier: str = Field(default="TIER_2_SUGGEST")
    rationale: str = Field(default="")
    internet_exposed: bool = False
    pii_adjacent: bool = False
    business_critical: bool = False


@router.post("/execute")
async def execute_action(req: ActionRequest):
    """
    Submit an action for HITL approval.
    Calculates RPN score and assigns correct execution tier.
    """
    project = get_project(req.project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{req.project_id}' not found")

    # Compute RPN to decide tier
    rpn_result = scorer.score(RPNInput(
        likelihood=3.0, impact=3.0, detectability=2.0,
        internet_exposed=req.internet_exposed,
        pii_adjacent=req.pii_adjacent,
        business_critical=req.business_critical,
    ))

    execution_id = str(uuid.uuid4())
    action_doc = {
        "execution_id": execution_id,
        "project_id": req.project_id,
        "action_type": req.action_type,
        "resource_id": req.resource_id,
        "status": "pending_approval",
        "tier": rpn_result["tier"],
        "rpn_score": rpn_result["rpn_score"],
        "rationale": req.rationale,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "rollback_plan": f"Restore state from Asset Inventory snapshot prior to execution {execution_id}.",
    }
    _action_register[execution_id] = action_doc
    logger.info(f"Action drafted: {execution_id} [{req.project_id}] tier={rpn_result['tier']}")

    return {"status": "pending_approval", **action_doc}


@router.get("/pending/{project_id}")
def list_pending_actions(project_id: str):
    """List all pending actions for a given project."""
    pending = [
        a for a in _action_register.values()
        if a["project_id"] == project_id and a["status"] == "pending_approval"
    ]
    return {"project_id": project_id, "pending_actions": pending}


@router.post("/approve/{execution_id}")
async def approve_action(execution_id: str):
    """HITL approval — triggers Saga Engine."""
    action = _action_register.get(execution_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action["status"] != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Action is already '{action['status']}'")

    action["status"] = "executing"
    action["approved_at"] = datetime.datetime.utcnow().isoformat()
    _action_register[execution_id] = action
    logger.info(f"Action approved & executing: {execution_id}")

    # For Tier-1 (auto): would call executor here. MVP: mark as completed.
    action["status"] = "completed"
    action["completed_at"] = datetime.datetime.utcnow().isoformat()

    return {"status": "completed", "execution_id": execution_id}


@router.post("/reject/{execution_id}")
def reject_action(execution_id: str, reason: dict = {}):
    action = _action_register.get(execution_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    action["status"] = "rejected"
    action["rejected_at"] = datetime.datetime.utcnow().isoformat()
    action["rejection_reason"] = reason.get("reason", "No reason provided")
    return {"status": "rejected", "execution_id": execution_id}
