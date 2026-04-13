"""
Approvals Router — HITL approval queue.
Uses actions router's _action_register for state.
"""
from fastapi import APIRouter, HTTPException
from datetime import datetime

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


@router.get("/")
async def list_pending():
    """List all pending approvals across all projects."""
    from routers.actions import _action_register
    pending = [a for a in _action_register.values() if a["status"] == "pending_approval"]
    return {"pending": pending, "count": len(pending)}


@router.post("/{execution_id}/approve")
async def approve(execution_id: str):
    """Delegate to actions router approve endpoint."""
    from routers.actions import _action_register, approve_action
    return await approve_action(execution_id)


@router.post("/{execution_id}/reject")
async def reject(execution_id: str, reason: dict = {}):
    from routers.actions import _action_register, reject_action
    return reject_action(execution_id, reason)
