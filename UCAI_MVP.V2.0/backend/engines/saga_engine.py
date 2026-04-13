import asyncio, uuid
from datetime import datetime
# Mock import for now
# from ..data.firestore_client import FirestoreClient

# db = FirestoreClient()
class MockDB:
    async def update(self, collection, doc_id, data):
        print(f"Mock update to {collection}/{doc_id}: {data}")

db = MockDB()

class SagaEngine:
    """
    Implements the Saga pattern for safe autonomous remediation.
    Every action has 3 phases: pre_check → execute → health_check
    If health_check fails: compensating transaction fires to revert
    """
    
    async def run(self, action: dict, executor) -> dict:
        saga_id = str(uuid.uuid4())
        action_doc = {
            "action_id": saga_id,
            "agent_name": action.get("agent", "unknown"),
            "action_type": action.get("action_type", "unknown"),
            "resource_id": action.get("resource_id", "unknown"),
            "tier": action.get("tier", "unknown"),
            "status": "starting",
            "pre_state_snapshot": None,
            "post_state_snapshot": None,
            "saga_steps": [],
            "rollback_executed": False,
            "created_at": datetime.utcnow().isoformat(),
        }
        
        # Step 1: Pre-check
        try:
            pre_state = await executor.pre_check(action)
            action_doc["pre_state_snapshot"] = pre_state
            action_doc["saga_steps"].append({"step": "pre_check", "status": "passed", "data": pre_state})
            action_doc["status"] = "pre_check_passed"
            await db.update("action_register", saga_id, action_doc)
        except Exception as e:
            action_doc["status"] = "aborted_pre_check"
            action_doc["saga_steps"].append({"step": "pre_check", "status": "failed", "error": str(e)})
            await db.update("action_register", saga_id, action_doc)
            return action_doc
        
        # Step 2: Execute
        try:
            result = await executor.execute(action)
            action_doc["saga_steps"].append({"step": "execute", "status": "completed", "data": result})
            action_doc["status"] = "executed"
            await db.update("action_register", saga_id, action_doc)
        except Exception as e:
            action_doc["status"] = "execute_failed"
            action_doc["saga_steps"].append({"step": "execute", "status": "failed", "error": str(e)})
            # Trigger compensating transaction
            await self._compensate(action, action_doc, dict() if 'pre_state' not in locals() else pre_state)
            return action_doc
        
        # Step 3: Health check (60 second window)
        await asyncio.sleep(5)  # brief wait for service to stabilize
        try:
            health = await executor.health_check(action)
            if not health["healthy"]:
                raise Exception(f"Health check failed: {health['reason']}")
            action_doc["post_state_snapshot"] = health
            action_doc["saga_steps"].append({"step": "health_check", "status": "passed", "data": health})
            action_doc["status"] = "completed"
            await db.update("action_register", saga_id, action_doc)
        except Exception as e:
            # HEALTH CHECK FAILED → COMPENSATING TRANSACTION
            action_doc["saga_steps"].append({"step": "health_check", "status": "failed", "error": str(e)})
            await self._compensate(action, action_doc, dict() if 'pre_state' not in locals() else pre_state)
        
        return action_doc
    
    async def _compensate(self, action: dict, action_doc: dict, pre_state: dict):
        """Compensating transaction: revert to pre_state_snapshot."""
        try:
            # Restore pre-state in Firestore resource document
            await db.update("resources", action.get("resource_id", ""), {
                "state": pre_state,
                "last_rollback": datetime.utcnow().isoformat(),
                "rollback_reason": f"Saga health check failed for action {action_doc['action_id']}"
            })
            action_doc["rollback_executed"] = True
            action_doc["status"] = "rolled_back"
            action_doc["rollback_reason"] = "Health check failed post-execution"
            await db.update("action_register", action_doc["action_id"], action_doc)
        except Exception as e:
            action_doc["status"] = "compensation_failed"
            await db.update("action_register", action_doc["action_id"], action_doc)
