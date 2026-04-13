from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from agents.orchestrator import OrchestratorAgent
import asyncio, json

router = APIRouter(prefix="/api/chat", tags=["chat"])
orchestrator = OrchestratorAgent()

@router.post("/")
async def chat(body: dict):
    """Natural language interface — streams Gemini response."""
    query = body.get("message", "")
    context = body.get("context", {})
    
    async def stream_response():
        yield f"data: {json.dumps({'type': 'thinking', 'content': 'Routing to specialist agents...'})}\n\n"
        await asyncio.sleep(0.1)
        
        result = await orchestrator.handle_query(query, context)
        
        yield f"data: {json.dumps({'type': 'result', 'content': result})}\n\n"
        yield "data: [DONE]\n\n"
    
    return StreamingResponse(stream_response(), media_type="text/event-stream")

@router.post("/rca")
async def run_rca(incident: dict):
    """Run full RCA on an incident."""
    from agents.sre_agent import SREAgent
    sre = SREAgent()
    return await sre.analyze_incident(incident)
