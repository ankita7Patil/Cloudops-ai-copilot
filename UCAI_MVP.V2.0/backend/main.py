"""
Production-grade FastAPI entry point.
- Structured JSON logging
- Global error handling middleware
- Health + readiness endpoints
- CORS properly configured
- All routers mounted with /api prefix
"""
import logging, json, time, os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from routers import chat, approvals, projects, health, actions, reports

# ── Structured logging ──────────────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
        })

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("uaci")

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="UACI MVP API",
    description="Unified Autonomous Cloud Intelligence — Multi-Project Control Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — tighten in production by listing exact origins ───────────────────
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── Request timing middleware ────────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    duration_ms = round((time.time() - start) * 1000)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} ({duration_ms}ms)")
    return response

# ── Global exception handler ──────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exc_handler(request: Request, exc: Exception):
    logger.error(f"Exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "An unexpected error occurred."})

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(chat.router)        # already has /api/chat prefix
app.include_router(approvals.router)   # already has /api/approvals prefix
app.include_router(projects.router, prefix="/api")
app.include_router(health.router, prefix="/api")
app.include_router(actions.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

# ── Health / Readiness ────────────────────────────────────────────────────────
@app.get("/health", tags=["ops"])
def liveness():
    """Liveness probe — Cloud Run & K8s."""
    return {"status": "ok", "service": "uaci-backend"}

@app.get("/ready", tags=["ops"])
def readiness():
    """Readiness probe — confirms Gemini key is set."""
    gemini_ok = bool(os.environ.get("GEMINI_API_KEY"))
    return {
        "ready": gemini_ok,
        "gemini_configured": gemini_ok,
    }
