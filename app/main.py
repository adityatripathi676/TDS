"""
FastAPI Application Entry Point
================================
Production-hardened setup:
  - Security headers middleware on every response
  - Rate limiter wired into app state
  - Docs/redoc disabled (no public API schema)
  - CORS restricted to localhost only
  - MongoDB indexes initialized at startup
  - Stack traces never leaked to clients
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import monitor, router
from app.config import FRONTEND_ASSETS_DIR, FRONTEND_DIST_DIR
from app.core.mongo_auth import init_mongo_indexes
from app.core.security import SECURITY_HEADERS, limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    print("[main] Initialising MongoDB Atlas indexes and seeding default user…")
    try:
        init_mongo_indexes()
        print("[main] MongoDB ready.")
    except Exception as e:
        print(f"[main] ⚠️ MongoDB Atlas connection unreachable ({e}). Operating in resilient mode (offline / local auth fallback enabled).")

    monitor.start()
    monitor.scan_now()
    print("[main] Host monitor started.")

    try:
        yield
    finally:
        # ── Shutdown ─────────────────────────────────────────────────────────
        monitor.stop()
        print("[main] Host monitor stopped.")


# ── Create FastAPI app — docs disabled in production ─────────────────────────
app = FastAPI(
    title="AI-HIDS Sentinel",
    version="2.0.0",
    description="Host Intrusion Detection & Threat Scoring Platform",
    lifespan=lifespan,
    # Disable public API docs — exposing schema aids attackers
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ── Rate limiter ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,  # Returns 429 with Retry-After header
)

# ── CORS — restrict to same-origin + localhost only ──────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5173",   # Vite dev server
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    expose_headers=["X-Request-ID"],
)


# ── Security headers middleware — applied to every response ───────────────────
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value
    # Strip server fingerprinting headers
    # MutableHeaders doesn't support .pop(); use del with a guard instead
    for _hdr in ("server", "x-powered-by"):
        try:
            del response.headers[_hdr]
        except KeyError:
            pass
    return response


# ── Global exception handler — never leak stack traces to clients ──────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import hashlib, traceback
    trace = traceback.format_exc()
    ref = hashlib.sha256(trace.encode()).hexdigest()[:8].upper()
    # Log full trace server-side, return opaque ref to client
    print(f"[ERROR] Unhandled exception ref={ref}:\n{trace}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error. Reference: {ref}"},
    )


# ── Include API routes ────────────────────────────────────────────────────────
app.include_router(router)

# ── Static assets ─────────────────────────────────────────────────────────────
if FRONTEND_ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS_DIR)), name="assets")


@app.get("/", include_in_schema=False)
def serve_frontend():
    index_file = FRONTEND_DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse(
        {"message": "Frontend build not found. Run: cd frontend && npm run build"},
        status_code=503,
    )


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    if full_path.startswith("api") or full_path.startswith("ws"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    index_file = FRONTEND_DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse({"message": "Frontend build not found."}, status_code=503)
