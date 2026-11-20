"""
Main FastAPI Entrypoint for the Agentic SOC Platform Server.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import mimetypes
import os
import sys
import threading
from pathlib import Path

mimetypes.add_type("image/svg+xml", ".svg")

# Ensure root workspace is on pythonpath
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import psycopg
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from server.src.api.dependencies import get_container
from server.src.api.v1.alerts import router as alerts_router
from server.src.api.v1.cases import router as cases_router
from server.src.api.v1.events import router as events_router
from server.src.api.v1.ingest import router as ingest_router
from server.src.common.config import ServerConfig

logger = logging.getLogger("agentic_soc.server")

MAX_INGEST_BODY_BYTES = 1_048_576  # 1 MB limit (Section 5)
CASE_REAPER_INTERVAL_SECONDS = 300


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Manages periodic idle-case reaper thread and clean DB pool shutdown."""
    stop_event = threading.Event()
    reaper_thread: threading.Thread | None = None

    if not os.getenv("PYTEST_CURRENT_TEST"):
        def _reaper_loop() -> None:
            while not stop_event.wait(CASE_REAPER_INTERVAL_SECONDS):
                try:
                    container = get_container()
                    closed = container.alert_repo.close_idle_cases(
                        container.case_idle_timeout_seconds
                    )
                    if closed:
                        logger.info("Idle case reaper closed %d expired case(s).", closed)
                except Exception as exc:
                    logger.warning("Idle case reaper cycle failed: %s", exc)

        reaper_thread = threading.Thread(
            target=_reaper_loop,
            name="asp-case-reaper",
            daemon=True,
        )
        reaper_thread.start()

    try:
        yield
    finally:
        stop_event.set()
        if reaper_thread is not None:
            reaper_thread.join(timeout=2.0)
        try:
            get_container().close()
        except Exception as exc:
            logger.warning("Error closing container on shutdown: %s", exc)


_startup_cfg = ServerConfig.from_env()

app = FastAPI(
    title="Agentic SOC Platform API",
    version="0.1.0",
    description="Clean Architecture MVP for Telemetry Ingestion, Threat Detection, and Case Management.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_startup_cfg.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(psycopg.OperationalError)
async def handle_db_unavailable(_request: Request, exc: psycopg.OperationalError):
    """Uniformly maps PostgreSQL connectivity/operational errors to HTTP 503 across all routers."""
    logger.error("PostgreSQL operational error: %s", exc)
    return JSONResponse(
        status_code=503,
        content={"detail": "Database temporarily unavailable"},
    )


@app.middleware("http")
async def enforce_ingest_body_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/api/v1/ingest/logs":
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_INGEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Batch payload exceeds 1 MB limit"},
                    )
            except ValueError:
                pass
        body = await request.body()
        if len(body) > MAX_INGEST_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "Batch payload exceeds 1 MB limit"},
            )
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


# Register routers
app.include_router(ingest_router)
app.include_router(alerts_router)
app.include_router(events_router)
app.include_router(cases_router)

WEB_DIR = Path(__file__).resolve().parent / "web"
if WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="web-static")


@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serves the SOC Web Dashboard SPA."""
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/v1/health", tags=["Health"])
def health_check():
    """Service health check (public)."""
    return {"status": "ok", "service": "agentic-soc-server"}


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("SOC_SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_SERVER_PORT", "8000"))
    uvicorn.run("server.main:app", host=host, port=port, workers=1)
