"""
Main FastAPI Entrypoint for the Agentic SOC Platform Server.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure root workspace is on pythonpath
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from server.src.api.v1.alerts import router as alerts_router
from server.src.api.v1.cases import router as cases_router
from server.src.api.v1.events import router as events_router
from server.src.api.v1.ingest import router as ingest_router

MAX_INGEST_BODY_BYTES = 1_048_576  # 1 MB limit (Section 5)

app = FastAPI(
    title="Agentic SOC Platform API",
    version="0.1.0",
    description="Clean Architecture MVP for Telemetry Ingestion, Threat Detection, and Case Management.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    return await call_next(request)


# Register routers
app.include_router(ingest_router)
app.include_router(alerts_router)
app.include_router(events_router)
app.include_router(cases_router)


@app.get("/api/v1/health", tags=["Health"])
def health_check():
    """Service health check (public)."""
    return {"status": "ok", "service": "agentic-soc-server"}


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("SOC_SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_SERVER_PORT", "8000"))
    uvicorn.run("server.main:app", host=host, port=port, workers=1)
