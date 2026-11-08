"""
Main FastAPI Entrypoint for the Agentic SOC Platform Server.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Prioritize standard Python site-packages if present
global_site_packages = "C:\\Python312\\Lib\\site-packages"
if Path(global_site_packages).exists():
    if global_site_packages in sys.path:
        sys.path.remove(global_site_packages)
    sys.path.insert(0, global_site_packages)

# Ensure root workspace is on pythonpath
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.src.api.v1.cases import router as cases_router
from server.src.api.v1.ingest import router as ingest_router

app = FastAPI(
    title="Agentic SOC Platform API",
    version="0.1.0",
    description="Clean Architecture MVP for Telemetry Ingestion, Threat Detection, and AI Agent Investigation.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(ingest_router)
app.include_router(cases_router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check."""
    return {"status": "ok", "service": "agentic-soc-server"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)
