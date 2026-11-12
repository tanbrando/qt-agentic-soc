"""
Ingest API v1 Router (Synchronous).
Receives telemetry batches from endpoint agents with Bearer API key auth,
agent.id verification, batch limits (500 events / 1 MB), and rate limiting.
"""

from __future__ import annotations

from datetime import datetime, timezone

import psycopg
from fastapi import APIRouter, Depends, HTTPException, status

from server.src.api.dependencies import (
    get_auth_repository,
    get_ingestion_service,
    get_rate_limiter,
    require_agent_auth,
)
from server.src.common.schemas import IngestBatchRequest, IngestBatchResponse
from server.src.common.security import InMemoryRateLimiter
from server.src.repositories.base import AgentRecord, IAuthRepository
from server.src.services.ingestion_service import IngestionService

MAX_EVENTS_PER_BATCH = 500

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])


@router.post("/logs", response_model=IngestBatchResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_logs(
    batch: IngestBatchRequest,
    auth_agent: AgentRecord = Depends(require_agent_auth),
    auth_repo: IAuthRepository = Depends(get_auth_repository),
    rate_limiter: InMemoryRateLimiter = Depends(get_rate_limiter),
    service: IngestionService = Depends(get_ingestion_service),
) -> IngestBatchResponse:
    """
    Ingests a batch of raw log events from an authenticated endpoint agent.
    """
    if batch.agent.id != auth_agent.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="agent.id does not match API key owner",
        )

    if len(batch.events) > MAX_EVENTS_PER_BATCH:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Batch exceeds maximum of {MAX_EVENTS_PER_BATCH} events",
        )

    if not rate_limiter.allow(auth_agent.id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Agent ingest rate limit exceeded",
        )

    try:
        auth_repo.touch_agent_last_seen(auth_agent.id, datetime.now(timezone.utc))
        return service.ingest_batch(batch)
    except psycopg.OperationalError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process ingestion batch: {str(exc)}",
        ) from exc
