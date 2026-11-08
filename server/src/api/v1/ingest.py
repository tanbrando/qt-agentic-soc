"""
Ingest API v1 Router.
Receives telemetry batches from endpoint agents.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from server.src.api.dependencies import get_ingestion_service
from server.src.common.schemas import IngestBatchRequest, IngestBatchResponse
from server.src.services.ingestion_service import IngestionService

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])


@router.post("/logs", response_model=IngestBatchResponse, status_code=status.HTTP_200_OK)
async def ingest_logs(
    batch: IngestBatchRequest,
    service: IngestionService = Depends(get_ingestion_service),
) -> IngestBatchResponse:
    """
    Ingests an ordered batch of LogEventEnvelopes from an endpoint agent.
    Runs normalization, log persistence, and rule detection pipeline.
    """
    try:
        response = await service.ingest_batch(batch)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process ingestion batch: {str(e)}",
        )

