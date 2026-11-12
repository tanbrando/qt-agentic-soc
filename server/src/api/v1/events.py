"""
Normalized Event Query API v1 Router (Synchronous).
Protected by operator Bearer tokens with 'read' scope.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Query

from server.src.api.dependencies import (
    get_log_repository,
    require_operator_scope,
    validate_optional_ip,
)
from server.src.common.schemas import ECSEvent, ParseStatus
from server.src.repositories.base import ILogRepository, OperatorRecord

router = APIRouter(prefix="/api/v1/events", tags=["Events"])


@router.get("", response_model=List[ECSEvent], response_model_by_alias=True)
def list_events(
    source_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    action: Optional[str] = None,
    dataset: Optional[str] = None,
    parse_status: Optional[ParseStatus] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _operator: OperatorRecord = Depends(require_operator_scope("read")),
    repo: ILogRepository = Depends(get_log_repository),
) -> List[ECSEvent]:
    """Lists normalized ECS events filtered by IP, user, action, dataset, parse_status, and time range."""
    norm_ip = validate_optional_ip(source_ip)
    return repo.list_events(
        source_ip=norm_ip,
        user_name=user_name,
        action=action,
        dataset=dataset,
        parse_status=parse_status,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )

