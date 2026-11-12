"""
Alert Query API v1 Router (Synchronous).
Protected by operator Bearer tokens with 'read' scope.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Query

from server.src.api.dependencies import get_alert_repository, require_operator_scope
from server.src.common.schemas import Alert, AlertLevel, AlertStatus
from server.src.repositories.base import IAlertRepository, OperatorRecord

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("", response_model=List[Alert])
def list_alerts(
    rule_id: Optional[str] = None,
    level: Optional[AlertLevel] = None,
    status_filter: Annotated[Optional[AlertStatus], Query(alias="status")] = None,
    case_id: Annotated[Optional[int], Query(ge=1)] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _operator: OperatorRecord = Depends(require_operator_scope("read")),
    repo: IAlertRepository = Depends(get_alert_repository),
) -> List[Alert]:
    """Lists alerts filtered by rule_id, level, status, case_id, and time range."""
    return repo.list_alerts(
        rule_id=rule_id,
        level=level,
        status=status_filter,
        case_id=case_id,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
