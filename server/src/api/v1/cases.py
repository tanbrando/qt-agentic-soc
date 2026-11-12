"""
Case Management & Agent Investigation API v1 Router (Synchronous).
Protected by scoped operator Bearer tokens.
"""

from __future__ import annotations

from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from server.src.agent.base import IAgentInvestigator
from server.src.api.dependencies import (
    get_agent_investigator,
    get_alert_repository,
    require_operator_scope,
    validate_optional_ip,
)
from server.src.common.schemas import AlertLevel, Case, CaseStatus
from server.src.repositories.base import IAlertRepository, OperatorRecord

router = APIRouter(prefix="/api/v1/cases", tags=["Cases"])


@router.get("", response_model=List[Case])
def list_cases(
    status_filter: Annotated[Optional[CaseStatus], Query(alias="status")] = None,
    level: Optional[AlertLevel] = None,
    source_ip: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _operator: OperatorRecord = Depends(require_operator_scope("read")),
    repo: IAlertRepository = Depends(get_alert_repository),
) -> List[Case]:
    """Lists security cases, optionally filtered by status, level, and source_ip."""
    norm_ip = validate_optional_ip(source_ip)
    return repo.list_cases(
        status=status_filter,
        level=level,
        source_ip=norm_ip,
        limit=limit,
        offset=offset,
    )


@router.get("/{case_id}", response_model=Case)
def get_case(
    case_id: int,
    _operator: OperatorRecord = Depends(require_operator_scope("read")),
    repo: IAlertRepository = Depends(get_alert_repository),
) -> Case:
    """Retrieves full case details by integer ID."""
    case = repo.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found",
        )
    return case


@router.post("/{case_id}/investigate", response_model=Case)
def trigger_case_investigation(
    case_id: int,
    _operator: OperatorRecord = Depends(require_operator_scope("investigate")),
    repo: IAlertRepository = Depends(get_alert_repository),
    investigator: IAgentInvestigator = Depends(get_agent_investigator),
) -> Case:
    """
    Triggers an autonomous AI agent investigation on the specified case.
    """
    case = repo.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found",
        )

    report_update = investigator.investigate_case(case)
    repo.update_case_with_agent_report(
        case_id=case_id,
        report_data=report_update.model_dump(),
    )

    updated_case = repo.get_case(case_id)
    assert updated_case is not None
    return updated_case
