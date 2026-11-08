"""
Case Management & Agent Investigation API v1 Router.
"""

from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from server.src.agent.base import IAgentInvestigator
from server.src.api.dependencies import get_agent_investigator, get_alert_repository
from server.src.common.schemas import AlertStatus, Case
from server.src.repositories.base import IAlertRepository

router = APIRouter(prefix="/api/v1/cases", tags=["Cases"])


@router.get("", response_model=List[Case])
async def list_cases(
    status_filter: Optional[AlertStatus] = None,
    repo: IAlertRepository = Depends(get_alert_repository),
) -> List[Case]:
    """Lists security cases, optionally filtered by status."""
    return await repo.list_cases(status=status_filter)


@router.get("/{case_id}", response_model=Case)
async def get_case(
    case_id: UUID,
    repo: IAlertRepository = Depends(get_alert_repository),
) -> Case:
    """Retrieves full case details by UUID."""
    case = await repo.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found",
        )
    return case


@router.post("/{case_id}/investigate", response_model=Case)
async def trigger_case_investigation(
    case_id: UUID,
    repo: IAlertRepository = Depends(get_alert_repository),
    investigator: IAgentInvestigator = Depends(get_agent_investigator),
) -> Case:
    """
    Triggers an autonomous AI agent investigation on the specified case.
    Gathers evidence, enriches threat intel, assigns verdict, and writes investigation report.
    """
    case = await repo.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found",
        )

    # Run agent triage and investigation
    report_update = await investigator.investigate_case(case)

    # Persist agent findings
    await repo.update_case_with_agent_report(
        case_id=case_id,
        report_data=report_update.model_dump(),
    )

    # Return refreshed case
    updated_case = await repo.get_case(case_id)
    assert updated_case is not None
    return updated_case

