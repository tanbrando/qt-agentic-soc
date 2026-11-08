"""
In-Memory implementations of ILogRepository and IAlertRepository for testing,
local development, and initial MVP execution without external DB dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from server.src.common.schemas import (
    AgentVerdict,
    Alert,
    AlertStatus,
    Artifact,
    Case,
    LogEventEnvelope,
)
from server.src.repositories.base import IAlertRepository, ILogRepository


class InMemoryLogRepository(ILogRepository):
    """In-memory store for log events."""

    def __init__(self) -> None:
        self._events: List[LogEventEnvelope] = []
        self._by_id: Dict[UUID, LogEventEnvelope] = {}

    async def save_events(self, events: List[LogEventEnvelope]) -> None:
        for ev in events:
            self._events.append(ev)
            self._by_id[ev.event_id] = ev

    async def find_events(self, query: Dict[str, Any], limit: int = 50) -> List[LogEventEnvelope]:
        results: List[LogEventEnvelope] = []
        for ev in reversed(self._events):
            matches = True
            for k, v in query.items():
                if k == "event_id":
                    if isinstance(v, list):
                        if ev.event_id not in v:
                            matches = False
                            break
                    elif ev.event_id != v:
                        matches = False
                        break
                elif k == "hostname" and ev.hostname != v:
                    matches = False
                    break
                elif k == "log_type" and ev.log_type.value != v and ev.log_type != v:
                    matches = False
                    break
                elif k.startswith("fields."):
                    field_name = k.split(".", 1)[1]
                    if ev.fields.get(field_name) != v:
                        matches = False
                        break
                elif k in ev.fields and ev.fields.get(k) != v:
                    matches = False
                    break
            if matches:
                results.append(ev)
                if len(results) >= limit:
                    break
        return results

    async def get_by_ids(self, event_ids: List[UUID]) -> List[LogEventEnvelope]:
        return [self._by_id[eid] for eid in event_ids if eid in self._by_id]


class InMemoryAlertRepository(IAlertRepository):
    """In-memory store for alerts and cases."""

    def __init__(self) -> None:
        self._alerts: Dict[UUID, Alert] = {}
        self._cases: Dict[UUID, Case] = {}
        self._dedup_map: Dict[str, UUID] = {}

    async def save_alert(self, alert: Alert) -> None:
        self._alerts[alert.alert_id] = alert

    async def save_case(self, case: Case) -> None:
        self._cases[case.case_id] = case
        if case.alerts:
            for alert in case.alerts:
                if alert.dedup_key:
                    self._dedup_map[alert.dedup_key] = case.case_id

    async def get_case(self, case_id: UUID) -> Optional[Case]:
        return self._cases.get(case_id)

    async def list_cases(self, status: Optional[AlertStatus] = None) -> List[Case]:
        cases = list(self._cases.values())
        if status:
            cases = [c for c in cases if c.status == status]
        return sorted(cases, key=lambda c: c.created_at, reverse=True)

    async def find_case_by_dedup_key(self, dedup_key: str) -> Optional[Case]:
        case_id = self._dedup_map.get(dedup_key)
        if case_id and case_id in self._cases:
            case = self._cases[case_id]
            if case.status in (AlertStatus.OPEN, AlertStatus.INVESTIGATING):
                return case
        return None

    async def update_case_with_agent_report(self, case_id: UUID, report_data: Dict[str, Any]) -> None:
        case = self._cases.get(case_id)
        if not case:
            raise ValueError(f"Case with ID {case_id} not found")

        if "agent_verdict" in report_data:
            verdict = report_data["agent_verdict"]
            case.agent_verdict = verdict.value if isinstance(verdict, AgentVerdict) else str(verdict)
        if "agent_confidence" in report_data:
            case.agent_confidence = float(report_data["agent_confidence"])
        if "agent_report_markdown" in report_data:
            case.agent_report_markdown = str(report_data["agent_report_markdown"])
        if "artifacts" in report_data:
            for item in report_data["artifacts"]:
                art = item if isinstance(item, Artifact) else Artifact(**item)
                if not any(a.value == art.value and a.artifact_type == art.artifact_type for a in case.artifacts):
                    case.artifacts.append(art)
        elif "extracted_artifacts" in report_data:
            for item in report_data["extracted_artifacts"]:
                art = item if isinstance(item, Artifact) else Artifact(**item)
                if not any(a.value == art.value and a.artifact_type == art.artifact_type for a in case.artifacts):
                    case.artifacts.append(art)

        case.status = AlertStatus.RESOLVED if case.agent_verdict == AgentVerdict.FALSE_POSITIVE.value else AlertStatus.INVESTIGATING
        case.updated_at = datetime.now(timezone.utc)
