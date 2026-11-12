"""
Database Repository Interfaces for Log Storage, Alert/Case Management,
and Agent/Operator Authentication (Synchronous).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from server.src.common.schemas import (
    AgentMetadata,
    Alert,
    AlertLevel,
    AlertStatus,
    Case,
    CaseStatus,
    ECSEvent,
    IngestBatchRequest,
    ParseStatus,
    RawLogEvent,
)


@dataclass
class BatchSaveOutcome:
    """Result of atomically inserting raw logs and parsed ECS events."""

    new_events: List[ECSEvent]
    duplicate_count: int
    unparsed_count: int
    parse_error_count: int


@dataclass
class AgentRecord:
    """Stored agent credential and status record."""

    id: str
    api_key_hash: str
    hostname: Optional[str] = None
    created_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class OperatorRecord:
    """Stored operator token and scopes record."""

    id: str
    token_hash: str
    scopes: List[str]
    created_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


ParserFn = Callable[[RawLogEvent, AgentMetadata, str, datetime], ECSEvent]


class ILogRepository(ABC):
    """Repository contract for raw and normalized log event telemetry."""

    @abstractmethod
    def save_batch_with_parser(
        self,
        batch: IngestBatchRequest,
        parser_fn: ParserFn,
        ingested_at: datetime,
    ) -> BatchSaveOutcome:
        """
        Atomically inserts raw events (ON CONFLICT DO NOTHING), parses ONLY new rows,
        and inserts normalized ECS events in a single transaction.
        """
        pass

    @abstractmethod
    def save_events(self, events: List[ECSEvent]) -> None:
        """Persists a batch of normalized ECS events (idempotent on event.id)."""
        pass

    @abstractmethod
    def find_events(self, query: Dict[str, Any], limit: int = 50) -> List[ECSEvent]:
        """Retrieves log events matching the query filter, ordered newest first."""
        pass

    @abstractmethod
    def get_by_ids(self, event_ids: List[str]) -> List[ECSEvent]:
        """Fetches events by their specific SHA-1 event.id strings."""
        pass

    @abstractmethod
    def get_raw_event(self, event_uid: str) -> Optional[Dict[str, Any]]:
        """Fetches raw event record from events_raw by event_uid."""
        pass

    @abstractmethod
    def get_max_event_ts(self) -> Optional[datetime]:
        """Returns the maximum event timestamp currently stored, or None if empty."""
        pass

    @abstractmethod
    def find_events_since(self, since: datetime) -> List[ECSEvent]:
        """Retrieves events with ts >= since, ordered ascending by ts."""
        pass

    @abstractmethod
    def list_events(
        self,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        action: Optional[str] = None,
        dataset: Optional[str] = None,
        parse_status: Optional[ParseStatus] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ECSEvent]:
        """Lists normalized events with filtering and pagination, newest first."""
        pass


class IAlertRepository(ABC):
    """Repository contract for alerts, incident cases, and agent investigation findings."""

    @abstractmethod
    def save_alert(self, alert: Alert) -> Optional[Alert]:
        """
        Persists a security alert (ON CONFLICT (alert_key) DO NOTHING).
        Returns the saved Alert with assigned id, or None if alert_key was a duplicate.
        """
        pass

    @abstractmethod
    def assign_alert_case(self, alert_id: int, case_id: int) -> None:
        """Links a saved alert to its correlated case_id."""
        pass

    @abstractmethod
    def save_case(self, case: Case) -> Case:
        """Creates or updates a case."""
        pass

    @abstractmethod
    def get_case(self, case_id: int) -> Optional[Case]:
        """Retrieves a security case (with correlated alerts) by integer ID."""
        pass

    @abstractmethod
    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        level: Optional[AlertLevel] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Case]:
        """Lists cases, optionally filtered by status, level, and source_ip."""
        pass

    @abstractmethod
    def list_alerts(
        self,
        rule_id: Optional[str] = None,
        level: Optional[AlertLevel] = None,
        status: Optional[AlertStatus] = None,
        case_id: Optional[int] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Alert]:
        """Lists alerts with filtering and pagination, newest first."""
        pass

    @abstractmethod
    def find_open_case_by_key(self, case_key: str) -> Optional[Case]:
        """Finds an existing open case matching a case_key."""
        pass

    @abstractmethod
    def list_alerts_since(self, window_end_since: datetime) -> List[Alert]:
        """Lists alerts with window_end >= window_end_since, ordered ascending."""
        pass

    @abstractmethod
    def update_case_with_agent_report(self, case_id: int, report_data: Dict[str, Any]) -> None:
        """Updates case triage verdict, confidence, and investigation report."""
        pass

    def correlate_alert_to_case(
        self,
        alert: Alert,
        case_key: str,
        source_ip: Optional[str],
        idle_timeout_seconds: int = 21_600,
    ) -> Optional[Case]:
        """
        Atomically deduplicates alert on alert_key and correlates it into an open case,
        closing an expired open case when event-time idle gap exceeds idle_timeout_seconds.
        """
        saved_alert = self.save_alert(alert)
        if saved_alert is None or saved_alert.id is None:
            return None

        level_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        activity_start = saved_alert.window_start or saved_alert.created_at
        activity_end = saved_alert.window_end or saved_alert.created_at
        now = datetime.now(timezone.utc)

        existing = self.find_open_case_by_key(case_key)
        if existing is not None:
            idle_gap = activity_end - existing.last_activity_at
            if idle_gap <= timedelta(seconds=idle_timeout_seconds):
                existing.alerts.append(saved_alert)
                if level_ranks.get(saved_alert.level.value, 0) > level_ranks.get(existing.level.value, 0):
                    existing.level = saved_alert.level
                if activity_start < existing.first_activity_at:
                    existing.first_activity_at = activity_start
                if activity_end > existing.last_activity_at:
                    existing.last_activity_at = activity_end
                existing.updated_at = now
                saved_case = self.save_case(existing)
                assert saved_case.id is not None
                self.assign_alert_case(saved_alert.id, saved_case.id)
                return saved_case

            existing.status = CaseStatus.CLOSED
            existing.updated_at = now
            self.save_case(existing)

        new_case = Case(
            case_key=case_key,
            source_ip=source_ip,
            level=saved_alert.level,
            status=CaseStatus.OPEN,
            first_activity_at=activity_start,
            last_activity_at=activity_end,
            created_at=now,
            updated_at=now,
            title=f"Security Incident: {saved_alert.title or saved_alert.rule_id}",
            alerts=[saved_alert],
        )
        saved_case = self.save_case(new_case)
        assert saved_case.id is not None
        self.assign_alert_case(saved_alert.id, saved_case.id)
        return saved_case


class IAuthRepository(ABC):
    """Repository contract for agent API keys and operator tokens."""

    @abstractmethod
    def create_agent(
        self,
        agent_id: str,
        api_key_hash: str,
        hostname: Optional[str] = None,
    ) -> AgentRecord:
        pass

    @abstractmethod
    def get_agent_by_key_hash(self, api_key_hash: str) -> Optional[AgentRecord]:
        pass

    @abstractmethod
    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        pass

    @abstractmethod
    def touch_agent_last_seen(self, agent_id: str, seen_at: datetime) -> None:
        pass

    @abstractmethod
    def revoke_agent(self, agent_id: str) -> bool:
        pass

    @abstractmethod
    def rotate_agent_key(self, agent_id: str, new_api_key_hash: str) -> bool:
        pass

    @abstractmethod
    def create_operator(
        self,
        operator_id: str,
        token_hash: str,
        scopes: List[str],
    ) -> OperatorRecord:
        pass

    @abstractmethod
    def get_operator_by_token_hash(self, token_hash: str) -> Optional[OperatorRecord]:
        pass

    @abstractmethod
    def revoke_operator(self, operator_id: str) -> bool:
        pass
