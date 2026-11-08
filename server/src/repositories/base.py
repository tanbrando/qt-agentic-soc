"""
Database Repository Interfaces for Log Storage and Alert/Case Management.
Decouples domain business logic from specific persistence backends (PostgreSQL, Elasticsearch, MongoDB, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from uuid import UUID

from server.src.common.schemas import Alert, AlertStatus, Case, LogEventEnvelope


class ILogRepository(ABC):
    """Repository contract for raw and normalized log event telemetry."""

    @abstractmethod
    async def save_events(self, events: List[LogEventEnvelope]) -> None:
        """Persists a batch of log event envelopes."""
        pass

    @abstractmethod
    async def find_events(self, query: Dict[str, Any], limit: int = 50) -> List[LogEventEnvelope]:
        """
        Retrieves log events matching the query filter.
        Example query: {"event_id": [...]} or {"hostname": "web-01", "fields.src_ip": "1.2.3.4"}
        """
        pass

    @abstractmethod
    async def get_by_ids(self, event_ids: List[UUID]) -> List[LogEventEnvelope]:
        """Fetches events by their specific event UUIDs."""
        pass


class IAlertRepository(ABC):
    """Repository contract for alerts, incident cases, and AI agent investigation findings."""

    @abstractmethod
    async def save_alert(self, alert: Alert) -> None:
        """Saves a security alert produced by the detection engine."""
        pass

    @abstractmethod
    async def save_case(self, case: Case) -> None:
        """Creates or updates a case."""
        pass

    @abstractmethod
    async def get_case(self, case_id: UUID) -> Optional[Case]:
        """Retrieves a security case by its UUID."""
        pass

    @abstractmethod
    async def list_cases(self, status: Optional[AlertStatus] = None) -> List[Case]:
        """Lists cases, optionally filtered by status."""
        pass

    @abstractmethod
    async def find_case_by_dedup_key(self, dedup_key: str) -> Optional[Case]:
        """Finds an existing open case matching a deduplication key."""
        pass

    @abstractmethod
    async def update_case_with_agent_report(self, case_id: UUID, report_data: Dict[str, Any]) -> None:
        """Updates case triage verdict, confidence, and markdown investigation report."""
        pass

