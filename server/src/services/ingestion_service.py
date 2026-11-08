"""
Ingestion Service Orchestrator.
Coordinates log parsing/enrichment, storage, rule detection, and incident case correlation.
"""

from __future__ import annotations

from typing import List
from uuid import UUID, uuid4

from server.src.common.schemas import (
    Alert,
    AlertStatus,
    Case,
    IngestBatchRequest,
    IngestBatchResponse,
    LogEventEnvelope,
)
from server.src.engine.base import RuleEngine
from server.src.parsers.base import ParserRegistry
from server.src.repositories.base import IAlertRepository, ILogRepository


class IngestionService:
    """
    Core pipeline service that:
    1. Normalizes raw logs via ParserRegistry (Hybrid parsing fallback).
    2. Persists events to ILogRepository.
    3. Feeds normalized events to the RuleEngine.
    4. Correlates firing Alerts into security Cases.
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        alert_repository: IAlertRepository,
        rule_engine: RuleEngine,
    ) -> None:
        self.log_repo = log_repository
        self.alert_repo = alert_repository
        self.rule_engine = rule_engine

    async def ingest_batch(self, batch: IngestBatchRequest) -> IngestBatchResponse:
        """Processes an incoming batch of log envelopes."""
        processed_events: List[LogEventEnvelope] = []

        # 1. Normalization & parsing fallback
        for event in batch.events:
            if not event.fields:
                event = ParserRegistry.parse_or_fallback(event)
            processed_events.append(event)

        # 2. Persist raw/normalized events
        await self.log_repo.save_events(processed_events)

        # 3. Detection evaluation
        alerts = self.rule_engine.evaluate_batch(processed_events)

        # 4. Alert & Case Correlation
        affected_case_ids: List[UUID] = []
        for alert in alerts:
            await self.alert_repo.save_alert(alert)
            case = await self._correlate_alert_to_case(alert)
            if case.case_id not in affected_case_ids:
                affected_case_ids.append(case.case_id)

        return IngestBatchResponse(
            accepted_count=len(processed_events),
            alerts_generated=len(alerts),
            case_ids=affected_case_ids,
            status="ok",
        )

    async def _correlate_alert_to_case(self, alert: Alert) -> Case:
        """Groups alert into an existing open case matching dedup_key, or creates a new one."""
        if alert.dedup_key:
            existing_case = await self.alert_repo.find_case_by_dedup_key(alert.dedup_key)
            if existing_case:
                existing_case.alerts.append(alert)
                # Keep highest severity
                severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                if severity_ranks.get(alert.severity.value, 0) > severity_ranks.get(existing_case.severity.value, 0):
                    existing_case.severity = alert.severity
                await self.alert_repo.save_case(existing_case)
                return existing_case

        # Create new Case
        new_case = Case(
            case_id=uuid4(),
            title=f"Security Incident: {alert.rule_name} on {alert.hostname}",
            severity=alert.severity,
            status=AlertStatus.OPEN,
            alerts=[alert],
        )
        await self.alert_repo.save_case(new_case)
        return new_case

