"""
Ingestion Service Orchestrator (Synchronous).
Coordinates atomic raw+parsed storage, post-commit rule detection under lock,
and alert/case correlation.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from server.src.common.schemas import (
    Alert,
    Case,
    CaseStatus,
    IngestBatchRequest,
    IngestBatchResponse,
)
from server.src.engine.base import RuleEngine
from server.src.parsers.base import ParserRegistry
from server.src.repositories.base import IAlertRepository, ILogRepository

logger = logging.getLogger(__name__)

_LEVEL_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class IngestionService:
    """
    Core synchronous pipeline service:
    1. Transactionally inserts raw events into events_raw (ON CONFLICT DO NOTHING),
       parses only newly inserted rows, and stores normalized ECSEvent into events.
    2. After commit, sorts newly ingested events by timestamp and runs RuleEngine
       under a shared threading.Lock. Engine errors are logged and never fail ingest.
    3. Saves non-duplicate alerts and correlates them to open cases.
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        alert_repository: IAlertRepository,
        rule_engine: RuleEngine,
        engine_lock: Optional[threading.Lock] = None,
        default_timezone: str = "Asia/Ho_Chi_Minh",
        future_tolerance_seconds: int = 300,
        case_idle_timeout_seconds: int = 21_600,
    ) -> None:
        self.log_repo = log_repository
        self.alert_repo = alert_repository
        self.rule_engine = rule_engine
        self._engine_lock = engine_lock or threading.Lock()
        self._default_timezone = default_timezone
        self._future_tolerance_seconds = future_tolerance_seconds
        self._case_idle_timeout_seconds = case_idle_timeout_seconds

    def ingest_batch(self, batch: IngestBatchRequest) -> IngestBatchResponse:
        """Processes an incoming batch of raw log events."""
        ingested_at = datetime.now(timezone.utc)

        def _parse_with_server_cfg(raw_ev, agent, uid, ts_ingested):
            return ParserRegistry.parse_raw_event(
                raw_event=raw_ev,
                agent=agent,
                event_uid=uid,
                ingested_at=ts_ingested,
                default_timezone=self._default_timezone,
                future_tolerance_seconds=self._future_tolerance_seconds,
            )

        # 1. Atomic raw-first insert, deduplication, parse, and events insert
        outcome = self.log_repo.save_batch_with_parser(
            batch=batch,
            parser_fn=_parse_with_server_cfg,
            ingested_at=ingested_at,
        )

        # 2. Post-commit Rule Engine evaluation on new events only, sorted by ts
        if outcome.new_events:
            ordered_events = sorted(outcome.new_events, key=lambda ev: ev.timestamp)
            try:
                with self._engine_lock:
                    alerts = self.rule_engine.evaluate_batch(ordered_events)
                    for alert in alerts:
                        self._persist_and_correlate_alert(alert)
            except Exception:
                logger.exception(
                    "Post-commit rule evaluation failed for batch_id=%s",
                    batch.batch_id,
                )

        return IngestBatchResponse(
            accepted=len(outcome.new_events),
            duplicates=outcome.duplicate_count,
            unparsed=outcome.unparsed_count,
            parse_errors=outcome.parse_error_count,
        )

    def _derive_case_key(self, alert: Alert) -> tuple[str, Optional[str]]:
        src_ip = alert.group_key.get("source.ip")
        if src_ip:
            return f"ip:{src_ip}", str(src_ip)
        host_name = alert.group_key.get("host.name")
        user_name = alert.group_key.get("user.name")
        if host_name and user_name:
            return f"host:{host_name}|user:{user_name}", None
        return f"alert:{alert.alert_key}", None

    def _persist_and_correlate_alert(self, alert: Alert) -> Optional[Case]:
        """Inserts alert (ON CONFLICT DO NOTHING) and correlates to an open case with idle timeout."""
        case_key, src_ip = self._derive_case_key(alert)
        return self.alert_repo.correlate_alert_to_case(
            alert=alert,
            case_key=case_key,
            source_ip=src_ip,
            idle_timeout_seconds=self._case_idle_timeout_seconds,
        )
