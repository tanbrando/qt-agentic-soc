"""
Synchronous PostgreSQL repositories implementing ILogRepository, IAlertRepository,
and IAuthRepository using psycopg (v3) and parameterized SQL.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg
from psycopg.types.json import Jsonb

from server.src.common.schemas import (
    AgentVerdict,
    Alert,
    AlertLevel,
    AlertStatus,
    Artifact,
    AspMetaInfo,
    Case,
    CaseStatus,
    ECSEvent,
    EcsAgentInfo,
    EcsEventMeta,
    EcsHostInfo,
    IngestBatchRequest,
    ParseStatus,
)
from server.src.repositories.base import (
    AgentRecord,
    BatchSaveOutcome,
    IAlertRepository,
    IAuthRepository,
    ILogRepository,
    OperatorRecord,
    ParserFn,
)

_SAFE_DOTTED_PATH_RE = re.compile(r"^[a-zA-Z0-9_@]+(\.[a-zA-Z0-9_@]+)*$")

_COLUMN_MAP: Dict[str, Tuple[str, str]] = {
    "hostname": ("host_name", "text"),
    "host.name": ("host_name", "text"),
    "src_ip": ("source_ip", "inet"),
    "source.ip": ("source_ip", "inet"),
    "user": ("user_name", "text"),
    "user.name": ("user_name", "text"),
    "service": ("process_name", "text"),
    "process.name": ("process_name", "text"),
    "action": ("action", "text"),
    "event.action": ("action", "text"),
    "dataset": ("dataset", "text"),
    "event.dataset": ("dataset", "text"),
    "agent.id": ("agent_id", "text"),
    "outcome": ("outcome", "text"),
    "event.outcome": ("outcome", "text"),
}


def _build_parse_error_event(
    event_uid: str,
    raw_msg: str,
    collected_at: datetime,
    ingested_at: datetime,
    batch: IngestBatchRequest,
    log_type_val: str,
) -> ECSEvent:
    dataset = "apache.access" if log_type_val == "apache" else f"linux.{log_type_val}"
    return ECSEvent(
        timestamp=collected_at,
        event=EcsEventMeta(
            id=event_uid,
            category=["host"],
            type=["info"],
            action="parse_error",
            dataset=dataset,
            original=raw_msg,
            created=collected_at,
            ingested=ingested_at,
        ),
        host=EcsHostInfo(name=batch.agent.hostname, ip=list(batch.agent.ip)),
        agent=EcsAgentInfo(id=batch.agent.id, version=batch.agent.version),
        asp=AspMetaInfo(parse_status=ParseStatus.ERROR),
    )


def _sanitize_pg_text(val: Optional[str]) -> Optional[str]:
    """PostgreSQL text/jsonb rejects NUL (0x00) bytes; replace them with U+FFFD."""
    if val is None or "\x00" not in val:
        return val
    return val.replace("\x00", "\ufffd")


def _sanitize_pg_value(obj: Any) -> Any:
    """Recursively strips NUL bytes from strings inside dicts/lists before PostgreSQL JSONB insert."""
    if isinstance(obj, str):
        return _sanitize_pg_text(obj)
    if isinstance(obj, list):
        return [_sanitize_pg_value(item) for item in obj]
    if isinstance(obj, dict):
        return {_sanitize_pg_text(k) if isinstance(k, str) else k: _sanitize_pg_value(v) for k, v in obj.items()}
    return obj


def _insert_event_row(cur: psycopg.Cursor[Any], ev: ECSEvent) -> None:
    doc = _sanitize_pg_value(ev.to_ecs_dict())
    cur.execute(
        """
        INSERT INTO events (
          event_uid, ts, ingested_at, agent_id, host_name, dataset,
          category, action, outcome, source_ip, user_name, process_name,
          parse_status, doc
        ) VALUES (
          %s, %s, %s, %s, %s, %s,
          %s, %s, %s, %s::inet, %s, %s,
          %s, %s
        )
        ON CONFLICT (event_uid) DO NOTHING
        """,
        (
            ev.event.id,
            ev.timestamp,
            ev.event.ingested,
            ev.agent.id,
            _sanitize_pg_text(ev.host.name),
            ev.event.dataset,
            [_sanitize_pg_text(c) for c in ev.event.category],
            _sanitize_pg_text(ev.event.action),
            ev.event.outcome.value if ev.event.outcome else None,
            ev.source.ip if ev.source else None,
            _sanitize_pg_text(ev.user.name) if ev.user else None,
            _sanitize_pg_text(ev.process.name) if ev.process else None,
            ev.asp.parse_status.value,
            Jsonb(doc),
        ),
    )


class PostgresLogRepository(ILogRepository):
    """PostgreSQL implementation of ILogRepository using psycopg v3."""

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def _connect(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self._db_url)

    def save_batch_with_parser(
        self,
        batch: IngestBatchRequest,
        parser_fn: ParserFn,
        ingested_at: datetime,
    ) -> BatchSaveOutcome:
        new_events: List[ECSEvent] = []
        duplicate_count = 0
        unparsed_count = 0
        parse_error_count = 0

        agent_meta = batch.agent.model_dump(mode="json")

        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    for raw_ev in batch.events:
                        event_uid = batch.event_id_for(raw_ev)
                        row = cur.execute(
                            """
                            INSERT INTO events_raw (
                              event_uid, agent_id, batch_id, log_type, message,
                              message_truncated, file_meta, agent_meta, collected_at, received_at
                            ) VALUES (
                              %s, %s, %s, %s, %s,
                              %s, %s, %s, %s, %s
                            )
                            ON CONFLICT (event_uid) DO NOTHING
                            RETURNING event_uid
                            """,
                            (
                                event_uid,
                                batch.agent.id,
                                _sanitize_pg_text(batch.batch_id),
                                raw_ev.log_type.value,
                                _sanitize_pg_text(raw_ev.message),
                                raw_ev.message_truncated,
                                Jsonb(_sanitize_pg_value(raw_ev.file.model_dump(mode="json"))),
                                Jsonb(_sanitize_pg_value(agent_meta)),
                                raw_ev.collected_at,
                                ingested_at,
                            ),
                        ).fetchone()

                        if row is None:
                            duplicate_count += 1
                            continue

                        try:
                            ecs_event = parser_fn(raw_ev, batch.agent, event_uid, ingested_at)
                        except Exception:
                            ecs_event = _build_parse_error_event(
                                event_uid=event_uid,
                                raw_msg=raw_ev.message,
                                collected_at=raw_ev.collected_at,
                                ingested_at=ingested_at,
                                batch=batch,
                                log_type_val=raw_ev.log_type.value,
                            )

                        if ecs_event.asp.parse_status == ParseStatus.UNPARSED:
                            unparsed_count += 1
                        elif ecs_event.asp.parse_status == ParseStatus.ERROR:
                            parse_error_count += 1

                        _insert_event_row(cur, ecs_event)
                        new_events.append(ecs_event)

        return BatchSaveOutcome(
            new_events=new_events,
            duplicate_count=duplicate_count,
            unparsed_count=unparsed_count,
            parse_error_count=parse_error_count,
        )

    def save_events(self, events: List[ECSEvent]) -> None:
        if not events:
            return
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    for ev in events:
                        inserted_raw = cur.execute(
                            """
                            INSERT INTO events_raw (
                              event_uid, agent_id, batch_id, log_type, message,
                              message_truncated, file_meta, agent_meta, collected_at, received_at
                            ) VALUES (
                              %s, %s, %s, %s, %s,
                              %s, %s, %s, %s, %s
                            )
                            ON CONFLICT (event_uid) DO NOTHING
                            RETURNING event_uid
                            """,
                            (
                                ev.event.id,
                                ev.agent.id,
                                None,
                                ev.event.dataset.split(".")[-1],
                                _sanitize_pg_text(ev.event.original),
                                bool(ev.asp.message_truncated),
                                Jsonb(_sanitize_pg_value({"path": ev.log.file.path if ev.log else ""})),
                                Jsonb(_sanitize_pg_value({"hostname": ev.host.name, "version": ev.agent.version})),
                                ev.event.created,
                                ev.event.ingested,
                            ),
                        ).fetchone()
                        if inserted_raw is not None:
                            _insert_event_row(cur, ev)

    def find_events(self, query: Dict[str, Any], limit: int = 50) -> List[ECSEvent]:
        clauses: List[str] = []
        params: List[Any] = []

        for key, val in query.items():
            if key in ("event_id", "event.id"):
                if isinstance(val, list):
                    clauses.append("event_uid = ANY(%s)")
                    params.append(list(val))
                else:
                    clauses.append("event_uid = %s")
                    params.append(val)
            elif key in _COLUMN_MAP:
                col, col_type = _COLUMN_MAP[key]
                if col_type == "inet":
                    clauses.append(f"{col} = %s::inet")
                else:
                    clauses.append(f"{col} = %s")
                params.append(val)
            else:
                if not _SAFE_DOTTED_PATH_RE.match(key):
                    raise ValueError(f"Invalid query field path: {key!r}")
                clauses.append("doc #>> %s = %s")
                params.append(key.split("."))
                params.append(str(val) if val is not None else None)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT doc FROM events {where_sql} ORDER BY ts DESC LIMIT %s"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [ECSEvent.model_validate(row[0]) for row in rows]

    def get_by_ids(self, event_ids: List[str]) -> List[ECSEvent]:
        if not event_ids:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT doc FROM events WHERE event_uid = ANY(%s)",
                (list(event_ids),),
            ).fetchall()
        by_id = {}
        for (doc,) in rows:
            ev = ECSEvent.model_validate(doc)
            by_id[ev.event.id] = ev
        return [by_id[eid] for eid in event_ids if eid in by_id]

    def get_raw_event(self, event_uid: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT event_uid, agent_id, batch_id, log_type, message,
                       message_truncated, file_meta, agent_meta, collected_at, received_at
                FROM events_raw
                WHERE event_uid = %s
                """,
                (event_uid,),
            ).fetchone()
        if row is None:
            return None
        return {
            "event_uid": row[0],
            "agent_id": row[1],
            "batch_id": row[2],
            "log_type": row[3],
            "message": row[4],
            "message_truncated": row[5],
            "file_meta": row[6],
            "agent_meta": row[7],
            "collected_at": row[8],
            "received_at": row[9],
        }

    def get_max_event_ts(self) -> Optional[datetime]:
        with self._connect() as conn:
            row = conn.execute("SELECT max(ts) FROM events").fetchone()
        return row[0] if row is not None else None

    def find_events_since(self, since: datetime) -> List[ECSEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT doc FROM events WHERE ts >= %s ORDER BY ts ASC, event_uid ASC",
                (since,),
            ).fetchall()
        return [ECSEvent.model_validate(row[0]) for row in rows]

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
        clauses: List[str] = []
        params: List[Any] = []
        if source_ip is not None:
            clauses.append("source_ip = %s::inet")
            params.append(source_ip)
        if user_name is not None:
            clauses.append("user_name = %s")
            params.append(user_name)
        if action is not None:
            clauses.append("action = %s")
            params.append(action)
        if dataset is not None:
            clauses.append("dataset = %s")
            params.append(dataset)
        if parse_status is not None:
            clauses.append("parse_status = %s")
            params.append(parse_status.value)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        if until is not None:
            clauses.append("ts <= %s")
            params.append(until)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT doc FROM events {where_sql} ORDER BY ts DESC, event_uid DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [ECSEvent.model_validate(row[0]) for row in rows]


class PostgresAlertRepository(IAlertRepository):
    """PostgreSQL implementation of IAlertRepository using psycopg v3."""

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def _connect(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self._db_url)

    def _row_to_alert(self, row: Tuple[Any, ...]) -> Alert:
        return Alert(
            id=row[0],
            alert_key=row[1],
            rule_id=row[2],
            title=row[3],
            level=AlertLevel(row[4]),
            created_at=row[5],
            window_start=row[6],
            window_end=row[7],
            group_key=row[8] or {},
            event_count=row[9] or 0,
            event_uids=list(row[10] or []),
            status=AlertStatus(row[11]),
            case_id=row[12],
        )

    def _row_to_case(self, row: Tuple[Any, ...], alerts: List[Alert]) -> Case:
        ai_report = row[9]
        agent_verdict = None
        agent_confidence = None
        agent_report_markdown = None
        title = None
        artifacts: List[Artifact] = []

        if isinstance(ai_report, dict):
            agent_verdict = ai_report.get("agent_verdict") or ai_report.get("verdict")
            agent_confidence = ai_report.get("agent_confidence") or ai_report.get("confidence")
            agent_report_markdown = ai_report.get("agent_report_markdown")
            for item in ai_report.get("extracted_artifacts") or ai_report.get("artifacts") or []:
                artifacts.append(Artifact(**item) if isinstance(item, dict) else item)

        if alerts:
            title = f"Security Incident: {alerts[0].title or alerts[0].rule_id}"

        return Case(
            id=row[0],
            case_key=row[1],
            source_ip=str(row[2]) if row[2] is not None else None,
            level=AlertLevel(row[3]),
            status=CaseStatus(row[4]),
            first_activity_at=row[5],
            last_activity_at=row[6],
            created_at=row[7],
            updated_at=row[8],
            ai_report=ai_report,
            ai_investigated_at=row[10],
            agent_verdict=agent_verdict,
            agent_confidence=agent_confidence,
            agent_report_markdown=agent_report_markdown,
            title=title,
            alerts=alerts,
            artifacts=artifacts,
        )

    def save_alert(self, alert: Alert) -> Optional[Alert]:
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    INSERT INTO alerts (
                      alert_key, rule_id, title, level, created_at,
                      window_start, window_end, group_key, event_count,
                      event_uids, status, case_id
                    ) VALUES (
                      %s, %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, %s
                    )
                    ON CONFLICT (alert_key) DO NOTHING
                    RETURNING id
                    """,
                    (
                        alert.alert_key,
                        alert.rule_id,
                        alert.title,
                        alert.level.value,
                        alert.created_at,
                        alert.window_start,
                        alert.window_end,
                        Jsonb(alert.group_key),
                        alert.event_count,
                        list(alert.event_uids[:200]),
                        alert.status.value,
                        alert.case_id,
                    ),
                ).fetchone()
        if row is None:
            return None
        saved = alert.model_copy(deep=True)
        saved.id = row[0]
        return saved

    def assign_alert_case(self, alert_id: int, case_id: int) -> None:
        with self._connect() as conn:
            with conn.transaction():
                conn.execute(
                    "UPDATE alerts SET case_id = %s WHERE id = %s",
                    (case_id, alert_id),
                )

    def save_case(self, case: Case) -> Case:
        ai_report_payload = case.ai_report
        if ai_report_payload is None and (
            case.agent_verdict is not None
            or case.agent_confidence is not None
            or case.agent_report_markdown is not None
            or case.artifacts
        ):
            ai_report_payload = {
                "agent_verdict": case.agent_verdict,
                "agent_confidence": case.agent_confidence,
                "agent_report_markdown": case.agent_report_markdown,
                "artifacts": [a.model_dump(mode="json") for a in case.artifacts],
            }

        with self._connect() as conn:
            with conn.transaction():
                if case.id is None:
                    row = conn.execute(
                        """
                        INSERT INTO cases (
                          case_key, source_ip, level, status,
                          first_activity_at, last_activity_at, created_at, updated_at,
                          ai_report, ai_investigated_at
                        ) VALUES (
                          %s, %s::inet, %s, %s,
                          %s, %s, %s, %s,
                          %s, %s
                        )
                        RETURNING id
                        """,
                        (
                            case.case_key,
                            case.source_ip,
                            case.level.value,
                            case.status.value,
                            case.first_activity_at,
                            case.last_activity_at,
                            case.created_at,
                            case.updated_at,
                            Jsonb(ai_report_payload) if ai_report_payload is not None else None,
                            case.ai_investigated_at,
                        ),
                    ).fetchone()
                    assert row is not None
                    saved_id = row[0]
                else:
                    conn.execute(
                        """
                        UPDATE cases
                        SET level = %s,
                            status = %s,
                            first_activity_at = %s,
                            last_activity_at = %s,
                            updated_at = %s,
                            ai_report = %s,
                            ai_investigated_at = %s
                        WHERE id = %s
                        """,
                        (
                            case.level.value,
                            case.status.value,
                            case.first_activity_at,
                            case.last_activity_at,
                            case.updated_at,
                            Jsonb(ai_report_payload) if ai_report_payload is not None else None,
                            case.ai_investigated_at,
                            case.id,
                        ),
                    )
                    saved_id = case.id

                for alert in case.alerts:
                    if alert.id is not None:
                        conn.execute(
                            "UPDATE alerts SET case_id = %s WHERE id = %s",
                            (saved_id, alert.id),
                        )

        saved = self.get_case(saved_id)
        assert saved is not None
        if case.title and not saved.title:
            saved.title = case.title
        return saved

    def _fetch_alerts_for_case_ids(
        self, conn: psycopg.Connection[Any], case_ids: List[int]
    ) -> Dict[int, List[Alert]]:
        if not case_ids:
            return {}
        rows = conn.execute(
            """
            SELECT id, alert_key, rule_id, title, level, created_at,
                   window_start, window_end, group_key, event_count,
                   event_uids, status, case_id
            FROM alerts
            WHERE case_id = ANY(%s)
            ORDER BY created_at ASC, id ASC
            """,
            (case_ids,),
        ).fetchall()
        grouped: Dict[int, List[Alert]] = {cid: [] for cid in case_ids}
        for row in rows:
            al = self._row_to_alert(row)
            if al.case_id is not None:
                grouped.setdefault(al.case_id, []).append(al)
        return grouped

    def get_case(self, case_id: int) -> Optional[Case]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, case_key, host(source_ip), level, status,
                       first_activity_at, last_activity_at, created_at, updated_at,
                       ai_report, ai_investigated_at
                FROM cases
                WHERE id = %s
                """,
                (case_id,),
            ).fetchone()
            if row is None:
                return None
            alerts_map = self._fetch_alerts_for_case_ids(conn, [case_id])
        return self._row_to_case(row, alerts_map.get(case_id, []))

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        level: Optional[AlertLevel] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Case]:
        clauses: List[str] = []
        params: List[Any] = []
        if status is not None:
            clauses.append("status = %s")
            params.append(status.value)
        if level is not None:
            clauses.append("level = %s")
            params.append(level.value)
        if source_ip is not None:
            clauses.append("source_ip = %s::inet")
            params.append(source_ip)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT id, case_key, host(source_ip), level, status,
                   first_activity_at, last_activity_at, created_at, updated_at,
                   ai_report, ai_investigated_at
            FROM cases
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            case_ids = [r[0] for r in rows]
            alerts_map = self._fetch_alerts_for_case_ids(conn, case_ids)
        return [self._row_to_case(r, alerts_map.get(r[0], [])) for r in rows]

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
        clauses: List[str] = []
        params: List[Any] = []
        if rule_id is not None:
            clauses.append("rule_id = %s")
            params.append(rule_id)
        if level is not None:
            clauses.append("level = %s")
            params.append(level.value)
        if status is not None:
            clauses.append("status = %s")
            params.append(status.value)
        if case_id is not None:
            clauses.append("case_id = %s")
            params.append(case_id)
        if since is not None:
            clauses.append("created_at >= %s")
            params.append(since)
        if until is not None:
            clauses.append("created_at <= %s")
            params.append(until)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT id, alert_key, rule_id, title, level, created_at,
                   window_start, window_end, group_key, event_count,
                   event_uids, status, case_id
            FROM alerts
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def find_open_case_by_key(self, case_key: str) -> Optional[Case]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, case_key, host(source_ip), level, status,
                       first_activity_at, last_activity_at, created_at, updated_at,
                       ai_report, ai_investigated_at
                FROM cases
                WHERE case_key = %s AND status = 'open'
                """,
                (case_key,),
            ).fetchone()
            if row is None:
                return None
            alerts_map = self._fetch_alerts_for_case_ids(conn, [row[0]])
        return self._row_to_case(row, alerts_map.get(row[0], []))

    def correlate_alert_to_case(
        self,
        alert: Alert,
        case_key: str,
        source_ip: Optional[str],
        idle_timeout_seconds: int = 21_600,
    ) -> Optional[Case]:
        """
        Atomically inserts the alert (ON CONFLICT DO NOTHING) and correlates it to an open case
        under a transaction-scoped PostgreSQL advisory lock on `case_key`, preventing races
        against `cases_one_open_per_key` even across concurrent connections/threads.
        """
        level_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        activity_start = alert.window_start or alert.created_at
        activity_end = alert.window_end or alert.created_at
        now = datetime.now(timezone.utc)

        with self._connect() as conn:
            with conn.transaction():
                alert_row = conn.execute(
                    """
                    INSERT INTO alerts (
                      alert_key, rule_id, title, level, created_at,
                      window_start, window_end, group_key, event_count,
                      event_uids, status, case_id
                    ) VALUES (
                      %s, %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, NULL
                    )
                    ON CONFLICT (alert_key) DO NOTHING
                    RETURNING id
                    """,
                    (
                        alert.alert_key,
                        alert.rule_id,
                        alert.title,
                        alert.level.value,
                        alert.created_at,
                        alert.window_start,
                        alert.window_end,
                        Jsonb(alert.group_key),
                        alert.event_count,
                        list(alert.event_uids[:200]),
                        alert.status.value,
                    ),
                ).fetchone()
                if alert_row is None:
                    return None
                alert_id = int(alert_row[0])

                conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (case_key,))
                existing_row = conn.execute(
                    """
                    SELECT id, case_key, host(source_ip), level, status,
                           first_activity_at, last_activity_at, created_at, updated_at,
                           ai_report, ai_investigated_at
                    FROM cases
                    WHERE case_key = %s AND status = 'open'
                    FOR UPDATE
                    """,
                    (case_key,),
                ).fetchone()

                target_case_id: Optional[int] = None
                if existing_row is not None:
                    existing_id = int(existing_row[0])
                    existing_level = AlertLevel(existing_row[3])
                    existing_first = existing_row[5]
                    existing_last = existing_row[6]
                    idle_gap = activity_end - existing_last

                    if idle_gap <= timedelta(seconds=idle_timeout_seconds):
                        new_level = (
                            alert.level
                            if level_ranks.get(alert.level.value, 0) > level_ranks.get(existing_level.value, 0)
                            else existing_level
                        )
                        new_first = activity_start if activity_start < existing_first else existing_first
                        new_last = activity_end if activity_end > existing_last else existing_last
                        conn.execute(
                            """
                            UPDATE cases
                            SET level = %s,
                                first_activity_at = %s,
                                last_activity_at = %s,
                                updated_at = %s
                            WHERE id = %s
                            """,
                            (new_level.value, new_first, new_last, now, existing_id),
                        )
                        target_case_id = existing_id
                    else:
                        conn.execute(
                            """
                            UPDATE cases
                            SET status = 'closed',
                                updated_at = %s
                            WHERE id = %s
                            """,
                            (now, existing_id),
                        )

                if target_case_id is None:
                    new_row = conn.execute(
                        """
                        INSERT INTO cases (
                          case_key, source_ip, level, status,
                          first_activity_at, last_activity_at, created_at, updated_at,
                          ai_report, ai_investigated_at
                        ) VALUES (
                          %s, %s::inet, %s, 'open',
                          %s, %s, %s, %s,
                          NULL, NULL
                        )
                        RETURNING id
                        """,
                        (
                            case_key,
                            source_ip,
                            alert.level.value,
                            activity_start,
                            activity_end,
                            now,
                            now,
                        ),
                    ).fetchone()
                    assert new_row is not None
                    target_case_id = int(new_row[0])

                conn.execute(
                    "UPDATE alerts SET case_id = %s WHERE id = %s",
                    (target_case_id, alert_id),
                )

                case_row = conn.execute(
                    """
                    SELECT id, case_key, host(source_ip), level, status,
                           first_activity_at, last_activity_at, created_at, updated_at,
                           ai_report, ai_investigated_at
                    FROM cases
                    WHERE id = %s
                    """,
                    (target_case_id,),
                ).fetchone()
                assert case_row is not None
                alerts_map = self._fetch_alerts_for_case_ids(conn, [target_case_id])
        return self._row_to_case(case_row, alerts_map.get(target_case_id, []))

    def list_alerts_since(self, window_end_since: datetime) -> List[Alert]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, alert_key, rule_id, title, level, created_at,
                       window_start, window_end, group_key, event_count,
                       event_uids, status, case_id
                FROM alerts
                WHERE window_end >= %s
                ORDER BY window_end ASC, id ASC
                """,
                (window_end_since,),
            ).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def update_case_with_agent_report(self, case_id: int, report_data: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        existing = self.get_case(case_id)
        if existing is None:
            raise ValueError(f"Case with ID {case_id} not found")

        payload: Dict[str, Any] = dict(existing.ai_report or {})
        if "ai_report" in report_data and isinstance(report_data["ai_report"], dict):
            payload.update(report_data["ai_report"])
        if "agent_verdict" in report_data and report_data["agent_verdict"] is not None:
            v = report_data["agent_verdict"]
            payload["agent_verdict"] = v.value if isinstance(v, AgentVerdict) else str(v)
        if "agent_confidence" in report_data and report_data["agent_confidence"] is not None:
            payload["agent_confidence"] = float(report_data["agent_confidence"])
        if "agent_report_markdown" in report_data and report_data["agent_report_markdown"] is not None:
            payload["agent_report_markdown"] = str(report_data["agent_report_markdown"])

        raw_artifacts = report_data.get("artifacts") or report_data.get("extracted_artifacts") or []
        if raw_artifacts:
            serialized = []
            for item in raw_artifacts:
                art = item if isinstance(item, Artifact) else Artifact(**item)
                serialized.append(art.model_dump(mode="json"))
            payload["extracted_artifacts"] = serialized

        with self._connect() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    UPDATE cases
                    SET ai_report = %s,
                        ai_investigated_at = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (Jsonb(payload), now, now, case_id),
                )


class PostgresAuthRepository(IAuthRepository):
    """PostgreSQL implementation of IAuthRepository for agents and operators."""

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def _connect(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self._db_url)

    def create_agent(
        self,
        agent_id: str,
        api_key_hash: str,
        hostname: Optional[str] = None,
    ) -> AgentRecord:
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    INSERT INTO agents (id, api_key_hash, hostname)
                    VALUES (%s, %s, %s)
                    RETURNING id, api_key_hash, hostname, created_at, revoked_at, last_seen
                    """,
                    (agent_id, api_key_hash, hostname),
                ).fetchone()
        assert row is not None
        return AgentRecord(*row)

    def get_agent_by_key_hash(self, api_key_hash: str) -> Optional[AgentRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, api_key_hash, hostname, created_at, revoked_at, last_seen
                FROM agents
                WHERE api_key_hash = %s AND revoked_at IS NULL
                """,
                (api_key_hash,),
            ).fetchone()
        return AgentRecord(*row) if row is not None else None

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, api_key_hash, hostname, created_at, revoked_at, last_seen
                FROM agents
                WHERE id = %s
                """,
                (agent_id,),
            ).fetchone()
        return AgentRecord(*row) if row is not None else None

    def touch_agent_last_seen(self, agent_id: str, seen_at: datetime) -> None:
        with self._connect() as conn:
            with conn.transaction():
                conn.execute(
                    "UPDATE agents SET last_seen = %s WHERE id = %s",
                    (seen_at, agent_id),
                )

    def revoke_agent(self, agent_id: str) -> bool:
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    "UPDATE agents SET revoked_at = now() WHERE id = %s RETURNING id",
                    (agent_id,),
                ).fetchone()
        return row is not None

    def rotate_agent_key(self, agent_id: str, new_api_key_hash: str) -> bool:
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    UPDATE agents
                    SET api_key_hash = %s, revoked_at = NULL
                    WHERE id = %s
                    RETURNING id
                    """,
                    (new_api_key_hash, agent_id),
                ).fetchone()
        return row is not None

    def create_operator(
        self,
        operator_id: str,
        token_hash: str,
        scopes: List[str],
    ) -> OperatorRecord:
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    """
                    INSERT INTO operators (id, token_hash, scopes)
                    VALUES (%s, %s, %s)
                    RETURNING id, token_hash, scopes, created_at, revoked_at
                    """,
                    (operator_id, token_hash, list(scopes)),
                ).fetchone()
        assert row is not None
        return OperatorRecord(
            id=row[0],
            token_hash=row[1],
            scopes=list(row[2]),
            created_at=row[3],
            revoked_at=row[4],
        )

    def get_operator_by_token_hash(self, token_hash: str) -> Optional[OperatorRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, token_hash, scopes, created_at, revoked_at
                FROM operators
                WHERE token_hash = %s AND revoked_at IS NULL
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        return OperatorRecord(
            id=row[0],
            token_hash=row[1],
            scopes=list(row[2]),
            created_at=row[3],
            revoked_at=row[4],
        )

    def revoke_operator(self, operator_id: str) -> bool:
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    "UPDATE operators SET revoked_at = now() WHERE id = %s RETURNING id",
                    (operator_id,),
                ).fetchone()
        return row is not None

