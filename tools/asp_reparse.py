"""
Re-parse tool rebuilding the `events` table from immutable `events_raw` rows (Section 8.5).
Never modifies `events_raw`.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

import psycopg
from psycopg.types.json import Jsonb

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Ensure parsers are registered
import server.src.parsers  # noqa: F401
from server.src.common.config import ServerConfig, parse_duration_seconds
from server.src.common.schemas import ECSEvent
from server.src.engine.base import RuleEngine
from server.src.parsers.base import parse
from server.src.repositories.base import IAlertRepository
from server.src.repositories.postgres import PostgresAlertRepository
from server.src.services.ingestion_service import IngestionService
from tools.asp_migrate import get_db_url


@dataclass
class ReparseStats:
    scanned: int
    changed: int
    updated: int
    alerts_generated: int = 0


def _parse_cli_dt(val: str) -> datetime:
    dt = datetime.fromisoformat(val)
    return dt


def reparse_events(
    db_url: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    dry_run: bool = False,
    replay_rules: bool = False,
    rule_engine: Optional[RuleEngine] = None,
    alert_repo: Optional[IAlertRepository] = None,
) -> ReparseStats:
    """
    Reads `events_raw`, re-runs pure `parse()` using stored `collected_at` & `agent_meta`,
    and upserts normalized rows into `events`. Never writes to `events_raw`.
    """
    conn_url = get_db_url(db_url)
    cfg = ServerConfig.from_env()
    future_tol = parse_duration_seconds(cfg.future_ts_tolerance)

    clauses: List[str] = []
    params: List[Any] = []
    if since is not None:
        clauses.append("r.collected_at >= %s")
        params.append(since)
    if until is not None:
        clauses.append("r.collected_at <= %s")
        params.append(until)
    if agent_id is not None:
        clauses.append("r.agent_id = %s")
        params.append(agent_id)
    if status is not None:
        clauses.append("e.parse_status = %s")
        params.append(status)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query_sql = f"""
        SELECT r.event_uid, r.agent_id, r.log_type, r.message, r.message_truncated,
               r.file_meta, r.agent_meta, r.collected_at, r.received_at,
               e.parse_status, e.doc
        FROM events_raw r
        LEFT JOIN events e ON e.event_uid = r.event_uid
        {where_sql}
        ORDER BY r.collected_at ASC, r.event_uid ASC
    """

    scanned = 0
    changed = 0
    updated = 0
    reparsed_for_rules: List[ECSEvent] = []

    with psycopg.connect(conn_url) as conn:
        rows = conn.execute(query_sql, params).fetchall()

        with conn.transaction():
            for row in rows:
                scanned += 1
                (
                    event_uid,
                    row_agent_id,
                    log_type,
                    message,
                    message_truncated,
                    file_meta,
                    agent_meta,
                    collected_at,
                    received_at,
                    existing_status,
                    existing_doc,
                ) = row

                meta = {
                    "event_uid": event_uid,
                    "collected_at": collected_at,
                    "received_at": received_at,
                    "agent": {"id": row_agent_id, **(agent_meta or {})},
                    "file": file_meta or {},
                    "message_truncated": bool(message_truncated),
                    "default_timezone": cfg.default_timezone,
                    "future_tolerance_seconds": future_tol,
                }
                ecs_ev = parse(log_type, message, meta)
                new_doc = ecs_ev.to_ecs_dict()

                if existing_status != ecs_ev.asp.parse_status.value or existing_doc != new_doc:
                    changed += 1
                    if not dry_run:
                        conn.execute(
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
                            ON CONFLICT (event_uid) DO UPDATE SET
                              ts = EXCLUDED.ts,
                              host_name = EXCLUDED.host_name,
                              dataset = EXCLUDED.dataset,
                              category = EXCLUDED.category,
                              action = EXCLUDED.action,
                              outcome = EXCLUDED.outcome,
                              source_ip = EXCLUDED.source_ip,
                              user_name = EXCLUDED.user_name,
                              process_name = EXCLUDED.process_name,
                              parse_status = EXCLUDED.parse_status,
                              doc = EXCLUDED.doc
                            """,
                            (
                                ecs_ev.event.id,
                                ecs_ev.timestamp,
                                ecs_ev.event.ingested,
                                ecs_ev.agent.id,
                                ecs_ev.host.name,
                                ecs_ev.event.dataset,
                                ecs_ev.event.category,
                                ecs_ev.event.action,
                                ecs_ev.event.outcome.value if ecs_ev.event.outcome else None,
                                ecs_ev.source.ip if ecs_ev.source else None,
                                ecs_ev.user.name if ecs_ev.user else None,
                                ecs_ev.process.name if ecs_ev.process else None,
                                ecs_ev.asp.parse_status.value,
                                Jsonb(new_doc),
                            ),
                        )
                        updated += 1
                if replay_rules:
                    reparsed_for_rules.append(ecs_ev)

    alerts_generated = 0
    if replay_rules and not dry_run and reparsed_for_rules and rule_engine is not None:
        target_alert_repo = alert_repo or PostgresAlertRepository(conn_url)
        helper_svc = IngestionService(
            log_repository=None,  # type: ignore[arg-type]
            alert_repository=target_alert_repo,
            rule_engine=rule_engine,
        )
        ordered = sorted(reparsed_for_rules, key=lambda e: e.timestamp)
        alerts = rule_engine.evaluate_batch(ordered)
        for alert in alerts:
            if helper_svc._persist_and_correlate_alert(alert) is not None:
                alerts_generated += 1

    return ReparseStats(
        scanned=scanned,
        changed=changed,
        updated=updated,
        alerts_generated=alerts_generated,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Re-parse events_raw into events.")
    parser.add_argument("--db-url", default=None)
    parser.add_argument("--since", type=_parse_cli_dt, default=None)
    parser.add_argument("--until", type=_parse_cli_dt, default=None)
    parser.add_argument("--agent", default=None, dest="agent_id")
    parser.add_argument("--status", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--replay-rules", action="store_true")
    args = parser.parse_args(argv)

    stats = reparse_events(
        db_url=args.db_url,
        since=args.since,
        until=args.until,
        agent_id=args.agent_id,
        status=args.status,
        dry_run=args.dry_run,
        replay_rules=args.replay_rules,
    )
    print(
        f"scanned={stats.scanned} changed={stats.changed} "
        f"updated={stats.updated} alerts={stats.alerts_generated}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

