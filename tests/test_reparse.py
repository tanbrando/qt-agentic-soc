"""
Tests for tools/asp_reparse.py (P2.3).
Live DB tests run against ASP_DB_URL when set and clean up test rows.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import psycopg
from psycopg.types.json import Jsonb
import pytest

from server.src.common.schemas import compute_event_id
from server.src.common.security import hash_secret
from server.src.repositories.postgres import PostgresAuthRepository, PostgresLogRepository
from tools.asp_migrate import run_migrations
from tools.asp_reparse import reparse_events


def test_reparse_updates_events_and_leaves_events_raw_untouched():
    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping PostgreSQL reparse test")

    run_migrations(db_url=db_url)
    agent_id = "reparse-test-agent"
    raw_msg = "Nov 10 08:30:00 lab-host sshd[1234]: Failed password for root from 198.51.100.23 port 41001 ssh2"
    uid = compute_event_id(agent_id, 2049, 100, "s1", 0)
    collected = datetime(2026, 11, 10, 1, 30, 5, tzinfo=timezone.utc)

    try:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

        PostgresAuthRepository(db_url).create_agent(agent_id, hash_secret("rp-key"), "lab-host")

        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO events_raw (
                      event_uid, agent_id, batch_id, log_type, message,
                      file_meta, agent_meta, collected_at, received_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        uid,
                        agent_id,
                        "rp-batch",
                        "auth",
                        raw_msg,
                        Jsonb({"path": "/var/log/auth.log", "device": 2049, "inode": 100, "stream_id": "s1", "offset": 0}),
                        Jsonb({"hostname": "lab-host", "version": "0.1.0", "ip": ["10.0.0.5"], "timezone": "Asia/Ho_Chi_Minh"}),
                        collected,
                        collected,
                    ),
                )
                # Insert stale/unparsed event row simulating older parser version
                conn.execute(
                    """
                    INSERT INTO events (
                      event_uid, ts, ingested_at, agent_id, host_name, dataset,
                      category, action, outcome, parse_status, doc
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        uid,
                        collected,
                        collected,
                        agent_id,
                        "lab-host",
                        "linux.auth",
                        ["host"],
                        "unparsed",
                        "unknown",
                        "unparsed",
                        Jsonb({"stale": True}),
                    ),
                )

        # 1. Dry-run must report 1 change without modifying DB
        dry = reparse_events(db_url=db_url, agent_id=agent_id, status="unparsed", dry_run=True)
        assert dry.scanned == 1
        assert dry.changed == 1
        assert dry.updated == 0

        # 2. Real re-parse updates `events` while leaving `events_raw` intact
        real = reparse_events(db_url=db_url, agent_id=agent_id, status="unparsed", dry_run=False)
        assert real.scanned == 1
        assert real.changed == 1
        assert real.updated == 1

        log_repo = PostgresLogRepository(db_url)
        raw_after = log_repo.get_raw_event(uid)
        assert raw_after is not None and raw_after["message"] == raw_msg
        reparsed = log_repo.get_by_ids([uid])
        assert len(reparsed) == 1
        ev = reparsed[0]
        assert ev.event.action == "ssh_login_failed"
        assert ev.source is not None and ev.source.ip == "198.51.100.23"
        assert ev.timestamp == datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    finally:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

