"""
Unit and PostgreSQL integration tests for schema migrations (DDL Section 8.3).
Live DB tests require ASP_DB_URL to be set in the environment.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import psycopg
import pytest

from tools.asp_migrate import DEFAULT_MIGRATIONS_DIR, get_db_url, list_migration_files, run_migrations


def _require_db_url() -> str:
    url = os.environ.get("ASP_DB_URL")
    if not url:
        pytest.skip("ASP_DB_URL is not set; skipping live PostgreSQL migration tests")
    return url


def test_get_db_url_requires_env(monkeypatch):
    monkeypatch.delenv("ASP_DB_URL", raising=False)
    with pytest.raises(ValueError, match="ASP_DB_URL"):
        get_db_url()


def test_list_migration_files_ordered():
    files = list_migration_files(DEFAULT_MIGRATIONS_DIR)
    names = [f.name for f in files]
    assert names == [
        "001_agents_and_operators.sql",
        "002_events_raw_and_events.sql",
        "003_cases_and_alerts.sql",
    ]


def test_migrations_apply_idempotently():
    db_url = _require_db_url()

    # Run once (applies any pending migrations), then run again (must be a no-op)
    run_migrations(db_url=db_url)
    second_run = run_migrations(db_url=db_url)
    assert second_run == []

    with psycopg.connect(db_url) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            ).fetchall()
        }
        assert {
            "schema_migrations",
            "agents",
            "operators",
            "events_raw",
            "events",
            "cases",
            "alerts",
        }.issubset(tables)

        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
            ).fetchall()
        }
        assert {
            "events_ts",
            "events_action_ts",
            "events_srcip_ts",
            "events_user_ts",
            "events_bad_parse",
            "cases_one_open_per_key",
            "alerts_case",
        }.issubset(indexes)

        recorded_versions = [
            row[0]
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert recorded_versions == [
            "001_agents_and_operators.sql",
            "002_events_raw_and_events.sql",
            "003_cases_and_alerts.sql",
        ]


def test_events_raw_immutable_trigger_blocks_update():
    db_url = _require_db_url()
    run_migrations(db_url=db_url)

    now = datetime.now(timezone.utc)
    agent_id = "test-mig-agent"
    event_uid = "a" * 40

    with psycopg.connect(db_url) as conn:
        try:
            conn.execute(
                "INSERT INTO agents (id, api_key_hash, hostname) VALUES (%s, %s, %s)",
                (agent_id, "test_hash_" + "0" * 54, "lab-host"),
            )
            conn.execute(
                """
                INSERT INTO events_raw (
                  event_uid, agent_id, batch_id, log_type, message,
                  file_meta, agent_meta, collected_at
                ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
                """,
                (
                    event_uid,
                    agent_id,
                    "batch-test",
                    "auth",
                    "original raw line",
                    '{"path": "/var/log/auth.log", "device": 1, "inode": 2, "stream_id": "s1", "offset": 0}',
                    '{"hostname": "lab-host", "version": "0.1.0", "timezone": "UTC"}',
                    now,
                ),
            )

            with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
                with conn.transaction():
                    conn.execute(
                        "UPDATE events_raw SET message = %s WHERE event_uid = %s",
                        ("tampered raw line", event_uid),
                    )

            row = conn.execute(
                "SELECT message FROM events_raw WHERE event_uid = %s",
                (event_uid,),
            ).fetchone()
            assert row is not None
            assert row[0] == "original raw line"
        finally:
            conn.rollback()


def test_cases_one_open_per_key_constraint():
    db_url = _require_db_url()
    run_migrations(db_url=db_url)

    now = datetime.now(timezone.utc)
    with psycopg.connect(db_url) as conn:
        try:
            conn.execute(
                """
                INSERT INTO cases (case_key, source_ip, level, status, first_activity_at, last_activity_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                ("ip:198.51.100.77", "198.51.100.77", "high", "open", now, now),
            )

            # Second open case with same case_key must be rejected
            with pytest.raises(psycopg.errors.UniqueViolation):
                with conn.transaction():
                    conn.execute(
                        """
                        INSERT INTO cases (case_key, source_ip, level, status, first_activity_at, last_activity_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        ("ip:198.51.100.77", "198.51.100.77", "high", "open", now, now),
                    )

            # A closed case with the same key is allowed alongside an open case
            conn.execute(
                """
                INSERT INTO cases (case_key, source_ip, level, status, first_activity_at, last_activity_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                ("ip:198.51.100.77", "198.51.100.77", "medium", "closed", now, now),
            )
        finally:
            conn.rollback()
