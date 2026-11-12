"""
Unit and end-to-end tests for GenericSyslogParser and 3-source ingestion (P4.2).
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import psycopg
import pytest

from server.main import app
from server.src.api.dependencies import reset_container
from server.src.common.schemas import (
    AgentMetadata,
    EventOutcome,
    LogType,
    ParseStatus,
    RawEventFileMeta,
    RawLogEvent,
    compute_event_id,
)
from server.src.common.security import generate_token, hash_secret
from server.src.parsers.auth_parser import AuthLogParser
from server.src.parsers.base import ParserRegistry
from server.src.parsers.syslog_parser import GenericSyslogParser
from tools.asp_migrate import run_migrations

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _parse_syslog(line: str):
    collected = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)
    agent = AgentMetadata(id="lab-1", hostname="DESKTOP-T9H4SPL", version="0.1.0", timezone="Asia/Ho_Chi_Minh")
    raw_ev = RawLogEvent(
        log_type=LogType.SYSLOG,
        file=RawEventFileMeta(
            path="/var/log/syslog",
            device=1,
            inode=1,
            stream_id="s1",
            offset=0,
        ),
        collected_at=collected,
        message=line,
    )
    uid = compute_event_id(agent.id, 1, 1, "s1", 0)
    return ParserRegistry.parse_raw_event(raw_ev, agent, uid, ingested_at=collected)


def test_syslog_parser_priority_does_not_shadow_auth():
    assert isinstance(ParserRegistry.get_parser("auth", "/var/log/auth.log"), AuthLogParser)
    assert isinstance(ParserRegistry.get_parser("syslog", "/var/log/syslog"), GenericSyslogParser)


def test_syslog_parser_parses_all_150_real_lab_lines():
    sample_path = _REPO_ROOT / "client" / "samples" / "syslog"
    lines = [l for l in sample_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 150

    for line in lines:
        ev = _parse_syslog(line)
        assert ev.asp.parse_status == ParseStatus.OK
        assert ev.event.dataset == "linux.syslog"
        assert ev.event.category == ["host"]
        assert ev.event.type == ["info"]
        assert ev.event.action == "syslog_message"
        assert ev.event.outcome == EventOutcome.UNKNOWN
        assert ev.asp.parser == "syslog_generic@1"
        assert ev.message is not None and len(ev.message) > 0

    # Specifically verify slash-prefixed proc & numeric proc
    ev_mysql = _parse_syslog(lines[36])
    assert ev_mysql.process is not None and ev_mysql.process.name == "/etc/mysql/debian-start"
    ev_motd = _parse_syslog(lines[142])
    assert ev_motd.process is not None and ev_motd.process.name == "50-motd-news"


def test_syslog_garbage_line_becomes_unparsed():
    ev = _parse_syslog("malformed line with no syslog header")
    assert ev.asp.parse_status == ParseStatus.UNPARSED
    assert ev.event.action == "unparsed"


def _post_ingest_asgi(api_key: str, payload: Dict[str, Any]) -> tuple[int, str]:
    raw = json.dumps(payload).encode("utf-8")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/ingest/logs",
        "raw_path": b"/api/v1/ingest/logs",
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"authorization", f"Bearer {api_key}".encode("latin-1")),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    sent: List[Dict[str, Any]] = []
    sent_done = False

    async def receive():
        nonlocal sent_done
        if not sent_done:
            sent_done = True
            return {"type": "http.request", "body": raw, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body").decode("utf-8")
    return int(start["status"]), body


def test_all_three_log_types_ingest_into_postgres_events():
    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping 3-source Postgres ingestion test")

    run_migrations(db_url=db_url)
    agent_id = "p42-3sources-agent"
    try:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

        container = reset_container(db_url=db_url, force_memory=False)
        key = generate_token()
        container.auth_repo.create_agent(agent_id, hash_secret(key), "multi-log-host")

        payload = {
            "schema_version": "1.1",
            "batch_id": "p42-batch",
            "sent_at": "2026-11-10T08:35:00Z",
            "agent": {
                "id": agent_id,
                "hostname": "multi-log-host",
                "version": "0.1.0",
                "ip": ["10.0.0.9"],
                "timezone": "Asia/Ho_Chi_Minh",
            },
            "events": [
                {
                    "log_type": "auth",
                    "file": {"path": "/var/log/auth.log", "device": 1, "inode": 10, "stream_id": "s1", "offset": 0},
                    "collected_at": "2026-11-10T08:35:00Z",
                    "message": "Nov 10 08:30:00 multi-log-host sshd[10]: Failed password for root from 198.51.100.1 port 2222 ssh2",
                },
                {
                    "log_type": "syslog",
                    "file": {"path": "/var/log/syslog", "device": 1, "inode": 11, "stream_id": "s2", "offset": 0},
                    "collected_at": "2026-11-10T08:35:00Z",
                    "message": "Nov 10 08:31:00 multi-log-host systemd[1]: Started Snap Daemon.",
                },
                {
                    "log_type": "apache",
                    "file": {"path": "/var/log/apache2/access.log", "device": 1, "inode": 12, "stream_id": "s3", "offset": 0},
                    "collected_at": "2026-11-10T08:35:00Z",
                    "message": '203.0.113.44 - - [10/Nov/2026:08:32:00 +0700] "GET /admin HTTP/1.1" 404 123 "-" "curl/8.0"',
                },
            ],
        }
        status_code, resp_text = _post_ingest_asgi(key, payload)
        assert status_code == 202
        assert json.loads(resp_text) == {"accepted": 3, "duplicates": 0, "unparsed": 0, "parse_errors": 0}

        events = container.log_repo.find_events({"agent.id": agent_id}, limit=10)
        assert {e.event.dataset for e in events} == {"linux.auth", "linux.syslog", "apache.access"}
    finally:
        reset_container(force_memory=True)
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

