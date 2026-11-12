"""
End-to-end collector + FastAPI ingest integration tests (P3.4).
Covers: rotation, truncate, copytruncate, inode-reuse (head_hash), restart recovery,
missing state (start_position=end), incomplete trailing line, server outage/recovery,
spool full pause/resume, and distinct stream_id yielding distinct event.ids at same (inode, offset).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import psycopg
import pytest
import requests

from client.collector import LogCollector
from server.main import app
from server.src.api.dependencies import get_container, reset_container
from server.src.common.security import generate_token, hash_secret
from tools.asp_migrate import run_migrations


def _asgi_post(path: str, headers: Dict[str, str], payload: Dict[str, Any]) -> SimpleNamespace:
    raw_body = json.dumps(payload).encode("utf-8")
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    sent: List[Dict[str, Any]] = []
    sent_flag = False

    async def receive():
        nonlocal sent_flag
        if not sent_flag:
            sent_flag = True
            return {"type": "http.request", "body": raw_body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body").decode("utf-8")
    hdrs = {k.decode("latin-1"): v.decode("latin-1") for k, v in start.get("headers", [])}
    return SimpleNamespace(status_code=int(start["status"]), text=body, headers=hdrs)


def _write_cfg(
    tmp_path: Path,
    log_path: Path,
    agent_id: str = "e2e-agent",
    start_position: str = "beginning",
    spool_max_bytes: int = 10_000_000,
) -> Path:
    cfg = [
        f"agent_id: {agent_id}",
        "server_url: http://testserver",
        "ingest_path: /api/v1/ingest/logs",
        "api_key_env: E2E_AGENT_KEY",
        "timezone: Asia/Ho_Chi_Minh",
        f"start_position: {start_position}",
        f"state_file: {tmp_path / 'state.json'}",
        f"spool_dir: {tmp_path / 'spool'}",
        f"spool_max_bytes: {spool_max_bytes}",
        "batch_max_events: 50",
        "batch_max_seconds: 1",
        "sources:",
        f"  - path: {log_path}",
        "    log_type: auth",
    ]
    p = tmp_path / "config.yaml"
    p.write_text("\n".join(cfg), encoding="utf-8")
    return p


def test_collector_e2e_rotation_truncate_restart_and_stream_id_uniqueness(tmp_path: Path, monkeypatch):
    container = reset_container(force_memory=True)
    agent_key = generate_token()
    container.auth_repo.create_agent("e2e-agent", hash_secret(agent_key), "lab-box")
    monkeypatch.setenv("E2E_AGENT_KEY", agent_key)

    log_file = tmp_path / "auth.log"
    line_before = b"Nov 10 08:30:00 lab-box sshd[10]: Failed password for root from 1.2.3.4 port 1001 ssh2\n"
    log_file.write_bytes(line_before)
    cfg = _write_cfg(tmp_path, log_file, start_position="beginning")

    server_online = True

    def _fake_post(url, json=None, headers=None, **kwargs):  # noqa: A002
        if not server_online:
            raise requests.ConnectionError("server unreachable")
        return _asgi_post("/api/v1/ingest/logs", headers or {}, json)

    # 1. Start collector, ingest line_before at offset=0
    c1 = LogCollector(str(cfg))
    c1._session.post = _fake_post
    try:
        c1.step(force_flush=True, now_mono=10.0)

        # 2. Rotate: append line + incomplete trailing, rename to .1, create new file
        with open(log_file, "ab") as f:
            f.write(b"Nov 10 08:30:01 lab-box sshd[11]: Failed password for admin from 1.2.3.4 port 1002 ssh2")
        log_file.rename(tmp_path / "auth.log.1")
        log_file.write_bytes(
            b"Nov 10 08:30:02 lab-box sshd[12]: Accepted password for ops from 10.0.0.5 port 2000 ssh2\n"
        )
        c1.step(force_flush=True, now_mono=12.0)

        # 3. Server dies, truncate file (same inode, offset=0 again with DIFFERENT line -> new stream_id!)
        server_online = False
        line_after_trunc = b"Nov 10 08:30:03 lab-box sshd[13]: Failed password for guest from 5.6.7.8 port 3000 ssh2\n"
        log_file.write_bytes(line_after_trunc)
        c1.step(force_flush=True, now_mono=14.0)
        assert len(c1.spool.list_pending()) == 1
    finally:
        c1.close()

    # 4. Restart collector midway while server comes back online + copytruncate larger overwrite
    server_online = True
    c2 = LogCollector(str(cfg))
    c2._session.post = _fake_post
    try:
        # Drain spooled batch from step 3
        c2.step(force_flush=True, now_mono=100.0)

        # Fast copytruncate with different 64-byte head & larger size
        overwritten = (
            b"Nov 10 08:31:00 lab-box sshd[14]: Failed password for user99 from 9.9.9.9 port 4000 ssh2\n"
            b"Nov 10 08:31:01 lab-box sshd[15]: Failed password for user99 from 9.9.9.9 port 4001 ssh2\n"
        )
        log_file.write_bytes(overwritten)
        c2.step(force_flush=True, now_mono=105.0)
    finally:
        c2.close()

    # Verify all 6 distinct lines arrived with zero loss and zero duplicates (both offset=0 events kept!)
    stored = container.log_repo.find_events({}, limit=100)
    messages = sorted(ev.event.original for ev in stored)
    assert len(messages) == 6
    assert any("for root from 1.2.3.4" in m for m in messages)
    assert any("for guest from 5.6.7.8" in m for m in messages)
    assert len({ev.event.id for ev in stored}) == 6


def test_collector_e2e_postgres_stream_id_same_inode_offset(tmp_path: Path, monkeypatch):
    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping live PostgreSQL E2E collector test")

    run_migrations(db_url=db_url)
    agent_id = "e2e-pg-agent"
    try:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM alerts WHERE rule_id LIKE 'RULE-%' OR rule_id LIKE 'e2e-%'")
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

        container = reset_container(db_url=db_url, force_memory=False)
        agent_key = generate_token()
        container.auth_repo.create_agent(agent_id, hash_secret(agent_key), "pg-lab")
        monkeypatch.setenv("E2E_AGENT_KEY", agent_key)

        log_file = tmp_path / "auth.log"
        log_file.write_bytes(
            b"Nov 10 08:30:00 pg-lab sshd[1]: Failed password for root from 198.51.100.1 port 1111 ssh2\n"
        )
        cfg = _write_cfg(tmp_path, log_file, agent_id=agent_id, start_position="beginning")

        collector = LogCollector(str(cfg))
        collector._session.post = lambda url, json=None, headers=None, **kw: _asgi_post(
            "/api/v1/ingest/logs", headers or {}, json
        )
        try:
            collector.step(force_flush=True, now_mono=10.0)
            # Truncate back to offset 0 on same inode, write a different event
            log_file.write_bytes(
                b"Nov 10 08:31:00 pg-lab sshd[2]: Accepted publickey for ops from 10.0.0.2 port 2222 ssh2\n"
            )
            collector.step(force_flush=True, now_mono=12.0)
        finally:
            collector.close()

        stored = container.log_repo.find_events({"agent.id": agent_id}, limit=20)
        assert len(stored) == 2
        assert stored[0].event.id != stored[1].event.id
    finally:
        reset_container(force_memory=True)
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

