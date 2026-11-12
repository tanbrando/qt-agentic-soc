"""
Tests for P5.5: Read APIs (/api/v1/alerts, /api/v1/events, /api/v1/cases, /api/v1/cases/{id}),
auth/scope enforcement (401/403), query filters, pagination, and Phase 6 investigate contract.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlencode

import psycopg
import pytest

from server.main import app
from server.src.api.dependencies import reset_container
from server.src.common.security import generate_token, hash_secret


def _asgi_call(
    method: str,
    path: str,
    query: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
) -> Tuple[int, Any]:
    qs = urlencode(query or {}).encode("ascii")
    raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1"))
        for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": qs,
        "headers": raw_headers,
        "client": ("127.0.0.1", 55000),
        "server": ("testserver", 80),
    }
    sent: List[Dict[str, Any]] = []
    sent_body = False

    async def receive() -> Dict[str, Any]:
        nonlocal sent_body
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg: Dict[str, Any]) -> None:
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    parsed = json.loads(payload.decode("utf-8")) if payload else None
    return int(start["status"]), parsed


@pytest.fixture(params=["memory", "postgres"])
def backend_container(request: pytest.FixtureRequest) -> Iterator[Any]:
    if request.param == "memory":
        c = reset_container(force_memory=True)
        yield c
        return

    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping Postgres read API test")

    c = reset_container(db_url=db_url)
    try:
        yield c
    finally:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute(
                    "DELETE FROM alerts WHERE case_id IN (SELECT id FROM cases WHERE case_key LIKE 'ip:198.51.100.%' OR case_key LIKE 'ip:203.0.113.%' OR case_key LIKE 'host:host-p55%') OR alert_key LIKE 'asp-%'"
                )
                conn.execute(
                    "DELETE FROM cases WHERE case_key LIKE 'ip:198.51.100.%' OR case_key LIKE 'ip:203.0.113.%' OR case_key LIKE 'host:host-p55%'"
                )
                conn.execute("DELETE FROM events WHERE agent_id = 'agent-p55'")
                conn.execute("DELETE FROM events_raw WHERE agent_id = 'agent-p55'")
                conn.execute("DELETE FROM agents WHERE id = 'agent-p55'")
                conn.execute("DELETE FROM operators WHERE id IN ('op-p55-read', 'op-p55-inv-only')")


def test_read_endpoints_auth_filters_pagination_and_phase6_contract(backend_container: Any):
    agent_key = generate_token()
    backend_container.auth_repo.create_agent("agent-p55", hash_secret(agent_key), "host-p55")

    read_tok = generate_token()
    backend_container.auth_repo.create_operator("op-p55-read", hash_secret(read_tok), ["read"])

    inv_only_tok = generate_token()
    backend_container.auth_repo.create_operator("op-p55-inv-only", hash_secret(inv_only_tok), ["investigate"])

    read_headers = {"Authorization": f"Bearer {read_tok}"}
    inv_headers = {"Authorization": f"Bearer {inv_only_tok}"}

    # 1. Auth guards: 401 when missing, 403 when wrong scope
    for ep in ("/api/v1/alerts", "/api/v1/events", "/api/v1/cases", "/api/v1/cases/1"):
        st_no_auth, _ = _asgi_call("GET", ep)
        assert st_no_auth == 401
        st_wrong_scope, _ = _asgi_call("GET", ep, headers=inv_headers)
        assert st_wrong_scope == 403

    # 2. Query validation bounds
    st_over_limit, _ = _asgi_call("GET", "/api/v1/events", query={"limit": 1001}, headers=read_headers)
    assert st_over_limit == 422
    st_bad_ip, _ = _asgi_call("GET", "/api/v1/events", query={"source_ip": "not_an_ip"}, headers=read_headers)
    assert st_bad_ip == 422
    st_bad_case_ip, _ = _asgi_call("GET", "/api/v1/cases", query={"source_ip": "bad-ip"}, headers=read_headers)
    assert st_bad_case_ip == 422

    # 3. Seed multi-source events via /api/v1/ingest/logs
    now = datetime(2026, 11, 10, 14, 0, 0, tzinfo=timezone.utc)
    raw_events = []
    # 5 SSH brute force events -> fires asp-ssh-bruteforce (high) + opens case ip:198.51.100.180
    for i in range(5):
        ts = now + timedelta(seconds=i * 5)
        raw_events.append(
            {
                "log_type": "auth",
                "file": {"path": "/var/log/auth.log", "device": 1, "inode": 55, "stream_id": "s-auth", "offset": i * 100},
                "collected_at": ts.isoformat(),
                "message": f"{ts.strftime('%b %d %H:%M:%S')} host-p55 sshd[{100+i}]: Failed password for root from 198.51.100.180 port 5100{i} ssh2",
            }
        )
    # 1 sudo root shell event with source_ip absent -> case host:host-p55|user:alice (Wait: rule has no IP)
    # Use SSH login fail from another IP? Even cleaner: 1 apache 200 OK line + 1 unparsed garbage line
    raw_events.append(
        {
            "log_type": "apache",
            "file": {"path": "/var/log/apache2/access.log", "device": 1, "inode": 56, "stream_id": "s-web", "offset": 0},
            "collected_at": (now + timedelta(seconds=30)).isoformat(),
            "message": '203.0.113.181 - bob [10/Nov/2026:14:00:30 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"',
        }
    )
    raw_events.append(
        {
            "log_type": "syslog",
            "file": {"path": "/var/log/syslog", "device": 1, "inode": 57, "stream_id": "s-sys", "offset": 0},
            "collected_at": (now + timedelta(seconds=35)).isoformat(),
            "message": "CORRUPTED NON SYSLOG LINE FOR UNPARSED FILTER TEST",
        }
    )

    # Also 1 sudo abuse line -> fires asp-sudo-abuse (medium) -> distinct case
    raw_events.append(
        {
            "log_type": "auth",
            "file": {"path": "/var/log/auth.log", "device": 1, "inode": 55, "stream_id": "s-auth", "offset": 900},
            "collected_at": (now + timedelta(seconds=40)).isoformat(),
            "message": "Nov 10 14:00:40 host-p55 sudo: mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/id",
        }
    )

    ingest_body = json.dumps(
        {
            "schema_version": "1.1",
            "batch_id": "b-p55-1",
            "sent_at": (now + timedelta(seconds=45)).isoformat(),
            "agent": {"id": "agent-p55", "hostname": "host-p55", "version": "0.1.0", "timezone": "UTC"},
            "events": raw_events,
        }
    ).encode("utf-8")
    st_in, res_in = _asgi_call(
        "POST",
        "/api/v1/ingest/logs",
        headers={"Authorization": f"Bearer {agent_key}", "Content-Type": "application/json"},
        body=ingest_body,
    )
    assert st_in == 202
    assert res_in["accepted"] == 8
    assert res_in["unparsed"] == 1

    # 4. Query /api/v1/events filters & pagination
    st_ev_ip, ev_ip = _asgi_call("GET", "/api/v1/events", query={"source_ip": "198.51.100.180"}, headers=read_headers)
    assert st_ev_ip == 200 and len(ev_ip) == 5
    assert "@timestamp" in ev_ip[0]

    st_ev_user, ev_user = _asgi_call("GET", "/api/v1/events", query={"user_name": "bob", "dataset": "apache.access"}, headers=read_headers)
    assert st_ev_user == 200 and len(ev_user) == 1
    assert ev_user[0]["http"]["response"]["status_code"] == 200

    st_ev_unparsed, ev_unparsed = _asgi_call("GET", "/api/v1/events", query={"parse_status": "unparsed"}, headers=read_headers)
    assert st_ev_unparsed == 200 and len(ev_unparsed) == 1

    st_ev_action, ev_action = _asgi_call(
        "GET",
        "/api/v1/events",
        query={
            "action": "ssh_login_failed",
            "since": (now + timedelta(seconds=10)).isoformat(),
            "until": (now + timedelta(seconds=20)).isoformat(),
            "limit": 2,
            "offset": 1,
        },
        headers=read_headers,
    )
    assert st_ev_action == 200 and len(ev_action) == 2

    # 5. Query /api/v1/cases & /api/v1/cases/{id}
    st_cases, cases_high = _asgi_call(
        "GET",
        "/api/v1/cases",
        query={"status": "open", "level": "high", "source_ip": "198.51.100.180"},
        headers=read_headers,
    )
    assert st_cases == 200 and len(cases_high) == 1
    high_case = cases_high[0]
    assert high_case["agent_verdict"] is None
    assert len(high_case["alerts"]) == 1

    st_case_detail, case_detail = _asgi_call("GET", f"/api/v1/cases/{high_case['id']}", headers=read_headers)
    assert st_case_detail == 200 and case_detail["id"] == high_case["id"]
    assert len(case_detail["alerts"]) == 1

    # 6. Query /api/v1/alerts filters & pagination
    st_al_all, al_all = _asgi_call("GET", "/api/v1/alerts", query={"limit": 1, "offset": 0}, headers=read_headers)
    assert st_al_all == 200 and len(al_all) == 1

    st_al_filtered, al_filtered = _asgi_call(
        "GET",
        "/api/v1/alerts",
        query={
            "rule_id": "asp-ssh-bruteforce",
            "level": "high",
            "status": "new",
            "case_id": high_case["id"],
            "since": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
            "until": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
        headers=read_headers,
    )
    assert st_al_filtered == 200 and len(al_filtered) == 1
    assert al_filtered[0]["rule_id"] == "asp-ssh-bruteforce"

    # 7. Keep POST /api/v1/cases/{id}/investigate intact for Phase 6
    st_inv, inv_res = _asgi_call("POST", f"/api/v1/cases/{high_case['id']}/investigate", headers=inv_headers)
    assert st_inv == 200
    assert inv_res["agent_verdict"] == "True Positive"
