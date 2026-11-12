"""
Integration tests for synchronous IngestionService, Auth Guards, Rate/Size Limits,
and FastAPI ASGI endpoints.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pytest

from server.main import app, health_check
from server.src.api.dependencies import get_container, reset_container
from server.src.api.v1.cases import get_case, list_cases, trigger_case_investigation
from server.src.api.v1.ingest import ingest_logs, router as ingest_router
from server.src.common.schemas import (
    AgentMetadata,
    AgentVerdict,
    AlertLevel,
    CaseStatus,
    IngestBatchRequest,
    LogType,
    RawEventFileMeta,
    RawLogEvent,
)
from server.src.common.security import generate_token, hash_secret


def _asgi_request(
    method: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
) -> Tuple[int, Dict[str, str], bytes]:
    """Minimal stdlib ASGI caller to exercise the full FastAPI stack without httpx."""
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
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    sent_messages: List[Dict[str, Any]] = []
    body_sent = False

    async def receive() -> Dict[str, Any]:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: Dict[str, Any]) -> None:
        sent_messages.append(message)

    asyncio.run(app(scope, receive, send))

    start_msg = next(m for m in sent_messages if m["type"] == "http.response.start")
    resp_headers = {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in start_msg.get("headers", [])
    }
    resp_body = b"".join(m.get("body", b"") for m in sent_messages if m["type"] == "http.response.body")
    return int(start_msg["status"]), resp_headers, resp_body


@pytest.fixture(autouse=True)
def clean_container():
    """Reset in-memory container before each test to ensure state isolation."""
    reset_container(force_memory=True)
    yield


def test_end_to_end_ingestion_and_case_creation():
    container = get_container()
    ingest_svc = container.ingestion_service

    attacker_ip = "198.51.100.23"
    now = datetime.now(timezone.utc)
    events = []
    for i in range(5):
        raw_line = (
            f"Oct 11 04:02:{10+i:02d} web-01 sshd[2849{i}]: "
            f"Failed password for root from {attacker_ip} port 5234{i} ssh2"
        )
        ev = RawLogEvent(
            log_type=LogType.AUTH,
            file=RawEventFileMeta(
                path="/var/log/auth.log",
                device=2049,
                inode=131077,
                stream_id="stream-01",
                offset=i * 120,
            ),
            collected_at=now,
            message=raw_line,
        )
        events.append(ev)

    batch = IngestBatchRequest(
        schema_version="1.1",
        batch_id="batch-001",
        sent_at=now,
        agent=AgentMetadata(id="agent-01", hostname="web-01", version="0.1.0", ip=["10.0.0.5"]),
        events=events,
    )

    # 1. Ingest batch synchronously
    response = ingest_svc.ingest_batch(batch)
    assert response.accepted == 5
    assert response.duplicates == 0
    assert response.unparsed == 0
    assert response.parse_errors == 0

    # 1b. Re-sending exact same batch is idempotent
    dup_response = ingest_svc.ingest_batch(batch)
    assert dup_response.accepted == 0
    assert dup_response.duplicates == 5

    # 2. Verify Case was created in AlertRepository
    cases = container.alert_repo.list_cases()
    assert len(cases) == 1
    case = cases[0]
    assert case.id is not None
    assert case.case_key == f"ip:{attacker_ip}"
    assert case.status == CaseStatus.OPEN
    assert case.level == AlertLevel.HIGH
    assert len(case.alerts) == 1
    assert case.alerts[0].rule_id == "asp-ssh-bruteforce"
    assert case.alerts[0].title == "SSH brute force"
    assert len(case.alerts[0].event_uids) == 5

    # 3. Trigger Agent Investigation
    report_update = container.agent_investigator.investigate_case(case)
    assert report_update.agent_verdict == AgentVerdict.TRUE_POSITIVE
    assert report_update.agent_confidence >= 0.8
    assert len(report_update.extracted_artifacts) >= 1
    assert report_update.extracted_artifacts[0].value == attacker_ip
    assert "Executive Summary" in report_update.agent_report_markdown

    # 4. Save report update to case
    container.alert_repo.update_case_with_agent_report(
        case_id=case.id,
        report_data=report_update.model_dump(),
    )

    updated_case = container.alert_repo.get_case(case.id)
    assert updated_case is not None
    assert updated_case.agent_verdict == AgentVerdict.TRUE_POSITIVE.value
    assert updated_case.agent_confidence is not None


def test_api_endpoints_direct_invocation():
    container = get_container()
    now = datetime.now(timezone.utc)

    raw_key = generate_token()
    agent_rec = container.auth_repo.create_agent("test-edge-agent", hash_secret(raw_key), "prod-db-01")
    raw_op_token = generate_token()
    op_rec = container.auth_repo.create_operator("alice", hash_secret(raw_op_token), ["read", "investigate"])

    ingest_route = next(r for r in ingest_router.routes if getattr(r, "path", None) == "/api/v1/ingest/logs")
    assert ingest_route.status_code == 202
    assert any(getattr(r, "path", None) == "/api/v1/health" for r in app.routes)
    assert health_check()["status"] == "ok"

    batch = IngestBatchRequest(
        schema_version="1.1",
        batch_id="batch-002",
        sent_at=now,
        agent=AgentMetadata(id="test-edge-agent", hostname="prod-db-01", version="0.1.0"),
        events=[
            RawLogEvent(
                log_type=LogType.AUTH,
                file=RawEventFileMeta(
                    path="/var/log/auth.log",
                    device=2049,
                    inode=22222,
                    stream_id="stream-02",
                    offset=0,
                ),
                collected_at=now,
                message="Oct 11 05:00:00 prod-db-01 sudo: attacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            )
        ],
    )

    res_ingest = ingest_logs(
        batch=batch,
        auth_agent=agent_rec,
        auth_repo=container.auth_repo,
        rate_limiter=container.rate_limiter,
        service=container.ingestion_service,
    )
    assert res_ingest.accepted == 1
    assert res_ingest.duplicates == 0

    all_cases = list_cases(_operator=op_rec, repo=container.alert_repo)
    assert len(all_cases) == 1
    case_id = all_cases[0].id
    assert case_id is not None

    case_data = get_case(case_id=case_id, _operator=op_rec, repo=container.alert_repo)
    assert case_data.id == case_id
    assert case_data.level == AlertLevel.MEDIUM
    assert case_data.status == CaseStatus.OPEN

    investigated = trigger_case_investigation(
        case_id=case_id,
        _operator=op_rec,
        repo=container.alert_repo,
        investigator=container.agent_investigator,
    )
    assert investigated.agent_verdict is not None
    assert investigated.agent_report_markdown is not None


def test_http_auth_size_and_scope_enforcement():
    container = get_container()
    agent_key = generate_token()
    container.auth_repo.create_agent("web-01", hash_secret(agent_key), "web-01")

    read_token = generate_token()
    container.auth_repo.create_operator("reader", hash_secret(read_token), ["read"])

    inv_token = generate_token()
    container.auth_repo.create_operator("analyst", hash_secret(inv_token), ["read", "investigate"])

    # Public health endpoint works without auth
    st, _, _ = _asgi_request("GET", "/api/v1/health")
    assert st == 200

    payload_dict = {
        "schema_version": "1.1",
        "batch_id": "b-http-1",
        "sent_at": "2026-11-10T08:30:02Z",
        "agent": {"id": "web-01", "hostname": "web-01", "version": "0.1.0"},
        "events": [
            {
                "log_type": "auth",
                "file": {
                    "path": "/var/log/auth.log",
                    "device": 2049,
                    "inode": 131077,
                    "stream_id": "s1",
                    "offset": 0,
                },
                "collected_at": "2026-11-10T08:30:01Z",
                "message": "Oct 11 05:00:00 web-01 sudo: attacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            }
        ],
    }
    raw_body = json.dumps(payload_dict).encode("utf-8")

    # 1. Missing / bad API key -> 401
    st, _, _ = _asgi_request("POST", "/api/v1/ingest/logs", {"Content-Type": "application/json"}, raw_body)
    assert st == 401

    st, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": "Bearer wrong-key"},
        raw_body,
    )
    assert st == 401

    # 2. agent.id mismatch -> 403
    mismatch_payload = dict(payload_dict)
    mismatch_payload["agent"] = {"id": "other-agent", "hostname": "web-02", "version": "0.1.0"}
    st, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {agent_key}"},
        json.dumps(mismatch_payload).encode("utf-8"),
    )
    assert st == 403

    # 3. Over 500 events -> 413
    too_many = dict(payload_dict)
    too_many["events"] = [
        {
            "log_type": "auth",
            "file": {"path": "/var/log/auth.log", "device": 1, "inode": 1, "stream_id": "s", "offset": i},
            "collected_at": "2026-11-10T08:30:01Z",
            "message": "line",
        }
        for i in range(501)
    ]
    st, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {agent_key}"},
        json.dumps(too_many).encode("utf-8"),
    )
    assert st == 413

    # 4. Over 1 MB payload -> 413
    oversized_body = b"x" * 1_048_577
    st, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {agent_key}"},
        oversized_body,
    )
    assert st == 413

    # 5. Valid batch -> 202, duplicate resend -> 202 with duplicates=1
    st, _, body = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {agent_key}"},
        raw_body,
    )
    assert st == 202
    assert json.loads(body) == {"accepted": 1, "duplicates": 0, "unparsed": 0, "parse_errors": 0}

    st, _, body = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {agent_key}"},
        raw_body,
    )
    assert st == 202
    assert json.loads(body)["duplicates"] == 1

    # 6. Operator scopes on /api/v1/cases
    st, _, _ = _asgi_request("GET", "/api/v1/cases")
    assert st == 401

    st, _, cases_body = _asgi_request(
        "GET",
        "/api/v1/cases",
        {"Authorization": f"Bearer {read_token}"},
    )
    assert st == 200
    cases_list = json.loads(cases_body)
    assert len(cases_list) == 1
    cid = cases_list[0]["id"]

    # read-only token cannot investigate -> 403
    st, _, _ = _asgi_request(
        "POST",
        f"/api/v1/cases/{cid}/investigate",
        {"Authorization": f"Bearer {read_token}"},
    )
    assert st == 403

    # investigate token succeeds -> 200
    st, _, _ = _asgi_request(
        "POST",
        f"/api/v1/cases/{cid}/investigate",
        {"Authorization": f"Bearer {inv_token}"},
    )
    assert st == 200

    # Revoked agent key returns 401
    assert container.auth_repo.revoke_agent("web-01") is True
    st, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {agent_key}"},
        raw_body,
    )
    assert st == 401

    # 7. Rate limit exceeded -> 429
    from server.src.common.security import InMemoryRateLimiter

    rl_key = generate_token()
    container.auth_repo.create_agent("rl-agent", hash_secret(rl_key), "rl-host")
    container.rate_limiter = InMemoryRateLimiter(rate_per_minute=1)
    rl_payload = dict(payload_dict)
    rl_payload["agent"] = {"id": "rl-agent", "hostname": "rl-host", "version": "0.1.0"}
    rl_body = json.dumps(rl_payload).encode("utf-8")

    st1, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {rl_key}"},
        rl_body,
    )
    st2, _, _ = _asgi_request(
        "POST",
        "/api/v1/ingest/logs",
        {"Content-Type": "application/json", "Authorization": f"Bearer {rl_key}"},
        rl_body,
    )
    assert st1 == 202
    assert st2 == 429
