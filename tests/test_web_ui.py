"""
Tests for the SOC Web Dashboard static serving and PATCH /api/v1/cases/{case_id}.
Tests invoke FastAPI routes and dependencies synchronously so they run fast in all environments.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request
from starlette.responses import FileResponse
from starlette.routing import Mount

from server.main import WEB_DIR, app, serve_dashboard
from server.src.api.dependencies import require_operator_scope, reset_container
from server.src.api.v1.cases import update_case_status
from server.src.common.schemas import AlertLevel, Case, CaseStatus, CaseStatusUpdate
from server.src.common.security import generate_token, hash_secret


def _fake_request(path: str = "/api/v1/cases/1", token: Optional[str] = None) -> Request:
    headers = []
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode("latin-1")))
    scope = {
        "type": "http",
        "method": "PATCH",
        "path": path,
        "headers": headers,
    }
    return Request(scope)


def test_web_dashboard_routes_and_static_assets():
    reset_container(force_memory=True)

    resp = serve_dashboard()
    assert isinstance(resp, FileResponse)
    index_path = WEB_DIR / "index.html"
    assert index_path.is_file()
    html = index_path.read_text(encoding="utf-8")
    assert "Agentic SOC Platform" in html
    assert "/static/app.js" in html
    assert "/static/styles.css" in html
    assert 'data-tab="overview"' in html
    assert 'data-tab="cases"' in html
    assert 'data-tab="ai-flow"' in html
    assert 'data-tab="telemetry"' in html
    assert "langgraph-diagram" in html
    assert "chart-severity-donut" in html
    assert "chart-alerts-timeline" in html

    static_mounts = [r for r in app.routes if isinstance(r, Mount) and r.path == "/static"]
    assert len(static_mounts) == 1

    for asset_name in (
        "styles.css",
        "markdown.js",
        "app.js",
        "css/tokens.css",
        "css/layout.css",
        "css/components.css",
        "css/views.css",
        "js/state.js",
        "js/ui.js",
        "js/api.js",
        "js/charts.js",
        "js/views/overview.js",
        "js/views/cases.js",
        "js/views/aiFlow.js",
        "js/views/telemetry.js",
    ):
        asset_path = WEB_DIR / asset_name
        assert asset_path.is_file()
        assert len(asset_path.read_text(encoding="utf-8")) > 0


def test_patch_case_status_auth_lifecycle_and_conflict():
    container = reset_container(force_memory=True)

    read_tok = generate_token()
    container.auth_repo.create_operator("op-read", hash_secret(read_tok), ["read"])

    inv_tok = generate_token()
    container.auth_repo.create_operator("op-inv", hash_secret(inv_tok), ["read", "investigate"])

    now = datetime(2026, 11, 13, 4, 0, 0, tzinfo=timezone.utc)
    saved_case = container.alert_repo.save_case(
        Case(
            case_key="ip:203.0.113.77",
            source_ip="203.0.113.77",
            level=AlertLevel.HIGH,
            status=CaseStatus.OPEN,
            first_activity_at=now,
            last_activity_at=now,
            title="Security Incident: SSH brute force",
        )
    )
    assert saved_case.id is not None

    guard = require_operator_scope("investigate")
    case_path = f"/api/v1/cases/{saved_case.id}"

    # 1. Auth guards: 401 missing token, 403 read-only scope
    with pytest.raises(HTTPException) as exc_401:
        guard(request=_fake_request(case_path), credentials=None, auth_repo=container.auth_repo)
    assert exc_401.value.status_code == 401

    with pytest.raises(HTTPException) as exc_403:
        guard(
            request=_fake_request(case_path, token=read_tok),
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=read_tok),
            auth_repo=container.auth_repo,
        )
    assert exc_403.value.status_code == 403

    op = guard(
        request=_fake_request(case_path, token=inv_tok),
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=inv_tok),
        auth_repo=container.auth_repo,
    )

    # 2. 404 on unknown case
    with pytest.raises(HTTPException) as exc_404:
        update_case_status(
            case_id=9999,
            payload=CaseStatusUpdate(status=CaseStatus.CLOSED),
            _operator=op,
            repo=container.alert_repo,
        )
    assert exc_404.value.status_code == 404

    # 3. Close then reopen case
    closed_case = update_case_status(
        case_id=saved_case.id,
        payload=CaseStatusUpdate(status=CaseStatus.CLOSED),
        _operator=op,
        repo=container.alert_repo,
    )
    assert closed_case.status == CaseStatus.CLOSED

    reopened_case = update_case_status(
        case_id=saved_case.id,
        payload=CaseStatusUpdate(status=CaseStatus.OPEN),
        _operator=op,
        repo=container.alert_repo,
    )
    assert reopened_case.status == CaseStatus.OPEN

    # 4. 409 Conflict when reopening older closed case while open case shares case_key
    older_closed = container.alert_repo.save_case(
        Case(
            case_key="ip:203.0.113.77",
            source_ip="203.0.113.77",
            level=AlertLevel.MEDIUM,
            status=CaseStatus.CLOSED,
            first_activity_at=now,
            last_activity_at=now,
        )
    )
    assert older_closed.id is not None

    with pytest.raises(HTTPException) as exc_409:
        update_case_status(
            case_id=older_closed.id,
            payload=CaseStatusUpdate(status=CaseStatus.OPEN),
            _operator=op,
            repo=container.alert_repo,
        )
    assert exc_409.value.status_code == 409


def test_investigation_populates_trace_steps_and_forensic_breakdown():
    from server.src.agent.workflow import create_investigator
    from server.src.api.v1.cases import trigger_case_investigation
    from server.src.common.schemas import Alert

    container = reset_container(force_memory=True)
    tok = generate_token()
    op = container.auth_repo.create_operator("op-trace", hash_secret(tok), ["read", "investigate"])

    now = datetime(2026, 11, 13, 5, 0, 0, tzinfo=timezone.utc)
    alert = Alert(
        alert_key="trace-test-alert-1",
        rule_id="asp-ssh-bruteforce",
        title="SSH Brute Force",
        level=AlertLevel.HIGH,
        created_at=now,
        window_start=now,
        window_end=now,
        group_key={"source.ip": "203.0.113.77", "host.name": "web-01"},
        event_count=6,
        event_uids=[],
    )
    case = container.alert_repo.correlate_alert_to_case(
        alert=alert,
        case_key="ip:203.0.113.77",
        source_ip="203.0.113.77",
    )
    assert case is not None and case.id is not None

    investigator = create_investigator(
        log_repository=container.log_repo,
        alert_repository=container.alert_repo,
        use_mock_threat_intel=True,
        use_mock_llm=True,
    )
    updated_case = trigger_case_investigation(
        case_id=case.id,
        _operator=op,
        repo=container.alert_repo,
        investigator=investigator,
    )

    assert updated_case.ai_investigated_at is not None
    assert isinstance(updated_case.ai_report, dict)
    steps = updated_case.ai_report.get("trace_steps")
    assert isinstance(steps, list) and len(steps) >= 3
    nodes_seen = {s["node"] for s in steps}
    assert {"load_case_context", "agent_reasoning", "synthesize_verdict"}.issubset(nodes_seen)

    breakdown = updated_case.ai_report.get("forensic_breakdown")
    assert isinstance(breakdown, dict)
    assert breakdown.get("verdict") == updated_case.agent_verdict
    assert "asp-ssh-bruteforce" in breakdown.get("matched_rules", [])
