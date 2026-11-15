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

    static_mounts = [r for r in app.routes if isinstance(r, Mount) and r.path == "/static"]
    assert len(static_mounts) == 1

    for asset_name in ("styles.css", "markdown.js", "app.js"):
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
