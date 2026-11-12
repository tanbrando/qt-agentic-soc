"""
Tests for P5.4: Case key derivation, event-time case_idle_timeout lifecycle (6h default),
and concurrent thread safety against duplicate open cases (cases_one_open_per_key).
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Iterator

import psycopg
import pytest

from server.src.common.schemas import Alert, AlertLevel, CaseStatus
from server.src.engine.base import RuleEngine
from server.src.repositories.base import IAlertRepository
from server.src.repositories.memory import InMemoryAlertRepository, InMemoryLogRepository
from server.src.repositories.postgres import PostgresAlertRepository, PostgresLogRepository
from server.src.services.ingestion_service import IngestionService


@pytest.fixture(params=["memory", "postgres"])
def alert_repo(request: pytest.FixtureRequest) -> Iterator[IAlertRepository]:
    if request.param == "memory":
        yield InMemoryAlertRepository()
        return

    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping Postgres case lifecycle test")

    repo = PostgresAlertRepository(db_url)
    test_prefix = "p54-case-"
    try:
        yield repo
    finally:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM alerts WHERE alert_key LIKE %s", (f"{test_prefix}%",))
                conn.execute(
                    "DELETE FROM cases WHERE case_key LIKE %s OR case_key LIKE %s OR case_key LIKE %s",
                    ("ip:198.51.100.2%", "host:p54-%", "alert:p54-%"),
                )


def _svc(repo: IAlertRepository, idle_timeout_seconds: int = 21_600) -> IngestionService:
    return IngestionService(
        log_repository=InMemoryLogRepository(),
        alert_repository=repo,
        rule_engine=RuleEngine([]),
        case_idle_timeout_seconds=idle_timeout_seconds,
    )


def test_case_key_fallback_priority(alert_repo: IAlertRepository):
    svc = _svc(alert_repo)
    now = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)

    # 1. source.ip present -> ip:<source.ip>
    c1 = svc._persist_and_correlate_alert(
        Alert(
            alert_key="p54-case-k1",
            rule_id="asp-ssh-bruteforce",
            title="SSH brute force",
            level=AlertLevel.HIGH,
            window_start=now,
            window_end=now,
            group_key={"source.ip": "198.51.100.201", "host.name": "p54-h1", "user.name": "root"},
            event_count=5,
            event_uids=["u1"],
        )
    )
    assert c1 is not None and c1.case_key == "ip:198.51.100.201"

    # 2. No source.ip -> host:<host.name>|user:<user.name>
    c2 = svc._persist_and_correlate_alert(
        Alert(
            alert_key="p54-case-k2",
            rule_id="asp-sudo-abuse",
            title="Sudo abuse",
            level=AlertLevel.MEDIUM,
            window_start=now,
            window_end=now,
            group_key={"host.name": "p54-h2", "user.name": "alice"},
            event_count=1,
            event_uids=["u2"],
        )
    )
    assert c2 is not None and c2.case_key == "host:p54-h2|user:alice"

    # 3. Neither ip nor user -> alert:<alert_key>
    c3 = svc._persist_and_correlate_alert(
        Alert(
            alert_key="p54-case-k3",
            rule_id="asp-sudo-abuse",
            title="Misc",
            level=AlertLevel.LOW,
            window_start=now,
            window_end=now,
            group_key={"host.name": "p54-h3"},
            event_count=1,
            event_uids=["u3"],
        )
    )
    assert c3 is not None and c3.case_key == "alert:p54-case-k3"


def test_case_idle_timeout_merges_within_6h_and_rolls_over_after_6h(alert_repo: IAlertRepository):
    svc = _svc(alert_repo, idle_timeout_seconds=6 * 3600)
    t0 = datetime(2026, 11, 10, 6, 0, 0, tzinfo=timezone.utc)

    a1 = Alert(
        alert_key="p54-case-t1",
        rule_id="asp-web-scan-404",
        title="Web scan",
        level=AlertLevel.MEDIUM,
        window_start=t0,
        window_end=t0,
        group_key={"source.ip": "198.51.100.205"},
        event_count=30,
        event_uids=["a1"],
    )
    case1 = svc._persist_and_correlate_alert(a1)
    assert case1 is not None and case1.id is not None
    assert case1.status == CaseStatus.OPEN
    assert case1.level == AlertLevel.MEDIUM

    # +3 hours later (<= 6h): attaches to SAME open case and elevates severity to HIGH
    t1 = t0 + timedelta(hours=3)
    a2 = Alert(
        alert_key="p54-case-t2",
        rule_id="asp-ssh-bruteforce",
        title="SSH brute force",
        level=AlertLevel.HIGH,
        window_start=t1 - timedelta(minutes=2),
        window_end=t1,
        group_key={"source.ip": "198.51.100.205"},
        event_count=5,
        event_uids=["a2"],
    )
    case1_updated = svc._persist_and_correlate_alert(a2)
    assert case1_updated is not None and case1_updated.id == case1.id
    assert case1_updated.status == CaseStatus.OPEN
    assert case1_updated.level == AlertLevel.HIGH
    assert case1_updated.last_activity_at == t1
    assert len(case1_updated.alerts) == 2

    # +6h01m after t1 (> 6h idle): closes case1 and opens a brand-new OPEN case!
    t2 = t1 + timedelta(hours=6, minutes=1)
    a3 = Alert(
        alert_key="p54-case-t3",
        rule_id="asp-bruteforce-then-success",
        title="Brute force then success",
        level=AlertLevel.CRITICAL,
        window_start=t2 - timedelta(minutes=5),
        window_end=t2,
        group_key={"source.ip": "198.51.100.205"},
        event_count=6,
        event_uids=["a3"],
    )
    case2 = svc._persist_and_correlate_alert(a3)
    assert case2 is not None and case2.id != case1.id
    assert case2.status == CaseStatus.OPEN
    assert case2.level == AlertLevel.CRITICAL
    assert len(case2.alerts) == 1

    old_reloaded = alert_repo.get_case(case1.id)
    assert old_reloaded is not None
    assert old_reloaded.status == CaseStatus.CLOSED
    assert len(old_reloaded.alerts) == 2


def test_concurrent_alert_correlation_never_violates_one_open_case_per_key(alert_repo: IAlertRepository):
    t0 = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)
    case_key = "ip:198.51.100.222"

    def _worker(idx: int):
        alert = Alert(
            alert_key=f"p54-case-conc-{idx}",
            rule_id="asp-ssh-bruteforce",
            title="SSH brute force",
            level=AlertLevel.HIGH,
            window_start=t0 + timedelta(seconds=idx),
            window_end=t0 + timedelta(seconds=idx),
            group_key={"source.ip": "198.51.100.222"},
            event_count=5,
            event_uids=[f"c-{idx}"],
        )
        return alert_repo.correlate_alert_to_case(
            alert=alert,
            case_key=case_key,
            source_ip="198.51.100.222",
            idle_timeout_seconds=21_600,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_worker, range(8)))

    assert all(r is not None and r.id is not None for r in results)
    open_case = alert_repo.find_open_case_by_key(case_key)
    assert open_case is not None
    assert open_case.status == CaseStatus.OPEN
    assert len(open_case.alerts) == 8
    assert {r.id for r in results if r is not None} == {open_case.id}

