"""
Shared contract tests run identically against InMemory repositories and PostgreSQL repositories.
PostgreSQL tests run against ASP_DB_URL (skipped if ASP_DB_URL is not set) and clean up all rows.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from server.src.common.schemas import (
    AgentMetadata,
    Alert,
    AlertLevel,
    Case,
    CaseStatus,
    IngestBatchRequest,
    LogType,
    ParseStatus,
    RawEventFileMeta,
    RawLogEvent,
)
from server.src.common.security import hash_secret
from server.src.parsers.base import ParserRegistry
from server.src.repositories.base import IAlertRepository, IAuthRepository, ILogRepository
from server.src.repositories.memory import (
    InMemoryAlertRepository,
    InMemoryAuthRepository,
    InMemoryLogRepository,
)
from server.src.repositories.postgres import (
    PostgresAlertRepository,
    PostgresAuthRepository,
    PostgresLogRepository,
)
from tools.asp_migrate import run_migrations


@dataclass
class RepoBundle:
    log_repo: ILogRepository
    alert_repo: IAlertRepository
    auth_repo: IAuthRepository


def _cleanup_postgres(db_url: str, prefix: str) -> None:
    with psycopg.connect(db_url) as conn:
        with conn.transaction():
            conn.execute("DELETE FROM alerts WHERE rule_id LIKE %s", (f"{prefix}%",))
            conn.execute("DELETE FROM cases WHERE case_key LIKE %s", (f"{prefix}%",))
            conn.execute("DELETE FROM events WHERE agent_id LIKE %s", (f"{prefix}%",))
            conn.execute("DELETE FROM events_raw WHERE agent_id LIKE %s", (f"{prefix}%",))
            conn.execute("DELETE FROM agents WHERE id LIKE %s", (f"{prefix}%",))
            conn.execute("DELETE FROM operators WHERE id LIKE %s", (f"{prefix}%",))


@pytest.fixture(params=["memory", "postgres"])
def repo_bundle(request) -> RepoBundle:
    if request.param == "memory":
        yield RepoBundle(
            log_repo=InMemoryLogRepository(),
            alert_repo=InMemoryAlertRepository(),
            auth_repo=InMemoryAuthRepository(),
        )
        return

    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping PostgreSQL contract tests")

    run_migrations(db_url=db_url)
    prefix = "contract-"
    _cleanup_postgres(db_url, prefix)
    try:
        yield RepoBundle(
            log_repo=PostgresLogRepository(db_url),
            alert_repo=PostgresAlertRepository(db_url),
            auth_repo=PostgresAuthRepository(db_url),
        )
    finally:
        _cleanup_postgres(db_url, prefix)


def test_contract_raw_before_parse_dedup_and_error_isolation(repo_bundle: RepoBundle):
    repo_bundle.auth_repo.create_agent("contract-agent-1", hash_secret("k1"), "web-01")
    now = datetime(2026, 11, 10, 8, 30, 0, tzinfo=timezone.utc)

    raw1 = RawLogEvent(
        log_type=LogType.AUTH,
        file=RawEventFileMeta(
            path="/var/log/auth.log",
            device=2049,
            inode=100,
            stream_id="st-1",
            offset=0,
        ),
        collected_at=now,
        message="Oct 11 04:02:11 web-01 sshd[123]: Failed password for root from 198.51.100.23 port 41001 ssh2",
    )
    raw2 = RawLogEvent(
        log_type=LogType.AUTH,
        file=RawEventFileMeta(
            path="/var/log/auth.log",
            device=2049,
            inode=100,
            stream_id="st-1",
            offset=120,
        ),
        collected_at=now + timedelta(seconds=1),
        message="explode-trigger-line",
    )
    batch = IngestBatchRequest(
        schema_version="1.1",
        batch_id="contract-batch-1",
        sent_at=now + timedelta(seconds=2),
        agent=AgentMetadata(id="contract-agent-1", hostname="web-01", version="0.1.0", ip=["10.0.0.5"]),
        events=[raw1, raw2],
    )

    def faulty_parser(ev: RawLogEvent, agent: AgentMetadata, uid: str, ingested: datetime):
        if ev.message == "explode-trigger-line":
            raise RuntimeError("simulated parser crash")
        return ParserRegistry.parse_raw_event(ev, agent, uid, ingested)

    outcome = repo_bundle.log_repo.save_batch_with_parser(batch, faulty_parser, now + timedelta(seconds=3))
    assert len(outcome.new_events) == 2
    assert outcome.duplicate_count == 0
    assert outcome.parse_error_count == 1

    # Raw lines preserved verbatim before/regardless of parse error
    uid1 = batch.event_id_for(raw1)
    uid2 = batch.event_id_for(raw2)
    stored_raw1 = repo_bundle.log_repo.get_raw_event(uid1)
    stored_raw2 = repo_bundle.log_repo.get_raw_event(uid2)
    assert stored_raw1 is not None and stored_raw1["message"] == raw1.message
    assert stored_raw2 is not None and stored_raw2["message"] == "explode-trigger-line"

    # Error row still stored in events with parse_status='error'
    fetched = repo_bundle.log_repo.get_by_ids([uid1, uid2])
    assert len(fetched) == 2
    assert fetched[0].asp.parse_status == ParseStatus.OK
    assert fetched[1].asp.parse_status == ParseStatus.ERROR

    # Sending the exact same batch twice yields 0 new events and 2 duplicates
    second = repo_bundle.log_repo.save_batch_with_parser(batch, faulty_parser, now + timedelta(seconds=4))
    assert second.new_events == []
    assert second.duplicate_count == 2

    # Query via find_events
    by_ip = repo_bundle.log_repo.find_events({"source.ip": "198.51.100.23"}, limit=10)
    assert len(by_ip) == 1
    assert by_ip[0].event.id == uid1


def test_contract_alerts_and_cases_lifecycle(repo_bundle: RepoBundle):
    now = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
    alert1 = Alert(
        alert_key="contract-rule-1:ip1:1",
        rule_id="contract-rule-1",
        title="SSH Brute Force",
        level=AlertLevel.HIGH,
        window_start=now,
        window_end=now,
        group_key={"source.ip": "198.51.100.50", "host.name": "web-01"},
        event_count=5,
        event_uids=["e" * 40],
    )
    saved1 = repo_bundle.alert_repo.save_alert(alert1)
    assert saved1 is not None and saved1.id is not None

    # Duplicate alert_key is ignored (returns None)
    dup = repo_bundle.alert_repo.save_alert(alert1)
    assert dup is None

    case = Case(
        case_key="contract-ip:198.51.100.50",
        source_ip="198.51.100.50",
        level=AlertLevel.HIGH,
        status=CaseStatus.OPEN,
        first_activity_at=now,
        last_activity_at=now,
        alerts=[saved1],
    )
    saved_case = repo_bundle.alert_repo.save_case(case)
    assert saved_case.id is not None
    assert len(saved_case.alerts) == 1

    found = repo_bundle.alert_repo.find_open_case_by_key("contract-ip:198.51.100.50")
    assert found is not None and found.id == saved_case.id

    repo_bundle.alert_repo.update_case_with_agent_report(
        saved_case.id,
        {
            "agent_verdict": "True Positive",
            "agent_confidence": 0.9,
            "agent_report_markdown": "# OK",
        },
    )
    reloaded = repo_bundle.alert_repo.get_case(saved_case.id)
    assert reloaded is not None
    assert reloaded.agent_verdict == "True Positive"
    assert reloaded.agent_confidence == 0.9


def test_contract_auth_agent_and_operator_crud(repo_bundle: RepoBundle):
    h1 = hash_secret("secret-agent-key-1")
    h2 = hash_secret("secret-agent-key-2")
    created = repo_bundle.auth_repo.create_agent("contract-ag-auth", h1, "node-1")
    assert created.id == "contract-ag-auth"

    found = repo_bundle.auth_repo.get_agent_by_key_hash(h1)
    assert found is not None and found.id == "contract-ag-auth"

    now = datetime.now(timezone.utc)
    repo_bundle.auth_repo.touch_agent_last_seen("contract-ag-auth", now)
    ag_after = repo_bundle.auth_repo.get_agent("contract-ag-auth")
    assert ag_after is not None and ag_after.last_seen is not None

    assert repo_bundle.auth_repo.rotate_agent_key("contract-ag-auth", h2) is True
    assert repo_bundle.auth_repo.get_agent_by_key_hash(h1) is None
    assert repo_bundle.auth_repo.get_agent_by_key_hash(h2) is not None

    assert repo_bundle.auth_repo.revoke_agent("contract-ag-auth") is True
    assert repo_bundle.auth_repo.get_agent_by_key_hash(h2) is None

    op_hash = hash_secret("secret-op-token")
    op = repo_bundle.auth_repo.create_operator("contract-op-1", op_hash, ["read", "investigate"])
    assert op.id == "contract-op-1"
    op_found = repo_bundle.auth_repo.get_operator_by_token_hash(op_hash)
    assert op_found is not None and "investigate" in op_found.scopes

    assert repo_bundle.auth_repo.revoke_operator("contract-op-1") is True
    assert repo_bundle.auth_repo.get_operator_by_token_hash(op_hash) is None



def test_contract_nul_bytes_in_raw_message_sanitized(repo_bundle: RepoBundle):
    repo_bundle.auth_repo.create_agent("contract-agent-nul", hash_secret("k-nul"), "web-nul")
    now = datetime(2026, 11, 10, 8, 30, 0, tzinfo=timezone.utc)
    raw = RawLogEvent(
        log_type=LogType.SYSLOG,
        file=RawEventFileMeta(
            path="/var/log/syslog",
            device=2049,
            inode=101,
            stream_id="st-nul",
            offset=0,
        ),
        collected_at=now,
        message="\x00\x00\x00Nov 10 08:30:00 web-nul app[1]: line with nul byte\x00",
    )
    batch = IngestBatchRequest(
        schema_version="1.1",
        batch_id="contract-batch-nul",
        sent_at=now,
        agent=AgentMetadata(id="contract-agent-nul", hostname="web-nul", version="0.1.0"),
        events=[raw],
    )

    def _ok_unparsed(raw_ev, agent, event_uid, ingested_at):
        return parse(
            raw_ev.log_type.value,
            raw_ev.message,
            {
                "event_uid": event_uid,
                "collected_at": raw_ev.collected_at,
                "received_at": ingested_at,
                "agent": agent.model_dump(mode="json"),
                "log": {"file": {"path": raw_ev.file.path}},
            },
        )

    outcome = repo_bundle.log_repo.save_batch_with_parser(batch, _ok_unparsed, now)
    assert len(outcome.new_events) == 1
    uid = outcome.new_events[0].event.id
    stored = repo_bundle.log_repo.get_by_ids([uid])
    assert len(stored) == 1
