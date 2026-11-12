"""
Unit tests for Phase 1 controls: asp_admin CLI helpers, rate limiter,
post-commit timestamp sorting, engine lock, and engine exception isolation.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from server.src.common.schemas import (
    AgentMetadata,
    AlertLevel,
    ECSEvent,
    IngestBatchRequest,
    LogType,
    RawEventFileMeta,
    RawLogEvent,
)
from server.src.common.security import InMemoryRateLimiter, hash_secret, verify_secret_hash
from server.src.engine.base import BaseRule, RuleEngine
from server.src.engine.state_store import InMemorySlidingWindowStore
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
from server.src.services.ingestion_service import IngestionService
from tools.asp_admin import run_admin_command
from tools.asp_migrate import run_migrations


def test_asp_admin_lifecycle():
    repo = InMemoryAuthRepository()

    key1 = run_admin_command(repo, "create-agent", "web-01", hostname="web-01")
    assert key1 is not None and len(key1) >= 32
    assert repo.get_agent_by_key_hash(hash_secret(key1)) is not None

    key2 = run_admin_command(repo, "rotate-agent-key", "web-01")
    assert key2 is not None and key2 != key1
    assert repo.get_agent_by_key_hash(hash_secret(key1)) is None
    assert repo.get_agent_by_key_hash(hash_secret(key2)) is not None

    run_admin_command(repo, "revoke-agent", "web-01")
    assert repo.get_agent_by_key_hash(hash_secret(key2)) is None

    op_tok = run_admin_command(repo, "create-operator", "alice", scopes=["read", "investigate"])
    assert op_tok is not None
    op = repo.get_operator_by_token_hash(hash_secret(op_tok))
    assert op is not None and op.scopes == ["read", "investigate"]

    run_admin_command(repo, "revoke-operator", "alice")
    assert repo.get_operator_by_token_hash(hash_secret(op_tok)) is None


def test_rate_limiter_token_bucket():
    limiter = InMemoryRateLimiter(rate_per_minute=2)
    assert limiter.allow("agent-1", now=100.0) is True
    assert limiter.allow("agent-1", now=100.0) is True
    assert limiter.allow("agent-1", now=100.0) is False
    # After 30 seconds at 2/min, 1 token refills
    assert limiter.allow("agent-1", now=130.0) is True


class _RecordingRule(BaseRule):
    rule_id = "rec-1"
    rule_name = "Recorder"
    level = AlertLevel.LOW
    supported_log_types = {LogType.AUTH}

    def __init__(self) -> None:
        self.seen_timestamps: list[datetime] = []

    def evaluate(self, event: ECSEvent):
        self.seen_timestamps.append(event.timestamp)
        return None


class _ExplodingRule(BaseRule):
    rule_id = "boom-1"
    rule_name = "Boom"
    level = AlertLevel.HIGH
    supported_log_types = {LogType.AUTH}

    def evaluate(self, event: ECSEvent):
        raise RuntimeError("rule engine boom")


def test_ingestion_sorts_by_ts_and_isolates_engine_failures():
    t0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
    raw_late = RawLogEvent(
        log_type=LogType.AUTH,
        file=RawEventFileMeta(path="/var/log/auth.log", device=1, inode=1, stream_id="s", offset=0),
        collected_at=t0 + timedelta(seconds=20),
        message="late timestamp line",
    )
    raw_early = RawLogEvent(
        log_type=LogType.AUTH,
        file=RawEventFileMeta(path="/var/log/auth.log", device=1, inode=1, stream_id="s", offset=50),
        collected_at=t0,
        message="early timestamp line",
    )
    batch = IngestBatchRequest(
        schema_version="1.1",
        batch_id="b-sort",
        sent_at=t0 + timedelta(seconds=30),
        agent=AgentMetadata(id="ag-1", hostname="h1", version="0.1.0"),
        events=[raw_late, raw_early],
    )

    log_repo = InMemoryLogRepository()
    alert_repo = InMemoryAlertRepository()
    rec_rule = _RecordingRule()
    svc = IngestionService(log_repo, alert_repo, RuleEngine([rec_rule]))

    res = svc.ingest_batch(batch)
    assert res.accepted == 2
    assert rec_rule.seen_timestamps == [t0, t0 + timedelta(seconds=20)]

    # Verify engine crash inside evaluate_batch does not fail ingest after commit
    class _BrokenEngine(RuleEngine):
        def evaluate_batch(self, events):
            raise RuntimeError("unexpected engine crash")

    log_repo2 = InMemoryLogRepository()
    svc2 = IngestionService(log_repo2, InMemoryAlertRepository(), _BrokenEngine())
    res2 = svc2.ingest_batch(batch)
    assert res2.accepted == 2
    assert len(log_repo2.get_by_ids([batch.event_id_for(raw_late), batch.event_id_for(raw_early)])) == 2


def test_verify_secret_hash_constant_time():
    secret = "super-secret-token-value"
    digest = hash_secret(secret)
    assert verify_secret_hash(secret, digest) is True
    assert verify_secret_hash("wrong-token", digest) is False


def test_state_store_memory_bounds():
    store = InMemorySlidingWindowStore(max_window_events=3, max_keys=2)
    t0 = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Cap per key at 3
    for i in range(5):
        win = store.add_and_get_window("k1", f"e{i}", t0 + timedelta(seconds=i), 60)
    assert win == ["e2", "e3", "e4"]

    # Adding k2 keeps both k1 and k2 (max_keys=2)
    store.add_and_get_window("k2", "x1", t0, 60)
    assert store.key_count() == 2

    # Touch k1 so k2 becomes least-recently-used; adding k3 evicts k2
    store.add_and_get_window("k1", "e5", t0 + timedelta(seconds=6), 60)
    store.add_and_get_window("k3", "y1", t0 + timedelta(seconds=7), 60)
    assert store.key_count() == 2
    assert store.get_window_events("k2", t0 + timedelta(seconds=7), 60) == []
    assert store.get_window_events("k1", t0 + timedelta(seconds=7), 60) == ["e3", "e4", "e5"]


def test_duplicate_events_do_not_enter_rule_engine():
    t0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
    raw = RawLogEvent(
        log_type=LogType.AUTH,
        file=RawEventFileMeta(path="/var/log/auth.log", device=1, inode=1, stream_id="s", offset=0),
        collected_at=t0,
        message="line 1",
    )
    batch = IngestBatchRequest(
        schema_version="1.1",
        batch_id="b-dup-engine",
        sent_at=t0,
        agent=AgentMetadata(id="ag-1", hostname="h1", version="0.1.0"),
        events=[raw],
    )
    rec_rule = _RecordingRule()
    svc = IngestionService(InMemoryLogRepository(), InMemoryAlertRepository(), RuleEngine([rec_rule]))

    res1 = svc.ingest_batch(batch)
    res2 = svc.ingest_batch(batch)
    assert res1.accepted == 1 and res1.duplicates == 0
    assert res2.accepted == 0 and res2.duplicates == 1
    assert len(rec_rule.seen_timestamps) == 1


def test_concurrent_ingest_threads_serialized_by_lock():
    overlap_detected = False
    active_count = 0
    counter_guard = threading.Lock()

    class _SlowNonReentrantRule(BaseRule):
        rule_id = "slow-1"
        rule_name = "Slow"
        level = AlertLevel.LOW
        supported_log_types = {LogType.AUTH}

        def evaluate(self, event: ECSEvent):
            nonlocal active_count, overlap_detected
            with counter_guard:
                active_count += 1
                if active_count > 1:
                    overlap_detected = True
            time.sleep(0.02)
            with counter_guard:
                active_count -= 1
            return None

    t0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
    shared_lock = threading.Lock()
    svc = IngestionService(
        InMemoryLogRepository(),
        InMemoryAlertRepository(),
        RuleEngine([_SlowNonReentrantRule()]),
        engine_lock=shared_lock,
    )

    def _worker(offset: int) -> None:
        batch = IngestBatchRequest(
            schema_version="1.1",
            batch_id=f"b-thread-{offset}",
            sent_at=t0,
            agent=AgentMetadata(id="ag-t", hostname="h1", version="0.1.0"),
            events=[
                RawLogEvent(
                    log_type=LogType.AUTH,
                    file=RawEventFileMeta(path="/var/log/auth.log", device=1, inode=1, stream_id="s", offset=offset),
                    collected_at=t0,
                    message=f"msg {offset}",
                )
            ],
        )
        svc.ingest_batch(batch)

    t1 = threading.Thread(target=_worker, args=(0,))
    t2 = threading.Thread(target=_worker, args=(100,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert overlap_detected is False


def test_postgres_post_commit_engine_failure_still_persists_rows():
    db_url = os.environ.get("ASP_DB_URL")
    if not db_url:
        pytest.skip("ASP_DB_URL not set; skipping live PostgreSQL P1.G check")

    run_migrations(db_url=db_url)
    agent_id = "p1g-agent-err"
    try:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

        auth_repo = PostgresAuthRepository(db_url)
        auth_repo.create_agent(agent_id, hash_secret("p1g-secret"), "lab-host")

        class _BrokenEngine(RuleEngine):
            def evaluate_batch(self, events):
                raise RuntimeError("post-commit boom")

        log_repo = PostgresLogRepository(db_url)
        svc = IngestionService(log_repo, PostgresAlertRepository(db_url), _BrokenEngine())
        t0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
        raw = RawLogEvent(
            log_type=LogType.AUTH,
            file=RawEventFileMeta(path="/var/log/auth.log", device=1, inode=1, stream_id="s1", offset=0),
            collected_at=t0,
            message="Oct 11 04:02:11 lab-host sshd[1]: Failed password for root from 198.51.100.23 port 22 ssh2",
        )
        batch = IngestBatchRequest(
            schema_version="1.1",
            batch_id="p1g-batch",
            sent_at=t0,
            agent=AgentMetadata(id=agent_id, hostname="lab-host", version="0.1.0"),
            events=[raw],
        )

        res = svc.ingest_batch(batch)
        assert res.accepted == 1
        uid = batch.event_id_for(raw)
        assert log_repo.get_raw_event(uid) is not None
        assert len(log_repo.get_by_ids([uid])) == 1
    finally:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))

