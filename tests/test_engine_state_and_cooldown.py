"""
Tests for P5.3: Event-time Cooldown, 200-UID capping, allowed_lateness out-of-order handling,
and Postgres startup window/cooldown state recovery.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import psycopg
import pytest

from server.src.api.dependencies import Container
from server.src.common.schemas import (
    AgentMetadata,
    ECSEvent,
    IngestBatchRequest,
    LogType,
    RawEventFileMeta,
    RawLogEvent,
    compute_event_id,
)
from server.src.engine.base import RuleEngine
from server.src.engine.generic_rules import build_rule_from_spec
from server.src.engine.loader import load_rule_spec_from_file
from server.src.engine.state_store import InMemorySlidingWindowStore
from server.src.parsers import parse

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"


def _make_ssh_fail(ip: str, ts: datetime, idx: int) -> ECSEvent:
    ts_str = ts.astimezone(timezone.utc).strftime("%b %d %H:%M:%S")
    uid = compute_event_id("agent-cd", 1, 1, "s-cd", idx)
    return parse(
        "auth",
        f"{ts_str} web-01 sshd[{idx}]: Failed password for root from {ip} port 51000 ssh2",
        {
            "event_uid": uid,
            "collected_at": ts,
            "received_at": ts,
            "agent": {"id": "agent-cd", "hostname": "web-01", "version": "0.1.0", "timezone": "UTC"},
            "default_timezone": "UTC",
        },
    )


def test_event_time_cooldown_and_slot_boundary():
    store = InMemorySlidingWindowStore()
    spec = load_rule_spec_from_file(RULES_DIR / "asp-ssh-bruteforce.yaml")
    rule = build_rule_from_spec(spec, state_store=store, allowed_lateness_seconds=60)
    assert rule.cooldown_seconds == 600  # 10m

    # Slot 0: epoch 1794384000 (divisible by 600)
    t_slot0 = datetime.fromtimestamp(1794384000 + 10, tz=timezone.utc)
    alerts = []
    for i in range(7):
        res = rule.evaluate(_make_ssh_fail("198.51.100.70", t_slot0 + timedelta(seconds=i * 5), i))
        if res is not None:
            alerts.append(res)

    # First fire on 5th event, 6th and 7th suppressed within same 10m slot
    assert len(alerts) == 1
    expected_slot0 = (int(t_slot0.timestamp()) + 20) // 600
    assert alerts[0].alert_key == f"asp-ssh-bruteforce:198.51.100.70:{expected_slot0}"

    # Next cooldown slot (t_slot0 + 605s, still inside 5m window? No, 5 new events at +610s)
    t_slot1 = t_slot0 + timedelta(seconds=610)
    slot1_alerts = []
    for i in range(5):
        res = rule.evaluate(_make_ssh_fail("198.51.100.70", t_slot1 + timedelta(seconds=i * 2), 100 + i))
        if res is not None:
            slot1_alerts.append(res)
    assert len(slot1_alerts) == 1
    assert slot1_alerts[0].alert_key != alerts[0].alert_key


def test_match_rule_no_cooldown_and_200_event_uids_cap():
    # 1. Match rule has no cooldown -> two identical sudo abuse events emit two alerts
    spec_match = load_rule_spec_from_file(RULES_DIR / "asp-sudo-abuse.yaml")
    match_rule = build_rule_from_spec(spec_match)
    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)
    for i in range(2):
        ev = parse(
            "auth",
            "Nov 10 08:00:05 web-01 sudo: mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/id",
            {
                "event_uid": f"sudo-match-{i}",
                "collected_at": t0,
                "received_at": t0,
                "agent": {"id": "a", "hostname": "web-01", "version": "0.1.0", "timezone": "UTC"},
                "default_timezone": "UTC",
            },
        )
        al = match_rule.evaluate(ev)
        assert al is not None
        assert al.alert_key == f"asp-sudo-abuse:sudo-match-{i}"

    # 2. 230 matching events in window -> event_count=230, event_uids capped at 200 (100 head + 100 tail)
    store = InMemorySlidingWindowStore()
    spec_high = load_rule_spec_from_file(RULES_DIR / "asp-ssh-bruteforce.yaml").model_copy(
        update={
            "detection": load_rule_spec_from_file(RULES_DIR / "asp-ssh-bruteforce.yaml").detection.model_copy(
                update={"condition": {"gte": 230}}
            )
        }
    )
    high_rule = build_rule_from_spec(spec_high, state_store=store)
    events: List[ECSEvent] = []
    fired = None
    for i in range(230):
        ev = _make_ssh_fail("198.51.100.77", t0 + timedelta(seconds=i), 500 + i)
        events.append(ev)
        res = high_rule.evaluate(ev)
        if res is not None:
            fired = res

    assert fired is not None
    assert fired.event_count == 230
    assert len(fired.event_uids) == 200
    assert fired.event_uids[:100] == [e.event.id for e in events[:100]]
    assert fired.event_uids[-100:] == [e.event.id for e in events[-100:]]


def test_allowed_lateness_updates_window_without_firing_late_alert():
    store = InMemorySlidingWindowStore()
    spec = load_rule_spec_from_file(RULES_DIR / "asp-ssh-bruteforce.yaml")
    rule = build_rule_from_spec(spec, state_store=store, allowed_lateness_seconds=60)

    t0 = datetime(2026, 11, 10, 8, 0, 0, tzinfo=timezone.utc)
    # 4 events up to t = 150s -> not yet 5
    for idx, sec in enumerate([0, 10, 20, 150]):
        assert rule.evaluate(_make_ssh_fail("198.51.100.80", t0 + timedelta(seconds=sec), idx)) is None

    # Late event arrives at ts = 30s (< 150 - 60 = 90) -> inserts into sorted window, NO alert fires!
    late_ev = _make_ssh_fail("198.51.100.80", t0 + timedelta(seconds=30), 99)
    assert rule.evaluate(late_ev) is None

    # Verify the late event is preserved in the sorted window
    entries = store.get_window_entries("asp-ssh-bruteforce:198.51.100.80", t0 + timedelta(seconds=150), 300)
    assert [e.event_id for e in entries] == [
        compute_event_id("agent-cd", 1, 1, "s-cd", 0),
        compute_event_id("agent-cd", 1, 1, "s-cd", 1),
        compute_event_id("agent-cd", 1, 1, "s-cd", 2),
        compute_event_id("agent-cd", 1, 1, "s-cd", 99),
        compute_event_id("agent-cd", 1, 1, "s-cd", 3),
    ]

    # Timely event at ts = 160s is not late -> triggers alert containing all 6 events
    alert = rule.evaluate(_make_ssh_fail("198.51.100.80", t0 + timedelta(seconds=160), 100))
    assert alert is not None
    assert alert.event_count == 6
    assert late_ev.event.id in alert.event_uids


def _get_db_url_or_skip() -> str:
    url = os.environ.get("ASP_DB_URL")
    if not url:
        pytest.skip("ASP_DB_URL not set; skipping Postgres startup reload test")
    return url


def test_postgres_restart_reloads_sliding_window_and_cooldown():
    db_url = _get_db_url_or_skip()
    agent_id = "test-p53-restart-agent"
    attacker_ip = "198.51.100.91"
    base_ts = datetime(2026, 11, 10, 10, 0, 10, tzinfo=timezone.utc)

    def _raw_batch(batch_id: str, start_idx: int, count: int) -> IngestBatchRequest:
        evs = []
        for offset_i in range(count):
            idx = start_idx + offset_i
            ts = base_ts + timedelta(seconds=idx * 10)
            ts_str = ts.strftime("%b %d %H:%M:%S")
            evs.append(
                RawLogEvent(
                    log_type=LogType.AUTH,
                    file=RawEventFileMeta(
                        path="/var/log/auth.log",
                        device=2049,
                        inode=55555,
                        stream_id="p53-restart-stream",
                        offset=idx * 150,
                    ),
                    collected_at=ts,
                    message=f"{ts_str} srv-p53 sshd[{idx}]: Failed password for root from {attacker_ip} port 5200{idx} ssh2",
                )
            )
        return IngestBatchRequest(
            schema_version="1.1",
            batch_id=batch_id,
            sent_at=base_ts + timedelta(minutes=2),
            agent=AgentMetadata(id=agent_id, hostname="srv-p53", version="0.1.0", timezone="UTC"),
            events=evs,
        )

    try:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO agents (id, api_key_hash, hostname)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (agent_id, "sha256:p53-test-hash", "srv-p53"),
                )

        # 1. Start server #1 and ingest 4 failures (below threshold 5)
        c1 = Container(db_url=db_url)
        res1 = c1.ingestion_service.ingest_batch(_raw_batch("b-p53-1", 0, 4))
        assert res1.accepted == 4
        assert c1.alert_repo.find_open_case_by_key(f"ip:{attacker_ip}") is None

        # 2. Simulate full server restart -> fresh store & rule_engine rehydrated from Postgres
        c2 = Container(db_url=db_url)
        # No alert should have been emitted just from reloading!
        assert c2.alert_repo.find_open_case_by_key(f"ip:{attacker_ip}") is None

        # 5th failure arrives -> rehydrated window hits 5 and fires alert!
        res2 = c2.ingestion_service.ingest_batch(_raw_batch("b-p53-2", 4, 1))
        assert res2.accepted == 1
        open_case = c2.alert_repo.find_open_case_by_key(f"ip:{attacker_ip}")
        assert open_case is not None
        assert len(open_case.alerts) == 1
        assert open_case.alerts[0].rule_id == "asp-ssh-bruteforce"
        assert open_case.alerts[0].event_count == 5

        # 3. Restart AGAIN -> reloads cooldown slot from DB alerts; 6th event must NOT create duplicate alert!
        c3 = Container(db_url=db_url)
        res3 = c3.ingestion_service.ingest_batch(_raw_batch("b-p53-3", 5, 1))
        assert res3.accepted == 1
        open_case_after = c3.alert_repo.find_open_case_by_key(f"ip:{attacker_ip}")
        assert open_case_after is not None
        assert len(open_case_after.alerts) == 1
    finally:
        with psycopg.connect(db_url) as conn:
            with conn.transaction():
                conn.execute("DELETE FROM alerts WHERE case_id IN (SELECT id FROM cases WHERE case_key = %s)", (f"ip:{attacker_ip}",))
                conn.execute("DELETE FROM cases WHERE case_key = %s", (f"ip:{attacker_ip}",))
                conn.execute("DELETE FROM events WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM events_raw WHERE agent_id = %s", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id = %s", (agent_id,))
