"""
Unit tests for Detection Rules (SudoAbuseRule and SSHBruteForceRule).
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from server.src.common.schemas import EventOutcome, LogEventEnvelope, LogType, Severity
from server.src.engine.rules.ssh_bruteforce import SSHBruteForceRule
from server.src.engine.rules.sudo_abuse import SudoAbuseRule
from server.src.engine.state_store import InMemorySlidingWindowStore


def make_envelope(
    raw: str,
    fields: dict,
    timestamp: datetime = None,
    hostname: str = "web-01",
    log_type: LogType = LogType.AUTH,
) -> LogEventEnvelope:
    return LogEventEnvelope(
        event_id=uuid4(),
        timestamp=timestamp or datetime.now(timezone.utc),
        agent_id="test-agent",
        hostname=hostname,
        log_type=log_type,
        source_file="/var/log/auth.log",
        raw=raw,
        fields=fields,
    )


# ============================================================================
# SudoAbuseRule Tests
# ============================================================================

def test_sudo_abuse_rule_triggers_on_failure():
    rule = SudoAbuseRule()
    event = make_envelope(
        raw="sudo: alice : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/sh",
        fields={
            "service": "sudo",
            "event_outcome": EventOutcome.FAILURE.value,
            "failure_reason": "user NOT in sudoers",
            "user": "alice",
            "target_user": "root",
            "command": "/bin/sh",
        },
    )

    alert = rule.evaluate(event)
    assert alert is not None
    assert alert.rule_id == "RULE-AUTH-SUDO-001"
    assert alert.severity == Severity.HIGH
    assert alert.context["user"] == "alice"
    assert alert.context["command"] == "/bin/sh"
    assert alert.evidence_raw_events == [event.event_id]
    assert "T1548.003" in alert.mitre_techniques


def test_sudo_abuse_rule_ignores_successful_sudo():
    rule = SudoAbuseRule()
    event = make_envelope(
        raw="sudo: ubuntu : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls",
        fields={
            "service": "sudo",
            "event_outcome": EventOutcome.SUCCESS.value,
            "user": "ubuntu",
            "target_user": "root",
            "command": "/bin/ls",
        },
    )

    alert = rule.evaluate(event)
    assert alert is None


# ============================================================================
# SSHBruteForceRule Tests
# ============================================================================

def test_ssh_bruteforce_rule_sliding_window():
    state_store = InMemorySlidingWindowStore()
    rule = SSHBruteForceRule(threshold=5, window_seconds=300, state_store=state_store)

    base_time = datetime(2026, 10, 11, 4, 0, 0, tzinfo=timezone.utc)
    attacker_ip = "198.51.100.99"
    created_events = []

    # Send 4 failed attempts spaced 30 seconds apart (under threshold)
    for i in range(4):
        event_time = base_time + timedelta(seconds=i * 30)
        ev = make_envelope(
            raw=f"Failed password for user{i} from {attacker_ip}",
            fields={
                "service": "sshd",
                "event_outcome": EventOutcome.FAILURE.value,
                "src_ip": attacker_ip,
                "user": f"user{i}",
            },
            timestamp=event_time,
        )
        created_events.append(ev)
        alert = rule.evaluate(ev)
        assert alert is None, f"Attempt {i+1} should not trigger an alert yet"

    # Send 5th attempt at t = 120s (within 300s window) -> should trigger Alert
    fifth_event_time = base_time + timedelta(seconds=120)
    ev5 = make_envelope(
        raw=f"Failed password for user4 from {attacker_ip}",
        fields={
            "service": "sshd",
            "event_outcome": EventOutcome.FAILURE.value,
            "src_ip": attacker_ip,
            "user": "user4",
        },
        timestamp=fifth_event_time,
    )
    created_events.append(ev5)
    alert = rule.evaluate(ev5)

    assert alert is not None
    assert alert.rule_id == "RULE-AUTH-SSH-002"
    assert alert.severity == Severity.HIGH
    assert alert.context["attacker_ip"] == attacker_ip
    assert alert.context["failure_count"] == 5
    assert len(alert.evidence_raw_events) == 5
    assert all(e.event_id in alert.evidence_raw_events for e in created_events)


def test_ssh_bruteforce_rule_window_expiration():
    state_store = InMemorySlidingWindowStore()
    rule = SSHBruteForceRule(threshold=5, window_seconds=300, state_store=state_store)

    base_time = datetime(2026, 10, 11, 4, 0, 0, tzinfo=timezone.utc)
    attacker_ip = "203.0.113.88"

    # 4 attempts at t = 0
    for i in range(4):
        ev = make_envelope(
            raw=f"Failed password from {attacker_ip}",
            fields={
                "service": "sshd",
                "event_outcome": EventOutcome.FAILURE.value,
                "src_ip": attacker_ip,
            },
            timestamp=base_time,
        )
        rule.evaluate(ev)

    # 5th attempt arrives 400 seconds later (window expired: 400 > 300)
    expired_time = base_time + timedelta(seconds=400)
    ev_late = make_envelope(
        raw=f"Failed password from {attacker_ip}",
        fields={
            "service": "sshd",
            "event_outcome": EventOutcome.FAILURE.value,
            "src_ip": attacker_ip,
        },
        timestamp=expired_time,
    )

    alert = rule.evaluate(ev_late)
    # The previous 4 attempts fell out of the 300s window, so current count is 1, not 5.
    assert alert is None


def test_ssh_bruteforce_rule_different_ips_isolated():
    state_store = InMemorySlidingWindowStore()
    rule = SSHBruteForceRule(threshold=3, window_seconds=300, state_store=state_store)
    now = datetime.now(timezone.utc)

    # 2 failures for IP A
    for _ in range(2):
        ev = make_envelope(
            raw="Failed password",
            fields={"service": "sshd", "event_outcome": EventOutcome.FAILURE.value, "src_ip": "1.1.1.1"},
            timestamp=now,
        )
        assert rule.evaluate(ev) is None

    # 2 failures for IP B
    for _ in range(2):
        ev = make_envelope(
            raw="Failed password",
            fields={"service": "sshd", "event_outcome": EventOutcome.FAILURE.value, "src_ip": "2.2.2.2"},
            timestamp=now,
        )
        assert rule.evaluate(ev) is None

    # Neither exceeded threshold 3

