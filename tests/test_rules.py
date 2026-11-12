"""
Tests for all 6 YAML detection rules (Section 9.7) and samples/rules/*.log.
Verifies positive/negative detection through the real parser + YAML RuleEngine pipeline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from server.src.common.schemas import Alert, AlertLevel, ECSEvent, LogType, ParseStatus, RawLogEvent
from server.src.engine.base import RuleEngine
from server.src.engine.generic_rules import build_rule_from_spec
from server.src.engine.loader import load_rule_specs_from_dir
from server.src.engine.state_store import InMemorySlidingWindowStore
from server.src.parsers import parse

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"
SAMPLES_RULES_DIR = REPO_ROOT / "samples" / "rules"


def _build_engine() -> tuple[RuleEngine, InMemorySlidingWindowStore]:
    store = InMemorySlidingWindowStore()
    specs = load_rule_specs_from_dir(RULES_DIR)
    rules = [build_rule_from_spec(spec, state_store=store, allowed_lateness_seconds=60) for spec in specs]
    return RuleEngine(rules), store


def _run_sample_file(filename: str, log_type: LogType) -> List[Alert]:
    engine, _ = _build_engine()
    collected_at = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
    lines = (SAMPLES_RULES_DIR / filename).read_text(encoding="utf-8").splitlines()
    events: List[ECSEvent] = []
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        raw = RawLogEvent.model_validate(
            {
                "log_type": log_type.value,
                "file": {
                    "path": "/var/log/auth.log" if log_type == LogType.AUTH else "/var/log/apache2/access.log",
                    "device": 2049,
                    "inode": 9001,
                    "stream_id": f"sample-{filename}",
                    "offset": idx * 128,
                },
                "collected_at": collected_at,
                "message": line,
            }
        )
        meta = {
            "event_uid": raw.file.stream_id + f":{idx}",
            "collected_at": collected_at,
            "received_at": collected_at,
            "agent": {"id": "test-agent", "hostname": "web-01", "version": "0.1.0", "timezone": "Asia/Ho_Chi_Minh"},
            "log": {"file": {"path": raw.file.path, "device": 2049, "inode": 9001, "offset": idx * 128}},
            "default_timezone": "Asia/Ho_Chi_Minh",
            "future_tolerance_seconds": 300,
        }
        ev = parse(log_type.value, line, meta)
        assert ev.asp.parse_status == ParseStatus.OK, f"Line failed to parse in {filename}: {line}"
        events.append(ev)

    return engine.evaluate_batch(events)


def test_all_six_yaml_rules_load_cleanly():
    specs = load_rule_specs_from_dir(RULES_DIR)
    rule_ids = {s.id for s in specs}
    assert rule_ids == {
        "asp-ssh-bruteforce",
        "asp-password-spraying",
        "asp-bruteforce-then-success",
        "asp-web-scan-404",
        "asp-sudo-to-root-shell",
        "asp-sudo-abuse",
    }


def test_ssh_bruteforce_pos_and_invalid_user_not_double_counted():
    pos_alerts = _run_sample_file("ssh_bruteforce_pos.log", LogType.AUTH)
    ssh_alerts = [a for a in pos_alerts if a.rule_id == "asp-ssh-bruteforce"]
    assert len(ssh_alerts) == 1
    assert ssh_alerts[0].level == AlertLevel.HIGH
    assert ssh_alerts[0].group_key["source.ip"] == "198.51.100.10"
    assert ssh_alerts[0].event_count == 5

    # 4 pairs of Invalid user + Failed password = 8 lines, must only count 4 failures (< 5)
    neg_alerts = _run_sample_file("ssh_bruteforce_invalid_user_neg.log", LogType.AUTH)
    assert neg_alerts == []


def test_ssh_bruteforce_window_expiration_and_ip_isolation():
    engine, _ = _build_engine()
    collected = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)

    def _ev(ip: str, sec_offset: int, idx: int) -> ECSEvent:
        ts_str = (datetime(2026, 11, 10, 8, 0, 0) + timedelta(seconds=sec_offset)).strftime("%b %d %H:%M:%S")
        line = f"{ts_str} web-01 sshd[{idx}]: Failed password for root from {ip} port 50000 ssh2"
        return parse(
            "auth",
            line,
            {
                "event_uid": f"ev-{ip}-{idx}",
                "collected_at": collected,
                "received_at": collected,
                "agent": {"id": "a1", "hostname": "web-01", "version": "0.1.0", "timezone": "UTC"},
                "default_timezone": "UTC",
            },
        )

    # 4 attempts at t=0..30s from IP A, then 1 late attempt after 5m -> expired -> no alert
    for i in range(4):
        assert engine.evaluate_event(_ev("203.0.113.88", i * 10, i)) == []
    assert engine.evaluate_event(_ev("203.0.113.88", 400, 10)) == []

    # Distinct IPs do not merge into each other's window
    for i in range(3):
        assert engine.evaluate_event(_ev("1.1.1.1", i, 100 + i)) == []
        assert engine.evaluate_event(_ev("2.2.2.2", i, 200 + i)) == []


def test_password_spraying_pos_and_neg():
    pos_alerts = _run_sample_file("password_spraying_pos.log", LogType.AUTH)
    spray_alerts = [a for a in pos_alerts if a.rule_id == "asp-password-spraying"]
    assert len(spray_alerts) == 1
    assert spray_alerts[0].level == AlertLevel.HIGH
    assert spray_alerts[0].group_key["source.ip"] == "198.51.100.20"

    neg_alerts = _run_sample_file("password_spraying_neg.log", LogType.AUTH)
    assert [a for a in neg_alerts if a.rule_id == "asp-password-spraying"] == []


def test_bruteforce_then_success_pos_and_neg():
    pos_alerts = _run_sample_file("bruteforce_then_success_pos.log", LogType.AUTH)
    seq_alerts = [a for a in pos_alerts if a.rule_id == "asp-bruteforce-then-success"]
    assert len(seq_alerts) == 1
    assert seq_alerts[0].level == AlertLevel.CRITICAL
    assert seq_alerts[0].group_key["source.ip"] == "198.51.100.30"
    assert seq_alerts[0].event_count == 6

    # Reverse order sample does not trigger
    neg_alerts = _run_sample_file("bruteforce_then_success_neg.log", LogType.AUTH)
    assert neg_alerts == []

    # Timespan overflow (> 10m between first fail and later success) must NOT fire sequence
    engine, _ = _build_engine()
    collected = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(5):
        ts_str = (datetime(2026, 11, 10, 7, 0, i * 5)).strftime("%b %d %H:%M:%S")
        events.append(
            parse(
                "auth",
                f"{ts_str} web-01 sshd[{i}]: Failed password for root from 198.51.100.33 port 4000{i} ssh2",
                {"event_uid": f"sq-f-{i}", "collected_at": collected, "received_at": collected, "agent": {"timezone": "UTC"}},
            )
        )
    events.append(
        parse(
            "auth",
            "Nov 10 07:12:00 web-01 sshd[99]: Accepted password for root from 198.51.100.33 port 40099 ssh2",
            {"event_uid": "sq-s-1", "collected_at": collected, "received_at": collected, "agent": {"timezone": "UTC"}},
        )
    )
    alerts = engine.evaluate_batch(events)
    assert [a for a in alerts if a.rule_id == "asp-bruteforce-then-success"] == []


def test_web_scan_404_pos_and_neg():
    pos_alerts = _run_sample_file("web_scan_404_pos.log", LogType.APACHE)
    scan_alerts = [a for a in pos_alerts if a.rule_id == "asp-web-scan-404"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0].level == AlertLevel.MEDIUM
    assert scan_alerts[0].group_key["source.ip"] == "203.0.113.40"
    assert scan_alerts[0].event_count == 30

    neg_alerts = _run_sample_file("web_scan_404_neg.log", LogType.APACHE)
    assert neg_alerts == []


def test_sudo_to_root_shell_pos_and_shutdown_negative():
    pos_alerts = _run_sample_file("sudo_to_root_shell_pos.log", LogType.AUTH)
    shell_alerts = [a for a in pos_alerts if a.rule_id == "asp-sudo-to-root-shell"]
    assert len(shell_alerts) == 2
    assert all(a.level == AlertLevel.MEDIUM for a in shell_alerts)

    # /bin/shutdown, /bin/systemctl, and USER=nobody COMMAND=/bin/sh MUST NOT trigger
    neg_alerts = _run_sample_file("sudo_to_root_shell_neg.log", LogType.AUTH)
    assert neg_alerts == []


def test_sudo_abuse_pos_and_neg():
    pos_alerts = _run_sample_file("sudo_abuse_pos.log", LogType.AUTH)
    abuse_alerts = [a for a in pos_alerts if a.rule_id == "asp-sudo-abuse"]
    assert len(abuse_alerts) == 3
    assert all(a.level == AlertLevel.MEDIUM for a in abuse_alerts)
    assert all("T1548.003" in a.tags for a in abuse_alerts)

    neg_alerts = _run_sample_file("sudo_abuse_neg.log", LogType.AUTH)
    assert neg_alerts == []
