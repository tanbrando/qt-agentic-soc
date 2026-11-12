"""
Smoke tests for F.1: scripts/demo_attack.py log generation and offline rule triggering.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scripts.demo_attack import append_logs_for_collector, build_demo_log_lines
from tools.asp_logtest import run_log_file


def test_demo_attack_logfiles_trigger_expected_siem_rules(tmp_path: Path):
    auth_lines, apache_lines = build_demo_log_lines(
        attacker_ip="203.0.113.77",
        hostname="lab-web-01",
        base_utc=datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc),
    )
    auth_file = tmp_path / "auth.log"
    apache_file = tmp_path / "access.log"

    n_auth, n_ap = append_logs_for_collector(auth_file, apache_file, auth_lines, apache_lines)
    assert n_auth == len(auth_lines)
    assert n_ap == len(apache_lines)

    auth_res = run_log_file(auth_file, log_type="auth", timezone_name="UTC")
    assert auth_res.unparsed == 0
    assert auth_res.parse_errors == 0
    auth_rule_ids = {al.rule_id for al in auth_res.alerts}
    assert {
        "asp-ssh-bruteforce",
        "asp-bruteforce-then-success",
        "asp-sudo-abuse",
        "asp-sudo-to-root-shell",
    }.issubset(auth_rule_ids)

    apache_res = run_log_file(apache_file, log_type="apache", timezone_name="UTC")
    assert apache_res.unparsed == 0
    assert apache_res.parse_errors == 0
    assert {al.rule_id for al in apache_res.alerts} == {"asp-web-scan-404"}

