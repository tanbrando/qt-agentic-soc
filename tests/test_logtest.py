"""
Tests for P5.6: CLI tools/asp_logtest.py in both single-line mode and --file batch replay mode
across all 6 YAML rules and samples/rules/*.log without requiring any database.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_RULES_DIR = REPO_ROOT / "samples" / "rules"
LOGTEST_SCRIPT = REPO_ROOT / "tools" / "asp_logtest.py"


def _run_cli(*args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(LOGTEST_SCRIPT), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def test_logtest_single_line_mode_parses_and_matches_stateless_rules():
    # Positive root shell sudo line matches asp-sudo-to-root-shell
    out_shell = _run_cli(
        "Nov 10 08:30:01 web-01 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
        "--type",
        "auth",
        "--timezone",
        "Asia/Ho_Chi_Minh",
        "--collected-at",
        "2026-11-10T09:00:00Z",
    )
    assert out_shell["event"]["event"]["action"] == "sudo_command"
    assert out_shell["event"]["@timestamp"] == "2026-11-10T01:30:01Z"
    assert [m["rule_id"] for m in out_shell["matched_rules"]] == ["asp-sudo-to-root-shell"]

    # Negative /bin/shutdown must NOT match asp-sudo-to-root-shell
    out_shutdown = _run_cli(
        "Nov 10 08:31:01 web-01 sudo: ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/bin/shutdown -r now",
        "--type",
        "auth",
        "--collected-at",
        "2026-11-10T09:00:00Z",
    )
    assert out_shutdown["event"]["event"]["action"] == "sudo_command"
    assert out_shutdown["matched_rules"] == []


@pytest.mark.parametrize(
    ("sample_file", "log_type", "expected_rule_id"),
    [
        ("ssh_bruteforce_pos.log", "auth", "asp-ssh-bruteforce"),
        ("password_spraying_pos.log", "auth", "asp-password-spraying"),
        ("bruteforce_then_success_pos.log", "auth", "asp-bruteforce-then-success"),
        ("web_scan_404_pos.log", "apache", "asp-web-scan-404"),
        ("sudo_to_root_shell_pos.log", "auth", "asp-sudo-to-root-shell"),
        ("sudo_abuse_pos.log", "auth", "asp-sudo-abuse"),
    ],
)
def test_logtest_file_mode_triggers_all_six_positive_samples(
    sample_file: str,
    log_type: str,
    expected_rule_id: str,
):
    out = _run_cli(
        "--file",
        str(SAMPLES_RULES_DIR / sample_file),
        "--type",
        log_type,
        "--rules-dir",
        "rules/",
        "--timezone",
        "Asia/Ho_Chi_Minh",
        "--collected-at",
        "2026-11-10T09:00:00Z",
    )
    assert out["unparsed"] == 0
    assert out["parse_errors"] == 0
    fired_ids = {al["rule_id"] for al in out["alerts"]}
    assert expected_rule_id in fired_ids


@pytest.mark.parametrize(
    ("sample_file", "log_type"),
    [
        ("ssh_bruteforce_invalid_user_neg.log", "auth"),
        ("password_spraying_neg.log", "auth"),
        ("bruteforce_then_success_neg.log", "auth"),
        ("web_scan_404_neg.log", "apache"),
        ("sudo_to_root_shell_neg.log", "auth"),
        ("sudo_abuse_neg.log", "auth"),
    ],
)
def test_logtest_file_mode_ignores_all_six_negative_samples(
    sample_file: str,
    log_type: str,
):
    out = _run_cli(
        "--file",
        str(SAMPLES_RULES_DIR / sample_file),
        "--type",
        log_type,
        "--rules-dir",
        "rules/",
        "--timezone",
        "Asia/Ho_Chi_Minh",
        "--collected-at",
        "2026-11-10T09:00:00Z",
    )
    assert out["unparsed"] == 0
    assert out["parse_errors"] == 0
    assert out["alerts"] == []

