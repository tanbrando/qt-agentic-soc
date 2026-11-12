"""
Unit tests for AuthLogParser and ParserRegistry (P2.2).
Covers sshd, sudo, useradd, pam_session, real lab samples, and unparsed fallback.
"""

from datetime import datetime, timezone
from pathlib import Path

from server.src.common.schemas import (
    AgentMetadata,
    EventOutcome,
    LogType,
    ParseStatus,
    RawEventFileMeta,
    RawLogEvent,
    compute_event_id,
)
from server.src.parsers.auth_parser import AuthLogParser
from server.src.parsers.base import ParserRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _parse_ecs(line: str, tz: str = "Asia/Ho_Chi_Minh"):
    collected = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)
    agent = AgentMetadata(id="agent-01", hostname="web-01", version="0.1.0", timezone=tz)
    raw_ev = RawLogEvent(
        log_type=LogType.AUTH,
        file=RawEventFileMeta(
            path="/var/log/auth.log",
            device=2049,
            inode=131077,
            stream_id="s-01",
            offset=0,
        ),
        collected_at=collected,
        message=line,
    )
    uid = compute_event_id(agent.id, 2049, 131077, "s-01", 0)
    return ParserRegistry.parse_raw_event(raw_ev, agent, uid, ingested_at=collected)


def test_auth_parser_registration():
    parser = ParserRegistry.get_parser("auth", "/var/log/auth.log")
    assert parser is not None
    assert isinstance(parser, AuthLogParser)


def test_parse_ssh_failed_password():
    raw = "Oct 11 04:02:11 web-01 sshd[28491]: Failed password for root from 198.51.100.23 port 52341 ssh2"
    ev = _parse_ecs(raw)

    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.asp.parser == "sshd_failed@1"
    assert ev.event.category == ["authentication"]
    assert ev.event.type == ["start"]
    assert ev.event.action == "ssh_login_failed"
    assert ev.event.outcome == EventOutcome.FAILURE
    assert ev.process is not None and ev.process.name == "sshd" and ev.process.pid == 28491
    assert ev.user is not None and ev.user.name == "root"
    assert ev.source is not None and ev.source.ip == "198.51.100.23" and ev.source.port == 52341
    assert ev.related is not None and ev.related.ip == ["198.51.100.23"] and ev.related.user == ["root"]
    assert ev.asp.auth_method == "password"


def test_parse_ssh_invalid_user_and_failed():
    raw_inv = "Nov 10 08:30:04 web-01 sshd[1236]: Invalid user oracle from 203.0.113.55 port 44123"
    ev_inv = _parse_ecs(raw_inv)
    assert ev_inv.event.action == "ssh_invalid_user"
    assert ev_inv.event.outcome == EventOutcome.FAILURE
    assert ev_inv.asp.parser == "sshd_invalid@1"
    assert ev_inv.user is not None and ev_inv.user.name == "oracle"
    assert ev_inv.source is not None and ev_inv.source.ip == "203.0.113.55"

    raw_fail = "Nov 10 08:30:04 web-01 sshd[1236]: Failed password for invalid user oracle from 203.0.113.55 port 44123 ssh2"
    ev_fail = _parse_ecs(raw_fail)
    assert ev_fail.event.action == "ssh_login_failed"
    assert ev_fail.event.outcome == EventOutcome.FAILURE
    assert ev_fail.user is not None and ev_fail.user.name == "oracle"


def test_parse_ssh_accepted():
    raw = "Oct 11 04:10:00 web-01 sshd[28600]: Accepted publickey for ubuntu from 10.0.0.15 port 39201 ssh2"
    ev = _parse_ecs(raw)
    assert ev.event.action == "ssh_login_success"
    assert ev.event.outcome == EventOutcome.SUCCESS
    assert ev.asp.parser == "sshd_accepted@1"
    assert ev.asp.auth_method == "publickey"
    assert ev.user is not None and ev.user.name == "ubuntu"
    assert ev.source is not None and ev.source.ip == "10.0.0.15"


def test_parse_sudo_variants():
    # 1. Normal sudo command (outcome unknown per Section 7.4)
    ev_ok = _parse_ecs(
        "Oct 11 04:15:22 web-01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
    )
    assert ev_ok.event.category == ["process"]
    assert ev_ok.event.type == ["start"]
    assert ev_ok.event.action == "sudo_command"
    assert ev_ok.event.outcome == EventOutcome.UNKNOWN
    assert ev_ok.asp.parser == "sudo_command@1"
    assert ev_ok.user is not None and ev_ok.user.name == "ubuntu"
    assert ev_ok.asp.sudo_target_user == "root"
    assert ev_ok.process is not None and ev_ok.process.args == "/usr/bin/systemctl restart nginx"

    # 2. user NOT in sudoers
    ev_nosudo = _parse_ecs(
        "Oct 11 04:16:01 web-01 sudo:    alice : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )
    assert ev_nosudo.event.category == ["process"]
    assert ev_nosudo.event.type == ["denied"]
    assert ev_nosudo.event.action == "sudo_not_in_sudoers"
    assert ev_nosudo.event.outcome == EventOutcome.FAILURE
    assert ev_nosudo.asp.parser == "sudo_not_in_sudoers@1"
    assert ev_nosudo.user is not None and ev_nosudo.user.name == "alice"

    # 3. incorrect password attempts
    ev_bad = _parse_ecs(
        "Oct 11 04:17:05 web-01 sudo:    bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
    )
    assert ev_bad.event.category == ["authentication"]
    assert ev_bad.event.type == ["denied"]
    assert ev_bad.event.action == "sudo_bad_password"
    assert ev_bad.event.outcome == EventOutcome.FAILURE
    assert ev_bad.asp.parser == "sudo_bad_password@1"
    assert ev_bad.user is not None and ev_bad.user.name == "bob"

    # 4. PAM sudo auth failure (matches real lab sample with double spaces after rhost=)
    ev_pam = _parse_ecs(
        "Nov 10 09:58:40 DESKTOP-T9H4SPL sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/5 ruser=cun rhost=  user=cun"
    )
    assert ev_pam.event.category == ["authentication"]
    assert ev_pam.event.type == ["denied"]
    assert ev_pam.event.action == "sudo_auth_failed"
    assert ev_pam.event.outcome == EventOutcome.FAILURE
    assert ev_pam.asp.parser == "sudo_auth_failed@1"
    assert ev_pam.user is not None and ev_pam.user.name == "cun"


def test_parse_useradd():
    raw = "Oct 11 04:20:00 web-01 useradd[29100]: new user: name=backdoor_svc, UID=1005, GID=1005, home=/home/backdoor_svc, shell=/bin/bash"
    ev = _parse_ecs(raw)
    assert ev.event.category == ["iam"]
    assert ev.event.type == ["creation"]
    assert ev.event.action == "user_created"
    assert ev.event.outcome == EventOutcome.SUCCESS
    assert ev.asp.parser == "useradd@1"
    assert ev.user is not None and ev.user.name == "backdoor_svc"


def test_parse_pam_session_opened_and_closed():
    ev_open = _parse_ecs(
        "Nov 10 09:36:28 DESKTOP-T9H4SPL login[521]: pam_unix(login:session): session opened for user cun(uid=1000) by (uid=0)"
    )
    assert ev_open.event.category == ["authentication"]
    assert ev_open.event.type == ["start"]
    assert ev_open.event.action == "session_opened"
    assert ev_open.event.outcome == EventOutcome.SUCCESS
    assert ev_open.asp.parser == "pam_session@1"
    assert ev_open.user is not None and ev_open.user.name == "cun"

    ev_close = _parse_ecs(
        "Nov 10 09:45:01 DESKTOP-T9H4SPL CRON[950]: pam_unix(cron:session): session closed for user root"
    )
    assert ev_close.event.type == ["end"]
    assert ev_close.event.action == "session_closed"
    assert ev_close.user is not None and ev_close.user.name == "root"


def test_sample_files_and_real_lab_auth_log_all_parse():
    sample_files = [
        _REPO_ROOT / "samples" / "auth" / "sshd_samples.log",
        _REPO_ROOT / "samples" / "auth" / "sudo_samples.log",
        _REPO_ROOT / "samples" / "auth" / "useradd_samples.log",
        _REPO_ROOT / "samples" / "auth" / "pam_samples.log",
        _REPO_ROOT / "client" / "samples" / "auth.log",
    ]
    for path in sample_files:
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) >= 5
        for line in lines:
            ev = _parse_ecs(line)
            assert ev.asp.parse_status == ParseStatus.OK, f"Failed on {path.name}: {line}"


def test_corrupted_auth_line_returns_unparsed():
    ev = _parse_ecs("Nov 10 09:58:45 host sshd[1]: corrupted invalid line format")
    assert ev.asp.parse_status == ParseStatus.UNPARSED
    assert ev.event.action == "unparsed"
