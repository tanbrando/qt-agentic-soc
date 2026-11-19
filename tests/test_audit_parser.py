"""
Unit tests for AuditLogParser.
Covers Linux audit daemon log parsing: SYSCALL, EXECVE, USER_CMD (with hex decoding),
USER_LOGIN, USER_AUTH, CONFIG_CHANGE, DAEMON_START, garbage line handling, and future timestamp clamping.
"""

from __future__ import annotations

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
from server.src.parsers.audit_parser import AuditLogParser
from server.src.parsers.base import ParserRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _parse_audit(line: str, collected_at: datetime | None = None):
    collected = collected_at or datetime(2026, 11, 10, 2, 0, 0, tzinfo=timezone.utc)
    agent = AgentMetadata(id="ubuntu-01", hostname="ubuntu-01", version="0.1.0")
    raw_ev = RawLogEvent(
        log_type=LogType.AUDIT,
        file=RawEventFileMeta(
            path="/var/log/audit/audit.log",
            device=1,
            inode=1,
            stream_id="s1",
            offset=0,
        ),
        collected_at=collected,
        message=line,
    )
    uid = compute_event_id(agent.id, 1, 1, "s1", 0)
    return ParserRegistry.parse_raw_event(raw_ev, agent, uid, ingested_at=collected)


def test_audit_parser_registration():
    parser = ParserRegistry.get_parser("audit", "/var/log/audit/audit.log")
    assert isinstance(parser, AuditLogParser)
    assert parser.supported_log_type == LogType.AUDIT
    assert parser.can_handle("audit", "/var/log/audit/audit.log")
    assert parser.can_handle("other", "/var/log/audit/audit.log")


def test_audit_parser_samples_file():
    sample_file = _REPO_ROOT / "samples" / "audit" / "audit_samples.log"
    lines = [l for l in sample_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) >= 5
    for line in lines:
        ev = _parse_audit(line)
        assert ev.asp.parse_status == ParseStatus.OK
        assert ev.event.dataset == "linux.audit"


def test_audit_syscall_record():
    line = (
        'type=SYSCALL msg=audit(1731301235.200:1002): arch=c000003e syscall=59 success=yes exit=0 '
        'a0=7ffd588e1a60 a1=7ffd588e27c8 a2=7ffd588e27d8 a3=7ffd588e1780 items=2 ppid=1234 pid=5678 '
        'auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cat" '
        'exe="/usr/bin/cat" key="shadow_access"'
    )
    ev = _parse_audit(line)
    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.event.dataset == "linux.audit"
    assert ev.event.action == "audit_syscall_cat"
    assert ev.event.outcome == EventOutcome.SUCCESS
    assert ev.process is not None
    assert ev.process.pid == 5678
    assert ev.process.name == "cat"
    assert ev.user is not None
    assert ev.user.name == "root"


def test_audit_execve_argument_reconstruction():
    line = 'type=EXECVE msg=audit(1731301235.200:1002): argc=3 a0="cat" a1="/etc/shadow" a2="/etc/passwd"'
    ev = _parse_audit(line)
    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.event.action == "process_execution"
    assert ev.event.outcome == EventOutcome.SUCCESS
    assert ev.process is not None
    assert ev.process.name == "cat"
    assert ev.process.args == "cat /etc/shadow /etc/passwd"


def test_audit_user_cmd_hex_decoding():
    # cmd=636174202F6574632F736861646F77 is hex for 'cat /etc/shadow'
    line = (
        "type=USER_CMD msg=audit(1731301236.300:1003): pid=5678 uid=1000 auid=1000 ses=1 subj=? "
        "msg='cwd=\"/home/cun\" cmd=636174202F6574632F736861646F77 terminal=pts/0 res=success'"
    )
    ev = _parse_audit(line)
    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.event.action == "user_command"
    assert ev.event.outcome == EventOutcome.SUCCESS
    assert ev.process is not None
    assert ev.process.args == "cat /etc/shadow"
    assert ev.process.name == "cat"
    assert ev.user is not None
    assert ev.user.name == "uid:1000"


def test_audit_user_login():
    line = (
        'type=USER_LOGIN msg=audit(1731301237.400:1004): pid=6789 uid=0 auid=1000 ses=2 subj=? '
        'msg=\'op=login id=1000 exe="/usr/sbin/sshd" hostname=192.168.1.50 addr=192.168.1.50 terminal=ssh res=success\''
    )
    ev = _parse_audit(line)
    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.event.action == "user_login"
    assert ev.event.outcome == EventOutcome.SUCCESS
    assert ev.source is not None
    assert ev.source.ip == "192.168.1.50"
    assert ev.process is not None
    assert ev.process.name == "sshd"


def test_audit_unparsed_garbage():
    line = "Random unformatted log line without audit signature"
    ev = _parse_audit(line)
    assert ev.asp.parse_status == ParseStatus.UNPARSED
    assert ev.event.action == "unparsed"
    assert ev.message == line


def test_audit_future_timestamp_clamping():
    # Timestamp far in future: epoch 2500000000 (~ year 2049)
    future_line = "type=DAEMON_START msg=audit(2500000000.000:9999): op=start ver=3.0.7 res=success"
    collected = datetime(2026, 11, 10, 2, 0, 0, tzinfo=timezone.utc)
    ev = _parse_audit(future_line, collected_at=collected)
    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.asp.ts_clamped is True
    assert ev.timestamp == collected
