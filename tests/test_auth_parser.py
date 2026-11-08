"""
Unit tests for AuthLogParser and ParserRegistry.
"""

from server.src.common.schemas import EventOutcome, LogEventEnvelope, LogType
from server.src.parsers.auth_parser import AuthLogParser
from server.src.parsers.base import ParserRegistry


def test_auth_parser_registration():
    parser = ParserRegistry.get_parser("auth", "/var/log/auth.log")
    assert parser is not None
    assert isinstance(parser, AuthLogParser)


def test_parse_ssh_failed_password():
    parser = AuthLogParser()
    raw = "Oct 11 04:02:11 web-01 sshd[28491]: Failed password for root from 198.51.100.23 port 52341 ssh2"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "sshd"
    assert fields["pid"] == 28491
    assert fields["event_action"] == "ssh_login"
    assert fields["event_outcome"] == EventOutcome.FAILURE.value
    assert fields["user"] == "root"
    assert fields["src_ip"] == "198.51.100.23"
    assert fields["src_port"] == 52341
    assert fields["is_invalid_user"] is False


def test_parse_ssh_invalid_user_failed():
    parser = AuthLogParser()
    raw = "Oct 11 04:03:00 web-01 sshd[28500]: Failed password for invalid user admin from 203.0.113.55 port 44123 ssh2"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "sshd"
    assert fields["event_outcome"] == EventOutcome.FAILURE.value
    assert fields["user"] == "admin"
    assert fields["src_ip"] == "203.0.113.55"
    assert fields["is_invalid_user"] is True


def test_parse_ssh_accepted():
    parser = AuthLogParser()
    raw = "Oct 11 04:10:00 web-01 sshd[28600]: Accepted publickey for ubuntu from 10.0.0.15 port 39201 ssh2"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "sshd"
    assert fields["event_outcome"] == EventOutcome.SUCCESS.value
    assert fields["user"] == "ubuntu"
    assert fields["src_ip"] == "10.0.0.15"
    assert fields["auth_method"] == "publickey"


def test_parse_sudo_success():
    parser = AuthLogParser()
    raw = "Oct 11 04:15:22 web-01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "sudo"
    assert fields["event_action"] == "sudo_command"
    assert fields["event_outcome"] == EventOutcome.SUCCESS.value
    assert fields["user"] == "ubuntu"
    assert fields["target_user"] == "root"
    assert fields["command"] == "/usr/bin/systemctl restart nginx"


def test_parse_sudo_not_in_sudoers():
    parser = AuthLogParser()
    raw = "Oct 11 04:16:01 web-01 sudo:    alice : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "sudo"
    assert fields["event_outcome"] == EventOutcome.FAILURE.value
    assert fields["failure_reason"] == "user NOT in sudoers"
    assert fields["user"] == "alice"
    assert fields["command"] == "/usr/bin/cat /etc/shadow"


def test_parse_sudo_incorrect_password():
    parser = AuthLogParser()
    raw = "Oct 11 04:17:05 web-01 sudo:    bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "sudo"
    assert fields["event_outcome"] == EventOutcome.FAILURE.value
    assert fields["failure_reason"] == "3 incorrect password attempts"
    assert fields["user"] == "bob"


def test_parse_useradd():
    parser = AuthLogParser()
    raw = "Oct 11 04:20:00 web-01 useradd[29100]: new user: name=backdoor_svc, UID=1005, GID=1005, home=/home/backdoor_svc, shell=/bin/bash"
    fields = parser.parse_line(raw)

    assert fields is not None
    assert fields["service"] == "useradd"
    assert fields["event_action"] == "user_created"
    assert fields["event_outcome"] == EventOutcome.SUCCESS.value
    assert fields["user"] == "backdoor_svc"
    assert fields["uid"] == 1005
    assert fields["shell"] == "/bin/bash"


def test_parser_registry_enrich_envelope():
    raw = "Oct 11 04:02:11 web-01 sshd[28491]: Failed password for root from 198.51.100.23 port 52341 ssh2"
    envelope = LogEventEnvelope(
        agent_id="agent-01",
        hostname="web-01",
        log_type=LogType.AUTH,
        source_file="/var/log/auth.log",
        raw=raw,
        fields={},  # Empty fields from edge
    )

    enriched = ParserRegistry.parse_or_fallback(envelope)
    assert enriched.fields.get("service") == "sshd"
    assert enriched.fields.get("src_ip") == "198.51.100.23"
    assert enriched.fields.get("event_outcome") == EventOutcome.FAILURE.value

