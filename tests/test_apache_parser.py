"""
Unit tests for ApacheAccessParser (P4.1).
Covers combined format, >= 5 sample lines, 404, malformed request '-', IPv6,
long lines, future timestamp clamping, and garbage lines -> unparsed.
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
from server.src.parsers.apache_parser import ApacheAccessParser
from server.src.parsers.base import ParserRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _parse_apache(line: str):
    collected = datetime(2026, 11, 10, 2, 0, 0, tzinfo=timezone.utc)
    agent = AgentMetadata(id="web-01", hostname="web-01", version="0.1.0")
    raw_ev = RawLogEvent(
        log_type=LogType.APACHE,
        file=RawEventFileMeta(
            path="/var/log/apache2/access.log",
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


def test_apache_parser_registration_and_samples():
    parser = ParserRegistry.get_parser("apache", "/var/log/apache2/access.log")
    assert isinstance(parser, ApacheAccessParser)

    sample_file = _REPO_ROOT / "samples" / "apache_access.log"
    lines = [l for l in sample_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) >= 5
    for line in lines:
        ev = _parse_apache(line)
        assert ev.asp.parse_status == ParseStatus.OK
        assert ev.event.dataset == "apache.access"
        assert ev.event.action == "http_request"


def test_apache_fields_404_user_and_utc_offset():
    ev = _parse_apache(
        '203.0.113.44 - bob [10/Nov/2026:08:30:00 +0700] "GET /secret HTTP/1.1" 404 200 "-" "Nikto/2.1"'
    )
    assert ev.timestamp == datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    assert ev.event.category == ["web"]
    assert ev.event.type == ["access"]
    assert ev.event.outcome == EventOutcome.FAILURE
    assert ev.source is not None and ev.source.ip == "203.0.113.44"
    assert ev.user is not None and ev.user.name == "bob"
    assert ev.http is not None and ev.http.request is not None and ev.http.request.method == "GET"
    assert ev.http.response is not None and ev.http.response.status_code == 404
    assert ev.url is not None and ev.url.original == "/secret"
    assert ev.user_agent is not None and ev.user_agent.original == "Nikto/2.1"
    assert ev.asp.parser == "apache_combined@1"


def test_apache_malformed_request_dash_and_ipv6_and_long_line():
    ev_dash = _parse_apache('192.0.2.55 - - [10/Nov/2026:08:33:00 +0700] "-" 408 0 "-" "-"')
    assert ev_dash.asp.parse_status == ParseStatus.OK
    assert ev_dash.event.action == "http_request"
    assert ev_dash.event.outcome == EventOutcome.FAILURE
    assert ev_dash.user is None
    assert ev_dash.http is not None and ev_dash.http.request is not None and ev_dash.http.request.method == ""
    assert ev_dash.url is not None and ev_dash.url.original == ""

    ev_v6 = _parse_apache('2001:db8::1 - - [10/Nov/2026:08:32:00 +0700] "GET /status HTTP/1.1" 200 512 "-" "UA"')
    assert ev_v6.source is not None and ev_v6.source.ip == "2001:db8::1"
    assert ev_v6.event.outcome == EventOutcome.SUCCESS

    long_path = "/a" * 6000
    ev_long = _parse_apache(
        f'198.51.100.1 - - [10/Nov/2026:08:32:00 +0700] "GET {long_path} HTTP/1.1" 200 1 "-" "{"x"*4000}"'
    )
    assert ev_long.asp.parse_status == ParseStatus.OK
    assert ev_long.url is not None and ev_long.url.original == long_path


def test_apache_future_ts_clamped_and_garbage_unparsed():
    ev_future = _parse_apache(
        '198.51.100.1 - - [10/Nov/2099:08:30:00 +0700] "GET / HTTP/1.1" 200 1 "-" "UA"'
    )
    assert ev_future.asp.ts_clamped is True
    assert ev_future.timestamp == datetime(2026, 11, 10, 2, 0, 0, tzinfo=timezone.utc)

    ev_bad = _parse_apache("totally invalid apache log line")
    assert ev_bad.asp.parse_status == ParseStatus.UNPARSED
    assert ev_bad.event.action == "unparsed"

