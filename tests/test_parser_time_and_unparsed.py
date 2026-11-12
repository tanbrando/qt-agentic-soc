"""
Unit tests for P2.1: syslog header preprocessing (BSD & ISO 8601),
timezone conversion, year/New Year rollover, future timestamp clamping,
unparsed/error states, and parser purity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from server.src.common.schemas import (
    AgentMetadata,
    EventOutcome,
    LogType,
    ParseStatus,
    RawEventFileMeta,
    RawLogEvent,
    compute_event_id,
)
from server.src.parsers.base import BaseLogParser, ParserRegistry, parse
from server.src.parsers.common import parse_syslog_header, resolve_syslog_timestamp


def _meta(
    collected_at: datetime,
    received_at: datetime | None = None,
    tz: str | None = "Asia/Ho_Chi_Minh",
    hostname: str = "web-01",
    default_timezone: str = "Asia/Ho_Chi_Minh",
    future_tolerance_seconds: int = 300,
) -> Dict[str, Any]:
    return {
        "event_uid": compute_event_id("ag-1", 1, 2, "st-1", 0),
        "collected_at": collected_at,
        "received_at": received_at or collected_at,
        "agent": {
            "id": "ag-1",
            "hostname": hostname,
            "version": "0.1.0",
            "ip": ["10.0.0.5"],
            "timezone": tz,
        },
        "file": {
            "path": "/var/log/auth.log",
            "device": 1,
            "inode": 2,
            "stream_id": "st-1",
            "offset": 0,
        },
        "message_truncated": False,
        "default_timezone": default_timezone,
        "future_tolerance_seconds": future_tolerance_seconds,
    }


def test_syslog_old_timezone_conversion_and_envelope_hostname():
    # Nov 10 08:30:00 in Asia/Ho_Chi_Minh (+07:00) == 2026-11-10T01:30:00Z
    collected = datetime(2026, 11, 10, 1, 30, 5, tzinfo=timezone.utc)
    # Line contains a spoofed hostname 'spoofed-host'; output host.name must come from envelope
    line = "Nov 10 08:30:00 spoofed-host sshd[1234]: Failed password for root from 1.2.3.4 port 41001 ssh2"
    ev = parse("auth", line, _meta(collected, tz="Asia/Ho_Chi_Minh", hostname="real-web-01"))

    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.timestamp == datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    assert ev.host.name == "real-web-01"
    assert ev.asp.ts_clamped is None


def test_syslog_old_multiple_timezones_and_fallback():
    # Nov 10 08:30:00 in America/New_York (EST = -05:00 in Nov) == 13:30:00Z
    collected = datetime(2026, 11, 10, 13, 35, 0, tzinfo=timezone.utc)
    line = "Nov 10 08:30:00 web-ny sshd[10]: Accepted publickey for ops from 10.0.0.2 port 2222 ssh2"
    ev_ny = parse("auth", line, _meta(collected, tz="America/New_York"))
    assert ev_ny.timestamp == datetime(2026, 11, 10, 13, 30, 0, tzinfo=timezone.utc)

    # Missing agent.timezone falls back to default_timezone (UTC)
    ev_utc = parse("auth", line, _meta(collected, tz=None, default_timezone="UTC"))
    assert ev_utc.timestamp == datetime(2026, 11, 10, 8, 30, 0, tzinfo=timezone.utc)


def test_syslog_old_year_boundary_new_years_eve():
    # Agent collected on Jan 01 2027 00:00:10+07:00 (2026-12-31T17:00:10Z)
    # Log line says "Dec 31 23:59:50" -> must resolve to 2026-12-31 23:59:50+07:00 == 2026-12-31T16:59:50Z
    collected = datetime(2026, 12, 31, 17, 0, 10, tzinfo=timezone.utc)
    ts, clamped = resolve_syslog_timestamp(
        ts_raw="Dec 31 23:59:50",
        is_iso=False,
        collected_at=collected,
        received_at=collected,
        agent_timezone="Asia/Ho_Chi_Minh",
    )
    assert clamped is False
    assert ts == datetime(2026, 12, 31, 16, 59, 50, tzinfo=timezone.utc)


def test_syslog_iso_8601_header_and_utc_conversion():
    collected = datetime(2026, 11, 10, 1, 35, 0, tzinfo=timezone.utc)
    line = "2026-11-10T08:30:00.125+07:00 ubuntu-24 sshd[999]: Failed password for admin from 1.2.3.4 port 5555 ssh2"
    ev = parse("auth", line, _meta(collected, tz="UTC"))

    assert ev.asp.parse_status == ParseStatus.OK
    assert ev.timestamp == datetime(2026, 11, 10, 1, 30, 0, 125000, tzinfo=timezone.utc)
    assert ev.process is not None and ev.process.name == "sshd" and ev.process.pid == 999


def test_future_timestamp_clamped_and_within_tolerance_allowed():
    collected = datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    received = datetime(2026, 11, 10, 1, 30, 5, tzinfo=timezone.utc)

    # Spoofed year 2099 via ISO 8601 -> clamped to collected_at + asp.ts_clamped = True
    spoofed_line = "2099-01-01T00:00:00Z web-01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ev_clamped = parse("auth", spoofed_line, _meta(collected, received_at=received))
    assert ev_clamped.timestamp == collected
    assert ev_clamped.asp.ts_clamped is True

    # +2m clock skew is within 5m (300s) tolerance -> not clamped
    skew_line = "2026-11-10T01:32:00Z web-01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ev_ok = parse("auth", skew_line, _meta(collected, received_at=received))
    assert ev_ok.timestamp == datetime(2026, 11, 10, 1, 32, 0, tzinfo=timezone.utc)
    assert ev_ok.asp.ts_clamped is None


def test_garbage_and_unrecognized_lines_produce_unparsed_without_error():
    collected = datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    for garbage in [
        "this is completely malformed garbage",
        "Nov 10 08:30:00 web-01 unknownproc[5]: unrecognized payload",
        "A" * 20000,
    ]:
        ev = parse("auth", garbage, _meta(collected))
        assert ev.asp.parse_status == ParseStatus.UNPARSED
        assert ev.timestamp == collected
        assert ev.event.category == ["host"]
        assert ev.event.type == ["info"]
        assert ev.event.action == "unparsed"
        assert ev.event.outcome == EventOutcome.UNKNOWN


def test_parser_exception_produces_error_status():
    class _ExplodingParser(BaseLogParser):
        @property
        def supported_log_type(self) -> LogType:
            return LogType.KERNEL

        def can_handle(self, log_type: str, source_path: str) -> bool:
            return log_type == LogType.KERNEL.value

        def parse_line(self, raw_line: str):
            raise RuntimeError("boom")

    collected = datetime(2026, 11, 10, 1, 30, 0, tzinfo=timezone.utc)
    ParserRegistry.register_instance(_ExplodingParser())
    try:
        ev = ParserRegistry.parse_raw_event(
            RawLogEvent(
                log_type=LogType.KERNEL,
                file=RawEventFileMeta(
                    path="/var/log/kern.log",
                    device=1,
                    inode=1,
                    stream_id="s1",
                    offset=0,
                ),
                collected_at=collected,
                message="some kernel line",
            ),
            AgentMetadata(id="ag-1", hostname="web-01", version="0.1.0"),
            "c" * 40,
            ingested_at=collected,
        )
        assert ev.asp.parse_status == ParseStatus.ERROR
        assert ev.event.action == "parse_error"
        assert ev.timestamp == collected
    finally:
        # Remove only the temporary exploding parser instance
        ParserRegistry._registry = [
            p for p in ParserRegistry._registry if not isinstance(p, _ExplodingParser)
        ]


def test_header_redos_safety_bounded():
    # Very long malformed input returns quickly without regex backtracking
    assert parse_syslog_header("Nov 10 08:30:00 " + "a" * 50000) is None

