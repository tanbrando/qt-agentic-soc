"""
Pure syslog header preprocessing and timestamp normalization helpers (Sections 6.3, 7.2).
Uses simple bounded regexes to avoid ReDoS on untrusted log inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Bound header matching slice to avoid catastrophic regex work on huge untrusted lines
MAX_HEADER_INSPECT_BYTES = 512

SYSLOG_OLD_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

SYSLOG_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)


@dataclass(frozen=True)
class SyslogHeader:
    """Parsed BSD or ISO-8601 syslog line prefix."""

    ts_raw: str
    is_iso: bool
    host: str
    proc: str
    pid: Optional[int]
    msg: str


def parse_syslog_header(raw_line: str) -> Optional[SyslogHeader]:
    """
    Matches BSD (old) or ISO 8601 syslog header.
    Returns None if the line does not begin with a valid syslog header.
    """
    if not raw_line:
        return None
    line = raw_line.rstrip("\r\n")
    # Inspect header prefix up to MAX_HEADER_INSPECT_BYTES + split rest of msg cleanly
    head_slice = line[:MAX_HEADER_INSPECT_BYTES]
    tail = line[MAX_HEADER_INSPECT_BYTES:]

    m_old = SYSLOG_OLD_RE.match(head_slice)
    if m_old:
        pid_str = m_old.group("pid")
        return SyslogHeader(
            ts_raw=" ".join(m_old.group("ts").split()),
            is_iso=False,
            host=m_old.group("host"),
            proc=m_old.group("proc"),
            pid=int(pid_str) if pid_str else None,
            msg=m_old.group("msg") + tail,
        )

    m_iso = SYSLOG_ISO_RE.match(head_slice)
    if m_iso:
        pid_str = m_iso.group("pid")
        return SyslogHeader(
            ts_raw=m_iso.group("ts"),
            is_iso=True,
            host=m_iso.group("host"),
            proc=m_iso.group("proc"),
            pid=int(pid_str) if pid_str else None,
            msg=m_iso.group("msg") + tail,
        )

    return None


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def resolve_syslog_timestamp(
    ts_raw: str,
    is_iso: bool,
    collected_at: datetime,
    received_at: datetime,
    agent_timezone: Optional[str] = None,
    default_timezone: str = "Asia/Ho_Chi_Minh",
    future_tolerance_seconds: int = 300,
) -> Tuple[datetime, bool]:
    """
    Normalizes syslog header timestamp to UTC and clamps future timestamps (Section 6.3).
    Returns (utc_timestamp, ts_clamped).
    """
    collected_utc = _ensure_utc(collected_at)
    received_utc = _ensure_utc(received_at)

    if is_iso:
        parsed_dt = datetime.fromisoformat(ts_raw)
        parsed_utc = _ensure_utc(parsed_dt)
    else:
        tz_name = agent_timezone or default_timezone
        try:
            tz = ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            tz = ZoneInfo(default_timezone)

        collected_local = collected_utc.astimezone(tz)
        naive_no_year = datetime.strptime(ts_raw, "%b %d %H:%M:%S")
        year = collected_local.year
        try:
            candidate_local = naive_no_year.replace(year=year, tzinfo=tz)
        except ValueError:
            # Handle Feb 29 when collected_local.year is non-leap
            candidate_local = naive_no_year.replace(year=year - 1, tzinfo=tz)

        # Year-boundary rollover: if parsed timestamp is > 1 day ahead of collected_at, subtract 1 year
        if candidate_local - collected_local > timedelta(days=1):
            try:
                candidate_local = candidate_local.replace(year=candidate_local.year - 1)
            except ValueError:
                candidate_local = naive_no_year.replace(year=candidate_local.year - 4, tzinfo=tz)

        parsed_utc = candidate_local.astimezone(timezone.utc)

    if parsed_utc > received_utc + timedelta(seconds=future_tolerance_seconds):
        return collected_utc, True

    return parsed_utc, False

