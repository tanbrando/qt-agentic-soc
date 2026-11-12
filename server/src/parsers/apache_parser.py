"""
Apache Combined Access Log Parser (Section 7.5).
Pure parser handling standard, malformed ('-'), IPv6, and long-line combined logs.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from server.src.common.schemas import EventOutcome, LogType
from server.src.parsers.base import BaseLogParser, ParserRegistry

# Uses negated classes and atomic-like token runs (linear time O(N), ReDoS-safe)
APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"\s*$'
)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@ParserRegistry.register
class ApacheAccessParser(BaseLogParser):
    """Parser for Apache combined access logs (/var/log/apache2/access.log)."""

    @property
    def supported_log_type(self) -> LogType:
        return LogType.APACHE

    def can_handle(self, log_type: str, source_path: str = "") -> bool:
        if log_type == LogType.APACHE.value or log_type == "apache":
            return True
        if "access.log" in source_path:
            return True
        return False

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        line = raw_line.strip()
        if not line:
            return None

        m = APACHE_COMBINED_RE.match(line)
        if not m:
            return None

        ts_str = m.group("ts")
        try:
            parsed_ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None

        status_code = int(m.group("status"))
        outcome = EventOutcome.SUCCESS.value if status_code < 400 else EventOutcome.FAILURE.value

        req_parts = m.group("req").split()
        if len(req_parts) == 3:
            http_method, url_original, _proto = req_parts
        else:
            http_method, url_original = "", ""

        fields: Dict[str, Any] = {
            "@timestamp": parsed_ts.astimezone(timezone.utc),
            "category": ["web"],
            "event_type": ["access"],
            "event_action": "http_request",
            "event_outcome": outcome,
            "parser": "apache_combined@1",
            "src_ip": m.group("ip"),
            "http_method": http_method,
            "url_original": url_original,
            "http_status": status_code,
            "user_agent_original": m.group("ua"),
        }
        user = m.group("user")
        if user and user != "-":
            fields["user"] = user
        return fields

    def parse_with_meta(
        self,
        message: str,
        meta: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        fields = self.parse_line(message)
        if fields is None:
            return None

        collected_raw = meta["collected_at"]
        received_raw = meta.get("received_at") or collected_raw
        collected_at = _ensure_utc(
            datetime.fromisoformat(collected_raw)
            if isinstance(collected_raw, str)
            else collected_raw
        )
        received_at = _ensure_utc(
            datetime.fromisoformat(received_raw)
            if isinstance(received_raw, str)
            else received_raw
        )
        tol = int(meta.get("future_tolerance_seconds", 300))

        if fields["@timestamp"] > received_at + timedelta(seconds=tol):
            fields["@timestamp"] = collected_at
            fields["ts_clamped"] = True
        else:
            fields["ts_clamped"] = False

        return fields

