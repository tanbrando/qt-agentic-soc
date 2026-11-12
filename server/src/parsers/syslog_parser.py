"""
Generic Linux Syslog Parser (Section 7.6).
Handles standard BSD and ISO-8601 syslog lines not matched by specialized parsers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from server.src.common.schemas import EventOutcome, LogType
from server.src.parsers.base import BaseLogParser, ParserRegistry
from server.src.parsers.common import parse_syslog_header, resolve_syslog_timestamp


@ParserRegistry.register
class GenericSyslogParser(BaseLogParser):
    """Fallback parser for /var/log/syslog and general Linux syslog streams."""

    @property
    def supported_log_type(self) -> LogType:
        return LogType.SYSLOG

    def can_handle(self, log_type: str, source_path: str = "") -> bool:
        if log_type == LogType.SYSLOG.value or log_type == "syslog":
            return True
        if log_type != LogType.AUTH.value and any(
            source_path.endswith(suffix) for suffix in ("/syslog", "syslog", "/messages")
        ):
            return True
        return False

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        line = raw_line.strip()
        if not line:
            return None

        header = parse_syslog_header(line)
        if header is None:
            return None

        fields: Dict[str, Any] = {
            "service": header.proc,
            "category": ["host"],
            "event_type": ["info"],
            "event_action": "syslog_message",
            "event_outcome": EventOutcome.UNKNOWN.value,
            "parser": "syslog_generic@1",
            "body_message": header.msg,
        }
        if header.pid is not None:
            fields["pid"] = header.pid
        return fields

    def parse_with_meta(
        self,
        message: str,
        meta: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        line = message.strip()
        if not line:
            return None

        header = parse_syslog_header(line)
        if header is None:
            return None

        collected_raw = meta["collected_at"]
        received_raw = meta.get("received_at") or collected_raw
        collected_at = (
            datetime.fromisoformat(collected_raw)
            if isinstance(collected_raw, str)
            else collected_raw
        )
        received_at = (
            datetime.fromisoformat(received_raw)
            if isinstance(received_raw, str)
            else received_raw
        )
        agent_meta = meta.get("agent") or {}
        event_ts, ts_clamped = resolve_syslog_timestamp(
            ts_raw=header.ts_raw,
            is_iso=header.is_iso,
            collected_at=collected_at,
            received_at=received_at,
            agent_timezone=agent_meta.get("timezone"),
            default_timezone=meta.get("default_timezone", "Asia/Ho_Chi_Minh"),
            future_tolerance_seconds=int(meta.get("future_tolerance_seconds", 300)),
        )

        fields: Dict[str, Any] = {
            "@timestamp": event_ts,
            "ts_clamped": ts_clamped,
            "service": header.proc,
            "category": ["host"],
            "event_type": ["info"],
            "event_action": "syslog_message",
            "event_outcome": EventOutcome.UNKNOWN.value,
            "parser": "syslog_generic@1",
            "body_message": header.msg,
        }
        if header.pid is not None:
            fields["pid"] = header.pid
        return fields

