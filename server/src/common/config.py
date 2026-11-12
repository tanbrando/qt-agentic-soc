"""
Server configuration loaded from environment variables (os.environ).
Does not depend on pydantic-settings.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration_seconds(spec: str) -> int:
    """Parses duration strings like '60s', '5m', '6h', '1d' into integer seconds."""
    m = _DURATION_RE.match(spec)
    if not m:
        raise ValueError(f"Invalid duration specification: {spec!r}")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


@dataclass(frozen=True)
class ServerConfig:
    """Runtime configuration populated from environment variables."""

    db_url: Optional[str]
    server_host: str
    server_port: int
    log_level: str
    default_timezone: str
    future_ts_tolerance: str
    allowed_lateness: str
    case_idle_timeout: str
    rules_dir: str
    rate_limit_ingest: int

    @classmethod
    def from_env(cls) -> ServerConfig:
        """Reads configuration directly from os.environ with safe defaults."""
        return cls(
            db_url=os.environ.get("ASP_DB_URL") or None,
            server_host=os.environ.get("SOC_SERVER_HOST", "0.0.0.0"),
            server_port=int(os.environ.get("SOC_SERVER_PORT", "8000")),
            log_level=os.environ.get("SOC_LOG_LEVEL", "INFO"),
            default_timezone=os.environ.get("ASP_DEFAULT_TIMEZONE", "Asia/Ho_Chi_Minh"),
            future_ts_tolerance=os.environ.get("ASP_FUTURE_TS_TOLERANCE", "5m"),
            allowed_lateness=os.environ.get("ASP_ALLOWED_LATENESS", "60s"),
            case_idle_timeout=os.environ.get("ASP_CASE_IDLE_TIMEOUT", "6h"),
            rules_dir=os.environ.get("ASP_RULES_DIR", "rules/"),
            rate_limit_ingest=int(os.environ.get("ASP_RATE_LIMIT_INGEST", "120")),
        )

