"""
ASP CLI rule & parser test runner (Section 9.6).
Runs single-line ECS parse + match-rule preview or full file replay through InMemory RuleEngine without DB.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Ensure all built-in parsers are registered
import server.src.parsers  # noqa: F401
from server.src.common.config import ServerConfig, parse_duration_seconds
from server.src.common.schemas import Alert, ECSEvent, ParseStatus, compute_event_id
from server.src.engine.base import RuleEngine
from server.src.engine.generic_rules import MatchRule, build_rule_from_spec
from server.src.engine.loader import load_rule_specs_from_dir
from server.src.engine.state_store import InMemorySlidingWindowStore
from server.src.parsers.base import parse


def _resolve_rules_dir(rules_dir: str) -> Path:
    candidate = Path(rules_dir)
    if candidate.exists() or rules_dir != "rules/":
        return candidate
    fallback = _ROOT / "rules"
    return fallback if fallback.exists() else candidate


def _load_engine(rules_dir: Path, allowed_lateness_seconds: int) -> RuleEngine:
    store = InMemorySlidingWindowStore()
    specs = load_rule_specs_from_dir(rules_dir)
    rules = [
        build_rule_from_spec(
            spec,
            state_store=store,
            allowed_lateness_seconds=allowed_lateness_seconds,
        )
        for spec in specs
    ]
    return RuleEngine(rules)


@dataclass
class FileLogtestResult:
    file_path: str
    log_type: str
    total_lines: int
    parsed_ok: int
    unparsed: int
    parse_errors: int
    events: List[ECSEvent]
    alerts: List[Alert]


def run_single_line(
    raw_line: str,
    log_type: str,
    rules_dir: str = "rules/",
    timezone_name: str = "Asia/Ho_Chi_Minh",
    collected_at: Optional[datetime] = None,
) -> tuple[ECSEvent, List[Alert]]:
    """Parses one raw log line and checks which stateless MatchRule rules match it."""
    cfg = ServerConfig.from_env()
    tol_sec = parse_duration_seconds(cfg.future_ts_tolerance)
    lateness_sec = parse_duration_seconds(cfg.allowed_lateness)
    ts = collected_at or datetime.now(timezone.utc)
    uid = compute_event_id("logtest-agent", 0, 0, "stdin", 0)
    meta: Dict[str, Any] = {
        "event_uid": uid,
        "collected_at": ts,
        "received_at": ts,
        "agent": {
            "id": "logtest-agent",
            "hostname": "logtest-host",
            "version": "0.1.0",
            "timezone": timezone_name,
        },
        "log": {"file": {"path": "<stdin>", "device": 0, "inode": 0, "offset": 0}},
        "default_timezone": timezone_name,
        "future_tolerance_seconds": tol_sec,
    }
    event = parse(log_type, raw_line, meta)

    engine = _load_engine(_resolve_rules_dir(rules_dir), allowed_lateness_seconds=lateness_sec)
    match_alerts: List[Alert] = []
    for rule in engine.rules:
        if isinstance(rule, MatchRule) and rule.applies_to(event):
            alert = rule.evaluate(event)
            if alert is not None:
                match_alerts.append(alert)
    return event, match_alerts


def run_log_file(
    file_path: Path,
    log_type: str,
    rules_dir: str = "rules/",
    timezone_name: str = "Asia/Ho_Chi_Minh",
    collected_at: Optional[datetime] = None,
) -> FileLogtestResult:
    """Parses every non-empty line in file_path and runs the full YAML RuleEngine in memory."""
    cfg = ServerConfig.from_env()
    tol_sec = parse_duration_seconds(cfg.future_ts_tolerance)
    lateness_sec = parse_duration_seconds(cfg.allowed_lateness)
    ts = collected_at or datetime.now(timezone.utc)

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    events: List[ECSEvent] = []
    parsed_ok = 0
    unparsed = 0
    parse_errors = 0

    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        uid = compute_event_id("logtest-agent", 0, 0, str(file_path), idx)
        meta: Dict[str, Any] = {
            "event_uid": uid,
            "collected_at": ts,
            "received_at": ts,
            "agent": {
                "id": "logtest-agent",
                "hostname": "logtest-host",
                "version": "0.1.0",
                "timezone": timezone_name,
            },
            "log": {"file": {"path": str(file_path), "device": 0, "inode": 0, "offset": idx}},
            "default_timezone": timezone_name,
            "future_tolerance_seconds": tol_sec,
        }
        ev = parse(log_type, line, meta)
        events.append(ev)
        if ev.asp.parse_status == ParseStatus.OK:
            parsed_ok += 1
        elif ev.asp.parse_status == ParseStatus.UNPARSED:
            unparsed += 1
        else:
            parse_errors += 1

    ordered = sorted(events, key=lambda e: e.timestamp)
    engine = _load_engine(_resolve_rules_dir(rules_dir), allowed_lateness_seconds=lateness_sec)
    alerts = engine.evaluate_batch(ordered)

    return FileLogtestResult(
        file_path=str(file_path),
        log_type=log_type,
        total_lines=len(events),
        parsed_ok=parsed_ok,
        unparsed=unparsed,
        parse_errors=parse_errors,
        events=ordered,
        alerts=alerts,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Test ASP parsers and YAML rules offline (single log line or log file)."
    )
    parser.add_argument("line", nargs="?", default=None, help="Single raw log line to parse and match")
    parser.add_argument("--file", dest="file_path", default=None, help="Path to log file for batch rule replay")
    parser.add_argument("--type", dest="log_type", required=True, choices=["auth", "apache", "syslog"], help="Log source type")
    parser.add_argument("--rules-dir", default="rules/", help="Directory containing YAML rule files")
    parser.add_argument("--timezone", default="Asia/Ho_Chi_Minh", help="Simulated agent IANA timezone")
    parser.add_argument("--collected-at", default=None, help="Simulated ISO-8601 collected_at timestamp")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    collected_at: Optional[datetime] = None
    if args.collected_at:
        collected_at = datetime.fromisoformat(args.collected_at)
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)

    if args.file_path:
        path = Path(args.file_path)
        if not path.is_file():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        result = run_log_file(
            file_path=path,
            log_type=args.log_type,
            rules_dir=args.rules_dir,
            timezone_name=args.timezone,
            collected_at=collected_at,
        )
        payload = {
            "file": result.file_path,
            "log_type": result.log_type,
            "total_lines": result.total_lines,
            "parsed_ok": result.parsed_ok,
            "unparsed": result.unparsed,
            "parse_errors": result.parse_errors,
            "alerts": [al.model_dump(mode="json") for al in result.alerts],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=True))
        return 0

    if not args.line:
        parser.error("Either a positional <line> or --file <path> must be provided.")

    event, matched = run_single_line(
        raw_line=args.line,
        log_type=args.log_type,
        rules_dir=args.rules_dir,
        timezone_name=args.timezone,
        collected_at=collected_at,
    )
    payload = {
        "event": event.to_ecs_dict(),
        "matched_rules": [
            {
                "rule_id": al.rule_id,
                "title": al.title,
                "level": al.level.value,
                "alert_key": al.alert_key,
            }
            for al in matched
        ],
    }
    print(json.dumps(payload, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

