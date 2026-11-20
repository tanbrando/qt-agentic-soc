"""
Linux Audit Log Parser (Section 7).
Parses /var/log/audit/audit.log records produced by Linux auditd / audit subsystem.
Handles SYSCALL, EXECVE, USER_CMD, USER_LOGIN, USER_AUTH, CONFIG_CHANGE, DAEMON_*, etc.
Extracts epoch timestamp to UTC datetime, key-value pairs, hex-encoded commands, user, process, and outcome.
Pure parser: no DB, network, or system clock access.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from server.src.common.schemas import EventOutcome, LogType
from server.src.parsers.base import BaseLogParser, ParserRegistry

# Matches standard and enriched audit log prefixes:
# type=TYPE msg=audit(epoch.msec:serial): body
# or node=hostname type=TYPE msg=audit(epoch.msec:serial): body
AUDIT_HEADER_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?"
    r"type=(?P<type>[A-Za-z0-9_]+)\s+"
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*"
    r"(?P<body>.*)$"
)

# Extracts key=value tokens where value is quoted, single-quoted, or unquoted
KV_RE = re.compile(r'([A-Za-z0-9_]+)=(?:\"([^\"]*)\"|\'([^\']*)\'|(\S*))')


def decode_audit_string(val: str) -> str:
    """Decodes hex-encoded audit strings (such as cmd=636174...) or strips quotes."""
    if not val:
        return ""
    v = val.strip("\"'")
    if len(v) >= 2 and len(v) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in v):
        try:
            raw = bytes.fromhex(v)
            decoded = raw.decode("utf-8")
            if all(b >= 32 or b in (9, 10, 13, 0) for b in raw):
                return decoded.replace("\x00", " ").strip()
        except Exception:
            pass
    return v


def parse_audit_kv(body: str) -> Dict[str, str]:
    """Parses key-value pairs from an audit record body, flattening nested msg='...' fields."""
    kv: Dict[str, str] = {}
    for match in KV_RE.finditer(body):
        k = match.group(1)
        val = match.group(2) if match.group(2) is not None else (
            match.group(3) if match.group(3) is not None else match.group(4)
        )
        kv[k] = val or ""

    # If msg field contains nested key-value pairs (e.g. msg='cwd=... cmd=... res=success')
    inner_msg = kv.get("msg", "")
    if inner_msg and ("=" in inner_msg):
        for match in KV_RE.finditer(inner_msg):
            k = match.group(1)
            val = match.group(2) if match.group(2) is not None else (
                match.group(3) if match.group(3) is not None else match.group(4)
            )
            # Do not overwrite if already defined in outer kv unless outer was placeholder
            if k not in kv or kv[k] in ("?", ""):
                kv[k] = val or ""

    return kv


@ParserRegistry.register
class AuditLogParser(BaseLogParser):
    """Parser for Linux audit daemon records (/var/log/audit/audit.log)."""

    @property
    def supported_log_type(self) -> LogType:
        return LogType.AUDIT

    def can_handle(self, log_type: str, source_path: str = "") -> bool:
        if log_type == LogType.AUDIT.value or log_type == "audit":
            return True
        if "audit.log" in source_path:
            return True
        return False

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        line = raw_line.strip()
        if not line:
            return None

        m = AUDIT_HEADER_RE.match(line)
        if not m:
            return None

        rec_type = m.group("type")
        epoch_str = m.group("epoch")
        serial_str = m.group("serial")
        body = m.group("body")

        try:
            event_ts = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        except (ValueError, OSError):
            return None

        kv = parse_audit_kv(body)

        # 1. Resolve outcome
        outcome = EventOutcome.UNKNOWN.value
        res_val = kv.get("res")
        success_val = kv.get("success")
        if res_val is not None:
            if res_val.lower() in ("success", "1"):
                outcome = EventOutcome.SUCCESS.value
            elif res_val.lower() in ("failed", "failure", "0"):
                outcome = EventOutcome.FAILURE.value
        elif success_val is not None:
            if success_val.lower() in ("yes", "1"):
                outcome = EventOutcome.SUCCESS.value
            elif success_val.lower() in ("no", "0"):
                outcome = EventOutcome.FAILURE.value

        # 2. Resolve User
        user = None
        for candidate_key in ("acct", "user", "UID", "AUID"):
            cand = kv.get(candidate_key)
            if cand and cand not in ("?", "none", "unset", "(none)"):
                user = cand
                break
        if not user:
            uid_cand = kv.get("uid")
            auid_cand = kv.get("auid")
            if uid_cand == "0":
                user = "root"
            elif uid_cand and uid_cand.isdigit() and uid_cand != "4294967295":
                user = f"uid:{uid_cand}"
            elif auid_cand and auid_cand.isdigit() and auid_cand != "4294967295":
                user = f"auid:{auid_cand}"

        # 3. Resolve Process / Command / Service
        pid = int(kv["pid"]) if "pid" in kv and kv["pid"].isdigit() else None
        service = None
        command = None

        if rec_type == "EXECVE":
            # Reconstruct arguments from a0, a1, a2, ...
            args: List[str] = []
            arg_indices = sorted(
                [int(k[1:]) for k in kv if k.startswith("a") and k[1:].isdigit()]
            )
            for idx in arg_indices:
                arg_val = kv.get(f"a{idx}", "")
                args.append(decode_audit_string(arg_val))
            if args:
                command = " ".join(args)
                service = Path(args[0]).name
        elif rec_type == "USER_CMD":
            raw_cmd = kv.get("cmd")
            if raw_cmd:
                command = decode_audit_string(raw_cmd)
                parts = command.split()
                if parts:
                    service = Path(parts[0]).name
            if not service:
                service = "sudo"
        elif rec_type == "SYSCALL":
            comm = kv.get("comm")
            exe = kv.get("exe")
            if comm:
                service = comm
            elif exe:
                service = Path(exe).name
            command = exe or comm
        else:
            exe = kv.get("exe")
            comm = kv.get("comm")
            if exe and exe not in ("?", "none"):
                service = Path(exe).name
                command = exe
            elif comm and comm not in ("?", "none"):
                service = comm
                command = comm

        # 4. Resolve Source IP / Port
        src_ip = kv.get("addr") or kv.get("hostname")
        if src_ip in ("?", "none", "unset", "(none)"):
            src_ip = None
        src_port = int(kv["port"]) if "port" in kv and kv["port"].isdigit() else None

        # 5. Resolve Categories & Actions
        if rec_type == "SYSCALL":
            category = ["process"]
            event_type = ["start"]
            event_action = f"audit_syscall_{service}" if service else "audit_syscall"
        elif rec_type == "EXECVE":
            category = ["process"]
            event_type = ["start"]
            event_action = "process_execution"
            outcome = EventOutcome.SUCCESS.value
        elif rec_type == "USER_CMD":
            category = ["process"]
            event_type = ["start"]
            event_action = "user_command"
        elif rec_type in ("USER_LOGIN", "LOGIN"):
            category = ["authentication"]
            event_type = ["start"]
            event_action = "user_login"
        elif rec_type == "USER_AUTH":
            category = ["authentication"]
            event_type = ["start"]
            event_action = "user_auth"
        elif rec_type == "USER_START":
            category = ["session"]
            event_type = ["start"]
            event_action = "session_start"
        elif rec_type == "USER_END":
            category = ["session"]
            event_type = ["end"]
            event_action = "session_end"
        elif rec_type == "CRED_ACQ":
            category = ["authentication"]
            event_type = ["start"]
            event_action = "credential_acquisition"
        elif rec_type == "CONFIG_CHANGE":
            category = ["configuration"]
            event_type = ["change"]
            event_action = "audit_config_change"
            if outcome == EventOutcome.UNKNOWN.value:
                outcome = EventOutcome.SUCCESS.value
        elif rec_type == "DAEMON_START":
            category = ["process"]
            event_type = ["start"]
            event_action = "daemon_start"
            service = "auditd"
        elif rec_type == "DAEMON_ABORT":
            category = ["process"]
            event_type = ["end"]
            event_action = "daemon_abort"
            service = "auditd"
        else:
            category = ["host"]
            event_type = ["info"]
            event_action = f"audit_{rec_type.lower()}"

        fields: Dict[str, Any] = {
            "@timestamp": event_ts,
            "category": category,
            "event_type": event_type,
            "event_action": event_action,
            "event_outcome": outcome,
            "parser": "audit_log@1",
            "body_message": line,
        }

        if service and service != "unknown":
            fields["service"] = service
        if pid is not None:
            fields["pid"] = pid
        if user:
            fields["user"] = user
        if command:
            fields["command"] = command
        if src_ip:
            fields["src_ip"] = src_ip
        if src_port is not None:
            fields["src_port"] = src_port

        failure_reason = kv.get("op") if outcome == EventOutcome.FAILURE.value else None
        if failure_reason:
            fields["failure_reason"] = failure_reason

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
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)
        if received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=timezone.utc)

        tol = int(meta.get("future_tolerance_seconds", 300))
        if fields["@timestamp"] > received_at + timedelta(seconds=tol):
            fields["@timestamp"] = collected_at
            fields["ts_clamped"] = True
        else:
            fields["ts_clamped"] = False

        return fields
