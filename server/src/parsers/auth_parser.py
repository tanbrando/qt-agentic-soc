"""
AuthLogParser for Linux authentication telemetry (/var/log/auth.log or /var/log/secure).
Extracts structured ECS attributes for sshd, sudo, useradd, and pam_unix session events.
Pure parser: no DB, network, or system clock access.
"""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Dict, Optional

from server.src.common.schemas import EventOutcome, LogType
from server.src.parsers.base import BaseLogParser, ParserRegistry
from server.src.parsers.common import parse_syslog_header, resolve_syslog_timestamp

MAX_AUTH_MSG_INSPECT_BYTES = 2048


@ParserRegistry.register
class AuthLogParser(BaseLogParser):
    """
    Parser for /var/log/auth.log telemetry (Sections 7.3, 7.4, 7.6).
    """

    # 1. SSH Patterns (Section 7.3)
    SSH_FAILED_RE = re.compile(
        r"^Failed\s+(?P<method>\S+)\s+for\s+(?:(?P<invalid>invalid\s+user)\s+)?(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )
    SSH_ACCEPTED_RE = re.compile(
        r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )
    SSH_INVALID_RE = re.compile(
        r"^Invalid\s+user\s+(?P<user>\S*)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
    )

    # 2. Sudo Patterns (Section 7.4)
    SUDO_NOT_IN_SUDOERS_RE = re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*user\s+NOT\s+in\s+sudoers\s*;\s*"
        r"(?:TTY=\S+\s*;\s*)?PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
    )
    SUDO_BAD_PASSWORD_RE = re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?P<n>\d+)\s+incorrect\s+password\s+attempts?\s*;\s*"
        r"(?:TTY=\S+\s*;\s*)?PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
    )
    SUDO_CMD_RE = re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*"
        r"(?:TTY=\S+\s*;\s*)?PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
    )
    SUDO_PAM_FAIL_RE = re.compile(
        r"^pam_unix\(sudo:auth\):\s+authentication\s+failure;\s+.*?"
        r"ruser=(?P<ruser>\S*)\s+.*?user=(?P<user>\S*)\s*$"
    )

    # 3. Useradd & PAM Session Patterns (Section 7.6)
    USERADD_RE = re.compile(
        r"new\s+user:\s*name=(?P<user>[^,]+),\s*UID=(?P<uid>\d+),\s*GID=(?P<gid>\d+),\s*"
        r"home=(?P<home>[^,]*),\s*shell=(?P<shell>\S*)"
    )
    PAM_SESSION_RE = re.compile(
        r"pam_unix\((?P<svc>[\w-]+):session\):\s+session\s+(?P<state>opened|closed)\s+for\s+user\s+(?P<user>[^\s(]+)"
    )

    @property
    def supported_log_type(self) -> LogType:
        return LogType.AUTH

    def can_handle(self, log_type: str, source_path: str = "") -> bool:
        if log_type == LogType.AUTH.value or log_type == "auth":
            return True
        if any(keyword in source_path for keyword in ("auth.log", "secure")):
            return True
        return False

    def parse_with_meta(
        self,
        message: str,
        meta: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        raw_line = message.strip()
        if not raw_line:
            return None

        header = parse_syslog_header(raw_line)
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

        fields = self._parse_body(header.proc, header.msg, header.pid)
        if fields is None:
            return None

        fields["@timestamp"] = event_ts
        fields["ts_clamped"] = ts_clamped
        return fields

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        header = parse_syslog_header(raw_line)
        if header is None:
            return None

        return self._parse_body(header.proc, header.msg, header.pid)

    def _parse_body(
        self,
        proc: str,
        msg: str,
        pid: Optional[int],
    ) -> Optional[Dict[str, Any]]:
        bounded_msg = msg[:MAX_AUTH_MSG_INSPECT_BYTES]
        fields: Dict[str, Any] = {
            "service": proc,
            "event_outcome": EventOutcome.UNKNOWN.value,
        }
        if pid is not None:
            fields["pid"] = pid

        proc_lower = proc.lower()
        if proc_lower == "sshd" or proc_lower.endswith("/sshd"):
            self._parse_sshd(bounded_msg, fields)
        elif proc_lower == "sudo" or proc_lower.endswith("/sudo"):
            self._parse_sudo(bounded_msg, fields)
        elif proc_lower == "useradd" or proc_lower.endswith("/useradd"):
            self._parse_useradd(bounded_msg, fields)

        # PAM session events can be emitted by login, systemd, CRON, sudo, sshd, etc.
        if "event_action" not in fields:
            self._parse_pam_session(bounded_msg, fields)

        if "event_action" not in fields:
            return None
        return fields

    def _parse_sshd(self, message: str, fields: Dict[str, Any]) -> None:
        m_failed = self.SSH_FAILED_RE.search(message)
        if m_failed:
            fields["category"] = ["authentication"]
            fields["event_type"] = ["start"]
            fields["event_action"] = "ssh_login_failed"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["parser"] = "sshd_failed@1"
            fields["auth_method"] = m_failed.group("method")
            fields["user"] = m_failed.group("user")
            fields["src_ip"] = m_failed.group("ip")
            fields["src_port"] = int(m_failed.group("port"))
            fields["is_invalid_user"] = bool(m_failed.group("invalid"))
            return

        m_accepted = self.SSH_ACCEPTED_RE.search(message)
        if m_accepted:
            fields["category"] = ["authentication"]
            fields["event_type"] = ["start"]
            fields["event_action"] = "ssh_login_success"
            fields["event_outcome"] = EventOutcome.SUCCESS.value
            fields["parser"] = "sshd_accepted@1"
            fields["auth_method"] = m_accepted.group("method")
            fields["user"] = m_accepted.group("user")
            fields["src_ip"] = m_accepted.group("ip")
            fields["src_port"] = int(m_accepted.group("port"))
            fields["is_invalid_user"] = False
            return

        m_inv = self.SSH_INVALID_RE.search(message)
        if m_inv:
            fields["category"] = ["authentication"]
            fields["event_type"] = ["start"]
            fields["event_action"] = "ssh_invalid_user"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["parser"] = "sshd_invalid@1"
            if m_inv.group("user"):
                fields["user"] = m_inv.group("user")
            fields["src_ip"] = m_inv.group("ip")
            if m_inv.group("port"):
                fields["src_port"] = int(m_inv.group("port"))
            fields["is_invalid_user"] = True

    def _parse_sudo(self, message: str, fields: Dict[str, Any]) -> None:
        m_pam = self.SUDO_PAM_FAIL_RE.match(message)
        if m_pam:
            fields["category"] = ["authentication"]
            fields["event_type"] = ["denied"]
            fields["event_action"] = "sudo_auth_failed"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["parser"] = "sudo_auth_failed@1"
            user = m_pam.group("user") or m_pam.group("ruser")
            if user:
                fields["user"] = user
            fields["failure_reason"] = "pam_authentication_failure"
            return

        m_not_sudoers = self.SUDO_NOT_IN_SUDOERS_RE.match(message)
        if m_not_sudoers:
            fields["category"] = ["process"]
            fields["event_type"] = ["denied"]
            fields["event_action"] = "sudo_not_in_sudoers"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["parser"] = "sudo_not_in_sudoers@1"
            fields["user"] = m_not_sudoers.group("user")
            fields["target_user"] = m_not_sudoers.group("target")
            fields["pwd"] = m_not_sudoers.group("pwd")
            fields["command"] = m_not_sudoers.group("cmd")
            fields["failure_reason"] = "user NOT in sudoers"
            return

        m_bad_pwd = self.SUDO_BAD_PASSWORD_RE.match(message)
        if m_bad_pwd:
            attempts = m_bad_pwd.group("n")
            fields["category"] = ["authentication"]
            fields["event_type"] = ["denied"]
            fields["event_action"] = "sudo_bad_password"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["parser"] = "sudo_bad_password@1"
            fields["user"] = m_bad_pwd.group("user")
            fields["target_user"] = m_bad_pwd.group("target")
            fields["pwd"] = m_bad_pwd.group("pwd")
            fields["command"] = m_bad_pwd.group("cmd")
            fields["failure_reason"] = f"{attempts} incorrect password attempts"
            return

        m_cmd = self.SUDO_CMD_RE.match(message)
        if m_cmd:
            fields["category"] = ["process"]
            fields["event_type"] = ["start"]
            fields["event_action"] = "sudo_command"
            fields["event_outcome"] = EventOutcome.UNKNOWN.value
            fields["parser"] = "sudo_command@1"
            fields["user"] = m_cmd.group("user")
            fields["target_user"] = m_cmd.group("target")
            fields["pwd"] = m_cmd.group("pwd")
            fields["command"] = m_cmd.group("cmd")

    def _parse_useradd(self, message: str, fields: Dict[str, Any]) -> None:
        m_useradd = self.USERADD_RE.search(message)
        if m_useradd:
            fields["category"] = ["iam"]
            fields["event_type"] = ["creation"]
            fields["event_action"] = "user_created"
            fields["event_outcome"] = EventOutcome.SUCCESS.value
            fields["parser"] = "useradd@1"
            fields["user"] = m_useradd.group("user")
            fields["uid"] = int(m_useradd.group("uid"))
            fields["gid"] = int(m_useradd.group("gid"))
            fields["home"] = m_useradd.group("home")
            fields["shell"] = m_useradd.group("shell")

    def _parse_pam_session(self, message: str, fields: Dict[str, Any]) -> None:
        m_pam = self.PAM_SESSION_RE.search(message)
        if m_pam:
            state = m_pam.group("state")
            fields["category"] = ["authentication"]
            fields["event_type"] = ["start" if state == "opened" else "end"]
            fields["event_action"] = f"session_{state}"
            fields["event_outcome"] = EventOutcome.SUCCESS.value
            fields["parser"] = "pam_session@1"
            fields["user"] = m_pam.group("user")
            fields["pam_service"] = m_pam.group("svc")
