"""
AuthLogParser for Linux authentication telemetry (/var/log/auth.log or /var/log/secure).
Extracts structured ECS attributes for sshd, sudo, useradd, and pam events.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from server.src.common.schemas import EventOutcome, LogType
from server.src.parsers.base import BaseLogParser, ParserRegistry


@ParserRegistry.register
class AuthLogParser(BaseLogParser):
    """
    Parser for /var/log/auth.log telemetry.
    Supports OpenSSH, Sudo privilege escalation, and Linux Account Management.
    """

    # Syslog header: <timestamp> <hostname> <service>[<pid>]: <message> or <service>: <message>
    # Supports both BSD syslog (Oct 11 04:02:11) and RFC 5424 / ISO 8601 timestamps
    SYSLOG_PREFIX_RE = re.compile(
        r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\S+))\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )

    # 1. SSH Patterns
    SSH_FAILED_PWD_RE = re.compile(
        r"^Failed\s+(?P<auth_method>\S+)\s+for\s+(?:(?P<invalid>invalid\s+user)\s+)?(?P<user>\S+)\s+"
        r"from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    )
    SSH_ACCEPTED_RE = re.compile(
        r"^Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+"
        r"from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    )
    SSH_INVALID_USER_RE = re.compile(
        r"^Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)(?:\s+port\s+(?P<src_port>\d+))?"
    )

    # 2. Sudo Patterns
    SUDO_CMD_RE = re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*"
        r"(?:(?P<error_note>user\s+NOT\s+in\s+sudoers|\d+\s+incorrect\s+password\s+attempts)\s*;\s*)?"
        r"TTY=(?P<tty>\S*)\s*;\s*"
        r"PWD=(?P<pwd>\S*)\s*;\s*"
        r"USER=(?P<target_user>\S+)\s*;\s*"
        r"COMMAND=(?P<command>.*)$"
    )
    SUDO_PAM_FAILURE_RE = re.compile(
        r"pam_unix\(sudo:auth\):\s+authentication\s+failure;\s+"
        r"logname=(?P<logname>\S*)\s+uid=(?P<uid>\d*)\s+euid=(?P<euid>\d*)\s+"
        r"tty=(?P<tty>\S*)\s+ruser=(?P<ruser>\S*)\s+rhost=(?P<rhost>\S*)\s+user=(?P<user>\S*)"
    )

    # 3. Useradd Patterns
    USERADD_RE = re.compile(
        r"new\s+user:\s*name=(?P<new_user>[^,]+),\s*UID=(?P<uid>\d+),\s*GID=(?P<gid>\d+),\s*"
        r"home=(?P<home>[^,]+),\s*shell=(?P<shell>[^,\s]+)"
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

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        fields: Dict[str, Any] = {
            "service": "unknown",
            "event_outcome": EventOutcome.UNKNOWN.value,
        }

        # Step 1: Extract Syslog standard prefix
        prefix_match = self.SYSLOG_PREFIX_RE.match(raw_line)
        if prefix_match:
            service = prefix_match.group("service")
            pid = prefix_match.group("pid")
            message = prefix_match.group("message")
            fields["service"] = service
            if pid:
                fields["pid"] = int(pid)
        else:
            # Standalone message or partial log line
            message = raw_line
            # Heuristic detection if service is prefixed without standard header
            if "sshd" in raw_line:
                fields["service"] = "sshd"
            elif "sudo" in raw_line:
                fields["service"] = "sudo"
            elif "useradd" in raw_line:
                fields["service"] = "useradd"

        service_lower = fields.get("service", "").lower()

        # Step 2: Parse specific services
        if "sshd" in service_lower:
            self._parse_sshd(message, fields)
        elif "sudo" in service_lower:
            self._parse_sudo(message, fields)
        elif "useradd" in service_lower:
            self._parse_useradd(message, fields)

        return fields

    def _parse_sshd(self, message: str, fields: Dict[str, Any]) -> None:
        # Failed password
        m_failed = self.SSH_FAILED_PWD_RE.search(message)
        if m_failed:
            fields["event_action"] = "ssh_login"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["auth_method"] = m_failed.group("auth_method")
            fields["user"] = m_failed.group("user")
            fields["src_ip"] = m_failed.group("src_ip")
            fields["src_port"] = int(m_failed.group("src_port"))
            fields["is_invalid_user"] = bool(m_failed.group("invalid"))
            return

        # Accepted login
        m_accepted = self.SSH_ACCEPTED_RE.search(message)
        if m_accepted:
            fields["event_action"] = "ssh_login"
            fields["event_outcome"] = EventOutcome.SUCCESS.value
            fields["auth_method"] = m_accepted.group("auth_method")
            fields["user"] = m_accepted.group("user")
            fields["src_ip"] = m_accepted.group("src_ip")
            fields["src_port"] = int(m_accepted.group("src_port"))
            fields["is_invalid_user"] = False
            return

        # Invalid user attempt
        m_inv = self.SSH_INVALID_USER_RE.search(message)
        if m_inv:
            fields["event_action"] = "ssh_login"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["user"] = m_inv.group("user")
            fields["src_ip"] = m_inv.group("src_ip")
            if m_inv.group("src_port"):
                fields["src_port"] = int(m_inv.group("src_port"))
            fields["is_invalid_user"] = True

    def _parse_sudo(self, message: str, fields: Dict[str, Any]) -> None:
        fields["service"] = "sudo"

        # Check for pam authentication failure
        m_pam = self.SUDO_PAM_FAILURE_RE.search(message)
        if m_pam:
            fields["event_action"] = "sudo_auth"
            fields["event_outcome"] = EventOutcome.FAILURE.value
            fields["user"] = m_pam.group("user") or m_pam.group("logname")
            fields["tty"] = m_pam.group("tty")
            fields["failure_reason"] = "pam_authentication_failure"
            return

        # Check for command execution or sudoer errors
        m_cmd = self.SUDO_CMD_RE.search(message)
        if m_cmd:
            fields["event_action"] = "sudo_command"
            fields["user"] = m_cmd.group("user")
            fields["target_user"] = m_cmd.group("target_user")
            fields["tty"] = m_cmd.group("tty")
            fields["pwd"] = m_cmd.group("pwd")
            fields["command"] = m_cmd.group("command")

            error_note = m_cmd.group("error_note")
            if error_note:
                fields["event_outcome"] = EventOutcome.FAILURE.value
                fields["failure_reason"] = error_note
            else:
                fields["event_outcome"] = EventOutcome.SUCCESS.value

    def _parse_useradd(self, message: str, fields: Dict[str, Any]) -> None:
        m_useradd = self.USERADD_RE.search(message)
        if m_useradd:
            fields["service"] = "useradd"
            fields["event_action"] = "user_created"
            fields["event_outcome"] = EventOutcome.SUCCESS.value
            fields["user"] = m_useradd.group("new_user")
            fields["uid"] = int(m_useradd.group("uid"))
            fields["gid"] = int(m_useradd.group("gid"))
            fields["home"] = m_useradd.group("home")
            fields["shell"] = m_useradd.group("shell")

