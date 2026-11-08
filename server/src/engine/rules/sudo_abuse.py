"""
Sudo Abuse / Privilege Escalation Detection Rule (Stateless).
Detects unauthorized sudo executions, authentication failures, and not-in-sudoers violations.
"""

from __future__ import annotations

from typing import List, Optional, Set
from uuid import uuid4

from server.src.common.schemas import Alert, EventOutcome, LogEventEnvelope, LogType, Severity
from server.src.engine.base import BaseRule


class SudoAbuseRule(BaseRule):
    """
    Detects unauthorized sudo invocation and privilege escalation attempts.
    MITRE ATT&CK: Privilege Escalation (TA0004), Sudo and Sudo Caching (T1548.003).
    """

    rule_id: str = "RULE-AUTH-SUDO-001"
    rule_name: str = "Sudo Privilege Escalation Failure / Abuse"
    severity: Severity = Severity.HIGH
    supported_log_types: Set[LogType] = {LogType.AUTH}
    mitre_tactics: List[str] = ["TA0004"]
    mitre_techniques: List[str] = ["T1548.003"]

    def evaluate(self, event: LogEventEnvelope) -> Optional[Alert]:
        service = str(event.fields.get("service", "")).lower()
        if "sudo" not in service:
            return None

        outcome = event.fields.get("event_outcome")
        failure_reason = str(event.fields.get("failure_reason", "")).lower()
        raw_lower = event.raw.lower()

        is_failed_auth = outcome == EventOutcome.FAILURE.value
        is_not_in_sudoers = "user not in sudoers" in failure_reason or "not in sudoers" in raw_lower
        is_bad_pwd = "incorrect password attempts" in failure_reason or "incorrect password" in raw_lower
        is_pam_fail = "authentication failure" in failure_reason or "authentication failure" in raw_lower

        if is_failed_auth or is_not_in_sudoers or is_bad_pwd or is_pam_fail:
            user = event.fields.get("user") or "unknown"
            command = event.fields.get("command") or "unknown"
            target_user = event.fields.get("target_user") or "root"

            reason = failure_reason or (
                "user NOT in sudoers" if is_not_in_sudoers
                else "incorrect password attempts" if is_bad_pwd
                else "sudo authentication failure"
            )

            return Alert(
                alert_id=uuid4(),
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                hostname=event.hostname,
                timestamp=event.timestamp,
                context={
                    "user": user,
                    "target_user": target_user,
                    "command": command,
                    "reason": reason,
                    "source_file": event.source_file,
                },
                evidence_raw_events=[event.event_id],
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                dedup_key=f"sudo_abuse:{event.hostname}:{user}",
            )

        return None

