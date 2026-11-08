"""
SSH Brute Force Detection Rule (Stateful).
Tracks failed SSH attempts per source IP within a sliding window (e.g., 5 failures in 5 minutes).
"""

from __future__ import annotations

from typing import List, Optional, Set
from uuid import uuid4

from server.src.common.schemas import Alert, EventOutcome, LogEventEnvelope, LogType, Severity
from server.src.engine.base import BaseRule
from server.src.engine.state_store import ISlidingWindowStore, InMemorySlidingWindowStore


class SSHBruteForceRule(BaseRule):
    """
    Stateful rule tracking SSH authentication failures over a sliding time window.
    MITRE ATT&CK: Credential Access (TA0006), Brute Force: Password Guessing (T1110.001).
    """

    rule_id: str = "RULE-AUTH-SSH-002"
    rule_name: str = "SSH Authentication Brute Force"
    severity: Severity = Severity.HIGH
    supported_log_types: Set[LogType] = {LogType.AUTH}
    mitre_tactics: List[str] = ["TA0006"]
    mitre_techniques: List[str] = ["T1110.001"]

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,  # 5 minutes
        state_store: Optional[ISlidingWindowStore] = None,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.state_store = state_store or InMemorySlidingWindowStore()

    def evaluate(self, event: LogEventEnvelope) -> Optional[Alert]:
        service = str(event.fields.get("service", "")).lower()
        if "sshd" not in service:
            return None

        outcome = event.fields.get("event_outcome")
        if outcome != EventOutcome.FAILURE.value:
            return None

        src_ip = event.fields.get("src_ip")
        if not src_ip or src_ip in ("127.0.0.1", "::1"):
            return None

        target_user = event.fields.get("user") or "unknown"
        bucket_key = f"ssh_fail:{event.hostname}:{src_ip}"

        # Add event to temporal window
        events_in_window = self.state_store.add_and_get_window(
            bucket_key=bucket_key,
            event_id=event.event_id,
            timestamp=event.timestamp,
            window_seconds=self.window_seconds,
        )

        # Trigger alert once threshold is reached
        if len(events_in_window) >= self.threshold:
            # We trigger the alert with all correlated event IDs in the window
            alert = Alert(
                alert_id=uuid4(),
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                hostname=event.hostname,
                timestamp=event.timestamp,
                context={
                    "attacker_ip": src_ip,
                    "target_user": target_user,
                    "failure_count": len(events_in_window),
                    "threshold": self.threshold,
                    "window_seconds": self.window_seconds,
                    "auth_method": event.fields.get("auth_method", "password"),
                },
                evidence_raw_events=list(events_in_window),
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                dedup_key=f"ssh_bruteforce:{event.hostname}:{src_ip}",
            )
            return alert

        return None

