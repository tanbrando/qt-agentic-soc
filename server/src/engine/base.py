"""
Detection and Correlation Engine Interfaces.
Provides extensible rule definitions and engine orchestrator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Set

from server.src.common.schemas import Alert, LogEventEnvelope, LogType, Severity


class BaseRule(ABC):
    """
    Abstract Base Class for detection rules.
    Can be stateless (single event matching) or stateful (time-window correlation).
    """

    rule_id: str
    rule_name: str
    severity: Severity
    supported_log_types: Set[LogType] = {LogType.AUTH}
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []

    def applies_to(self, event: LogEventEnvelope) -> bool:
        """Fast filter to skip rules that do not process this log_type."""
        if not self.supported_log_types:
            return True
        return event.log_type in self.supported_log_types

    @abstractmethod
    def evaluate(self, event: LogEventEnvelope) -> Optional[Alert]:
        """
        Evaluates an event. For stateful rules, uses internal caching / sliding window.
        Returns an Alert if a security condition is met, else None.
        """
        pass


class RuleEngine:
    """
    Detection engine orchestrator.
    Evaluates incoming events across all registered rules and collects alerts.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None) -> None:
        self.rules: List[BaseRule] = list(rules) if rules else []

    def register_rule(self, rule: BaseRule) -> None:
        """Registers a detection rule."""
        if rule not in self.rules:
            self.rules.append(rule)

    def evaluate_event(self, event: LogEventEnvelope) -> List[Alert]:
        """Runs all applicable rules on a single log event."""
        alerts: List[Alert] = []
        for rule in self.rules:
            if rule.applies_to(event):
                try:
                    alert = rule.evaluate(event)
                    if alert:
                        alerts.append(alert)
                except Exception as e:
                    # In production, log warning without halting pipeline
                    print(f"[RuleEngine] Error evaluating rule {rule.rule_name}: {e}")
        return alerts

    def evaluate_batch(self, events: List[LogEventEnvelope]) -> List[Alert]:
        """Runs rules sequentially across an ordered batch of events."""
        alerts: List[Alert] = []
        for event in events:
            alerts.extend(self.evaluate_event(event))
        return alerts

