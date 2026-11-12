"""
Detection and Correlation Engine Interfaces.
Provides extensible rule definitions and engine orchestrator.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Set

from server.src.common.schemas import Alert, AlertLevel, ECSEvent, LogType

logger = logging.getLogger(__name__)


class BaseRule(ABC):
    """
    Abstract Base Class for detection rules.
    Can be stateless (single event matching) or stateful (time-window correlation).
    """

    rule_id: str
    rule_name: str
    level: AlertLevel
    supported_log_types: Set[LogType] = {LogType.AUTH}
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []

    def applies_to(self, event: ECSEvent) -> bool:
        """Fast filter to skip rules that do not process this event dataset."""
        if not self.supported_log_types:
            return True
        dataset = event.event.dataset
        return any(lt.value in dataset for lt in self.supported_log_types)

    @abstractmethod
    def evaluate(self, event: ECSEvent) -> Optional[Alert]:
        """Evaluates an event and returns an Alert if triggered."""
        pass


class RuleEngine:
    """
    Detection engine orchestrator.
    Evaluates incoming events across all registered rules and collects alerts.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None) -> None:
        self.rules: List[BaseRule] = list(rules) if rules else []

    def register_rule(self, rule: BaseRule) -> None:
        if rule not in self.rules:
            self.rules.append(rule)

    def evaluate_event(self, event: ECSEvent, replay_only: bool = False) -> List[Alert]:
        """Runs all applicable rules on a single log event."""
        alerts: List[Alert] = []
        for rule in self.rules:
            if rule.applies_to(event):
                try:
                    if replay_only:
                        try:
                            rule.evaluate(event, replay_only=True)  # type: ignore[call-arg]
                        except TypeError:
                            rule.evaluate(event)
                        continue
                    alert = rule.evaluate(event)
                    if alert:
                        alerts.append(alert)
                except Exception as exc:
                    logger.warning("Error evaluating rule %s: %s", rule.rule_name, exc)
        return alerts

    def evaluate_batch(self, events: List[ECSEvent], replay_only: bool = False) -> List[Alert]:
        """Runs rules sequentially across an ordered batch of events."""
        alerts: List[Alert] = []
        for event in events:
            alerts.extend(self.evaluate_event(event, replay_only=replay_only))
        return alerts
