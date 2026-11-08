"""
FastAPI Dependency Injection Providers.
Manages application singletons and repository wiring.
"""

from __future__ import annotations

from typing import Optional

from server.src.agent.base import IAgentInvestigator, MockThreatIntelProvider
from server.src.agent.workflow import DefaultAgentInvestigator
from server.src.engine.base import RuleEngine
from server.src.engine.rules.ssh_bruteforce import SSHBruteForceRule
from server.src.engine.rules.sudo_abuse import SudoAbuseRule
from server.src.engine.state_store import InMemorySlidingWindowStore
from server.src.repositories.base import IAlertRepository, ILogRepository
from server.src.repositories.memory import InMemoryAlertRepository, InMemoryLogRepository
from server.src.services.ingestion_service import IngestionService


class Container:
    """Dependency injection container holding system singletons."""

    def __init__(self) -> None:
        self.log_repo: ILogRepository = InMemoryLogRepository()
        self.alert_repo: IAlertRepository = InMemoryAlertRepository()

        # Shared sliding window store
        self.window_store = InMemorySlidingWindowStore()

        # Rule Engine with default detection rules
        self.rule_engine = RuleEngine([
            SudoAbuseRule(),
            SSHBruteForceRule(threshold=5, window_seconds=300, state_store=self.window_store),
        ])

        # Pipeline service
        self.ingestion_service = IngestionService(
            log_repository=self.log_repo,
            alert_repository=self.alert_repo,
            rule_engine=self.rule_engine,
        )

        # Agent investigator
        self.threat_intel = MockThreatIntelProvider()
        self.agent_investigator: IAgentInvestigator = DefaultAgentInvestigator(
            log_repository=self.log_repo,
            threat_intel=self.threat_intel,
        )


# Global container instance
_container: Optional[Container] = None


def get_container() -> Container:
    global _container
    if _container is None:
        _container = Container()
    return _container


def reset_container() -> Container:
    """Resets container (useful for test isolation)."""
    global _container
    _container = Container()
    return _container


def get_ingestion_service() -> IngestionService:
    return get_container().ingestion_service


def get_log_repository() -> ILogRepository:
    return get_container().log_repo


def get_alert_repository() -> IAlertRepository:
    return get_container().alert_repo


def get_agent_investigator() -> IAgentInvestigator:
    return get_container().agent_investigator

