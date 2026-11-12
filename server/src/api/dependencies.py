"""
FastAPI Dependency Injection Providers & Authentication Guards (Synchronous).
Manages application singletons, repository wiring, engine lock, and Bearer auth.
"""

from __future__ import annotations

import hmac
import ipaddress
import threading
from pathlib import Path
from typing import Callable, Optional

import psycopg
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from server.src.agent.base import IAgentInvestigator
from server.src.agent.workflow import create_investigator
from server.src.common.config import ServerConfig, parse_duration_seconds
from server.src.common.security import InMemoryRateLimiter, hash_secret
from server.src.engine.base import RuleEngine
from server.src.engine.generic_rules import build_rule_from_spec
from server.src.engine.loader import load_rule_specs_from_dir
from server.src.engine.recovery import reload_engine_state
from server.src.engine.state_store import InMemorySlidingWindowStore
from server.src.repositories.base import (
    AgentRecord,
    IAlertRepository,
    IAuthRepository,
    ILogRepository,
    OperatorRecord,
)
from server.src.repositories.memory import (
    InMemoryAlertRepository,
    InMemoryAuthRepository,
    InMemoryLogRepository,
)
from server.src.repositories.postgres import (
    PostgresAlertRepository,
    PostgresAuthRepository,
    PostgresLogRepository,
)
from server.src.services.ingestion_service import IngestionService


class Container:
    """Dependency injection container holding system singletons."""

    def __init__(self, db_url: Optional[str] = None, force_memory: bool = False) -> None:
        cfg = ServerConfig.from_env()
        effective_db_url = None if force_memory else (db_url or cfg.db_url)

        if effective_db_url:
            self.log_repo: ILogRepository = PostgresLogRepository(effective_db_url)
            self.alert_repo: IAlertRepository = PostgresAlertRepository(effective_db_url)
            self.auth_repo: IAuthRepository = PostgresAuthRepository(effective_db_url)
        else:
            self.log_repo = InMemoryLogRepository()
            self.alert_repo = InMemoryAlertRepository()
            self.auth_repo = InMemoryAuthRepository()

        self.window_store = InMemorySlidingWindowStore()
        self.engine_lock = threading.Lock()
        self.rate_limiter = InMemoryRateLimiter(rate_per_minute=cfg.rate_limit_ingest)

        allowed_lateness_sec = parse_duration_seconds(cfg.allowed_lateness)
        rules_path = Path(cfg.rules_dir)
        if not rules_path.exists() and cfg.rules_dir == "rules/":
            fallback_rules = Path(__file__).resolve().parents[3] / "rules"
            if fallback_rules.exists():
                rules_path = fallback_rules

        rule_specs = load_rule_specs_from_dir(rules_path)
        self.rule_engine = RuleEngine(
            [
                build_rule_from_spec(
                    spec,
                    state_store=self.window_store,
                    allowed_lateness_seconds=allowed_lateness_sec,
                )
                for spec in rule_specs
            ]
        )

        if effective_db_url:
            reload_engine_state(
                rule_engine=self.rule_engine,
                state_store=self.window_store,
                log_repo=self.log_repo,
                alert_repo=self.alert_repo,
                allowed_lateness_seconds=allowed_lateness_sec,
            )

        self.ingestion_service = IngestionService(
            log_repository=self.log_repo,
            alert_repository=self.alert_repo,
            rule_engine=self.rule_engine,
            engine_lock=self.engine_lock,
            default_timezone=cfg.default_timezone,
            future_tolerance_seconds=parse_duration_seconds(cfg.future_ts_tolerance),
            case_idle_timeout_seconds=parse_duration_seconds(cfg.case_idle_timeout),
        )

        investigator = create_investigator(
            log_repository=self.log_repo,
            alert_repository=self.alert_repo,
        )
        self.threat_intel = investigator.threat_intel
        self.agent_investigator: IAgentInvestigator = investigator


_container: Optional[Container] = None


def get_container() -> Container:
    global _container
    if _container is None:
        _container = Container()
    return _container


def reset_container(db_url: Optional[str] = None, force_memory: bool = False) -> Container:
    """Resets container (useful for test isolation)."""
    global _container
    _container = Container(db_url=db_url, force_memory=force_memory)
    return _container


def get_ingestion_service() -> IngestionService:
    return get_container().ingestion_service


def get_log_repository() -> ILogRepository:
    return get_container().log_repo


def get_alert_repository() -> IAlertRepository:
    return get_container().alert_repo


def get_auth_repository() -> IAuthRepository:
    return get_container().auth_repo


def get_rate_limiter() -> InMemoryRateLimiter:
    return get_container().rate_limiter


def get_agent_investigator() -> IAgentInvestigator:
    return get_container().agent_investigator


def validate_optional_ip(ip_value: Optional[str]) -> Optional[str]:
    """Validates an optional IPv4/IPv6 query filter string, raising HTTP 422 if malformed."""
    if ip_value is None or ip_value == "":
        return None
    try:
        return str(ipaddress.ip_address(ip_value.strip()))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid source_ip filter: {ip_value!r}",
        ) from exc


_bearer_scheme = HTTPBearer(auto_error=False)


def _extract_bearer_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
) -> str:
    # Kiểm tra raw header trước để giữ nguyên thông báo lỗi 401 chuẩn
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )
    return parts[1].strip()


def require_agent_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    auth_repo: IAuthRepository = Depends(get_auth_repository),
) -> AgentRecord:
    """Validates Bearer API key against non-revoked agents."""
    raw_key = _extract_bearer_token(request, credentials)
    key_hash = hash_secret(raw_key)
    try:
        agent = auth_repo.get_agent_by_key_hash(key_hash)
    except psycopg.OperationalError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable",
        ) from exc

    if agent is None or not hmac.compare_digest(key_hash, agent.api_key_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked agent API key",
        )
    return agent


def require_operator_scope(required_scope: str) -> Callable[..., OperatorRecord]:
    """Dependency factory verifying operator Bearer token and required scope."""

    def _dependency(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
        auth_repo: IAuthRepository = Depends(get_auth_repository),
    ) -> OperatorRecord:
        raw_token = _extract_bearer_token(request, credentials)
        token_hash = hash_secret(raw_token)
        try:
            operator = auth_repo.get_operator_by_token_hash(token_hash)
        except psycopg.OperationalError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database temporarily unavailable",
            ) from exc

        if operator is None or not hmac.compare_digest(token_hash, operator.token_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked operator token",
            )
        if required_scope not in operator.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {required_scope}",
            )
        return operator

    return _dependency
