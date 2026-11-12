"""
Agent Tools suite for autonomous security incident investigation (Synchronous).
Supports LangChain / LangGraph tool binding with Pydantic args_schema while
remaining completely usable standalone without optional dependencies.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from server.src.agent.base import IThreatIntelProvider, MockThreatIntelProvider
from server.src.repositories.base import ILogRepository

try:
    from langchain_core.tools import tool as lc_tool  # type: ignore

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    lc_tool = None  # type: ignore


# ============================================================================
# Pydantic Tool Input Schemas
# ============================================================================

class SearchLogsArgs(BaseModel):
    query_filter: Dict[str, Any] = Field(
        default_factory=dict,
        description="ECS key-value filters such as {'src_ip': '198.51.100.23', 'user': 'root', 'event.id': [...]}",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Maximum number of ECS events to return")


class CheckIPReputationArgs(BaseModel):
    ip: str = Field(..., description="Target IPv4 or IPv6 address to query in Threat Intelligence")


class GetUserActivityArgs(BaseModel):
    user_name: str = Field(..., description="Username to inspect activity history for (ECS user.name)")
    limit: int = Field(default=20, ge=1, le=200, description="Maximum number of recent events")


class SearchEventsByUidsArgs(BaseModel):
    event_uids: List[str] = Field(..., description="List of deterministic SHA-1 event.id hashes")


# ============================================================================
# Uniform Tool Shim (Standalone + LangGraph Compatible)
# ============================================================================

class ToolShim:
    """Fallback wrapper providing `.name`, `.description`, `.args_schema`, and `.invoke(...)`."""

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        args_schema: Optional[Type[BaseModel]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self._func = func
        self.args_schema = args_schema

    def invoke(self, input_args: Dict[str, Any]) -> Any:
        if isinstance(input_args, str):
            try:
                input_args = json.loads(input_args)
            except Exception:
                input_args = {}
        return self._func(**input_args)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._func(*args, **kwargs)


def _wrap_tool(
    name: str,
    description: str,
    func: Callable[..., Any],
    args_schema: Optional[Type[BaseModel]] = None,
) -> Any:
    if HAS_LANGCHAIN and lc_tool is not None:
        decorated = lc_tool(args_schema=args_schema)(func)
        decorated.name = name
        return decorated
    return ToolShim(name=name, description=description, func=func, args_schema=args_schema)


# ============================================================================
# Tool Suite & Factory Functions
# ============================================================================

class SecurityAgentTools:
    """
    Read-only tool suite for AI SOC Analysts.
    Injected with synchronous ILogRepository and IThreatIntelProvider.
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        threat_intel: Optional[IThreatIntelProvider] = None,
    ) -> None:
        self.log_repo = log_repository
        self.threat_intel = threat_intel or MockThreatIntelProvider()

    def search_logs(
        self,
        query_filter: Dict[str, Any],
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve related normalized ECS logs from the database repository."""
        events = self.log_repo.find_events(query_filter, limit=limit)
        return [e.to_ecs_dict() for e in events]

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB / VirusTotal / Threat Intel for reputation and abuse history."""
        return self.threat_intel.lookup_ip(ip)

    def get_user_activity_history(self, user_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve chronological recent ECS events associated with a given user.name."""
        events = self.log_repo.list_events(user_name=user_name, limit=limit)
        return [e.to_ecs_dict() for e in events]

    def search_events_by_uids(self, event_uids: List[str]) -> List[Dict[str, Any]]:
        """Fetch exact normalized ECS events by their deterministic SHA-1 event.id values."""
        events = self.log_repo.get_by_ids(event_uids)
        return [e.to_ecs_dict() for e in events]

    def get_investigation_tools(self) -> List[Any]:
        """Returns standardized tool wrappers with Pydantic schemas for LangGraph / Gemini."""
        return [
            create_search_logs_tool(self.log_repo),
            create_check_ip_reputation_tool(self.threat_intel),
            create_get_user_activity_tool(self.log_repo),
            create_search_events_by_uids_tool(self.log_repo),
        ]

    def get_langchain_tools(self) -> List[Any]:
        """Backward-compatible alias returning callable tools."""
        return self.get_investigation_tools()


def create_search_logs_tool(log_repo: ILogRepository) -> Any:
    def search_logs(query_filter: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
        """Search normalized ECS security logs matching query_filter fields."""
        events = log_repo.find_events(query_filter, limit=limit)
        return [e.to_ecs_dict() for e in events]

    return _wrap_tool(
        name="search_logs",
        description="Search normalized ECS security logs matching key-value filters (e.g. src_ip, user, event.id).",
        func=search_logs,
        args_schema=SearchLogsArgs,
    )


def create_check_ip_reputation_tool(ti_provider: IThreatIntelProvider) -> Any:
    def check_ip_reputation(ip: str) -> Dict[str, Any]:
        """Query external Threat Intelligence (e.g., AbuseIPDB) for IP reputation score and abuse history."""
        return ti_provider.lookup_ip(ip)

    return _wrap_tool(
        name="check_ip_reputation",
        description="Look up an IP address in Threat Intelligence (AbuseIPDB) to inspect reputation score (0-100) and abuse reports.",
        func=check_ip_reputation,
        args_schema=CheckIPReputationArgs,
    )


def create_get_user_activity_tool(log_repo: ILogRepository) -> Any:
    def get_user_activity_history(user_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Inspect recent authentication, sudo, and command execution history for a specific username."""
        events = log_repo.list_events(user_name=user_name, limit=limit)
        return [e.to_ecs_dict() for e in events]

    return _wrap_tool(
        name="get_user_activity_history",
        description="Retrieve recent ECS telemetry events for a specific username to detect post-compromise sudo or shell activity.",
        func=get_user_activity_history,
        args_schema=GetUserActivityArgs,
    )


def create_search_events_by_uids_tool(log_repo: ILogRepository) -> Any:
    def search_events_by_uids(event_uids: List[str]) -> List[Dict[str, Any]]:
        """Fetch exact ECS log events by their SHA-1 event_uid list from an alert."""
        events = log_repo.get_by_ids(event_uids)
        return [e.to_ecs_dict() for e in events]

    return _wrap_tool(
        name="search_events_by_uids",
        description="Retrieve exact ECS evidence log events by their SHA-1 event_uid identifiers.",
        func=search_events_by_uids,
        args_schema=SearchEventsByUidsArgs,
    )
