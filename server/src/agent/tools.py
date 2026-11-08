"""
Agent Tools interface for autonomous security incident investigation.
Supports LangChain / LangGraph tool binding while remaining usable standalone.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from server.src.agent.base import IThreatIntelProvider, MockThreatIntelProvider
from server.src.repositories.base import ILogRepository

# Optional integration with langchain_core
try:
    from langchain_core.tools import tool as lc_tool  # type: ignore
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

    def lc_tool(func: Callable) -> Callable:
        """Fallback decorator if langchain_core is not installed."""
        func.is_tool = True  # type: ignore
        return func


class SecurityAgentTools:
    """
    Tool suite for AI SOC Analysts.
    Injected with Log Repository and Threat Intelligence provider.
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        threat_intel: Optional[IThreatIntelProvider] = None,
    ) -> None:
        self.log_repo = log_repository
        self.threat_intel = threat_intel or MockThreatIntelProvider()

    async def search_logs(
        self,
        query_filter: Dict[str, Any],
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve related raw logs from the database repository.

        Args:
            query_filter: Key-value filters, e.g. {"hostname": "web-01", "service": "sshd"}
                          or {"fields.src_ip": "198.51.100.23"}.
            limit: Maximum number of log records to return (default: 50).
        """
        envelopes = await self.log_repo.find_events(query_filter, limit=limit)
        return [
            {
                "event_id": str(e.event_id),
                "timestamp": e.timestamp.isoformat(),
                "hostname": e.hostname,
                "log_type": e.log_type.value,
                "source_file": e.source_file,
                "raw": e.raw,
                "fields": e.fields,
            }
            for e in envelopes
        ]

    async def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Query AbuseIPDB / VirusTotal / Threat Intel for reputation and abuse history.

        Args:
            ip: IPv4 or IPv6 address to check.
        """
        return await self.threat_intel.lookup_ip(ip)

    def get_langchain_tools(self) -> List[Callable]:
        """Returns LangChain @tool decorated functions bound to these repository instances."""

        @lc_tool
        async def tool_search_logs(query_json: str, limit: int = 50) -> str:
            """
            Search raw security logs from the repository.
            `query_json` must be a valid JSON dictionary filter string.
            """
            try:
                query_dict = json.loads(query_json) if isinstance(query_json, str) else query_json
            except Exception:
                query_dict = {"raw": query_json}
            res = await self.search_logs(query_dict, limit)
            return json.dumps(res, indent=2)

        @lc_tool
        async def tool_check_ip_reputation(ip: str) -> str:
            """Check threat reputation score and vendor reports for an IP address."""
            res = await self.check_ip_reputation(ip)
            return json.dumps(res, indent=2)

        return [tool_search_logs, tool_check_ip_reputation]

