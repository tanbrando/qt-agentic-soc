"""
Interfaces for Threat Intelligence Providers and Agent Investigation Workflows.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from server.src.common.schemas import AgentReportUpdate, Case


class IThreatIntelProvider(ABC):
    """Abstract interface for external Threat Intelligence lookup (AbuseIPDB, VirusTotal, etc.)."""

    @abstractmethod
    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Queries external reputation for an IP address."""
        pass


class MockThreatIntelProvider(IThreatIntelProvider):
    """
    Mock Threat Intel provider for local development, unit testing, and sandbox environments.
    """

    KNOWN_MALICIOUS_IPS = {
        "198.51.100.23": {"score": 98.0, "vendor": "AbuseIPDB", "reports": 450, "country": "RU"},
        "203.0.113.195": {"score": 85.0, "vendor": "AbuseIPDB", "reports": 120, "country": "CN"},
        "45.33.32.156": {"score": 75.0, "vendor": "VirusTotal", "reports": 35, "country": "US"},
    }

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if ip in self.KNOWN_MALICIOUS_IPS:
            data = self.KNOWN_MALICIOUS_IPS[ip]
            return {
                "ip": ip,
                "reputation_score": data["score"],
                "reputation_vendor": data["vendor"],
                "is_malicious": data["score"] > 50.0,
                "details": data,
            }

        # Check for private / RFC1918 IPs
        if ip.startswith(("10.", "192.168.", "172.16.", "127.", "::1")):
            return {
                "ip": ip,
                "reputation_score": 0.0,
                "reputation_vendor": "LocalNetwork",
                "is_malicious": False,
                "details": {"type": "private_network"},
            }

        # Neutral default score for unknown internet IPs
        return {
            "ip": ip,
            "reputation_score": 15.0,
            "reputation_vendor": "MockThreatIntel",
            "is_malicious": False,
            "details": {"status": "clean", "total_reports": 0},
        }


class IAgentInvestigator(ABC):
    """Abstract orchestrator for autonomous agent investigation on a security case."""

    @abstractmethod
    async def investigate_case(self, case: Case) -> AgentReportUpdate:
        """Runs the agent workflow to investigate the case and generate a conclusion."""
        pass

