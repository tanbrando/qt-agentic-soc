"""
Interfaces for Threat Intelligence Providers and Agent Investigation Workflows (Synchronous).
Includes deterministic Mock provider and live AbuseIPDB v2 HTTP client using `requests`.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import requests

from server.src.common.schemas import AgentReportUpdate, Case

logger = logging.getLogger("agentic_soc.agent.base")

_PLACEHOLDER_PREFIXES = ("your_", "CHANGE_ME")


class IThreatIntelProvider(ABC):
    """Abstract interface for external Threat Intelligence lookup (AbuseIPDB, VirusTotal, etc.)."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Queries external reputation for an IP address.
        Returns a standardized dict containing:
        {
            "ip": str,
            "reputation_score": float (0.0 - 100.0),
            "is_malicious": bool,
            "total_reports": int,
            "country": str,
            "vendor": str,
            "reputation_vendor": str,
            "details": Dict[str, Any],
        }
        """
        pass


class MockThreatIntelProvider(IThreatIntelProvider):
    """
    Offline and deterministic Mock Threat Intel provider for unit testing, CI/CD, and sandboxes.
    """

    KNOWN_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
        "198.51.100.23": {"score": 98.0, "vendor": "AbuseIPDB", "reports": 450, "country": "RU"},
        "203.0.113.195": {"score": 85.0, "vendor": "AbuseIPDB", "reports": 120, "country": "CN"},
        "203.0.113.77": {"score": 92.0, "vendor": "AbuseIPDB", "reports": 310, "country": "RU"},
        "45.33.32.156": {"score": 75.0, "vendor": "VirusTotal", "reports": 35, "country": "US"},
    }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        normalized_ip = ip.strip()

        # 1. Deterministic fixture match
        if normalized_ip in self.KNOWN_MALICIOUS_IPS:
            data = self.KNOWN_MALICIOUS_IPS[normalized_ip]
            return {
                "ip": normalized_ip,
                "reputation_score": float(data["score"]),
                "is_malicious": data["score"] >= 50.0,
                "total_reports": int(data.get("reports", 100)),
                "country": data.get("country", "UNKNOWN"),
                "vendor": data.get("vendor", "MockThreatIntel"),
                "reputation_vendor": data.get("vendor", "MockThreatIntel"),
                "details": data,
            }

        # 2. Documentation / test subnet 203.0.113.x (TEST-NET-3 used as attacker fixture)
        if normalized_ip.startswith("203.0.113."):
            return {
                "ip": normalized_ip,
                "reputation_score": 100.0,
                "is_malicious": True,
                "total_reports": 250,
                "country": "CN",
                "vendor": "MockThreatIntel",
                "reputation_vendor": "MockThreatIntel",
                "details": {"category": "ssh_bruteforce", "fixture": "test_net_3_malicious"},
            }

        # 3. Private / RFC1918 / loopback / malformed IPs
        is_private = False
        is_valid_ip = True
        try:
            addr = ipaddress.ip_address(normalized_ip)
            is_private = addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            is_valid_ip = False

        if not is_valid_ip:
            return {
                "ip": normalized_ip,
                "reputation_score": 0.0,
                "is_malicious": False,
                "total_reports": 0,
                "country": "UNKNOWN",
                "vendor": "LocalValidation",
                "reputation_vendor": "LocalValidation",
                "details": {"status": "invalid_ip"},
            }

        if is_private:
            return {
                "ip": normalized_ip,
                "reputation_score": 0.0,
                "is_malicious": False,
                "total_reports": 0,
                "country": "LOCAL",
                "vendor": "LocalNetwork",
                "reputation_vendor": "LocalNetwork",
                "details": {"type": "private_network"},
            }

        # 4. Neutral clean default for unknown internet IPs
        return {
            "ip": normalized_ip,
            "reputation_score": 15.0,
            "is_malicious": False,
            "total_reports": 0,
            "country": "US",
            "vendor": "MockThreatIntel",
            "reputation_vendor": "MockThreatIntel",
            "details": {"status": "clean", "total_reports": 0},
        }


class AbuseIPDBThreatIntelProvider(IThreatIntelProvider):
    """
    Synchronous Production Threat Intelligence provider querying AbuseIPDB v2 API via `requests`.
    Gracefully degrades with fallback if API key is missing, placeholder, invalid, or quota exceeded.
    """

    BASE_URL: str = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 5.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        raw_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
        cleaned = raw_key.strip()
        if cleaned.startswith(_PLACEHOLDER_PREFIXES):
            cleaned = ""
        self.api_key = cleaned
        self.timeout = timeout
        self._session = session

    def _fallback_response(self, ip: str, vendor_msg: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "reputation_score": 0.0,
            "is_malicious": False,
            "total_reports": 0,
            "country": "UNKNOWN",
            "vendor": vendor_msg,
            "reputation_vendor": vendor_msg,
            "details": {"fallback": True, "reason": vendor_msg},
        }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        normalized_ip = ip.strip()

        if not self.api_key:
            logger.warning(
                "AbuseIPDB API key not configured. Falling back to clean reputation for IP: %s",
                normalized_ip,
            )
            return self._fallback_response(normalized_ip, "AbuseIPDB (Unconfigured API Key)")

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": normalized_ip,
            "maxAgeInDays": "90",
            "verbose": "",
        }

        try:
            requester = self._session or requests
            response = requester.get(
                self.BASE_URL,
                headers=headers,
                params=params,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                payload = response.json().get("data", {})
                score = float(payload.get("abuseConfidenceScore", 0.0))
                total_reports = int(payload.get("totalReports", 0))
                country = str(payload.get("countryCode") or "UNKNOWN")
                is_malicious = score >= 50.0

                return {
                    "ip": normalized_ip,
                    "reputation_score": score,
                    "is_malicious": is_malicious,
                    "total_reports": total_reports,
                    "country": country,
                    "vendor": "AbuseIPDB",
                    "reputation_vendor": "AbuseIPDB",
                    "details": payload,
                }

            logger.warning(
                "AbuseIPDB API returned status %d for IP %s: %s",
                response.status_code,
                normalized_ip,
                response.text[:300],
            )
            return self._fallback_response(normalized_ip, f"AbuseIPDB (HTTP {response.status_code})")

        except Exception as exc:
            logger.warning(
                "AbuseIPDB lookup error for IP %s: %s",
                normalized_ip,
                exc,
            )
            return self._fallback_response(normalized_ip, "AbuseIPDB (Error Fallback)")


class IAgentInvestigator(ABC):
    """Abstract orchestrator for autonomous agent investigation on a security case."""

    @abstractmethod
    def investigate_case(self, case: Case) -> AgentReportUpdate:
        """Runs the agent workflow to investigate the case and generate a conclusion."""
        pass
