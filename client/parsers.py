"""
Client-side edge parser module.
Performs lightweight attribute extraction on the endpoint to minimize network payload or server CPU,
or delegates to shared server parsers when present.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional


class ClientEdgeParser:
    """Lightweight regex parser running at edge agent collector."""

    SSH_QUICK_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    SSH_QUICK_ACCEPT = re.compile(r"Accepted \S+ for (\S+) from (\S+)")

    @classmethod
    def parse_auth_line_fast(cls, line: str) -> Optional[Dict[str, Any]]:
        """Fast edge-level extraction for high-throughput ssh lines."""
        m_fail = cls.SSH_QUICK_FAIL.search(line)
        if m_fail:
            return {
                "service": "sshd",
                "event_action": "ssh_login",
                "event_outcome": "failure",
                "user": m_fail.group(1),
                "src_ip": m_fail.group(2),
            }

        m_acc = cls.SSH_QUICK_ACCEPT.search(line)
        if m_acc:
            return {
                "service": "sshd",
                "event_action": "ssh_login",
                "event_outcome": "success",
                "user": m_acc.group(1),
                "src_ip": m_acc.group(2),
            }

        return None

