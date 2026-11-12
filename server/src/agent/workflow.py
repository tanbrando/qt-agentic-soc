"""
Agentic Investigation Workflow & Skeleton State Machine (Synchronous).
Defines the autonomous investigation pipeline for SOC incidents.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from server.src.agent.base import IAgentInvestigator, IThreatIntelProvider
from server.src.agent.tools import SecurityAgentTools
from server.src.common.schemas import (
    AgentReportUpdate,
    AgentVerdict,
    Artifact,
    ArtifactType,
    Case,
)
from server.src.repositories.base import ILogRepository


class DefaultAgentInvestigator(IAgentInvestigator):
    """
    Automated SOC Investigator.
    Follows a multi-step investigation loop:
    1. Triage: Inspects alerts and extracts observable IoCs (IPs, users).
    2. Evidence Collection: Queries related log records using search_logs.
    3. Threat Intelligence: Enriches observable IPs with reputation scores.
    4. Synthesis: Computes confidence and produces an executive incident report.
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        threat_intel: Optional[IThreatIntelProvider] = None,
    ) -> None:
        self.tools = SecurityAgentTools(log_repository, threat_intel)

    def investigate_case(self, case: Case) -> AgentReportUpdate:
        """Executes the autonomous investigation workflow on a security Case."""
        extracted_artifacts: List[Artifact] = []
        observed_ips: set[str] = set()
        evidence_logs: List[Dict[str, Any]] = []

        if case.source_ip:
            observed_ips.add(case.source_ip)

        for alert in case.alerts:
            attacker_ip = alert.group_key.get("source.ip") or alert.group_key.get("attacker_ip")
            if attacker_ip:
                observed_ips.add(str(attacker_ip))

            if alert.event_uids:
                logs = self.tools.search_logs(
                    query_filter={"event.id": alert.event_uids},
                    limit=len(alert.event_uids) + 5,
                )
                evidence_logs.extend(logs)

        max_reputation_score = 0.0
        reputation_details = []

        for ip in observed_ips:
            ti_res = self.tools.check_ip_reputation(ip)
            rep_score = float(ti_res.get("reputation_score", 0.0))
            if rep_score > max_reputation_score:
                max_reputation_score = rep_score

            artifact = Artifact(
                artifact_type=ArtifactType.IP,
                value=ip,
                reputation_score=rep_score,
                reputation_vendor=ti_res.get("reputation_vendor"),
                metadata=ti_res.get("details", {}),
            )
            extracted_artifacts.append(artifact)
            reputation_details.append(f"- **IP {ip}**: Score {rep_score}/100 ({ti_res.get('reputation_vendor', 'Unknown')})")

        has_bruteforce = any(
            "brute force" in (a.title or "").lower() or "bruteforce" in (a.rule_id or "").lower()
            for a in case.alerts
        )
        has_sudo_abuse = any(
            "sudo" in (a.title or "").lower() or "sudo" in (a.rule_id or "").lower()
            for a in case.alerts
        )

        if max_reputation_score >= 50.0 or (has_bruteforce and len(case.alerts) >= 1):
            verdict = AgentVerdict.TRUE_POSITIVE
            confidence = min(0.95, 0.70 + (max_reputation_score / 400.0))
            executive_summary = "Malicious activity confirmed based on threshold correlation and threat intelligence score."
        elif has_sudo_abuse and any(
            "user NOT in sudoers" in str(a.group_key) or "sudo_not_in_sudoers" in str(a.group_key)
            for a in case.alerts
        ):
            verdict = AgentVerdict.TRUE_POSITIVE
            confidence = 0.85
            executive_summary = "Unauthorized privilege escalation attempt detected on critical host."
        else:
            verdict = AgentVerdict.INCONCLUSIVE
            confidence = 0.50
            executive_summary = "Activity requires human Tier 2 SOC Analyst inspection."

        rep_section = "\n".join(reputation_details) if reputation_details else "No external observables enriched."
        evidence_count = len(evidence_logs) or sum(len(a.event_uids) for a in case.alerts)
        impacted_hosts = {str(a.group_key.get("host.name")) for a in case.alerts if a.group_key.get("host.name")}

        report_markdown = f"""# Security Incident Investigation Report: {case.title or case.case_key}

## Executive Summary
- **Verdict**: {verdict.value}
- **Confidence**: {confidence * 100:.1f}%
- **Level**: {case.level.value}
- **Summary**: {executive_summary}

## Correlated Threat Intelligence
{rep_section}

## Investigation Findings & Evidence
- **Total Correlated Alerts**: {len(case.alerts)}
- **Evidence Raw Log Count**: {evidence_count}
- **Impacted Hostname(s)**: {', '.join(sorted(impacted_hosts)) if impacted_hosts else 'unknown'}

### Recommended Mitigations
1. Isolate endpoint or add offending source IP(s) to perimeter blocklist / firewall.
2. Revoke active sessions for target accounts.
3. Conduct credential hygiene review.
"""

        return AgentReportUpdate(
            agent_verdict=verdict,
            agent_confidence=confidence,
            agent_report_markdown=report_markdown.strip(),
            extracted_artifacts=extracted_artifacts,
        )
