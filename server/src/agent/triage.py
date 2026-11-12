"""
Forensic Triage Decision Engine & Evidence-Grounded Markdown Report Builder.
Supports ECS v1.1 telemetry and all 6 YAML detection rules.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from server.src.common.schemas import AgentVerdict


def is_ip_private_or_local(ip: str) -> bool:
    """
    Determines whether an IP belongs to internal RFC1918/loopback/link-local ranges.
    Explicitly excludes RFC 5737 TEST-NET lab attacker ranges (`192.0.2.0/24`,
    `198.51.100.0/24`, `203.0.113.0/24`) so they are evaluated as external endpoints.
    """
    clean_ip = ip.strip()
    if clean_ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
        return False
    try:
        addr = ipaddress.ip_address(clean_ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


@dataclass(frozen=True)
class TriageDecision:
    """Structured triage assessment synthesized from alerts, ECS logs, and Threat Intel."""

    verdict: AgentVerdict
    confidence: float
    executive_summary: str
    root_cause: str
    recommended_actions: List[str]


def _extract_ips_from_inputs(
    case_source_ip: Optional[str],
    alerts: List[Dict[str, Any]],
    artifacts: List[Dict[str, Any]],
) -> List[str]:
    ips: List[str] = []
    if case_source_ip:
        ips.append(str(case_source_ip))
    for art in artifacts:
        if art.get("artifact_type") == "IP" and art.get("value"):
            val = str(art["value"])
            if val not in ips:
                ips.append(val)
    for alert in alerts:
        gk = alert.get("group_key") or {}
        for key in ("source.ip", "src_ip", "attacker_ip"):
            val = gk.get(key)
            if val and str(val) not in ips:
                ips.append(str(val))
    return ips


def evaluate_forensic_evidence(
    alerts: List[Dict[str, Any]],
    artifacts: List[Dict[str, Any]],
    evidence_logs: Optional[List[Dict[str, Any]]] = None,
    case_source_ip: Optional[str] = None,
) -> TriageDecision:
    """
    Evaluates alert signatures, Threat Intelligence scores, and ECS evidence logs
    to produce a deterministic verdict, confidence score, and Human-in-the-Loop proposals.
    """
    evidence_logs = evidence_logs or []
    rule_ids = {str(a.get("rule_id") or "").lower() for a in alerts}
    titles = " ".join(str(a.get("title") or "").lower() for a in alerts)
    ecs_actions = {
        str((ev.get("event") or {}).get("action", "")).lower()
        for ev in evidence_logs
    }

    max_rep_score = max(
        (float(art.get("reputation_score") or 0.0) for art in artifacts),
        default=0.0,
    )
    observed_ips = _extract_ips_from_inputs(case_source_ip, alerts, artifacts)
    all_private = bool(observed_ips) and all(is_ip_private_or_local(ip) for ip in observed_ips)

    has_bf_then_success = (
        "asp-bruteforce-then-success" in rule_ids
        or ("ssh_login_failed" in ecs_actions and "ssh_login_success" in ecs_actions)
    )
    has_sudo_root_shell = (
        "asp-sudo-to-root-shell" in rule_ids
        or "mở shell root" in titles
    )
    has_sudo_abuse = (
        "asp-sudo-abuse" in rule_ids
        or "sudo" in titles
        or bool(ecs_actions & {"sudo_not_in_sudoers", "sudo_bad_password", "sudo_auth_failed"})
    )
    has_spraying = "asp-password-spraying" in rule_ids or "spraying" in titles
    has_web_scan = "asp-web-scan-404" in rule_ids or "quét web" in titles or "http_request" in ecs_actions
    has_bruteforce = (
        "asp-ssh-bruteforce" in rule_ids
        or "brute force" in titles
        or "bruteforce" in titles
    )

    ip_list_str = ", ".join(observed_ips) if observed_ips else "offending endpoint"

    # 1. Critical Post-Compromise / Root Shell Escalation
    if has_bf_then_success:
        return TriageDecision(
            verdict=AgentVerdict.TRUE_POSITIVE,
            confidence=min(0.98, 0.90 + (max_rep_score / 1200.0)),
            executive_summary=(
                "Critical True Positive: Repeated SSH authentication failures were followed by a "
                "successful login from the same source IP, indicating probable credential compromise."
            ),
            root_cause="Successful SSH brute-force compromise leading to unauthorized interactive access.",
            recommended_actions=[
                f"Immediately block source IP {ip_list_str} at perimeter firewall and terminate active SSH sessions.",
                "Force password reset and revoke/rotate SSH keys for the compromised account.",
                "Audit post-login commands (`sudo`, `useradd`, authorized_keys) for lateral movement or persistence.",
            ],
        )

    if has_sudo_root_shell:
        return TriageDecision(
            verdict=AgentVerdict.TRUE_POSITIVE,
            confidence=0.90,
            executive_summary=(
                "High-confidence True Positive: A user escalated privileges to an interactive root shell "
                "via sudo execution, requiring immediate authorization verification."
            ),
            root_cause="Interactive root shell spawning via sudo (`USER=root`, shell binary invocation).",
            recommended_actions=[
                "Verify with the system owner whether root shell access was part of an approved change window.",
                "Inspect shell history and audit logs following the `sudo` escalation timestamp.",
                "Temporarily restrict sudoers privileges if the escalation was unauthorized.",
            ],
        )

    # 2. High-Confidence Malicious Threat Intel
    if max_rep_score >= 50.0:
        return TriageDecision(
            verdict=AgentVerdict.TRUE_POSITIVE,
            confidence=min(0.97, 0.72 + (max_rep_score / 400.0)),
            executive_summary=(
                f"High-confidence True Positive confirmed. Source IP {ip_list_str} carries malicious "
                f"Threat Intelligence reputation ({max_rep_score:.1f}/100) corroborated by security alerts."
            ),
            root_cause="External threat actor conducting active credential attack or vulnerability scanning.",
            recommended_actions=[
                f"Block offending IP address(es) {ip_list_str} on perimeter firewall / fail2ban.",
                "Enforce SSH key-only authentication and disable root password login.",
                "Review recent successful logins to confirm zero unauthorized entry occurred.",
            ],
        )

    # 3. Internal / Private IP Benign Anomaly (no compromise / no root shell)
    if all_private and max_rep_score == 0.0 and not has_sudo_abuse:
        return TriageDecision(
            verdict=AgentVerdict.FALSE_POSITIVE,
            confidence=0.90,
            executive_summary=(
                f"Benign internal anomaly / False Positive. Observed source ({ip_list_str}) belongs to "
                "trusted RFC1918/local subnets with zero malicious Threat Intelligence reports and no compromise signs."
            ),
            root_cause="Internal administrator credential typo or automated monitoring/CI script misconfiguration.",
            recommended_actions=[
                "Verify internal host administration schedule or automated test script configuration.",
                "Resolve case and mark alert as False Positive after confirming with the internal operator.",
            ],
        )

    # 4. Sudo Policy Violations / Bad Password Abuse
    if has_sudo_abuse:
        return TriageDecision(
            verdict=AgentVerdict.TRUE_POSITIVE,
            confidence=0.88,
            executive_summary=(
                "High-confidence True Positive: Unauthorized privilege escalation attempt (`sudo` policy "
                "violation or repeated authentication failures) detected on endpoint."
            ),
            root_cause="Local account attempting unauthorized elevated execution via sudo.",
            recommended_actions=[
                "Suspend the involved local user account temporarily pending HR/Ops verification.",
                "Audit `/etc/sudoers` and inspect user home directory for unauthorized tools or scripts.",
            ],
        )

    # 5. External Behavioral Attacks without high TI score yet (Spraying / Web Scan)
    if has_spraying or has_web_scan:
        return TriageDecision(
            verdict=AgentVerdict.TRUE_POSITIVE,
            confidence=0.82,
            executive_summary=(
                f"True Positive based on behavioral signature: Source IP {ip_list_str} exhibited "
                "high-volume multi-account password spraying or web path enumeration (HTTP 404 spike)."
            ),
            root_cause="Automated reconnaissance or password-spraying campaign from an emerging/unflagged external IP.",
            recommended_actions=[
                f"Rate-limit or temporarily block {ip_list_str} on WAF / perimeter firewall.",
                "Check targeted usernames and verify account lockout / MFA enforcement.",
            ],
        )

    # 6. External Brute Force confirmed by correlation threshold (even on newly observed scanner IPs)
    if has_bruteforce and observed_ips:
        confidence = min(0.95, 0.80 + (max_rep_score / 500.0))
        note = (
            f"Threat Intel score is {max_rep_score:.1f}/100 (emerging or unindexed external IP); "
            if max_rep_score < 50.0
            else ""
        )
        return TriageDecision(
            verdict=AgentVerdict.TRUE_POSITIVE,
            confidence=confidence,
            executive_summary=(
                f"True Positive: External source IP {ip_list_str} exceeded the SSH brute-force correlation "
                f"threshold. {note}Threshold-based automated containment review is recommended."
            ),
            root_cause="Automated external SSH credential brute-force attempt targeting authentication daemon.",
            recommended_actions=[
                f"Block or rate-limit external IP {ip_list_str} via perimeter firewall / fail2ban.",
                "Enforce SSH key-only authentication and monitor auth logs for any subsequent login success.",
            ],
        )

    return TriageDecision(
        verdict=AgentVerdict.INCONCLUSIVE,
        confidence=0.50,
        executive_summary="Insufficient telemetry correlation to assign definitive malicious intent; Tier-2 review required.",
        root_cause="Telemetry requires deeper host/network forensic correlation.",
        recommended_actions=[
            "Escalate case to Tier-2 SOC Analyst for deeper endpoint inspection.",
            "Pull additional syslog/audit events around the incident time window.",
        ],
    )


def build_investigation_markdown_report(
    case_id: Any,
    title: str,
    level: str,
    hostname: str,
    triage: TriageDecision,
    artifacts: List[Dict[str, Any]],
    alert_count: int,
    evidence_count: int,
    llm_analysis: Optional[str] = None,
) -> str:
    """Generates a clean, evidence-grounded Markdown SOC incident report."""
    artifact_lines: List[str] = []
    for art in artifacts:
        a_type = art.get("artifact_type", "IP")
        val = art.get("value", "N/A")
        score = art.get("reputation_score")
        vendor = art.get("reputation_vendor") or "Unknown"
        score_str = f"Score {score}/100" if score is not None else "Observed"
        artifact_lines.append(f"- **Observable `{val}`** ({a_type}): {score_str} | Vendor: {vendor}")

    ti_section = "\n".join(artifact_lines) if artifact_lines else "- No external IoCs queried or enriched."
    remediation_section = "\n".join(
        f"{idx}. {act}" for idx, act in enumerate(triage.recommended_actions, start=1)
    )
    ip_observables = ", ".join(
        str(a.get("value")) for a in artifacts if a.get("artifact_type") == "IP" and a.get("value")
    )

    ai_notes_section = ""
    if llm_analysis and llm_analysis.strip():
        ai_notes_section = f"\n---\n\n## 🧠 AI Analyst Reasoning Notes\n{llm_analysis.strip()}\n"

    return (
        f"# 🛡️ Security Incident Investigation Report: {title}\n\n"
        f"## Executive Summary\n"
        f"- **Case ID**: `{case_id}`\n"
        f"- **Assigned Verdict**: **{triage.verdict.value}**\n"
        f"- **Confidence Level**: **{triage.confidence * 100:.1f}%**\n"
        f"- **Incident Level**: **{level.upper()}**\n"
        f"- **Target Host**: `{hostname}`\n\n"
        f"### Summary\n{triage.executive_summary}\n\n"
        f"---\n\n"
        f"## 🔍 Root Cause Analysis\n{triage.root_cause}\n\n"
        f"---\n\n"
        f"## 🌐 Threat Intelligence & Enriched Artifacts\n{ti_section}\n\n"
        f"---\n\n"
        f"## 📋 Investigation Findings & Evidence\n"
        f"- **Total Correlated Alerts**: {alert_count}\n"
        f"- **Evidence Raw Log Count**: {evidence_count}\n"
        f"- **Impacted Hostname(s)**: `{hostname}`\n"
        f"- **Correlated Attacker Observables**: {ip_observables or 'None'}\n"
        f"{ai_notes_section}\n"
        f"---\n\n"
        f"## 🛠️ Recommended Remediation Proposals (Human-in-the-Loop)\n"
        f"> **Note**: Automated containment is withheld. The following actions require human approval:\n"
        f"{remediation_section}\n"
    )
