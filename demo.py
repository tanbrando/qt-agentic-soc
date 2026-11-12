#!/usr/bin/env python3
"""
Agentic SOC Platform - Zero-Infrastructure Demonstration & Investigation Harness (Synchronous).
Runs 100% in-memory without requiring PostgreSQL, Docker, Log Collector daemons, or Web Servers,
while executing the exact same YAML Rule Engine (6 rules), ECS v1.1 Parsers, LangGraph Agent,
Gemini AI adapter, and AbuseIPDB Threat Intelligence client as production.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from typing import List, Optional
from uuid import uuid4

try:
    import dotenv

    dotenv.load_dotenv()
except ImportError:
    pass

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.src.agent.workflow import create_investigator
from server.src.common.schemas import (
    AgentMetadata,
    AgentVerdict,
    Case,
    IngestBatchRequest,
    LogType,
    RawEventFileMeta,
    RawLogEvent,
)
from server.src.engine.base import RuleEngine
from server.src.engine.generic_rules import build_rule_from_spec
from server.src.engine.loader import load_rule_specs_from_dir
from server.src.engine.state_store import InMemorySlidingWindowStore
from server.src.repositories.memory import InMemoryAlertRepository, InMemoryLogRepository
from server.src.services.ingestion_service import IngestionService


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _mask_key(val: str) -> str:
    if len(val) <= 10:
        return "***"
    return f"{val[:6]}...{val[-4:]}"


def print_banner() -> None:
    """Displays platform header and live API configuration status."""
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite").strip()

    gemini_ok = bool(gemini_key) and not gemini_key.startswith(("your_", "CHANGE_ME"))
    abuse_ok = bool(abuse_key) and not abuse_key.startswith(("your_", "CHANGE_ME"))

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*75}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}       QT-AGENTIC-SOC: ZERO-INFRASTRUCTURE INVESTIGATION HARNESS{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*75}{Colors.RESET}")
    print(f"  {Colors.BOLD}Storage Engine:{Colors.RESET}   InMemory Repositories (100% In-RAM, Zero DB/Docker)")
    print(f"  {Colors.BOLD}SIEM Pipeline:{Colors.RESET}    ECS v1.1 Parsers + 6 YAML Rules + Case Correlation")

    if gemini_ok:
        print(f"  {Colors.BOLD}Gemini AI:{Colors.RESET}       {Colors.GREEN}[CONNECTED]{Colors.RESET} Model: {model} (Key: {_mask_key(gemini_key)})")
    else:
        print(f"  {Colors.BOLD}Gemini AI:{Colors.RESET}       {Colors.YELLOW}[OFFLINE MOCK]{Colors.RESET} RuleGuidedSOCAnalystLLM")

    if abuse_ok:
        print(f"  {Colors.BOLD}Threat Intel:{Colors.RESET}    {Colors.GREEN}[CONNECTED]{Colors.RESET} AbuseIPDB Live v2 API (Key: {_mask_key(abuse_key)})")
    else:
        print(f"  {Colors.BOLD}Threat Intel:{Colors.RESET}    {Colors.YELLOW}[OFFLINE MOCK]{Colors.RESET} MockThreatIntelProvider")
    print(f"{Colors.CYAN}{'='*75}{Colors.RESET}\n")


class SOCDemoHarness:
    """Manages synchronous in-memory SIEM + Agentic AI pipeline execution."""

    def __init__(
        self,
        use_mock_threat_intel: bool = False,
        use_mock_llm: bool = False,
    ) -> None:
        self.use_mock_threat_intel = use_mock_threat_intel
        self.use_mock_llm = use_mock_llm
        self.reports_dir = PROJECT_ROOT / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        self.reset()

    def reset(self) -> None:
        """Resets in-memory repositories and sliding-window state between scenarios."""
        self.log_repo = InMemoryLogRepository()
        self.alert_repo = InMemoryAlertRepository()
        self.window_store = InMemorySlidingWindowStore()

        specs = load_rule_specs_from_dir(PROJECT_ROOT / "rules")
        rules = [build_rule_from_spec(spec, state_store=self.window_store) for spec in specs]
        self.rule_engine = RuleEngine(rules)

        self.ingestion_service = IngestionService(
            log_repository=self.log_repo,
            alert_repository=self.alert_repo,
            rule_engine=self.rule_engine,
            default_timezone="UTC",
        )
        self.investigator = create_investigator(
            log_repository=self.log_repo,
            alert_repository=self.alert_repo,
            use_mock_threat_intel=self.use_mock_threat_intel,
            use_mock_llm=self.use_mock_llm,
        )

    def ingest_and_correlate(
        self,
        logs: List[str],
        hostname: str = "web-01",
        log_type: LogType = LogType.AUTH,
    ) -> List[Case]:
        """Feeds raw logs through IngestionService -> ECS Parser -> YAML Rules -> Case Correlation."""
        now = datetime.now(timezone.utc)
        src_path = "/var/log/apache2/access.log" if log_type == LogType.APACHE else "/var/log/auth.log"
        stream_id = uuid4().hex[:12]

        raw_events = [
            RawLogEvent(
                log_type=log_type,
                file=RawEventFileMeta(
                    path=src_path,
                    device=2049,
                    inode=10001,
                    stream_id=stream_id,
                    offset=idx * 256,
                ),
                collected_at=now,
                message=line,
            )
            for idx, line in enumerate(logs)
        ]

        batch_req = IngestBatchRequest(
            batch_id=f"demo-{uuid4().hex[:8]}",
            sent_at=now,
            agent=AgentMetadata(
                id="demo-agent-01",
                hostname=hostname,
                version="0.1.0",
                timezone="UTC",
            ),
            events=raw_events,
        )

        print(f"{Colors.BLUE}[+] Ingesting {len(raw_events)} raw security log events...{Colors.RESET}")
        resp = self.ingestion_service.ingest_batch(batch_req)
        cases = self.alert_repo.list_cases()
        alerts = self.alert_repo.list_alerts()

        print(f"    - Accepted (ECS): {resp.accepted} events (unparsed={resp.unparsed}, errors={resp.parse_errors})")
        print(f"    - Alerts Fired:   {len(alerts)}")
        print(f"    - Cases Created:  {len(cases)}")
        return cases

    def run_investigation(self, case: Case) -> Case:
        """Executes LangGraph investigation and persists findings back to InMemoryAlertRepository."""
        assert case.id is not None
        print(f"\n{Colors.YELLOW}[*] Triggering Autonomous LangGraph Investigation for Case #{case.id}...{Colors.RESET}")

        report_update = self.investigator.investigate_case(case)
        self.alert_repo.update_case_with_agent_report(
            case_id=case.id,
            report_data=report_update.model_dump(),
        )
        updated_case = self.alert_repo.get_case(case.id)
        assert updated_case is not None

        print(f"\n{Colors.GREEN}{'='*75}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}                    INVESTIGATION RESULT SUMMARY{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*75}{Colors.RESET}")
        print(f"  {Colors.BOLD}Case ID / Key:{Colors.RESET}    #{updated_case.id} ({updated_case.case_key})")
        print(f"  {Colors.BOLD}Case Title:{Colors.RESET}       {updated_case.title}")
        print(f"  {Colors.BOLD}Level:{Colors.RESET}            {updated_case.level.value.upper()}")

        v_color = Colors.RED if updated_case.agent_verdict == AgentVerdict.TRUE_POSITIVE.value else Colors.GREEN
        print(f"  {Colors.BOLD}Agent Verdict:{Colors.RESET}    {v_color}{updated_case.agent_verdict}{Colors.RESET}")
        print(f"  {Colors.BOLD}Confidence:{Colors.RESET}       {(updated_case.agent_confidence or 0.0) * 100:.1f}%")

        if updated_case.artifacts:
            print(f"\n  {Colors.BOLD}Extracted Security Artifacts ({len(updated_case.artifacts)}):{Colors.RESET}")
            for art in updated_case.artifacts:
                rep = f"(Reputation: {art.reputation_score} via {art.reputation_vendor})" if art.reputation_score is not None else ""
                print(f"    - [{art.artifact_type.value}] {art.value} {rep}")

        report_file = self.reports_dir / f"case_{updated_case.id}_report.md"
        report_file.write_text(updated_case.agent_report_markdown or "# No report", encoding="utf-8")
        print(f"\n  {Colors.BOLD}Saved Full Markdown Report:{Colors.RESET} {report_file}")
        print(f"{Colors.GREEN}{'='*75}{Colors.RESET}\n")
        return updated_case

    def _ts_prefix(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def run_scenario_ssh_bruteforce(self, attacker_ip: str = "203.0.113.77") -> Optional[Case]:
        """Scenario 1: External SSH Brute Force (`asp-ssh-bruteforce`)."""
        self.reset()
        print(f"\n{Colors.BOLD}--- SCENARIO 1: External SSH Brute Force ({attacker_ip}) ---{Colors.RESET}")
        ts = self._ts_prefix()
        raw_logs = [
            f"{ts} edge-gateway-01 sshd[{1001+i}]: Failed password for root from {attacker_ip} port {45120+i} ssh2"
            for i in range(5)
        ]
        cases = self.ingest_and_correlate(raw_logs, hostname="edge-gateway-01")
        return self.run_investigation(cases[0]) if cases else None

    def run_scenario_bruteforce_then_success(self, attacker_ip: str = "192.0.2.15") -> Optional[Case]:
        """Scenario 2: SSH Brute Force followed by Compromise (`asp-bruteforce-then-success`)."""
        self.reset()
        print(f"\n{Colors.BOLD}--- SCENARIO 2: SSH Brute Force Then Compromise ({attacker_ip}) ---{Colors.RESET}")
        ts = self._ts_prefix()
        raw_logs = [
            f"{ts} app-prod-01 sshd[{2001+i}]: Failed password for deploy from {attacker_ip} port {52100+i} ssh2"
            for i in range(5)
        ]
        raw_logs.append(f"{ts} app-prod-01 sshd[2099]: Accepted password for deploy from {attacker_ip} port 52199 ssh2")
        cases = self.ingest_and_correlate(raw_logs, hostname="app-prod-01")
        return self.run_investigation(cases[0]) if cases else None

    def run_scenario_sudo_abuse(self) -> Optional[Case]:
        """Scenario 3: Sudo Abuse & Unauthorized Privilege Escalation (`asp-sudo-abuse`)."""
        self.reset()
        print(f"\n{Colors.BOLD}--- SCENARIO 3: Sudo Privilege Escalation Abuse ---{Colors.RESET}")
        ts = self._ts_prefix()
        raw_logs = [
            f"{ts} dev-station-02 sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser=dev01 rhost=  user=dev01",
            f"{ts} dev-station-02 sudo: dev01 : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/dev01 ; USER=root ; COMMAND=/bin/bash",
        ]
        cases = self.ingest_and_correlate(raw_logs, hostname="dev-station-02")
        return self.run_investigation(cases[0]) if cases else None

    def run_scenario_internal_admin_anomaly(self) -> Optional[Case]:
        """Scenario 4: Internal Admin RFC1918 Anomaly (Benign False Positive)."""
        self.reset()
        print(f"\n{Colors.BOLD}--- SCENARIO 4: Internal Admin RFC1918 Anomaly (False Positive) ---{Colors.RESET}")
        ts = self._ts_prefix()
        private_ip = "192.168.1.50"
        raw_logs = [
            f"{ts} core-srv-01 sshd[{3001+i}]: Failed password for sysadmin from {private_ip} port {51100+i} ssh2"
            for i in range(5)
        ]
        cases = self.ingest_and_correlate(raw_logs, hostname="core-srv-01")
        return self.run_investigation(cases[0]) if cases else None

    def run_interactive_log_input(self) -> None:
        """Scenario 5: Interactive Live Log Sandbox."""
        self.reset()
        print(f"\n{Colors.BOLD}--- SCENARIO 5: Interactive Live Log Sandbox ---{Colors.RESET}")
        print("Enter raw Linux auth log lines (press Enter on empty line to finish):")
        logs: List[str] = []
        while True:
            try:
                line = input(f"Log [{len(logs)+1}] > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            logs.append(line)

        if not logs:
            print(f"{Colors.YELLOW}[*] No logs entered.{Colors.RESET}")
            return

        cases = self.ingest_and_correlate(logs, hostname="sandbox-host")
        if not cases:
            print(f"{Colors.YELLOW}[*] Logs parsed cleanly, but did not trigger any rule thresholds.{Colors.RESET}")
            return
        for c in cases:
            self.run_investigation(c)

    def run_all_scenarios(self) -> None:
        """Executes scenarios 1–4 sequentially and displays a scorecard."""
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== RUNNING ALL AUTOMATED SCENARIOS ==={Colors.RESET}\n")
        results: List[Case] = []
        for fn in (
            lambda: self.run_scenario_ssh_bruteforce("203.0.113.77"),
            lambda: self.run_scenario_bruteforce_then_success("192.0.2.15"),
            self.run_scenario_sudo_abuse,
            self.run_scenario_internal_admin_anomaly,
        ):
            case = fn()
            if case:
                results.append(case)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*75}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}                 AUTOMATED DEMO EXECUTION SCORECARD{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*75}{Colors.RESET}")
        print(f"  {'ID':<4} {'Case Title':<40} {'Verdict':<18} {'Confidence':<10}")
        print(f"  {'-'*70}")
        for c in results:
            title = (c.title or c.case_key)[:38]
            verdict_str = c.agent_verdict or "UNKNOWN"
            conf_str = f"{(c.agent_confidence or 0.0) * 100:.0f}%"
            print(f"  {str(c.id):<4} {title:<40} {verdict_str:<18} {conf_str:<10}")
        print(f"{Colors.CYAN}{'='*75}{Colors.RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="QT-Agentic-SOC Zero-Infrastructure Demo")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4, 5], help="Scenario number to run directly")
    parser.add_argument("--all", action="store_true", help="Run all automated scenarios")
    parser.add_argument("--ip", type=str, default="203.0.113.77", help="Target attacker IP for Scenario 1")
    args = parser.parse_args()

    print_banner()
    harness = SOCDemoHarness()

    if args.all:
        harness.run_all_scenarios()
        return

    if args.scenario:
        if args.scenario == 1:
            harness.run_scenario_ssh_bruteforce(args.ip)
        elif args.scenario == 2:
            harness.run_scenario_bruteforce_then_success()
        elif args.scenario == 3:
            harness.run_scenario_sudo_abuse()
        elif args.scenario == 4:
            harness.run_scenario_internal_admin_anomaly()
        elif args.scenario == 5:
            harness.run_interactive_log_input()
        return

    while True:
        print(f"{Colors.BOLD}Select Investigation Scenario:{Colors.RESET}")
        print("  [1] External SSH Brute Force (asp-ssh-bruteforce)")
        print("  [2] Brute Force -> Compromise (asp-bruteforce-then-success)")
        print("  [3] Sudo Privilege Escalation Abuse (asp-sudo-abuse)")
        print("  [4] Benign Admin RFC1918 Anomaly (False Positive Triage)")
        print("  [5] Interactive Live Log Sandbox (Paste custom raw auth logs)")
        print("  [6] Run All Automated Scenarios (Batch Scorecard)")
        print("  [q] Quit")

        try:
            choice = input(f"\n{Colors.BOLD}Enter choice (1-6, q): {Colors.RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if choice == "1":
            ip_in = input("Enter Attacker IP (default: 203.0.113.77): ").strip() or "203.0.113.77"
            harness.run_scenario_ssh_bruteforce(attacker_ip=ip_in)
        elif choice == "2":
            harness.run_scenario_bruteforce_then_success()
        elif choice == "3":
            harness.run_scenario_sudo_abuse()
        elif choice == "4":
            harness.run_scenario_internal_admin_anomaly()
        elif choice == "5":
            harness.run_interactive_log_input()
        elif choice == "6":
            harness.run_all_scenarios()
        elif choice in ("q", "quit", "exit"):
            print("Goodbye!")
            break
        else:
            print(f"{Colors.RED}Invalid selection. Please choose 1-6 or q.{Colors.RESET}\n")


if __name__ == "__main__":
    main()

