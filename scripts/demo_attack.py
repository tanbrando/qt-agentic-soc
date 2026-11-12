"""
End-to-End Demo Attack Simulator (F.1).
Cross-platform (Windows/Linux) script using stdlib + requests only.
All target hosts, URLs, attacker IPs, and credentials are configured via CLI args or env vars.

Simulates:
1. SSH brute force failures followed by a successful login (`asp-ssh-bruteforce`, `asp-bruteforce-then-success`).
2. Sudo authentication/policy failures plus opening a root shell (`asp-sudo-abuse`, `asp-sudo-to-root-shell`).
3. Apache HTTP 404 directory scan (live HTTP requests against `--target-url` or generated Apache log lines).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import requests

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _env_or_required(cli_val: Optional[str], env_name: str, label: str) -> str:
    val = cli_val or os.environ.get(env_name)
    if not val:
        raise SystemExit(f"Missing {label}: provide CLI flag or set environment variable {env_name}.")
    return val


def build_demo_log_lines(
    attacker_ip: str,
    hostname: str,
    base_utc: Optional[datetime] = None,
) -> Tuple[List[str], List[str]]:
    """Builds chronological auth and apache log lines for the three demo attack scenarios."""
    t0 = (base_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def _iso_syslog(offset_s: int) -> str:
        return (t0.replace(microsecond=0)).isoformat() if offset_s == 0 else datetime.fromtimestamp(
            int(t0.timestamp()) + offset_s, tz=timezone.utc
        ).isoformat()

    def _clf_ts(offset_s: int) -> str:
        dt = datetime.fromtimestamp(int(t0.timestamp()) + offset_s, tz=timezone.utc)
        return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

    auth_lines: List[str] = []
    # 1. SSH brute force (5 failures) + 1 successful login
    for i in range(5):
        auth_lines.append(
            f"{_iso_syslog(i * 2)} {hostname} sshd[{3100 + i}]: "
            f"Failed password for deploy from {attacker_ip} port {52100 + i} ssh2"
        )
    auth_lines.append(
        f"{_iso_syslog(15)} {hostname} sshd[3199]: "
        f"Accepted password for deploy from {attacker_ip} port 52199 ssh2"
    )

    # 2. Sudo failures + root shell escalation
    auth_lines.append(
        f"{_iso_syslog(20)} {hostname} sudo: alice : user NOT in sudoers ; "
        "TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/id"
    )
    auth_lines.append(
        f"{_iso_syslog(24)} {hostname} sudo: alice : 3 incorrect password attempts ; "
        "TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    auth_lines.append(
        f"{_iso_syslog(28)} {hostname} sudo: deploy : TTY=pts/1 ; "
        "PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    )

    # 3. Apache HTTP 404 directory scan (32 requests within 1m)
    scan_paths = [
        "/.env", "/wp-login.php", "/admin", "/phpmyadmin", "/.git/config",
        "/backup.zip", "/config.php", "/api/v1/debug", "/server-status", "/xmlrpc.php",
    ]
    apache_lines = [
        f'{attacker_ip} - - [{_clf_ts(30 + i)}] "GET {scan_paths[i % len(scan_paths)]}?p={i} HTTP/1.1" '
        '404 196 "-" "asp-demo-scanner/1.0"'
        for i in range(32)
    ]
    return auth_lines, apache_lines


def run_http_scan(target_url: str, count: int = 32, timeout_sec: float = 5.0) -> Dict[str, int]:
    """Performs HTTP 404 probe requests against a lab web server using requests."""
    session = requests.Session()
    base = target_url.rstrip("/")
    counts: Dict[str, int] = {"total": 0, "status_404": 0, "other_status": 0, "errors": 0}
    for i in range(count):
        url = f"{base}/asp-demo-scan-{i:03d}"
        counts["total"] += 1
        try:
            resp = session.get(url, timeout=timeout_sec)
            if resp.status_code == 404:
                counts["status_404"] += 1
            else:
                counts["other_status"] += 1
        except requests.RequestException:
            counts["errors"] += 1
    return counts


def append_logs_for_collector(
    auth_log_path: Path,
    apache_log_path: Path,
    auth_lines: Sequence[str],
    apache_lines: Sequence[str],
    delay_seconds: float = 0.0,
) -> Tuple[int, int]:
    """Appends demo lines into local log files tailed by client/collector.py."""
    auth_log_path.parent.mkdir(parents=True, exist_ok=True)
    apache_log_path.parent.mkdir(parents=True, exist_ok=True)

    with auth_log_path.open("a", encoding="utf-8", newline="\n") as fh:
        for line in auth_lines:
            fh.write(line + "\n")
            fh.flush()
            if delay_seconds > 0:
                time.sleep(delay_seconds)

    with apache_log_path.open("a", encoding="utf-8", newline="\n") as fh:
        for line in apache_lines:
            fh.write(line + "\n")
            fh.flush()
            if delay_seconds > 0:
                time.sleep(delay_seconds)

    return len(auth_lines), len(apache_lines)


def send_direct_ingest(
    server_url: str,
    agent_id: str,
    hostname: str,
    api_key: str,
    auth_lines: Sequence[str],
    apache_lines: Sequence[str],
    timeout_sec: float = 10.0,
) -> Dict[str, int]:
    """Sends demo events directly to POST /api/v1/ingest/logs via v1.1 protocol."""
    now = datetime.now(timezone.utc)
    events = []
    offset = 0
    for idx, line in enumerate(auth_lines):
        events.append(
            {
                "log_type": "auth",
                "file": {
                    "path": "/var/log/auth.log",
                    "device": 1,
                    "inode": 9001,
                    "stream_id": f"demo-auth-{uuid.uuid4().hex[:8]}",
                    "offset": offset,
                },
                "collected_at": now.isoformat(),
                "message": line,
            }
        )
        offset += len(line.encode("utf-8")) + 1

    ap_offset = 0
    stream_web = f"demo-web-{uuid.uuid4().hex[:8]}"
    for idx, line in enumerate(apache_lines):
        events.append(
            {
                "log_type": "apache",
                "file": {
                    "path": "/var/log/apache2/access.log",
                    "device": 1,
                    "inode": 9002,
                    "stream_id": stream_web,
                    "offset": ap_offset,
                },
                "collected_at": now.isoformat(),
                "message": line,
            }
        )
        ap_offset += len(line.encode("utf-8")) + 1

    payload = {
        "schema_version": "1.1",
        "batch_id": f"demo-{uuid.uuid4().hex}",
        "sent_at": now.isoformat(),
        "agent": {
            "id": agent_id,
            "hostname": hostname,
            "version": "0.1.0",
            "timezone": "UTC",
        },
        "events": events,
    }
    url = server_url.rstrip("/") + "/api/v1/ingest/logs"
    resp = requests.post(
        url,
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout_sec,
    )
    resp.raise_for_status()
    return dict(resp.json())


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simulate multi-stage SOC attacks for ASP demo (zero hardcoded IP/key)."
    )
    parser.add_argument(
        "--mode",
        choices=["logfiles", "ingest", "http-scan"],
        required=True,
        help="logfiles: append auth/apache logs for collector.py; ingest: POST batch to server; http-scan: send real HTTP 404 scan requests.",
    )
    parser.add_argument(
        "--attacker-ip",
        default=None,
        help="Simulated attacker IP (or env ASP_DEMO_ATTACKER_IP).",
    )
    parser.add_argument(
        "--hostname",
        default=os.environ.get("ASP_DEMO_HOSTNAME", "lab-web-01"),
        help="Simulated victim hostname (default env ASP_DEMO_HOSTNAME or lab-web-01).",
    )
    parser.add_argument(
        "--auth-log",
        default=os.environ.get("ASP_DEMO_AUTH_LOG"),
        help="Target auth.log path for --mode logfiles (or env ASP_DEMO_AUTH_LOG).",
    )
    parser.add_argument(
        "--apache-log",
        default=os.environ.get("ASP_DEMO_APACHE_LOG"),
        help="Target apache access.log path for --mode logfiles (or env ASP_DEMO_APACHE_LOG).",
    )
    parser.add_argument(
        "--server-url",
        default=os.environ.get("ASP_SERVER_URL"),
        help="ASP Server base URL for --mode ingest (or env ASP_SERVER_URL).",
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("ASP_AGENT_ID", "web-01"),
        help="Registered agent ID for --mode ingest (or env ASP_AGENT_ID).",
    )
    parser.add_argument(
        "--api-key-env",
        default="ASP_AGENT_API_KEY",
        help="Environment variable name storing the agent Bearer API key (default ASP_AGENT_API_KEY).",
    )
    parser.add_argument(
        "--target-url",
        default=os.environ.get("ASP_DEMO_TARGET_URL"),
        help="Target HTTP base URL for --mode http-scan (or env ASP_DEMO_TARGET_URL).",
    )
    parser.add_argument(
        "--scan-count",
        type=int,
        default=32,
        help="Number of HTTP 404 probe requests to send in http-scan mode (default 32).",
    )
    args = parser.parse_args(argv)

    if args.mode == "http-scan":
        target_url = _env_or_required(args.target_url, "ASP_DEMO_TARGET_URL", "--target-url")
        stats = run_http_scan(target_url, count=args.scan_count)
        print(f"HTTP scan complete -> {stats}")
        return 0

    attacker_ip = _env_or_required(args.attacker_ip, "ASP_DEMO_ATTACKER_IP", "--attacker-ip")
    auth_lines, apache_lines = build_demo_log_lines(attacker_ip=attacker_ip, hostname=args.hostname)

    if args.mode == "logfiles":
        auth_path = Path(_env_or_required(args.auth_log, "ASP_DEMO_AUTH_LOG", "--auth-log"))
        apache_path = Path(_env_or_required(args.apache_log, "ASP_DEMO_APACHE_LOG", "--apache-log"))
        n_auth, n_ap = append_logs_for_collector(auth_path, apache_path, auth_lines, apache_lines)
        print(f"Appended {n_auth} auth lines to {auth_path} and {n_ap} apache lines to {apache_path}.")
        return 0

    server_url = _env_or_required(args.server_url, "ASP_SERVER_URL", "--server-url")
    api_key = _env_or_required(None, args.api_key_env, f"agent API key in env {args.api_key_env}")
    resp = send_direct_ingest(
        server_url=server_url,
        agent_id=args.agent_id,
        hostname=args.hostname,
        api_key=api_key,
        auth_lines=auth_lines,
        apache_lines=apache_lines,
    )
    print(f"Ingest complete -> {resp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

