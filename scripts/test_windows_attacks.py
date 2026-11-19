"""
Windows Client Attack Simulator & Manual Test Helper for ASP SIEM.
Writes authentic log lines into local Windows log files (logs/auth.log, logs/access.log, logs/audit.log, logs/syslog.log)
so that client/collector.py running on Windows tails them and ships them to ASP Server.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOGS_DIR = _ROOT / "logs"


def _ensure_log_files() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    for name in ["auth.log", "syslog.log", "audit.log", "access.log"]:
        f = LOGS_DIR / name
        if not f.exists():
            f.touch()


def _get_timestamp_syslog() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def _append_lines(file_path: Path, lines: list[str]) -> None:
    _ensure_log_files()
    with file_path.open("a", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(line + "\n")
            fh.flush()


def attack_ssh_bruteforce(attacker_ip: str = "203.0.113.77") -> None:
    ts = _get_timestamp_syslog()
    lines = [
        f"{ts} lab-windows sshd[{5000 + i}]: Failed password for root from {attacker_ip} port {51000 + i} ssh2"
        for i in range(1, 7)
    ]
    _append_lines(LOGS_DIR / "auth.log", lines)
    print(f"[✓] Đã ghi 6 lần SSH Failed từ IP {attacker_ip} vào logs/auth.log -> Kích hoạt asp-ssh-bruteforce (High)")


def attack_password_spraying(attacker_ip: str = "198.51.100.99") -> None:
    ts = _get_timestamp_syslog()
    users = ["admin", "devops", "tester", "backup", "guest", "postgres", "mysql", "nginx", "apache", "oracle", "git", "jenkins"]
    lines = [
        f"{ts} lab-windows sshd[{5100 + i}]: Failed password for invalid user {u} from {attacker_ip} port 52001 ssh2"
        for i, u in enumerate(users)
    ]
    _append_lines(LOGS_DIR / "auth.log", lines)
    print(f"[✓] Đã ghi 12 user SSH Failed từ IP {attacker_ip} vào logs/auth.log -> Kích hoạt asp-password-spraying (High)")


def attack_bruteforce_then_success(attacker_ip: str = "192.0.2.15") -> None:
    ts = _get_timestamp_syslog()
    lines = [
        f"{ts} lab-windows sshd[{5200 + i}]: Failed password for ubuntu from {attacker_ip} port {53000 + i} ssh2"
        for i in range(1, 6)
    ]
    lines.append(f"{ts} lab-windows sshd[5299]: Accepted password for ubuntu from {attacker_ip} port 53010 ssh2")
    _append_lines(LOGS_DIR / "auth.log", lines)
    print(f"[✓] Đã ghi chuỗi Brute Force rồi Login thành công từ IP {attacker_ip} vào logs/auth.log -> Kích hoạt asp-bruteforce-then-success (Critical)")


def attack_sudo_abuse() -> None:
    ts = _get_timestamp_syslog()
    line = f"{ts} lab-windows sudo: alice : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    _append_lines(LOGS_DIR / "auth.log", [line])
    print("[✓] Đã ghi log Sudo nhập sai mật khẩu vào logs/auth.log -> Kích hoạt asp-sudo-abuse (Medium)")


def attack_sudo_root_shell() -> None:
    ts = _get_timestamp_syslog()
    line = f"{ts} lab-windows sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
    _append_lines(LOGS_DIR / "auth.log", [line])
    print("[✓] Đã ghi log Sudo mở /bin/bash root vào logs/auth.log -> Kích hoạt asp-sudo-to-root-shell (Critical)")


def attack_web_scan_404(attacker_ip: str = "198.51.100.44") -> None:
    now_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    paths = ["/.env", "/wp-login.php", "/admin", "/phpmyadmin", "/.git/config", "/backup.zip", "/config.php", "/api/v1/debug"]
    lines = [
        f'{attacker_ip} - - [{now_str}] "GET {paths[i % len(paths)]}?id={i} HTTP/1.1" 404 432 "-" "curl/7.81.0"'
        for i in range(32)
    ]
    _append_lines(LOGS_DIR / "access.log", lines)
    print(f"[✓] Đã ghi 32 request HTTP 404 từ IP {attacker_ip} vào logs/access.log -> Kích hoạt asp-web-scan-404 (Medium)")


def attack_audit_logs() -> None:
    ts_sec = int(time.time())
    lines = [
        f"type=USER_CMD msg=audit({ts_sec}.100:101): pid=1234 uid=1000 auid=1000 ses=1 subj=? msg='cwd=\"/home/ubuntu\" cmd=636174202f6574632f736861646f77 terminal=pts/0 res=success'",
        f"type=SYSCALL msg=audit({ts_sec}.200:102): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd588e1a60 a1=7ffd588e27c8 a2=7ffd588e27d8 a3=7ffd588e1780 items=2 ppid=100 pid=1235 auid=1000 uid=0 gid=0 euid=0 comm=\"nmap\" exe=\"/usr/bin/nmap\" key=\"recon_tool\"",
    ]
    _append_lines(LOGS_DIR / "audit.log", lines)
    print("[✓] Đã ghi 2 bản ghi Linux/Windows Audit vào logs/audit.log -> Server AuditLogParser chuẩn hóa dataset: linux.audit")


def attack_syslog() -> None:
    ts = _get_timestamp_syslog()
    line = f"{ts} lab-windows systemd-custom[1420]: Service database-worker failed to reconnect: connection refused"
    _append_lines(LOGS_DIR / "syslog.log", [line])
    print("[✓] Đã ghi log hệ thống vào logs/syslog.log -> Server GenericSyslogParser chuẩn hóa dataset: linux.syslog")


def run_all_attacks() -> None:
    print("\n--- BẮT ĐẦU CHẠY TOÀN BỘ KỊCH BẢN TẤN CÔNG TRÊN WINDOWS CLIENT ---")
    attack_ssh_bruteforce("203.0.113.77")
    attack_password_spraying("198.51.100.99")
    attack_bruteforce_then_success("192.0.2.15")
    attack_sudo_abuse()
    attack_sudo_root_shell()
    attack_web_scan_404("198.51.100.44")
    attack_audit_logs()
    attack_syslog()
    print("\n[✓] HOÀN TẤT: 8 kịch bản đã được ghi vào thư mục logs/. Client Agent sẽ đọc và gửi về Server ngay lập tức!\n")


def show_cheat_sheet() -> None:
    print(r'''
========================================================================================
 BẢNG TRA CỨU LỆNH TEST TAY THỦ CÔNG TRÊN WINDOWS (POWERSHELL & CMD)
 (Copy & Paste trực tiếp vào cửa sổ PowerShell / CMD tại thư mục dự án)
========================================================================================

[1] Test Tay SSH Brute Force (High):
  PowerShell:
    1..6 | ForEach-Object { Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[500$_]: Failed password for root from 203.0.113.77 port $(51000+$_) ssh2" }
  CMD:
    for /L %i in (1,1,6) do @echo Nov 20 10:00:00 lab-windows sshd[500%i]: Failed password for root from 203.0.113.77 port 5100%i ssh2>> logs\auth.log

[2] Test Tay Password Spraying (High):
  PowerShell:
    "admin","devops","tester","backup","guest","postgres","mysql","nginx","apache","oracle","git","jenkins" | ForEach-Object { Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[5100]: Failed password for invalid user $_ from 198.51.100.99 port 52001 ssh2" }

[3] Test Tay Brute Force Then Success (Critical):
  PowerShell:
    1..5 | ForEach-Object { Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[520$_]: Failed password for ubuntu from 192.0.2.15 port $(53000+$_) ssh2" }
    Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[5299]: Accepted password for ubuntu from 192.0.2.15 port 53010 ssh2"

[4] Test Tay Sudo Abuse (Medium):
  PowerShell:
    Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sudo: alice : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"

[5] Test Tay Sudo Root Shell (Critical):
  PowerShell:
    Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"

[6] Test Tay Web Scan 404 (Medium):
  PowerShell:
    1..32 | ForEach-Object { Add-Content -Path logs\access.log -Value "198.51.100.44 - - [20/Nov/2026:10:00:00 +0000] \"GET /scan-$_.php HTTP/1.1\" 404 432 \"-\" \"curl/7.81.0\"" }

[7] Test Tay Audit Log (Linux/Windows Audit):
  PowerShell:
    Add-Content -Path logs\audit.log -Value "type=USER_CMD msg=audit(1732060000.100:101): pid=1234 uid=1000 auid=1000 ses=1 subj=? msg='cwd=\"/home/ubuntu\" cmd=636174202f6574632f736861646f77 terminal=pts/0 res=success'"
========================================================================================
''')


def interactive_menu() -> None:
    while True:
        print("""
=============================================================================
     CÔNG CỤ KIỂM THỬ TẤN CÔNG DÀNH CHO WINDOWS CLIENT AGENT
=============================================================================
 [1] Chạy FULL TẤT CẢ KỊCH BẢN (Kích hoạt 6 Alerts cùng lúc vào logs/)
 [2] Kịch bản 1: SSH Brute Force (6 failed attempts từ 203.0.113.77)
 [3] Kịch bản 2: Password Spraying (12 accounts từ 198.51.100.99)
 [4] Kịch bản 3: Brute Force Then Success (Dò 5 lần rồi thành công)
 [5] Kịch bản 4: Sudo Abuse (Nhập sai mật khẩu sudo 3 lần)
 [6] Kịch bản 5: Sudo Root Shell (Sudo mở /bin/bash đặc quyền)
 [7] Kịch bản 6: Web Scan 404 (32 requests 404 trong 1 phút)
 [8] Kịch bản 7: Audit Log (Lệnh quản trị USER_CMD hex-encoded & SYSCALL)
 [9] BẢNG TRA CỨU LỆNH TEST TAY THỦ CÔNG TRÊN POWERSHELL / CMD
 [0] Thoát
=============================================================================
""")
        choice = input("Nhập lựa chọn của bạn [0-9]: ").strip()
        if choice == "1":
            run_all_attacks()
        elif choice == "2":
            attack_ssh_bruteforce()
        elif choice == "3":
            attack_password_spraying()
        elif choice == "4":
            attack_bruteforce_then_success()
        elif choice == "5":
            attack_sudo_abuse()
        elif choice == "6":
            attack_sudo_root_shell()
        elif choice == "7":
            attack_web_scan_404()
        elif choice == "8":
            attack_audit_logs()
        elif choice == "9":
            show_cheat_sheet()
        elif choice == "0":
            print("Tạm biệt!")
            break
        else:
            print("[-] Lựa chọn không hợp lệ, vui lòng thử lại.")


def main() -> int:
    parser = argparse.ArgumentParser(description="ASP Windows Client Attack Tester")
    parser.add_argument(
        "--scenario",
        choices=["all", "ssh-bruteforce", "password-spraying", "bruteforce-then-success", "sudo-abuse", "sudo-root", "web-scan", "audit", "cheat-sheet"],
        help="Run specific attack scenario non-interactively.",
    )
    args = parser.parse_args()

    if args.scenario:
        if args.scenario == "all":
            run_all_attacks()
        elif args.scenario == "ssh-bruteforce":
            attack_ssh_bruteforce()
        elif args.scenario == "password-spraying":
            attack_password_spraying()
        elif args.scenario == "bruteforce-then-success":
            attack_bruteforce_then_success()
        elif args.scenario == "sudo-abuse":
            attack_sudo_abuse()
        elif args.scenario == "sudo-root":
            attack_sudo_root_shell()
        elif args.scenario == "web-scan":
            attack_web_scan_404()
        elif args.scenario == "audit":
            attack_audit_logs()
        elif args.scenario == "cheat-sheet":
            show_cheat_sheet()
        return 0

    interactive_menu()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
