#!/usr/bin/env bash
# ==============================================================================
# Script giả lập tấn công thực tế trên Ubuntu để kích hoạt FULL 6/6 RULES
# HOÀN TOÀN KHÔNG CẦN NHẬP PASSWORD SUDO!
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}   ASP SIEM - Bộ công cụ kiểm thử FULL 6/6 RULES trên Ubuntu    ${NC}"
echo -e "${CYAN}   (Tự động hoàn toàn 100% - KHÔNG CẦN NHẬP MẬT KHẨU SUDO)      ${NC}"
echo -e "${CYAN}================================================================${NC}"

echo -e "Chọn kịch bản bạn muốn kiểm thử:"
echo -e "  ${YELLOW}1${NC}) CHẠY FULL TẤT CẢ 6 RULES (SSH, Sudo, Password Spraying, Web 404 Scan)"
echo -e "  ${YELLOW}2${NC}) Test SSH Brute Force (Rule: asp-ssh-bruteforce)"
echo -e "  ${YELLOW}3${NC}) Test Password Spraying (Rule: asp-password-spraying)"
echo -e "  ${YELLOW}4${NC}) Test Brute Force rồi Success (Rule: asp-bruteforce-then-success)"
echo -e "  ${YELLOW}5${NC}) Test Sudo Abuse (Rule: asp-sudo-abuse)"
echo -e "  ${YELLOW}6${NC}) Test Sudo to Root Shell (Rule: asp-sudo-to-root-shell)"
echo -e "  ${YELLOW}7${NC}) Test Web Scan 404 (Rule: asp-web-scan-404)"
echo -e "  ${YELLOW}0${NC}) Thoát"
echo ""
read -p "Nhập lựa chọn của bạn [1-7]: " choice

ATTACKER_IP="203.0.113.77"
CURRENT_USER="$(whoami)"

# Lấy thư mục gốc dự án
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Hàm gửi log auth vào hệ thống chuẩn Ubuntu bằng lệnh logger (không cần root/sudo)
log_auth() {
  local msg="$1"
  logger -p auth.info -t sshd "$msg" 2>/dev/null || logger -t sshd "$msg"
}

log_sudo() {
  local msg="$1"
  logger -p authpriv.notice -t sudo "$msg" 2>/dev/null || logger -t sudo "$msg"
}

# 1. Rule: asp-ssh-bruteforce
test_ssh_bruteforce() {
  echo -e "\n${YELLOW}[1/6] Đang chạy Rule: asp-ssh-bruteforce (6 lần ssh fail liên tiếp)...${NC}"
  for i in {1..6}; do
    PORT=$((51000 + i))
    log_auth "Failed password for root from ${ATTACKER_IP} port ${PORT} ssh2"
    echo -e "  -> Thử sai mật khẩu lần $i/6 từ IP ${ATTACKER_IP}"
    sleep 0.1
  done
  echo -e "${GREEN}[✓] Đã kích hoạt Rule 1: asp-ssh-bruteforce (Level: Medium)${NC}"
}

# 2. Rule: asp-password-spraying (Yeu cau >= 10 users khac nhau trong 5 phut)
test_password_spraying() {
  echo -e "\n${YELLOW}[2/6] Đang chạy Rule: asp-password-spraying (Dò 1 pass trên 12 user khác nhau)...${NC}"
  local users=("admin" "devops" "tester" "backup" "guest" "postgres" "mysql" "nginx" "apache" "oracle" "git" "jenkins")
  local port=52000
  local spray_ip="198.51.100.99"
  for u in "${users[@]}"; do
    port=$((port + 1))
    log_auth "Failed password for invalid user $u from ${spray_ip} port ${port} ssh2"
    echo -e "  -> Thử mật khẩu user '$u' từ IP ${spray_ip}"
    sleep 0.1
  done
  echo -e "${GREEN}[✓] Đã kích hoạt Rule 2: asp-password-spraying (Level: High)${NC}"
}

# 3. Rule: asp-bruteforce-then-success
test_bruteforce_then_success() {
  echo -e "\n${YELLOW}[3/6] Đang chạy Rule: asp-bruteforce-then-success (5 lần fail rồi 1 lần success)...${NC}"
  local target_ip="192.0.2.15"
  for i in {1..5}; do
    log_auth "Failed password for ubuntu from ${target_ip} port $((53000 + i)) ssh2"
    echo -e "  -> Dò mật khẩu thất bại lần $i/5 từ IP ${target_ip}"
    sleep 0.1
  done
  log_auth "Accepted password for ubuntu from ${target_ip} port 53010 ssh2"
  echo -e "  -> [!] ĐĂNG NHẬP THÀNH CÔNG từ IP ${target_ip}!"
  echo -e "${GREEN}[✓] Đã kích hoạt Rule 3: asp-bruteforce-then-success (Level: Critical)${NC}"
}

# 4. Rule: asp-sudo-abuse
test_sudo_abuse() {
  echo -e "\n${YELLOW}[4/6] Đang chạy Rule: asp-sudo-abuse (3 lần nhập sai pass sudo)...${NC}"
  for i in {1..3}; do
    log_sudo "pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/1 ruser=$CURRENT_USER rhost= user=$CURRENT_USER"
    log_sudo "$CURRENT_USER : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/$CURRENT_USER ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    echo -e "  -> Gõ sai mật khẩu sudo lần $i/3"
    sleep 0.1
  done
  echo -e "${GREEN}[✓] Đã kích hoạt Rule 4: asp-sudo-abuse (Level: High)${NC}"
}

# 5. Rule: asp-sudo-to-root-shell
test_sudo_root_shell() {
  echo -e "\n${YELLOW}[5/6] Đang chạy Rule: asp-sudo-to-root-shell (Leo quyền mở root shell)...${NC}"
  log_sudo "$CURRENT_USER : TTY=pts/0 ; PWD=/home/$CURRENT_USER ; USER=root ; COMMAND=/bin/bash"
  echo -e "  -> Phát sinh log user '$CURRENT_USER' leo quyền mở shell /bin/bash dưới quyền root"
  echo -e "${GREEN}[✓] Đã kích hoạt Rule 5: asp-sudo-to-root-shell (Level: Critical)${NC}"
}

# 6. Rule: asp-web-scan-404
test_web_scan_404() {
  echo -e "\n${YELLOW}[6/6] Đang chạy Rule: asp-web-scan-404 (32 request 404 quét web)...${NC}"
  local py_bin="$ROOT_DIR/.venv-client/bin/python"
  if [[ ! -x "$py_bin" ]]; then
    py_bin="python3"
  fi
  
  "$py_bin" - "$ROOT_DIR/.env" <<'PY'
import sys, os, requests, uuid
from datetime import datetime, timezone
from pathlib import Path

env_file = sys.argv[1]
env_vars = {}
if os.path.exists(env_file):
    for line in Path(env_file).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip()

server_url = env_vars.get("ASP_SERVER_URL", "http://172.19.240.1:8000")
agent_id = env_vars.get("ASP_AGENT_ID", "web-01")
api_key = env_vars.get("ASP_AGENT_API_KEY", "")

scan_ip = "198.51.100.44"
now = datetime.now(timezone.utc).isoformat()

events = []
for i in range(1, 33):
    events.append({
        "log_type": "apache",
        "file": {
            "path": "/var/log/apache2/access.log",
            "device": 1,
            "inode": 99999,
            "offset": i * 100,
            "stream_id": str(uuid.uuid4())
        },
        "collected_at": now,
        "message": f'{scan_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /scan-path-{i}.php HTTP/1.1" 404 432 "-" "curl/7.81.0"'
    })

batch = {
    "schema_version": "1.1",
    "batch_id": str(uuid.uuid4()),
    "sent_at": now,
    "agent": {"id": agent_id, "hostname": "ubuntu-lab", "version": "1.0.0", "ip": ["127.0.0.1"], "timezone": "UTC"},
    "events": events
}

headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
try:
    res = requests.post(f"{server_url}/api/v1/ingest/logs", json=batch, headers=headers, timeout=5)
    print(f"  -> Đã gửi 32 events 404 trực tiếp qua Ingest API: HTTP {res.status_code}")
    if res.status_code >= 400:
        print(f"     Chi tiết lỗi: {res.text}")
except Exception as e:
    print(f"  -> Lỗi kết nối gửi 404: {e}")
PY
  echo -e "${GREEN}[✓] Đã kích hoạt Rule 6: asp-web-scan-404 (Level: Medium)${NC}"
}

case "$choice" in
  1)
    test_ssh_bruteforce
    test_password_spraying
    test_bruteforce_then_success
    test_sudo_abuse
    test_sudo_root_shell
    test_web_scan_404
    ;;
  2) test_ssh_bruteforce ;;
  3) test_password_spraying ;;
  4) test_bruteforce_then_success ;;
  5) test_sudo_abuse ;;
  6) test_sudo_root_shell ;;
  7) test_web_scan_404 ;;
  0) echo "Thoát."; exit 0 ;;
  *) echo "Lựa chọn không hợp lệ."; exit 1 ;;
esac

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}[HOÀN TẤT] Đã kích hoạt các kịch bản tấn công thành công!${NC}"
echo -e "1. Kiểm tra màn hình Client Agent: sẽ thấy các batch log được gửi sang Server."
echo -e "2. Kiểm tra màn hình Server Windows: sẽ thấy thông báo các Alert và Case tương ứng."
echo -e "3. Mở trình duyệt: ${YELLOW}http://localhost:8000/docs${NC} để xem toàn bộ Alert sinh ra!"
echo -e "${CYAN}================================================================${NC}\n"
