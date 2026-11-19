#!/usr/bin/env bash
# ==============================================================================
# Script kiểm thử thu thập và phân tích log /var/log/audit/audit.log
# Bao gồm Bảng Tra Cứu Lệnh Test Tay Thật & Kịch Bản Giả Lập Tự Động
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  source <(sed 's/\r$//' "$ENV_FILE")
  set +a
fi

SERVER_URL="${ASP_SERVER_URL:-http://172.19.240.1:8000}"
OP_TOKEN="${ASP_OP_TOKEN:-4xWxQAbNY25vCxqEBBu_CnKlLNoPsu-hCWr_DXI10pc}"
AUDIT_LOG_FILE="/var/log/audit/audit.log"

# Kiểm tra file audit.log
if [[ ! -f "$AUDIT_LOG_FILE" ]]; then
  sudo mkdir -p /var/log/audit 2>/dev/null || mkdir -p /var/log/audit 2>/dev/null || true
  sudo touch "$AUDIT_LOG_FILE" 2>/dev/null || touch "$AUDIT_LOG_FILE" 2>/dev/null || true
  sudo chmod 664 "$AUDIT_LOG_FILE" 2>/dev/null || true
fi

get_epoch_now() {
  python3 -c "import time; print(f'{time.time():.3f}')"
}

get_serial() {
  python3 -c "import random; print(random.randint(1000, 9999))"
}

append_audit() {
  local line="$1"
  if [[ -w "$AUDIT_LOG_FILE" ]]; then
    echo "$line" >> "$AUDIT_LOG_FILE"
  else
    echo "$line" | sudo tee -a "$AUDIT_LOG_FILE" >/dev/null || echo "$line" >> "$AUDIT_LOG_FILE"
  fi
}

# ------------------------------------------------------------------------------
# Chức năng 1: Bảng Tra Cứu Lệnh Test Tay Thật 100% (Không qua script trung gian)
# ------------------------------------------------------------------------------
show_manual_cheat_sheet() {
  echo -e "\n${CYAN}========================================================================================${NC}"
  echo -e "${BOLD}${YELLOW}       BẢNG TRA CỨU CÁC LỆNH TEST TAY THẬT 100% TRÊN TERMINAL UBUNTU${NC}"
  echo -e "${CYAN} (Mở một Terminal Ubuntu bất kỳ, Copy lệnh dưới đây dán vào để kích hoạt Alert thật) ${NC}"
  echo -e "${CYAN}========================================================================================${NC}\n"

  echo -e "${BOLD}${MAGENTA}[1] Kích hoạt Alert: SSH Brute Force (Level: High)${NC}"
  echo -e "  ${YELLOW}Lệnh chạy thẳng:${NC}"
  echo -e "  for i in {1..6}; do logger -p auth.info -t sshd \"Failed password for root from 203.0.113.77 port \$((51000+i)) ssh2\"; done\n"

  echo -e "${BOLD}${MAGENTA}[2] Kích hoạt Alert: Password Spraying - Dò pass trên nhiều user (Level: High)${NC}"
  echo -e "  ${YELLOW}Lệnh chạy thẳng:${NC}"
  echo -e "  for u in admin devops tester backup guest postgres mysql nginx apache oracle git jenkins; do logger -p auth.info -t sshd \"Failed password for invalid user \$u from 198.51.100.99 port 52001 ssh2\"; done\n"

  echo -e "${BOLD}${MAGENTA}[3] Kích hoạt Alert: Brute Force rồi Success (Level: Critical)${NC}"
  echo -e "  ${YELLOW}Lệnh chạy thẳng:${NC}"
  echo -e "  for i in {1..5}; do logger -p auth.info -t sshd \"Failed password for ubuntu from 192.0.2.15 port \$((53000+i)) ssh2\"; done; logger -p auth.info -t sshd \"Accepted password for ubuntu from 192.0.2.15 port 53010 ssh2\"\n"

  echo -e "${BOLD}${MAGENTA}[4] Kích hoạt Alert: Sudo Abuse - Nhập sai mật khẩu Sudo (Level: Medium)${NC}"
  echo -e "  ${YELLOW}Cách 1 (Thao tác tay thật trên bàn phím):${NC}"
  echo -e "    sudo -k; sudo ls /root   ${CYAN}# Cố tình gõ sai mật khẩu 3 lần liên tiếp${NC}"
  echo -e "  ${YELLOW}Cách 2 (Lệnh 1 dòng không cần gõ sai pass):${NC}"
  echo -e "    logger -p authpriv.notice -t sudo \"\$USER : 3 incorrect password attempts ; TTY=pts/1 ; PWD=\$HOME ; USER=root ; COMMAND=/bin/cat /etc/shadow\"\n"

  echo -e "${BOLD}${MAGENTA}[5] Kích hoạt Alert: Sudo to Root Shell - Leo quyền mở bash/sh (Level: Critical)${NC}"
  echo -e "  ${YELLOW}Cách 1 (Thao tác tay thật trên bàn phím):${NC}"
  echo -e "    sudo /bin/bash           ${CYAN}# Nhập pass sudo để vào root shell, sau đó gõ: exit${NC}"
  echo -e "  ${YELLOW}Cách 2 (Lệnh 1 dòng):${NC}"
  echo -e "    logger -p authpriv.notice -t sudo \"\$USER : TTY=pts/0 ; PWD=\$HOME ; USER=root ; COMMAND=/bin/bash\"\n"

  echo -e "${BOLD}${MAGENTA}[6] Ghi Log Linux Audit Thực Tế vào /var/log/audit/audit.log${NC}"
  echo -e "  ${YELLOW}Lệnh ghi bản ghi Audit thật:${NC}"
  echo -e "  echo \"type=USER_CMD msg=audit(\$(date +%s).000:\$RANDOM): pid=\$\$ uid=\$(id -u) auid=\$(id -u) ses=1 subj=? msg='cwd=\\\"\$PWD\\\" cmd=636174202f6574632f736861646f77 terminal=pts/0 res=success'\" | sudo tee -a /var/log/audit/audit.log\n"

  echo -e "${CYAN}----------------------------------------------------------------------------------------${NC}"
  echo -e "${GREEN}[*] Sau khi bạn chạy bất kỳ lệnh nào ở trên:${NC}"
  echo -e "  1. Client Agent sẽ tự động bám đuôi đọc log và gửi về Server trong vòng 0.5s - 2s."
  echo -e "  2. Server Rule Engine kích hoạt Alert và gom Case tương ứng."
  echo -e "  3. Bạn có thể mở web: ${YELLOW}http://localhost:8000/docs${NC} hoặc chọn tùy chọn 4 dưới đây để xem ngay kết quả!"
  echo -e "${CYAN}========================================================================================${NC}\n"
}

# ------------------------------------------------------------------------------
# Chức năng 2: Tự động ghi 1 bản ghi Audit Log thực tế ngay (Không cần hỏi nhập)
# ------------------------------------------------------------------------------
run_live_audit_test() {
  echo -e "\n${YELLOW}[*] Đang thực thi lệnh 'whoami' thực tế và phát sinh bản ghi Audit...${NC}"
  local curr_user uid auid pid epoch serial
  curr_user=$(whoami)
  uid=$(id -u)
  auid=$(id -u)
  pid=$$
  epoch=$(get_epoch_now)
  serial=$(get_serial)

  local audit_user_cmd="type=USER_CMD msg=audit(${epoch}:${serial}): pid=${pid} uid=${uid} auid=${auid} ses=1 subj=? msg='cwd=\"$(pwd)\" cmd=77686f616d69 terminal=pts/0 res=success'"
  append_audit "$audit_user_cmd"
  echo -e "  -> Đã append USER_CMD (whoami) vào ${AUDIT_LOG_FILE}"

  local audit_syscall="type=SYSCALL msg=audit(${epoch}:$((serial+1))): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd588e1a60 a1=7ffd588e27c8 a2=7ffd588e27d8 a3=7ffd588e1780 items=2 ppid=$PPID pid=${pid} auid=${auid} uid=${uid} gid=$(id -g) euid=${uid} comm=\"whoami\" exe=\"/bin/whoami\" key=\"real_manual_execution\""
  append_audit "$audit_syscall"
  echo -e "  -> Đã append SYSCALL (whoami) vào ${AUDIT_LOG_FILE}"

  echo -e "${GREEN}[✓] Đã ghi log thành công! Đang chờ 3s để Server tiếp nhận...${NC}"
  sleep 3
  verify_via_api
}

# ------------------------------------------------------------------------------
# Chức năng 3: Chạy Giả Lập Full 5 Kịch Bản Audit
# ------------------------------------------------------------------------------
test_simulated_scenarios() {
  echo -e "\n${MAGENTA}--- [CHẾ ĐỘ TEST GIẢ LẬP FULL 5 KỊCH BẢN AUDIT] ---${NC}"
  local epoch serial

  # Kịch bản 1: EXECVE
  epoch=$(get_epoch_now); serial=$(get_serial)
  echo -e "\n${YELLOW}[1/5] Kịch bản EXECVE: Phân tách đối số lệnh (cat /etc/shadow)...${NC}"
  local rec_execve="type=EXECVE msg=audit(${epoch}:${serial}): argc=2 a0=\"cat\" a1=\"/etc/shadow\""
  append_audit "$rec_execve"
  echo -e "  -> Đã append: $rec_execve"

  # Kịch bản 2: USER_CMD
  sleep 0.2
  epoch=$(get_epoch_now); serial=$(get_serial)
  echo -e "\n${YELLOW}[2/5] Kịch bản USER_CMD: Command hex-encoded (useradd -m hacker)...${NC}"
  local hex_useradd
  hex_useradd=$(python3 -c "print('useradd -m hacker'.encode('utf-8').hex())")
  local rec_usercmd="type=USER_CMD msg=audit(${epoch}:${serial}): pid=6123 uid=0 auid=1000 ses=2 subj=? msg='cwd=\"/root\" cmd=${hex_useradd} terminal=pts/1 res=success'"
  append_audit "$rec_usercmd"
  echo -e "  -> Đã append: $rec_usercmd"

  # Kịch bản 3: USER_LOGIN
  sleep 0.2
  epoch=$(get_epoch_now); serial=$(get_serial)
  echo -e "\n${YELLOW}[3/5] Kịch bản USER_LOGIN: Remote login từ IP lạ 203.0.113.88...${NC}"
  local rec_login="type=USER_LOGIN msg=audit(${epoch}:${serial}): pid=7234 uid=0 auid=1000 ses=3 subj=? msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=203.0.113.88 addr=203.0.113.88 terminal=ssh res=success'"
  append_audit "$rec_login"
  echo -e "  -> Đã append: $rec_login"

  # Kịch bản 4: CONFIG_CHANGE
  sleep 0.2
  epoch=$(get_epoch_now); serial=$(get_serial)
  echo -e "\n${YELLOW}[4/5] Kịch bản CONFIG_CHANGE: Thay đổi luật auditctl theo dõi shadow...${NC}"
  local rec_config="type=CONFIG_CHANGE msg=audit(${epoch}:${serial}): auid=1000 ses=1 op=add_rule key=\"shadow_tamper_watch\" list=4 res=1"
  append_audit "$rec_config"
  echo -e "  -> Đã append: $rec_config"

  # Kịch bản 5: SYSCALL
  sleep 0.2
  epoch=$(get_epoch_now); serial=$(get_serial)
  echo -e "\n${YELLOW}[5/5] Kịch bản SYSCALL: Syscall 59 (execve) công cụ nmap...${NC}"
  local rec_syscall="type=SYSCALL msg=audit(${epoch}:${serial}): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd588e1a60 a1=7ffd588e27c8 a2=7ffd588e27d8 a3=7ffd588e1780 items=2 ppid=1234 pid=8345 auid=1000 uid=0 gid=0 euid=0 comm=\"nmap\" exe=\"/usr/bin/nmap\" key=\"recon_tool\""
  append_audit "$rec_syscall"
  echo -e "  -> Đã append: $rec_syscall"

  echo -e "\n${GREEN}[✓] Đã tạo thành công FULL 5 kịch bản Audit Log giả lập!${NC}"
  echo -e "\n${CYAN}Đang chờ 3 giây để Collector gửi log sang Server...${NC}"
  sleep 3
  verify_via_api
}

# ------------------------------------------------------------------------------
# Chức năng 4: Truy Vấn API & Xác Nhận Log Đã Vào Database
# ------------------------------------------------------------------------------
verify_via_api() {
  echo -e "\n${MAGENTA}--- [XÁC MINH SỰ KIỆN QUA API ASP SIEM] ---${NC}"
  echo -e "${YELLOW}[*] Đang truy vấn API: ${SERVER_URL}/api/v1/events?dataset=linux.audit&limit=10${NC}"
  
  local tmp_file="/tmp/asp_audit_events.json"
  local http_code
  http_code=$(curl -s -o "$tmp_file" -w "%{http_code}" -H "Authorization: Bearer ${OP_TOKEN}" "${SERVER_URL}/api/v1/events?dataset=linux.audit&limit=10" || echo "000")

  if [[ "$http_code" != "200" ]]; then
    echo -e "${RED}[✗] Truy vấn API thất bại (HTTP ${http_code})!${NC}"
    if [[ -f "$tmp_file" ]]; then cat "$tmp_file"; echo ""; fi
    return 1
  fi

  echo -e "${GREEN}[✓] Kết nối API thành công (HTTP 200)!${NC}"
  
  python3 - "$tmp_file" <<'PY'
import json, sys
from pathlib import Path

path = sys.argv[1]
try:
    events = json.loads(Path(path).read_text(encoding="utf-8"))
except Exception as e:
    print(f"Error parsing JSON: {e}")
    sys.exit(0)

if not events:
    print("\033[1;33m[!] Chưa có sự kiện audit nào được Server ghi nhận. Hãy đảm bảo Collector Agent đang chạy để gửi log.\033[0m")
    sys.exit(0)

print(f"\033[0;32m[✓] Tìm thấy {len(events)} sự kiện linux.audit mới nhất đã được thu thập và parse thành công:\033[0m\n")
print(f"{'TIMESTAMP':<24} | {'ACTION':<24} | {'OUTCOME':<10} | {'PROCESS':<15} | {'USER':<12} | {'STATUS'}")
print("-" * 100)
for ev in events:
    ts = ev.get("@timestamp") or ev.get("timestamp") or "N/A"
    event_meta = ev.get("event") or {}
    action = event_meta.get("action", "N/A")
    outcome = event_meta.get("outcome", "N/A")
    proc = (ev.get("process") or {}).get("name") or "N/A"
    user = (ev.get("user") or {}).get("name") or "N/A"
    asp = ev.get("asp") or {}
    status = asp.get("parse_status", "ok")
    print(f"{ts[:23]:<24} | {action:<24} | {outcome:<10} | {proc:<15} | {user:<12} | \033[0;32m{status}\033[0m")
PY
  rm -f "$tmp_file"
}

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}   ASP SIEM - Bộ Kiểm Thử Thu Thập & Phân Tích Linux Audit Log   ${NC}"
echo -e "${CYAN}   Target Log: ${YELLOW}${AUDIT_LOG_FILE}${NC}"
echo -e "${CYAN}   Server URL: ${YELLOW}${SERVER_URL}${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "Chọn thao tác kiểm thử:"
echo -e "  ${YELLOW}1${NC}) ${BOLD}Xem Bảng Tra Cứu Lệnh Test Tay Thật 100%${NC} (Copy & paste chạy thẳng trên terminal)"
echo -e "  ${YELLOW}2${NC}) ${BOLD}Tự Động Phát Sinh 1 Bản Ghi Audit Thật Ngay${NC} (Chạy whoami & ghi audit log thật)"
echo -e "  ${YELLOW}3${NC}) ${BOLD}Chạy Giả Lập Full 5 Kịch Bản Audit${NC} (EXECVE, USER_CMD, USER_LOGIN, CONFIG_CHANGE, SYSCALL)"
echo -e "  ${YELLOW}4${NC}) ${BOLD}Xác Minh Sự Kiện Đã Thu Thập${NC} (Query API SIEM /api/v1/events)"
echo -e "  ${YELLOW}0${NC}) Thoát"
echo ""
read -p "Lựa chọn [0-4]: " opt

case "$opt" in
  1) show_manual_cheat_sheet ;;
  2) run_live_audit_test ;;
  3) test_simulated_scenarios ;;
  4) verify_via_api ;;
  0) exit 0 ;;
  *) echo "Lựa chọn không hợp lệ."; exit 1 ;;
esac

echo -e "\n${GREEN}[HOÀN TẤT]${NC}\n"
