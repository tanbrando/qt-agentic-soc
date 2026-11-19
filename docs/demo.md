# Hướng Dẫn Demo & Kiểm Thử Toàn Diện Hệ Thống ASP SIEM (A - Z)

Tài liệu này cung cấp quy trình vận hành, kiểm thử và demo toàn diện hệ thống **Agentic SOC Platform (ASP SIEM Core)**, hỗ trợ thu thập và phát hiện đồng thời từ **Client Linux (Ubuntu)** và **Client Windows**:

1. **PHẦN I — Kiểm Thử Theo Kịch Bản Giả Lập (Simulation Attack Scenarios):** Chạy kiểm thử mô phỏng đa kịch bản từ máy Windows bằng Python (`scripts/demo_attack.py` bắn trực tiếp qua Ingest API) và kiểm thử offline các rule/parser bằng `tools/asp_logtest.py` mà không cần máy ảo Ubuntu.
2. **PHẦN II — Hướng Dẫn Test Tay Thủ Công (Pure Manual Live Test):** Cung cấp chính xác các lệnh shell thực tế phân theo **TỪNG LOẠI NGUỒN LOG** và **TỪNG HỆ ĐIỀU HÀNH (Ubuntu & Windows)** để bạn tự gõ hoặc copy & paste thẳng vào Terminal / PowerShell (không qua bất kỳ script trung gian nào) và kích hoạt trực tiếp các Cảnh báo (Alerts).
3. **PHẦN III — Hướng Dẫn Test Thực Tế Bằng Script (Interactive Scripted Test):** Hướng dẫn vận hành các script kiểm thử tự động trên cả Ubuntu (`scripts/test_ubuntu_attacks.sh`, `scripts/test_audit_flow.sh`) và Windows (`scripts/test_windows_attacks.bat`) nhằm sinh ra nhiều loại log nhất và khớp tối đa với các quy tắc phát hiện (Rules) của SIEM.
4. **Quy Trình Xác Minh & Điều Tra:** Kiểm tra toàn vẹn chuỗi sự cố: **Log Thô $\rightarrow$ Chuẩn Hóa ECS $\rightarrow$ Kích Hoạt Alerts $\rightarrow$ Gom Cụm Cases $\rightarrow$ AI Agent Điều Tra**.

---

## 1. Tổng Quan Kiến Trúc & Danh Mục Nguồn Log

Hệ thống hỗ trợ kết nối đa client đồng thời giữa **Server SIEM (Windows)** với các **Client Thu Thập (Ubuntu Linux & Windows)**:

```mermaid
flowchart LR
    subgraph ClientUbuntu ["Client Thu Thập 1 (Ubuntu Linux - web-01)"]
        U1["/var/log/auth.log"] --> CU["collector.py Agent"]
        U2["/var/log/syslog"] --> CU
        U3["/var/log/audit/audit.log"] --> CU
        CU -->|"HTTP POST (Bearer API Key 1)"| SPU["Spool ($HOME/.asp-agent)"]
    end

    subgraph ClientWin ["Client Thu Thập 2 (Windows - win-01)"]
        W1["logs/auth.log"] --> CW["collector.py Agent"]
        W2["logs/syslog.log"] --> CW
        W3["logs/audit.log"] --> CW
        W4["logs/access.log"] --> CW
        CW -->|"HTTP POST (Bearer API Key 2)"| SPW["Spool (logs/spool)"]
    end

    subgraph Server ["Server SIEM Trung Tâm (Port 8000)"]
        SPU --> API["FastAPI Ingest API (/api/v1/ingest/logs)"]
        SPW --> API
        API --> RAW[("events_raw<br>(Deduplication per Agent)")]
        API --> PARSE["Parsers Registry<br>(Auth, Audit, Syslog, Apache)")]
        PARSE --> ECS[("events<br>(Chuẩn ECS v1.1)")]
        ECS --> ENGINE["Rule Engine (Sliding Window & Cooldown)"]
        ENGINE --> ALERTS[("alerts<br>(Critical / High / Medium)")]
        ENGINE --> CASES[("cases<br>(Gom cụm theo Entity & Rule)")]
        CASES --> AGENT["AI Agentic SOC (/investigate)"]
    end
```

### Danh mục 4 loại nguồn log trong hệ thống:

| Loại Nguồn Log | Đường Dẫn Linux | Đường Dẫn Windows | Parser Phụ Trách | ECS Dataset | Mục Đích Giám Sát SOC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Auth Log** | `/var/log/auth.log` | `logs/auth.log` | `AuthLogParser` | `linux.auth` | Xác thực SSH, lệnh Sudo, phiên PAM, quản trị user |
| **2. Web Telemetry** | Web Access Log | `logs/access.log` | `ApacheAccessParser` | `apache.access` | Yêu cầu HTTP, mã phản hồi 404 Not Found, quét web |
| **3. Audit Log** | `/var/log/audit/audit.log` | `logs/audit.log` | `AuditLogParser` | `linux.audit` | Kiểm toán nhân: Syscall, Execve, User Cmd hex-decode |
| **4. Syslog** | `/var/log/syslog` | `logs/syslog.log` | `GenericSyslogParser` | `linux.syslog` | Log hệ thống chung, daemons, dịch vụ nền |

---

## 2. Bảng Ma Trận Quy Tắc Phát Hiện (Detection Rules & Alerts)

| STT | Rule ID | Tên Quy Tắc | Severity | Detection Type | Nguồn Log / Dataset | Điều Kiện Ngưỡng Kích Hoạt | MITRE ATT&CK |
| :---: | :--- | :--- | :---: | :---: | :--- | :--- | :---: |
| **1** | `asp-ssh-bruteforce` | SSH Brute Force | **High** | `event_count` | `auth.log`<br>`linux.auth` | $\ge 5$ lần `ssh_login_failed` từ 1 IP trong 5 phút. Cooldown: 10m. | T1110.001 |
| **2** | `asp-password-spraying` | Password Spraying | **High** | `value_count` | `auth.log`<br>`linux.auth` | $\ge 10$ `user.name` khác nhau bị thử sai từ 1 IP trong 5 phút. Cooldown: 10m. | T1110.003 |
| **3** | `asp-bruteforce-then-success` | Dò pass rồi đăng nhập thành công | **Critical** | `sequence` | `auth.log`<br>`linux.auth` | Chuỗi: $\ge 5$ lần `ssh_login_failed` tiếp nối bởi $\ge 1$ lần `ssh_login_success` từ cùng 1 IP trong 10m. Cooldown: 30m. | T1110 |
| **4** | `asp-sudo-abuse` | Lạm dụng hoặc nhập sai mật khẩu Sudo | **Medium** | `match` | `auth.log`<br>`linux.auth` | Bắt ngay khi có `sudo_not_in_sudoers`, `sudo_bad_password`, hoặc `sudo_auth_failed`. | T1548.003 |
| **5** | `asp-sudo-to-root-shell` | Sudo mở shell đặc quyền Root | **Critical** | `match` | `auth.log`<br>`linux.auth` | `sudo_command` với target `root` và lệnh thực thi là shell: `/bin/bash`, `/bin/sh`, `/bin/su`... | T1548.003 |
| **6** | `asp-web-scan-404` | Quét đường dẫn Web (Scan 404) | **Medium** | `event_count` | `access.log`<br>`apache.access` | $\ge 30$ request HTTP `404` từ cùng 1 IP trong vòng 1 phút. Cooldown: 10m. | T1595.003 |

---

## 3. PHẦN I: KIỂM THỬ THEO KỊCH BẢN GIẢ LẬP (SIMULATION ATTACK SCENARIOS)

> [!NOTE]
> **Mục tiêu của Kiểm Thử Giả Lập:**
> - Cho phép kiểm thử toàn bộ khả năng phát hiện của SIEM Server **ngay trên máy Windows (hoặc bất kỳ máy nào)** bằng Python mà không bắt buộc phải mở máy ảo Ubuntu hay chạy agent thu thập.
> - Bắn trực tiếp các batch log chứa chuỗi sự kiện tấn công mô phỏng vào Ingest API `/api/v1/ingest/logs` hoặc kiểm thử offline parser và rule logic mà không cần nạp cơ sở dữ liệu.

### 3.1. Giả Lập Toàn Bộ Chuỗi Tấn Công Trọn Gói (1 Lệnh Duy Nhất)

```cmd
.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --attacker-ip 203.0.113.88
```
* **Cơ chế hoạt động:** Script tự nạp cấu hình từ `.env` (`ASP_SERVER_URL`, `ASP_AGENT_ID`, `ASP_AGENT_API_KEY`), đóng gói 62 events chuẩn v1.1 gửi đến API Ingest Server.
* **Kết quả kỳ vọng:** API trả về `accepted: 62`, Server Rule Engine kích hoạt đồng loạt tất cả các Alerts và gom cụm thành các Cases sự cố tương ứng.

---

### 3.2. Giả Lập Từng Kịch Bản Tấn Công Riêng Lẻ Bằng Python (`--scenario`)

| STT | Kịch Bản Giả Lập | Lệnh Chạy Mô Phỏng | Alert Kỳ Vọng |
| :---: | :--- | :--- | :--- |
| **1** | **SSH Brute Force** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario ssh-bruteforce --attacker-ip 203.0.113.51` | `asp-ssh-bruteforce` (High) |
| **2** | **Password Spraying** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario password-spraying --attacker-ip 203.0.113.52` | `asp-password-spraying` (High - 12 users) |
| **3** | **Bruteforce $\rightarrow$ Success** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario bruteforce-then-success --attacker-ip 203.0.113.53` | `asp-bruteforce-then-success` (Critical) |
| **4** | **Sudo Abuse** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario sudo-abuse --attacker-ip 203.0.113.54` | `asp-sudo-abuse` (Medium) |
| **5** | **Sudo mở Root Shell** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario sudo-root --attacker-ip 203.0.113.55` | `asp-sudo-to-root-shell` (Critical) |
| **6** | **Web Scan 404** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario web-scan --attacker-ip 203.0.113.56` | `asp-web-scan-404` (Medium) |
| **7** | **Linux Audit Simulation** | `.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --scenario audit --attacker-ip 203.0.113.57` | `linux.audit` status `ok` |

---

### 3.3. Kiểm Thử Giả Lập Offline Tức Thì Không Cần Database (`tools/asp_logtest.py`)

| Mục tiêu kiểm thử | Lệnh chạy mẫu | File log mô phỏng | Kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **SSH Brute Force** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/rules/ssh_bruteforce_pos.log --type auth` | `samples/rules/ssh_bruteforce_pos.log` | `alerts: ["asp-ssh-bruteforce"]` |
| **Password Spraying** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/rules/password_spraying_pos.log --type auth` | `samples/rules/password_spraying_pos.log` | `alerts: ["asp-password-spraying"]` |
| **Bruteforce $\rightarrow$ Success** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/rules/bruteforce_then_success_pos.log --type auth` | `samples/rules/bruteforce_then_success_pos.log` | `alerts: ["asp-bruteforce-then-success"]` |
| **Sudo Abuse** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/rules/sudo_abuse_pos.log --type auth` | `samples/rules/sudo_abuse_pos.log` | `alerts: ["asp-sudo-abuse"]` |
| **Sudo Root Shell** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/rules/sudo_to_root_shell_pos.log --type auth` | `samples/rules/sudo_to_root_shell_pos.log` | `alerts: ["asp-sudo-to-root-shell"]` |
| **Web Scan 404** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/rules/web_scan_404_pos.log --type apache` | `samples/rules/web_scan_404_pos.log` | `alerts: ["asp-web-scan-404"]` |
| **Linux Audit Parser** | `.venv\Scripts\python.exe tools/asp_logtest.py --file samples/audit/audit_samples.log --type audit` | `samples/audit/audit_samples.log` | `parsed_ok: 7`, giải mã hex command |

---

## 4. PHẦN II: HƯỚNG DẪN TEST TAY THỦ CÔNG (PURE MANUAL) THEO TỪNG HỆ ĐIỀU HÀNH

---

### 4.1. Hướng Dẫn Test Tay Trên Client UBUNTU (Mở Terminal Ubuntu)

> Gõ hoặc copy & paste trực tiếp từng lệnh dưới đây vào Terminal Ubuntu nơi agent collector đang chạy:

* **1. Kích hoạt SSH Brute Force (`asp-ssh-bruteforce` - High):**
  ```bash
  for i in {1..6}; do logger -p auth.info -t sshd "Failed password for root from 203.0.113.77 port $((51000+i)) ssh2"; done
  ```

* **2. Kích hoạt Password Spraying (`asp-password-spraying` - High):**
  ```bash
  for u in admin devops tester backup guest postgres mysql nginx apache oracle git jenkins; do logger -p auth.info -t sshd "Failed password for invalid user $u from 198.51.100.99 port 52001 ssh2"; done
  ```

* **3. Kích hoạt Brute Force Thành Công (`asp-bruteforce-then-success` - Critical):**
  ```bash
  for i in {1..5}; do logger -p auth.info -t sshd "Failed password for ubuntu from 192.0.2.15 port $((53000+i)) ssh2"; done
  logger -p auth.info -t sshd "Accepted password for ubuntu from 192.0.2.15 port 53010 ssh2"
  ```

* **4. Kích hoạt Lạm dụng Sudo (`asp-sudo-abuse` - Medium):**
  ```bash
  logger -p authpriv.notice -t sudo "$USER : 3 incorrect password attempts ; TTY=pts/1 ; PWD=$HOME ; USER=root ; COMMAND=/bin/cat /etc/shadow"
  ```

* **5. Kích hoạt Leo quyền Root Shell (`asp-sudo-to-root-shell` - Critical):**
  ```bash
  logger -p authpriv.notice -t sudo "$USER : TTY=pts/0 ; PWD=$HOME ; USER=root ; COMMAND=/bin/bash"
  ```

* **6. Ghi nhận Linux Audit thực tế (Giải mã hex `cat /etc/shadow`):**
  ```bash
  echo "type=USER_CMD msg=audit($(date +%s).000:$RANDOM): pid=$$ uid=$(id -u) auid=$(id -u) ses=1 subj=? msg='cwd=\"$PWD\" cmd=636174202f6574632f736861646f77 terminal=pts/0 res=success'" | sudo tee -a /var/log/audit/audit.log
  ```

* **7. Ghi nhận log hệ thống Syslog:**
  ```bash
  logger -p daemon.warn -t systemd-custom "Service database-worker failed to reconnect: connection refused"
  ```

---

### 4.2. Hướng Dẫn Test Tay Trên Client WINDOWS (Mở PowerShell hoặc CMD)

> Mở cửa sổ PowerShell hoặc CMD tại thư mục `qt-agentic-soc` nơi Windows Client Agent đang chạy, gõ trực tiếp các lệnh sau:

#### Cách Dùng PowerShell:

* **1. Kích hoạt SSH Brute Force (`asp-ssh-bruteforce` - High):**
  ```powershell
  1..6 | ForEach-Object { Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[500$_]: Failed password for root from 203.0.113.77 port $(51000+$_) ssh2" }
  ```

* **2. Kích hoạt Password Spraying (`asp-password-spraying` - High):**
  ```powershell
  "admin","devops","tester","backup","guest","postgres","mysql","nginx","apache","oracle","git","jenkins" | ForEach-Object { Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[5100]: Failed password for invalid user $_ from 198.51.100.99 port 52001 ssh2" }
  ```

* **3. Kích hoạt Brute Force Thành Công (`asp-bruteforce-then-success` - Critical):**
  ```powershell
  1..5 | ForEach-Object { Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[520$_]: Failed password for ubuntu from 192.0.2.15 port $(53000+$_) ssh2" }
  Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sshd[5299]: Accepted password for ubuntu from 192.0.2.15 port 53010 ssh2"
  ```

* **4. Kích hoạt Lạm dụng Sudo (`asp-sudo-abuse` - Medium):**
  ```powershell
  Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sudo: alice : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
  ```

* **5. Kích hoạt Leo quyền Root Shell (`asp-sudo-to-root-shell` - Critical):**
  ```powershell
  Add-Content -Path logs\auth.log -Value "Nov 20 10:00:00 lab-windows sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
  ```

* **6. Kích hoạt Web Scan 404 (`asp-web-scan-404` - Medium):**
  ```powershell
  1..32 | ForEach-Object { Add-Content -Path logs\access.log -Value "198.51.100.44 - - [20/Nov/2026:10:00:00 +0000] ""GET /scan-$_.php HTTP/1.1"" 404 432 ""-"" ""curl/7.81.0""" }
  ```

* **7. Ghi nhận log Audit:**
  ```powershell
  Add-Content -Path logs\audit.log -Value "type=USER_CMD msg=audit(1732060000.100:101): pid=1234 uid=1000 auid=1000 ses=1 subj=? msg='cwd=""/home/ubuntu"" cmd=636174202f6574632f736861646f77 terminal=pts/0 res=success'"
  ```

#### Cách Dùng CMD (Command Prompt):
```cmd
:: SSH Brute Force
for /L %i in (1,1,6) do @echo Nov 20 10:00:00 lab-windows sshd[500%i]: Failed password for root from 203.0.113.77 port 5100%i ssh2>> logs\auth.log

:: Sudo Abuse
echo Nov 20 10:00:00 lab-windows sudo: alice : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow>> logs\auth.log

:: Sudo Root Shell
echo Nov 20 10:00:00 lab-windows sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash>> logs\auth.log
```

---

## 5. PHẦN III: HƯỚNG DẪN TEST THỰC TẾ BẰNG SCRIPT THEO TỪNG HỆ ĐIỀU HÀNH

---

### 5.1. Dành Cho Client Ubuntu: `test_ubuntu_attacks.sh` & `test_audit_flow.sh`

Mở terminal tại `/home/cun/qt-agentic-soc` và chạy:

```bash
bash scripts/test_ubuntu_attacks.sh
```
* **Phím `1`**: Kích hoạt **toàn bộ 6 alerts cùng một lúc** chỉ trong 5 giây.
* **Phím `2` – `7`**: Kiểm thử riêng rẽ từng kịch bản (SSH, Sudo, Web).
* **Phím `9`**: Hiển thị bảng tra cứu lệnh test tay trực tiếp trên terminal.

Kiểm thử chuyên sâu Audit log:
```bash
bash scripts/test_audit_flow.sh
```
* **Phím `2`**: Tự động lấy PID/UID thực tế của lệnh `whoami`, ghi vào audit.log và tự gọi API hiển thị kết quả.
* **Phím `3`**: Mô phỏng đầy đủ 5 dạng log Audit thực tế (`EXECVE`, `USER_CMD`, `USER_LOGIN`, `CONFIG_CHANGE`, `SYSCALL`).

---

### 5.2. Dành Cho Client Windows: `test_windows_attacks.bat`

Mở CMD / PowerShell trên Windows tại thư mục dự án và chạy:

```cmd
scripts\test_windows_attacks.bat
```

Giao diện Menu trực quan hiển thị:
```text
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
```

* **Chạy tự động toàn bộ 1 dòng:**
  ```cmd
  scripts\test_windows_attacks.bat --scenario all
  ```

---

## 6. Quy Trình Khởi Động Chuẩn (Server, Ubuntu Client & Windows Client)

### Bước 1: Khởi động Server SIEM (Trên Windows CMD)
```cmd
setup\server_setup_win.bat
```
*(Hoặc chạy lệnh tương đương `setup\server_setup.bat`). Script tự tạo `.venv`, nạp `.env`, chạy DB migration và bật FastAPI Uvicorn engine tại `http://0.0.0.0:8000`.*

### Bước 2: Đăng ký Client mới (Trên Windows CMD)
* Đăng ký máy Ubuntu:
  ```cmd
  setup\create_newClient.bat web-01 lab-ubuntu
  ```
* Đăng ký máy Windows:
  ```cmd
  setup\create_newClient.bat win-01 lab-windows
  ```
* Tool tự động lưu mã băm API key vào PostgreSQL và cập nhật `.env`.

### Bước 3A: Khởi động Client trên Ubuntu (Linux Terminal)
```bash
cd /home/cun/qt-agentic-soc
bash setup/client_setup_linux.sh
```
*(Hoặc `bash setup/client_setup.sh`).*

### Bước 3B: Khởi động Client trên Windows (Windows CMD / PowerShell)
```cmd
cd d:\ATTT\CK\qt-agentic-soc
setup\client_setup_win.bat
```
*(Hoặc `setup\client_setup.bat`. Nếu chỉ muốn khởi tạo thư mục logs và cấu hình mà chưa chạy ngay, thêm cờ `--setup-only`: `setup\client_setup_win.bat --setup-only`)*.

---

## 7. Quy Trình Xem & Đánh Giá Kết Quả Đa Client Trên SOC

### Cách 1: Giao diện Web Swagger UI (Khuyên Dùng)

1. Mở trình duyệt web truy cập: **[http://localhost:8000/docs](http://localhost:8000/docs)**.
2. Bấm nút **Authorize** $\rightarrow$ Nhập token: `4xWxQAbNY25vCxqEBBu_CnKlLNoPsu-hCWr_DXI10pc`.
3. Kiểm tra:
   * **`GET /api/v1/alerts`**: Xem danh sách toàn bộ Alerts phát sinh từ cả Ubuntu và Windows.
   * **`GET /api/v1/cases`**: Xem các Hồ sơ sự cố gom cụm theo Host và Rule.
   * **`GET /api/v1/events`**: Lọc log chuẩn hóa ECS theo `host_name` hoặc `agent_id` (`web-01` vs `win-01`).

---

### Cách 2: Xem Phân Tách Đa Client Trong Database PostgreSQL (`asp_db`)

Mở terminal chạy đoạn script python sau để kiểm tra dữ liệu phân tách giữa các Agent:

```cmd
.venv\Scripts\python.exe -c "
import psycopg
conn = psycopg.connect('postgresql://postgres:admin@localhost:5432/asp_db')
cur = conn.cursor()
print('=== THỐNG KÊ LOG THEO TỪNG AGENT CLIENT ===')
cur.execute('SELECT agent_id, count(*) FROM events_raw GROUP BY agent_id ORDER BY agent_id')
for row in cur.fetchall():
    print(f'  - Agent [{row[0]}]: {row[1]} raw events')

print('\n=== PHÂN BỔ ECS DATASET CỦA WINDOWS CLIENT (win-01) ===')
cur.execute('SELECT dataset, parse_status, count(*) FROM events WHERE agent_id = %s GROUP BY 1, 2', ('win-01',))
for row in cur.fetchall():
    print(f'  - Dataset: {row[0]:<15} | Status: {row[1]:<5} | Count: {row[2]}')

print('\n=== 5 CẢNH BÁO MỚI NHẤT TRÊN HỆ THỐNG ===')
cur.execute('SELECT id, rule_id, level, group_key->>\'host.name\', created_at FROM alerts ORDER BY id DESC LIMIT 5')
for row in cur.fetchall():
    print(f'  - Alert #{row[0]}: {row[1]} [{row[2]}] on Host: {row[3]} at {row[4]}')
"
```

---

## 8. Xử Lý Các Sự Cố Thường Gặp (Troubleshooting FAQ)

| Hiện tượng | Nguyên nhân | Cách khắc phục triệt để |
| :--- | :--- | :--- |
| **Client báo lỗi HTTP 401 Unauthorized** | `ASP_AGENT_API_KEY` trên Client không khớp với mã băm trong database trên Server. | Trên Windows chạy: `setup\create_newClient.bat <agent_id> <hostname>`, sau đó cập nhật lại file `.env` trên client. |
| **Client báo không kết nối được tới Server (Connection Refused/Timeout)** | Cấu hình sai địa chỉ `ASP_SERVER_URL` hoặc Windows Firewall chặn port 8000. | Trên máy Client kiểm tra bằng `curl -v http://<IP_SERVER>:8000/api/v1/health`. Đảm bảo mở port 8000 trên Windows Firewall. |
| **Báo lỗi Permission Denied với `/var/log/audit/audit.log` trên Ubuntu** | User trên Ubuntu chưa thuộc nhóm `adm` hoặc file audit.log chưa cấp quyền đọc. | Chạy lệnh trên Ubuntu: `sudo usermod -aG adm $(whoami)` và `sudo chmod 664 /var/log/audit/audit.log`. |
| **Không thấy sinh Alert mới dù đã gửi log** | Rule đang trong thời gian giãn cách Cooldown (ví dụ 10 - 30 phút cho cùng 1 IP). | Đổi địa chỉ IP tấn công khác (ví dụ: `203.0.113.80`) hoặc khởi động lại server để reset bộ nhớ cửa sổ trượt. |

---

## 9. Chạy Toàn Bộ Test Tự Động (`pytest`)

Hệ thống sở hữu bộ kiểm thử tự động toàn diện kiểm chứng từ mô hình dữ liệu, chuẩn hóa ECS, tính toán mã băm, logic Rule Engine đến các API routers:

```cmd
.venv\Scripts\python.exe -m pytest -v
```

> **Kết quả kỳ vọng:** Toàn bộ **118 test passed**, 18 skipped, **0 failed** (100% tỷ lệ thành công).
