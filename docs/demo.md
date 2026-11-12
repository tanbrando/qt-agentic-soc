# Hướng dẫn Demo & Kiểm thử Toàn diện Hệ thống ASP (SIEM Core)

Tài liệu này hướng dẫn quy trình chạy demo End-to-End chuẩn cho hệ thống **ASP SIEM** với mô hình thực tế:

- **Phía Server:** Chạy trên **Windows** (PostgreSQL 17 local + FastAPI Uvicorn `--workers 1`).
- **Phía Client thu thập log:** Chạy trên **Ubuntu / WSL2** (`client/collector.py` trong môi trường ảo `.venv-client`).

---

## 1. Khởi động Hệ thống (Chỉ mất 2 bước)

### Bước 1.1: Khởi động Server (Trên Windows CMD)

Mở cửa sổ **CMD** tại thư mục dự án và chạy:

```cmd
setup\server_setup.bat
```

*Script này tự động kiểm tra `.venv`, cài gói, nạp `.env`, chạy DB migration và bật Uvicorn lắng nghe tại `http://0.0.0.0:8000`.*

*(Tùy chọn: Nếu cần đăng ký thêm máy mới hoặc đổi API key cho Agent, chạy: `setup\create_newClient.bat` — script tự lưu vào DB và tự động ghi đè key mới vào file `.env`).*

---

### Bước 1.2: Khởi động Client Thu thập Log (Trên Ubuntu / WSL)

Mở terminal **Ubuntu** (đảm bảo đã copy hoặc trỏ vào thư mục dự án, ví dụ `/home/cun/qt-agentic-soc`) và chạy:

```bash
bash setup/client_setup.sh
```

*Script tự tạo `.venv-client`, nạp `.env`, sinh file cấu hình an toàn `$HOME/asp-agent-config.yaml` và bắt đầu thu thập log gửi sang Server Windows.*

> **Dấu hiệu kết nối thành công:**
>
> - Bên **Ubuntu Client**: In dòng `INFO Starting ASP collector agent_id=web-01 target=http://172.19.240.1:8000`.
> - Bên **Windows Server**: Xuất hiện các dòng `POST /api/v1/ingest/logs HTTP/1.1" 202 Accepted`.

---

## 2. Chế độ Test 1: Demo trực tiếp trên Ubuntu (`test_ubuntu_attacks.sh`) — KHUYÊN DÙNG

Đây là cách mô phỏng thực tế nhất: mở một **tab Terminal Ubuntu mới** (giữ nguyên tab Client đang chạy) và thực thi:

```bash
cd /home/cun/qt-agentic-soc
bash scripts/test_ubuntu_attacks.sh
```

Màn hình sẽ hiện Menu tương tác đầy đủ **6/6 Rules** (tự động hoàn toàn, không yêu cầu mật khẩu `sudo`):

- Nhấn **`1`** rồi Enter để chạy **FULL TẤT CẢ 6 RULES**:
  1. `asp-ssh-bruteforce` (Medium): 6 lần đăng nhập SSH thất bại từ `203.0.113.77`.
  2. `asp-password-spraying` (High): Thử mật khẩu trên 5 tài khoản khác nhau từ `198.51.100.99`.
  3. `asp-bruteforce-then-success` (Critical): 5 lần sai mật khẩu liên tiếp rồi đăng nhập thành công từ `192.0.2.15`.
  4. `asp-sudo-abuse` (High): 3 lần nhập sai mật khẩu lệnh `sudo`.
  5. `asp-sudo-to-root-shell` (Critical): Leo quyền mở shell `/bin/bash` dưới quyền `root`.
  6. `asp-web-scan-404` (Medium): Gửi 32 request HTTP 404 quét đường dẫn web từ `198.51.100.44`.

*Hoặc nhấn từ `2` đến `7` để test lẻ từng rule một.*

---

## 3. Chế độ Test 2: Kiểm thử bằng Thao tác Tay Thật trên Ubuntu

Nếu muốn chứng minh trực tiếp cho người xem việc gõ lệnh tay cũng bị phát hiện:

1. **Test bắt log Sudo sai mật khẩu thật (`asp-sudo-abuse`):**
   ```bash
   sudo ls
   # Cố tình gõ sai mật khẩu 3 lần liên tiếp
   ```
2. **Test leo quyền Root Shell thật (`asp-sudo-to-root-shell`):**
   ```bash
   sudo su
   # Nhập đúng mật khẩu để lên shell root, sau đó gõ 'exit' để thoát ra
   ```

➡️ Ngay lập tức Client Agent đọc `/var/log/auth.log` và bắn sang Server Windows (`202 Accepted`), sinh Alert tức thì!

---

## 4. Chế độ Test 3: Chạy Script Python tổng lực từ Windows (`scripts/demo_attack.py`)

Nếu chỉ muốn test nhanh các API & Rule Engine ngay trên Windows mà không qua Ubuntu:

```cmd
.venv\Scripts\python.exe scripts\demo_attack.py --mode ingest --server-url http://127.0.0.1:8000 --attacker-ip 203.0.113.77
```

*(Lưu ý: Trước khi chạy từ Windows, nhớ nạp `ASP_AGENT_API_KEY` từ `.env` hoặc chạy trong shell đã có biến môi trường).*

---

## 5. Xem Kết quả: Alerts, Events và Cases

Sau khi kích hoạt tấn công ở Mục 2, 3 hoặc 4, bạn có **2 cách** cực nhanh để kiểm tra kết quả:

### Cách A: Xem qua Giao diện Web Swagger UI (Trực quan nhất)

1. Mở trình duyệt web trên Windows truy cập: **[http://localhost:8000/docs](http://localhost:8000/docs)**
2. Bấm nút **Authorize** (ổ khóa màu xanh góc phải) ➡️ dán chuỗi `ASP_OP_TOKEN` (lấy trong file `.env`) vào ô Value ➡️ bấm **Authorize**.
3. Thử lần lượt các API đọc:
   - **`GET /api/v1/alerts`**: Xem toàn bộ các Cảnh báo đã kích hoạt (tên Rule, mức độ Critical/High/Medium, IP tấn công).
   - **`GET /api/v1/cases`**: Xem các Hồ sơ vụ việc đã được tự động gom nhóm theo `rule_id + entity_key`.
   - **`GET /api/v1/events`**: Xem chi tiết từng dòng log đã được chuẩn hóa sang chuẩn **ECS v1.1**.
   - **`POST /api/v1/cases/{case_id}/investigate`**: Kiểm tra chuyển trạng thái Case sang `investigating` (điểm nối cho Phase 6 Agentic AI).

### Cách B: Xem nhanh bằng PowerShell / Curl

```powershell
# Nạp nhanh .env vào PowerShell
Get-Content .env | ForEach-Object { if ($_ -match '^([^#=]+)=(.*)$') { Set-Item -Path "env:$($matches[1].Trim())" -Value $matches[2].Trim() } }
$headers = @{ Authorization = "Bearer $env:ASP_OP_TOKEN" }

# 1. Xem danh sách Alerts mới nhất
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/alerts?limit=20" -Headers $headers | ConvertTo-Json -Depth 5

# 2. Xem danh sách Cases đang mở
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/cases?status=open" -Headers $headers | ConvertTo-Json -Depth 5
```

---

## 6. Kiểm thử Offline & Automated Tests (Dành cho phát triển)

- **Kiểm tra phân tích log & rule offline** bằng công cụ [tools/asp_logtest.py](file:///d:/ATTT/CK/qt-agentic-soc/tools/asp_logtest.py):
  ```cmd
  .venv\Scripts\python.exe tools\asp_logtest.py --file samples\rules\ssh_bruteforce_pos.log --type auth
  ```
- **Chạy toàn bộ bộ Test tự động (`pytest`)**:
  ```cmd
  .venv\Scripts\python.exe -m pytest -v
  ```
