# Agentic SOC Platform (ASP – SIEM Core)

Hệ thống SIEM thu thập, chuẩn hóa ECS, phát hiện mối đe dọa bằng YAML Rule Engine, gom **Alert** thành **Case** trên PostgreSQL, và chừa giao diện bàn giao cho lớp AI Agentic (Phase 6).

---

## 1. Cấu trúc gọn của dự án

```text
qt-agentic-soc/
├── .env.example                 # Mẫu biến môi trường duy nhất (copy thành .env để chạy)
├── client_setup.sh              # Cài .venv-client trên Ubuntu/Linux và chạy thu thập log
├── server_setup.sh              # Cài venv Server, chạy migration DB và bật Uvicorn
├── requirements.txt             # Thư viện Python cho Server & Test
├── client/
│   ├── collector.py             # Agent mỏng đọc log theo (device, inode, stream_id, offset) + spool
│   ├── config.yaml              # Cấu hình mẫu collector (client_parse: false)
│   └── parsers.py               # Parser dự phòng phía client (tắt mặc định)
├── migrations/                  # DDL PostgreSQL đánh số 001..003 (events_raw append-only)
├── rules/                       # 6 rule phát hiện dạng YAML (match, event_count, value_count, sequence)
├── samples/                     # Bộ log mẫu dương/âm cho parser và rule
├── scripts/
│   └── demo_attack.py           # Kịch bản mô phỏng tấn công SSH/sudo/HTTP 404
├── tools/
│   ├── asp_migrate.py           # Áp dụng SQL migrations (idempotent)
│   ├── asp_admin.py             # Tạo/thu hồi/xoay agent API key & operator token
│   ├── asp_reparse.py           # Parse lại từ events_raw -> events
│   └── asp_logtest.py           # Test nhanh parser + YAML rule offline
├── server/
│   ├── main.py                  # FastAPI entrypoint (chạy --workers 1)
│   └── src/
│       ├── common/              # schemas.py (ECS v1.1 + Alert/Case), config.py, security.py
│       ├── parsers/             # auth_parser, apache_parser, syslog_parser (hàm thuần)
│       ├── engine/              # loader.py, generic_rules.py, state_store.py, recovery.py
│       ├── repositories/        # memory.py & postgres.py (psycopg v3 đồng bộ)
│       ├── services/            # ingestion_service.py (raw-first, lock, case lifecycle)
│       ├── api/                 # v1/ingest.py, alerts.py, events.py, cases.py + auth
│       └── agent/               # Khung bàn giao Phase 6 (AI Agentic)
├── docs/                        # handover-phase6.md, demo.md, final-review.md, phase0-report.md
└── tests/                       # Bộ test tự động pytest (InMemory + PostgreSQL)
```

---

## 2. Cấu hình `.env` hợp nhất

Chỉ dùng **một file `.env` duy nhất** (copy từ `.env.example`, không commit lên Git):

| Biến                                                                                                                                                    | Nhóm           | Ý nghĩa                                                                                                                       |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `ASP_DB_URL`                                                                                                                                           | Server & Tools  | Chuỗi kết nối PostgreSQL (`postgresql://postgres:<MAT_KHAU>@localhost:5432/asp_db`)                                        |
| `SOC_SERVER_HOST`, `SOC_SERVER_PORT`, `SOC_LOG_LEVEL`                                                                                              | Server          | Địa chỉ, cổng lắng nghe và mức log server                                                                                |
| `ASP_DEFAULT_TIMEZONE`, `ASP_FUTURE_TS_TOLERANCE`, `ASP_ALLOWED_LATENESS`, `ASP_CASE_IDLE_TIMEOUT`, `ASP_RULES_DIR`, `ASP_RATE_LIMIT_INGEST` | Server Engine   | Múi giờ mặc định, ngưỡng thời gian tương lai/đến muộn, timeout đóng case, thư mục rule YAML, rate limit ingest |
| `ASP_SERVER_URL`, `ASP_AGENT_ID`, `ASP_VERIFY_TLS`                                                                                                 | Client          | URL server nhận log, ID của agent (khớp DB), bật/tắt kiểm tra TLS                                                         |
| `ASP_AGENT_API_KEY`                                                                                                                                    | Client          | API key của agent (sinh bằng `tools/asp_admin.py create-agent`)                                                             |
| `ASP_OP_TOKEN`                                                                                                                                         | SOC / API đọc | Token operator để gọi `/api/v1/alerts`, `/events`, `/cases`, `/investigate`                                          |

---

## 3. Setup & Chạy Phía Server (Windows)

Server ASP chạy trên môi trường **Windows** (kết nối PostgreSQL 17 local). Các bước thực hiện tuần tự như sau:

### Bước 3.1: Khởi động Server (`setup\server_setup.bat`)

Mở CMD (hoặc PowerShell) tại thư mục dự án và chạy:

```cmd
# Chạy tự động: tạo .venv, cài requirements.txt, nạp .env, chạy migration và start server:
setup\server_setup.bat

# Hoặc chỉ tạo venv, cài thư viện và migrate DB (không bật server ngay):
setup\server_setup.bat --setup-only
```

### Bước 3.2: Đăng ký Agent Client & Tự động cập nhật `.env` (`setup\create_newClient.bat`)

**Trước khi chuyển sang máy Ubuntu thu thập log**, bạn chạy file `.bat` này trên Windows CMD để cấp quyền cho Agent:

```cmd
# Cách 1: Chỉ gõ lệnh không truyền tham số (script sẽ dừng lại hỏi bạn nhập tên, hoặc nhấn Enter để lấy mặc định 'web-01'):
setup\create_newClient.bat

# Cách 2: Truyền trực tiếp tên máy muốn tạo (ví dụ web-02):
setup\create_newClient.bat web-02
```

**Cơ chế hoạt động của `create_newClient.bat`:**

1. Kết nối PostgreSQL (`asp_db`), kiểm tra xem `AgentId` đã tồn tại chưa:
   - **Nếu chưa có:** Thêm mới bản ghi vào bảng `agents`.
   - **Nếu đã có:** Tự động xoay khóa (rotate key) mới và mở lại quyền.
2. Sinh ngẫu nhiên chuỗi `API Key` an toàn và lưu bản băm SHA-256 vào database.
3. **Tự động ghi đè ngay `ASP_AGENT_ID` và `ASP_AGENT_API_KEY` mới vào file `.env`** (không cần copy - paste thủ công).
4. In thông tin ra màn hình để bạn đối chiếu.

*(Lưu ý: Nếu agent client chạy từ WSL2 gửi sang server Windows, mở inbound port `8000` trên Windows Firewall bằng PowerShell Administrator: `New-NetFirewallRule -DisplayName "ASP Server from WSL" -InterfaceAlias "vEthernet (WSL)" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow`.)*

---

## 4. Setup & Chạy Phía Client Thu Thập Log (Ubuntu / WSL)

Sau khi Bước 3.2 đã cập nhật `ASP_AGENT_ID` và `ASP_AGENT_API_KEY` vào `.env`:

1. Copy toàn bộ thư mục dự án (hoặc file `.env`) sang máy Ubuntu (nếu dùng chung trên WSL thì thư mục đã có sẵn tại `/mnt/d/ATTT/CK/qt-agentic-soc`).
2. Mở terminal trên Ubuntu và chỉ cần chạy 1 lệnh duy nhất:

```bash
# Khởi chạy thu thập log ngay (tự tạo .venv-client nếu là lần đầu chạy):
bash setup/client_setup.sh

# Hoặc chỉ cài đặt môi trường .venv-client và cấu hình (chưa gửi log ngay):
bash setup/client_setup.sh --setup-only
```

**Script `client_setup.sh` tự động làm gì?**

1. Tạo môi trường ảo riêng `.venv-client` (không đè lên `.venv` của Windows) và chỉ cài 3 gói nhẹ: `requests`, `pyyaml`, `pydantic`.
2. Đọc `.env` (tự xử lý ký tự `\r` nếu file được sửa từ Windows).
3. Sinh cấu hình chạy `$HOME/asp-agent-config.yaml` (quyền `0600`) trỏ `state_file` và `spool_dir` về `$HOME/.asp-agent/` (ext4 Linux) và lấy `server_url`, `agent_id`, `verify_tls` từ `.env`.
4. Chạy `client/collector.py --config "$HOME/asp-agent-config.yaml"`.

*(Lưu ý trên Ubuntu: user chạy `client_setup.sh` cần thuộc nhóm `adm` để đọc `/var/log/auth.log` và `/var/log/syslog`.)*

---

## 5. Tài liệu tham khảo nhanh khác

- Test toàn bộ hệ thống: `.\.venv\Scripts\python.exe -m pytest -v`
- Kiểm thử rule YAML offline: `python tools/asp_logtest.py --file samples/rules/ssh_bruteforce_pos.log --type auth`
- Hướng dẫn demo chi tiết: [docs/demo.md](file:///d:/ATTT/CK/qt-agentic-soc/docs/demo.md)
- Tài liệu bàn giao cho team AI Agentic SOC: [docs/AGENTIC_SOC_HANDOVER.md](file:///d:/ATTT/CK/qt-agentic-soc/docs/AGENTIC_SOC_HANDOVER.md)
- Đánh giá thiết kế & giới hạn: [docs/final-review.md](file:///d:/ATTT/CK/qt-agentic-soc/docs/final-review.md)
