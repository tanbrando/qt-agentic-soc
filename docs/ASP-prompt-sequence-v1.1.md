# ASP – Chuỗi prompt thực hiện cho AI coding (khớp thiết kế v1.1 & hiện trạng repo)

Dùng kèm file `ASP-thiet-ke-he-thong-v1.1.md` và `docs/phase0-report.md`.  
Chạy **tuần tự từ trên xuống**; xong prompt nào, kiểm DoD và kết quả `pytest` thật rồi mới sang prompt kế tiếp. **Phase 6 (AI Agentic)** do thành viên khác phụ trách; chuỗi này kết thúc ở cổng kiểm & bàn giao cuối **Phase 5**.

---

## Trạng thái tổng thể & Quyết định đã chốt

| Hạng mục | Trạng thái / Quyết định đã chốt |
| --- | --- |
| **Phạm vi** | Làm từ Phase 0 đến hết Phase 5 (SIEM lõi). Phase 6 (AI Agentic) bàn giao cho thành viên khác. |
| **Mô hình thực thi** | Toàn bộ server (API, Repository, Service, Agent skeleton) dùng **`def` đồng bộ** + **`psycopg` v3 đồng bộ** + **`threading.Lock`** (chưa dùng `psycopg[pool]`). Chạy `uvicorn` với `--workers 1`. |
| **Database** | PostgreSQL local (`asp_db`), dùng **một biến môi trường `ASP_DB_URL` duy nhất** cho cả migration và server. **Không** tạo role `asp_app` / `asp_ai_ro` ở giai đoạn SIEM; giữ nguyên toàn bộ bảng, index và trigger `events_raw_immutable` theo mục 8.3. |
| **Schema & Hợp đồng** | `common/schemas.py` đã nâng lên v1.1 ở P0.3a; `Alert`/`Case` theo DDL 8.3; giữ `agent_verdict`, `agent_confidence`, `ai_report` (và `alerts`/`artifacts`/`title`) dạng tùy chọn mặc định `None`/`[]` để không vỡ Phase 6. |
| **HTTP Client (Agent)** | Dùng **`requests`** (đã bỏ `httpx`, `pydantic-settings`, `pytest-asyncio`). |
| **Phase 0 (`P0.1`, `P0.2`, `P0.3a–c`)** | **ĐÃ XONG** (43/43 tests đang pass ở cuối Phase 1). |
| **Phase 1 (`P1.1`–`P1.5`, `P1.G`)** | **ĐÃ XONG** (48/48 tests pass). Bước kế tiếp trong kế hoạch là **Phase 2 (`P2.1`)**. |

---

## Cách dùng

1. Mỗi prompt = **một task độc lập**; mở session mới hoặc giữ context gọn theo từng task.
2. Luôn đính kèm `ASP-thiet-ke-he-thong-v1.1.md` và cho AI truy cập repo `qt-agentic-soc/`.
3. Đầu session mới: dán **Prompt nền (mục A)** trước, rồi dán **một** prompt task.
4. AI phải tóm tắt hiểu biết và nêu điểm chưa rõ **trước khi sửa/viết code**. Bạn duyệt rồi mới cho viết code.
5. Cuối task: yêu cầu AI chạy `.\.venv\Scripts\python.exe -m pytest -v` (hoặc `python -m pytest -v` trong `.venv`) và dán nguyên văn kết quả.
6. Sau mỗi task ổn định: `git commit` riêng để dễ quay lui.
7. Nếu cần đổi schema JSON (mục 5, 6) hoặc DDL (mục 8.3): AI phải hỏi và chờ bạn chốt.

---

## A. Prompt nền (dán đầu MỌI session mới)

```text
Đây là tài liệu thiết kế dự án ASP (Agentic SOC Platform) v1.1, đính kèm. Codebase nằm ở qt-agentic-soc/.

Các quyết định nền đã chốt (KHÔNG tự ý đảo ngược):
- Phạm vi: chỉ làm lõi SIEM (Phase 0–5); Phase 6 (AI Agentic) bàn giao thành viên khác.
- Server dùng hàm `def` đồng bộ, `psycopg` v3 đồng bộ (CHƯA dùng `psycopg[pool]`), `threading.Lock`, chạy `uvicorn --workers 1`.
- PostgreSQL local (`asp_db`) dùng MỘT biến `ASP_DB_URL`; chưa tạo role `asp_app` / `asp_ai_ro` ở giai đoạn này.
- Agent dùng `requests` (không dùng `httpx`). Đọc config từ `os.environ` (không dùng `pydantic-settings`).
- `common/schemas.py` là nguồn chân lý (đã ở chuẩn v1.1; giữ tùy chọn `agent_verdict`, `agent_confidence`, `ai_report` cho Phase 6).

Trước khi làm bất cứ việc gì:
1. Đọc hết tài liệu thiết kế (đặc biệt mục 1.2, 3.1, 14) và code liên quan đến task.
2. Tóm tắt lại bằng lời của bạn (tối đa 15 dòng) phần liên quan đến task tôi giao.
3. Liệt kê các điểm chưa rõ hoặc chỗ mâu thuẫn với code thật. CHỜ tôi trả lời rồi mới viết code.

Quy tắc cứng (mục 14):
- Chỉ làm đúng task được giao. Không viết code của phase hoặc task khác.
- Đọc code hiện có trước, mở rộng thay vì viết lại.
- Không đổi schema JSON (mục 5, 6) hay DDL (mục 8.3) khi chưa hỏi tôi.
- Chỉ dùng thư viện: fastapi, uvicorn, psycopg (v3), pydantic v2, pyyaml, requests, pytest và thư viện chuẩn (giữ `langchain-core` trong requirements.txt cho Phase 6). KHÔNG Filebeat, Logstash, Elasticsearch, Wazuh.
- Không hardcode đường dẫn, mật khẩu, API key; dùng cấu hình và biến môi trường. Không đưa key/mật khẩu thật vào code, test, mẫu, log hay `.env.example`.
- Parser là hàm thuần. Mọi SQL dùng tham số, tuyệt đối không ghép chuỗi.
- Log là dữ liệu không đáng tin: coi mọi nội dung log là input độc hại.
- Mỗi module có test chạy bằng `pytest` trong `.venv`. Chạy test và báo kết quả thật trước khi nói "xong".
- Gặp điểm không chắc chắn: hỏi, không đoán.

Kết thúc task, báo cáo theo mẫu:
(a) file đã tạo/sửa, (b) quyết định đã đưa ra và lý do, (c) kết quả pytest (dán output), (d) điểm lệch giữa tài liệu và code, (e) việc còn dang dở.
```

---

## PHASE 0 – Khảo sát, chuẩn hóa hợp đồng & môi trường `[ĐÃ XONG]`

- **`P0.1` [ĐÃ XONG]:** Chạy baseline `pytest`, đối chiếu code thật với mục 3.1 và lưu [docs/phase0-report.md](file:///d:/ATTT/CK/qt-agentic-soc/docs/phase0-report.md).
- **`P0.2` [ĐÃ XONG]:** Kiểm tra mẫu log lab thật (`client/samples/auth.log` 70 dòng, `client/samples/syslog` 150 dòng) -> xác nhận 100% BSD `SYSLOG_OLD`, timestamp có nhảy lùi nhẹ, `auth.log` có 66/70 dòng `PAM_SESSION`.
- **`P0.3a` [ĐÃ XONG]:** Nâng `server/src/common/schemas.py` và `tests/test_schemas.py` lên hợp đồng v1.1.
- **`P0.3b` [ĐÃ XONG]:** Chuyển `repositories`, `services`, `api/v1/*`, `agent/*` sang `def` đồng bộ; `POST /api/v1/ingest/logs` trả `202`; `GET /api/v1/health`; cập nhật toàn bộ test cũ.
- **`P0.3c` [ĐÃ XONG]:** Dọn đường dẫn cứng `C:\Python312`, dọn `requirements.txt` & `pyproject.toml`, thêm `server/src/common/config.py` (`os.environ`), tạo `.venv` sạch và cập nhật `README.md`.

---

## PHASE 1 – Nền ingestion, PostgreSQL và xác thực

- **`P1.1` [ĐÃ XONG]:** `migrations/001..003.sql` (đúng DDL mục 8.3, bỏ qua role), `tools/asp_migrate.py` (`ASP_DB_URL`, idempotent qua `schema_migrations`), test trigger `events_raw_immutable` trên `asp_db`.
- **`P1.2` [ĐÃ XONG]:** `server/src/repositories/postgres.py` cài `ILogRepository`, `IAlertRepository`, `IAuthRepository` và bộ test hợp đồng chung `tests/test_repositories_contract.py` chạy cả `memory` và `postgres`.
- **`P1.3` [ĐÃ XONG]:** `tools/asp_admin.py`, `server/src/common/security.py`, `require_agent_auth` (`401`/`403`) và `require_operator_scope` (`read`/`investigate`).
- **`P1.4` [ĐÃ XONG]:** `save_batch_with_parser` ghi `events_raw` (`ON CONFLICT DO NOTHING`) trước khi parse dòng mới sang `events` trong cùng transaction; giới hạn `500` events / `1 MB` (`413`) và rate limit token bucket (`429`).
- **`P1.5` [ĐÃ XONG]:** Sau commit, sắp sự kiện mới theo `ts` tăng dần, chạy `RuleEngine` dưới `threading.Lock`, bắt ngoại lệ engine không biến thành 5xx.

### `P1.G` – Cổng kiểm & gia cố cuối Phase 1 `[ĐÃ XONG]`

```text
Phase 1, task G (Cổng kiểm cuối Phase 1). Đọc mục 8, 9.0, 11, 14 và rà soát toàn bộ code Phase 1 hiện có.

Việc cần kiểm tra và bổ sung nhỏ (nếu thiếu):
1. Kiểm tra an toàn so sánh băm trong `dependencies.py`: bổ sung `hmac.compare_digest` đối chiếu `key_hash` sau khi tra DB/bộ nhớ; kiểm tra bằng grep để chắc chắn không có chỗ nào ghép chuỗi SQL, hardcode secret/mật khẩu thật, hoặc ghi API key/token ra log.
2. Kiểm tra giới hạn bộ nhớ `InMemorySlidingWindowStore` (`server/src/engine/state_store.py`) theo mục 9.0: giới hạn `max_window_events` (mặc định 10.000 phần tử/khóa) và `max_keys` (mặc định 100.000 khóa, loại khóa cũ nhất khi đầy), thêm unit test kiểm tra không tràn RAM.
3. Chạy và xác nhận đủ 5 kịch bản trên PostgreSQL thật (`ASP_DB_URL` trỏ `asp_db`):
   - Gửi cùng lô 2 lần -> 1 bản trong `events_raw` và `events`, lần 2 báo `duplicates`, bản trùng không vào `RuleEngine`.
   - `agent.id` lệch key -> `403`; key sai hoặc đã thu hồi (`asp_admin.py`) -> `401`; > 500 events hoặc > 1 MB -> `413`; quá tải -> `429`.
   - `UPDATE` trên `events_raw` bị trigger chặn.
   - `memory.py` và `postgres.py` qua cùng bộ test hợp đồng.
   - `RuleEngine` ném exception sau commit -> request ingest vẫn trả `202` và dữ liệu vẫn nằm trong DB; hai thread ingest đồng thời an toàn dưới `threading.Lock`.

Chưa sửa parser (Phase 2), chưa sửa `client/collector.py` (Phase 3), chưa chuyển rule sang YAML (Phase 5).
```

---

## PHASE 2 – Parser auth và công cụ re-parse

### `P2.1` – Tiền xử lý chung, quy tắc thời gian và trạng thái `unparsed`/`error` `[ĐÃ XONG]`

```text
Phase 2, task 1. Đọc mục 6.3, 7.1, 7.2, 7.7 và kiểm lại mục 6 trong docs/phase0-report.md.

Việc cần làm:
1. Chuẩn hóa giao diện parser thuần túy: `parse(log_type: str, message: str, meta: dict) -> ECSEvent` (hoặc giữ `BaseLogParser` mở rộng sạch sẽ với `meta`: `event_uid`, `collected_at`, `received_at`, `agent`, `file`, `message_truncated`), KHÔNG đọc DB, KHÔNG gọi mạng, KHÔNG gọi `datetime.now()`.
2. Tiền xử lý chung cho `auth` và `syslog`: hỗ trợ cả `SYSLOG_OLD` (`Nov 10 08:30:00`) lẫn `SYSLOG_ISO`, trích xuất `ts`, `proc`, `pid`, `msg` (`host.name` lấy từ envelope, không lấy từ tiêu đề syslog).
3. Quy tắc thời gian mục 6.3:
   - `SYSLOG_OLD`: lấy năm từ `collected_at`, trừ 1 năm nếu kết quả vượt `collected_at` quá 1 ngày (xử lý giao thừa); đổi từ `agent.timezone` (fallback `ASP_DEFAULT_TIMEZONE`) sang UTC bằng `zoneinfo`.
   - `SYSLOG_ISO`: đổi múi giờ sang UTC.
   - Chặn timestamp tương lai: nếu `@timestamp > received_at + ASP_FUTURE_TS_TOLERANCE` (mặc định `5m`), ép `@timestamp = collected_at` và đặt `asp.ts_clamped = true`.
4. Trạng thái `unparsed` và `error` theo mục 7.7: dòng không khớp tiêu đề/mẫu vẫn tạo `ECSEvent` hợp lệ với `asp.parse_status = "unparsed"`, `@timestamp = collected_at`, `category = ["host"]`, `type = ["info"]`, `action = "unparsed"`. Regex đơn giản, không lượng từ lồng nhau (chống ReDoS).
5. Test: năm, giao thừa (31/12 -> 01/01), nhiều múi giờ, ISO 8601, timestamp tương lai (`ts_clamped`), dòng rác ra `unparsed` không ném exception.
```

### `P2.2` – Hoàn thiện `AuthLogParser` (`sshd`, `sudo`, `useradd`, `pam`) `[ĐÃ XONG]`

```text
Phase 2, task 2. Đọc mục 7.3, 7.4, 7.6 và mục 6.2 trong docs/phase0-report.md. Mở rộng `auth_parser.py` hiện có, không viết lại từ đầu.

Việc cần làm:
1. Chuẩn hóa các parser con trong `AuthLogParser`:
   - `sshd` (mục 7.3): tách 3 action `ssh_login_failed`, `ssh_invalid_user`, `ssh_login_success`; gán `asp.auth_method`, `source.ip`, `source.port`, `user.name`, `related.ip`, `related.user`, `asp.parser`.
   - `sudo` (mục 7.4): `sudo_command` (outcome `unknown`, `process.args`, `asp.sudo_target_user`), `sudo_not_in_sudoers`, `sudo_bad_password`, `sudo_auth_failed` (chú ý mẫu thật trong `client/samples/auth.log:10` có khoảng trắng sau `rhost=`).
   - `useradd` (mục 7.6): `user_created`, `category=["iam"]`, `type=["creation"]`, `outcome="success"`.
   - `PAM_SESSION` (mục 7.6): bổ sung `session_opened` (`type=["start"]`) và `session_closed` (`type=["end"]`) áp dụng cho mọi `proc` (`login`, `systemd`, `CRON`, `sudo` — khớp đủ 66/66 dòng PAM trong `client/samples/auth.log`).
2. Đồng bộ tối thiểu ở 2 rule Python hiện tại (`SSHBruteForceRule`, `SudoAbuseRule`) và `test_rules.py` / `test_integration.py` nếu cần để khớp `event.action` mới (`ssh_login_failed`, `sudo_not_in_sudoers`...) và giữ toàn bộ `pytest` xanh (chưa chuyển sang YAML ở phase này).
3. Gom/tổ chức bộ mẫu trong `samples/auth/` (dùng log thật từ `client/samples/auth.log` + thêm >= 5 dòng mẫu chuẩn cho `sshd` và `useradd`), viết test kiểm từng trường ECS và ca dòng hỏng ra `unparsed`.
4. Thêm `client_parse: false` vào `client/config.yaml`; bảo đảm server luôn parse từ `message` gốc.

DoD: `tests/test_auth_parser.py` mở rộng và toàn bộ `pytest` hiện có đều pass.
```

### `P2.3` – Công cụ `tools/asp_reparse.py` *(mức N)* `[ĐÃ XONG]`

```text
Phase 2, task 3 (ưu tiên N). Đọc mục 8.5.

Việc cần làm:
1. Viết `tools/asp_reparse.py` đọc `events_raw` (lọc theo `--since`, `--until`, `--agent`, `--status`), dựng `meta` từ `collected_at` và `agent_meta`, chạy lại `ParserRegistry`, rồi `UPSERT` vào `events`.
2. Hỗ trợ `--dry-run` (in số dòng sẽ cập nhật, không ghi DB) và `--replay-rules` (chỉ chạy thêm rule khi được chỉ định rõ). Tuyệt đối KHÔNG sửa `events_raw`.
3. Test trên `asp_db`: thay đổi dữ liệu/parser -> chạy `asp_reparse.py` -> `events` được cập nhật đúng, `events_raw` không thay đổi.
```

---

## PHASE 3 – Agent collector (Linux thin agent)

### `P3.1` – Cấu hình, theo dõi `(device, inode)`, `stream_id` và thuật toán tail `[ĐÃ XONG]`

```text
Phase 3, task 1. Đọc mục 4.1, 4.2, 4.4, 5. Mở rộng `client/collector.py` và `client/config.yaml`, bỏ `asyncio`/`httpx`, giữ `client/parsers.py` nhưng tắt mặc định (`client_parse: false`).

Việc cần làm:
1. Đọc `client/config.yaml` theo mục 4.1: `agent_id`, `server_url`, `ingest_path`, `api_key_env` (lấy key từ biến môi trường, không lưu key vào yaml), `verify_tls`, `ca_file`, `timezone: auto` (lấy IANA timezone hệ thống), `start_position`, `state_file`, `spool_dir`, `spool_max_mb`, `poll_interval_seconds`, `batch_max_events`, `batch_max_bytes`, `batch_max_seconds`, `max_line_bytes`, `http_timeout_seconds`, `client_parse: false`, `sources`.
2. Theo dõi `(st_dev, st_ino)` và sinh `stream_id` ngẫu nhiên cho mỗi "đời" file; lưu `state.json` đúng cấu trúc mục 4.2 (`version: 1`, `sources` gồm `device`, `inode`, `stream_id`, `offset`, `head_len`, `head_hash`, `pending_rotated`).
3. Thuật toán tail:
   - Khởi tạo từ EOF (`start_position: end`) hoặc đầu file (`beginning`).
   - Xoay vòng (đổi `st_dev, st_ino`): đọc nốt phần còn lại của file cũ (giữ fd đang mở hoặc tìm lại theo inode trong cùng thư mục) dưới `stream_id` cũ rồi mới chuyển sang file mới `offset = 0` với `stream_id` mới.
   - Truncate (`st_size < read_offset`): sinh `stream_id` mới, `offset = 0`.
   - Kiểm tra 64 byte đầu (`head_hash`, dùng `seek(0)` + `read(64)` để chạy được trên cả Windows test lẫn Linux): khác `head_hash` thì coi như truncate/thay file.
   - Chỉ nhận dòng kết thúc bằng `\n`; giữ dòng dở; cắt dòng quá `max_line_bytes` và gắn `message_truncated: true`; decode UTF-8 `errors="replace"`.
4. Tạo `RawLogEvent` đúng envelope mục 5 (`offset` = byte đầu dòng). Chưa làm spool/HTTP ở task này; test hoàn toàn trên `tmp_path`, KHÔNG đụng `/var/log` thật.
```

### `P3.2` – Spool trên đĩa và commit offset an toàn `[ĐÃ XONG]`

```text
Phase 3, task 2. Đọc mục 4.3.

Việc cần làm:
1. Cài đặt spool trong `spool_dir`: mỗi lô ghi file tạm -> `flush` + `os.fsync` -> `os.replace` nguyên tử; đọc lại theo thứ tự cũ đến mới.
2. Ghi `state.json` cũng bằng file tạm -> `os.fsync` -> `os.replace`.
3. Xử lý `spool_max_mb`: khi spool đầy, ngừng đọc thêm từ các nguồn (KHÔNG tiến offset, KHÔNG bỏ dòng), ghi log cảnh báo.
4. Thiết lập quyền `0o700` cho thư mục state/spool trên POSIX (bọc tương thích an toàn khi chạy test trên Windows).
5. Test: giả lập agent dừng giữa lúc ghi spool và ghi `state.json` -> khởi động lại đọc phần chưa commit, không mất dòng nào.
```

### `P3.3` – Gửi lô bằng `requests`, backoff và quy tắc xử lý mã HTTP `[ĐÃ XONG]`

```text
Phase 3, task 3. Đọc mục 4.3, 5, 11.

Việc cần làm:
1. Chuyển luồng gửi trong `client/collector.py` sang `requests` đồng bộ (bỏ `httpx` và `asyncio`), gửi `POST` khi đạt `batch_max_events`, `batch_max_bytes`, hoặc `batch_max_seconds`, có `timeout`, `verify_tls`, `ca_file`, header `Authorization: Bearer <api_key>`.
2. Quy tắc commit offset: chỉ tiến `committed_offset` trong `state.json` khi server trả `2xx` HOẶC lô đã ghi bền vào spool.
3. Xử lý mã phản hồi:
   - `2xx`: commit offset (hoặc xóa file spool tương ứng).
   - Mất mạng / timeout / `5xx` / `429`: ghi vào spool (nếu là lô mới) rồi commit offset; thử lại với backoff mũ (1s, 2s, 4s... tối đa 60s + jitter; tôn trọng `Retry-After` nếu có); ưu tiên gửi spool trước lô mới, giữ nguyên `batch_id` và tọa độ file (`event.id` không đổi).
   - `401` / `403`: giữ lô trong spool, log mức `ERROR` (TUYỆT ĐỐI không in API key), thử lại với backoff, không bỏ lô.
   - `413` *(mức N)*: chia đôi lô và gửi lại từng nửa.
   - `400` / `422` *(mức N)*: chuyển vào `spool_dir/rejected/` kèm lý do để không kẹt hàng đợi.
4. Test dùng server HTTP giả từ thư viện chuẩn (`http.server`) hoặc mock `requests`: kiểm tra thứ tự gửi spool -> mới, server chết rồi sống lại, `401` giữ lô, `413` chia đôi, `422` vào `rejected/`, không rò rỉ API key trong log.
```

### `P3.4` – Kiểm thử đầu-cuối Agent collector `[ĐÃ XONG]`

```text
Phase 3, task 4. Đọc mục 4.4 và mục 12 (phần Agent & event.id).

Việc cần làm:
Viết bộ test tích hợp (`tests/test_collector_e2e.py`, dùng `tmp_path` + ASGI/HTTP server thật hoặc `http.server` + repository):
1. Xoay vòng file (đổi tên + tạo file mới), truncate, `copytruncate`, thay file cùng inode (`head_hash` đổi).
2. Khởi động lại giữa chừng, chạy lần đầu không có state (`start_position: end`), dòng dở cuối file, server chết rồi sống lại, spool đầy.
3. Kiểm chứng riêng `stream_id`: hai dòng khác nhau ghi tại cùng `(inode, offset)` sau truncate phải tạo hai `event.id` khác nhau và cả hai đều lưu thành công vào server.
Tiêu chí: không mất dòng hoàn chỉnh, không trùng dòng ngoài phần trùng hợp lệ do server tự loại bằng `event.id`.
```

---

## PHASE 4 – Parser Apache và Syslog chung

### `P4.1` – Parser Apache Combined `[ĐÃ XONG]`

```text
Phase 4, task 1. Đọc mục 7.5, 7.7.

Việc cần làm:
1. Tạo `server/src/parsers/apache_parser.py` đăng ký vào `ParserRegistry` cho `log_type == "apache"` (và `access.log`), dùng regex `APACHE` ở mục 7.5 tách chuỗi `req` trước để bắt được cả request hỏng (`"-"`).
2. Quy đổi timestamp `10/Nov/2026:08:30:00 +0700` sang UTC + kiểm tra chặn timestamp tương lai (`asp.ts_clamped`).
3. Ánh xạ chuẩn ECS: `event.dataset = "apache.access"`, `event.category = ["web"]`, `event.type = ["access"]`, `event.action = "http_request"`, `event.outcome` (`success` nếu status < 400, `failure` nếu >= 400), `source.ip`, `http.request.method`, `url.original`, `http.response.status_code` (int), `user_agent.original`, `user.name` (chỉ gán khi khác `"-"`), `related.ip`, `related.user`, `asp.parser = "apache_combined@1"`.
4. Tạo mẫu tại `samples/apache_access.log` (>= 5 dòng thật + ca status 404, request hỏng `"-"`, IPv6, dòng dài/rác ra `unparsed`) và viết `tests/test_apache_parser.py`.
```

### `P4.2` – Parser Syslog chung và kiểm thử 3 nguồn log `[ĐÃ XONG]`

```text
Phase 4, task 2. Đọc mục 7.6, 7.7, 6.2.

Việc cần làm:
1. Tạo `server/src/parsers/syslog_parser.py` cho `log_type == "syslog"` (đặt thứ tự ưu tiên sau `AuthLogParser` để không đè lên `auth.log`).
2. Dòng khớp tiêu đề `SYSLOG_OLD` / `SYSLOG_ISO` -> `event.dataset = "linux.syslog"`, `event.category = ["host"]`, `event.type = ["info"]`, `event.action = "syslog_message"`, `event.outcome = "unknown"`, giữ phần thân `msg` trong `ECSEvent.message`, gán `process.name`, `process.pid`, `@timestamp` theo quy tắc 6.3. Dòng không khớp tiêu đề -> `unparsed`.
3. Kiểm thử bằng mẫu thật từ `client/samples/syslog` (150 dòng có `/etc/mysql/debian-start`, `50-motd-news`, `#033[...]`, `message repeated N times`) trong `tests/test_syslog_parser.py`.
4. Thêm test tích hợp ingest cả 3 loại `auth`, `syslog`, `apache` qua `POST /api/v1/ingest/logs` vào DB/repository đều thành công.
```

---

## PHASE 5 – Rule Engine YAML, Cooldown, Case vòng đời & API đọc

### `P5.1` – YAML Rule Loader và 4 class tổng quát `[ĐÃ XONG]`

```text
Phase 5, task 1. Đọc mục 9.0, 9.1, 9.2, 9.3 và quy ước mục 14 về rule.

Việc cần làm:
1. `server/src/engine/loader.py`: đọc `rules/*.yaml` (từ `ASP_RULES_DIR`), validate bằng Pydantic v2 (hỗ trợ `timespan`/`cooldown` kiểu `1m`, `5m`, `10m`, `30m`, `6h`), báo lỗi rõ file/trường khi YAML sai; một rule lỗi bị ghi log và bỏ qua, không làm chết engine.
2. `server/src/engine/generic_rules.py`: cài 4 class kế thừa `BaseRule`: `MatchRule`, `EventCountRule`, `ValueCountRule`, `SequenceRule` đúng ngữ nghĩa mục 9.3 (`sequence`: toàn chuỗi từ bước 1 đến bước cuối nằm trong `timespan`; cửa sổ `(ts_mới_nhất - timespan, ts_mới_nhất]`).
3. Biên dịch trước `selection` với đầy đủ toán tử mục 9.2 (`eq`, list `in`, `contains`, `startswith`, `endswith`, `re`, `gte`, `gt`, `lte`, `lt`, `exists`), hỗ trợ truy vấn đường dẫn chấm trên `ECSEvent` (`event.action`, `http.response.status_code`, `asp.sudo_target_user`, `process.args`...) và mảng (`event.category`). Giới hạn độ dài input chuỗi trước khi chạy regex rule để chống ReDoS.
4. Rule chỉ dùng `ISlidingWindowStore`, không truy cập DB trực tiếp. Chưa chuyển/tạo 6 rule thật ở task này; test bằng rule thử trong `tests/test_generic_rules.py` (mỗi loại có case "nên nổ" và "không nên nổ").
```

### `P5.2` – Chuyển 6 rule sang YAML `[ĐÃ XONG]`

```text
Phase 5, task 2. Đọc mục 9.7.

Việc cần làm:
1. Tạo 6 file YAML trong `rules/`:
   - `asp-ssh-bruteforce.yaml` (`event_count`, >= 5 `ssh_login_failed` / `source.ip` / 5m)
   - `asp-password-spraying.yaml` (`value_count`, >= 10 `user.name` khác nhau / `source.ip` / 5m)
   - `asp-bruteforce-then-success.yaml` (`sequence`, >= 5 `ssh_login_failed` rồi 1 `ssh_login_success` / `source.ip` / 10m)
   - `asp-web-scan-404.yaml` (`event_count`, >= 30 `http_request` status 404 / `source.ip` / 1m)
   - `asp-sudo-to-root-shell.yaml` (`match`, `sudo_command` + `asp.sudo_target_user: root` + `process.args|re: '^(/usr)?/bin/((ba|da|z)?sh|su)(\s|$)'`)
   - `asp-sudo-abuse.yaml` (`match`, `sudo_not_in_sudoers` | `sudo_bad_password` | `sudo_auth_failed`)
2. Nối `Container` trong `dependencies.py` nạp rule từ `ASP_RULES_DIR` bằng `loader.py` (thay thế `ssh_bruteforce.py` và `sudo_abuse.py` sau khi chứng minh test tương đương đều pass, rồi xóa 2 class Python cũ).
3. Tạo mẫu log "nên nổ" và "không nên nổ" cho từng rule trong `samples/rules/` và test đầy đủ trong `tests/test_rules.py` (bắt buộc có ca `/bin/shutdown` KHÔNG làm nổ `asp-sudo-to-root-shell`, và ca `Invalid user` + `Failed password` không đếm đôi `asp-ssh-bruteforce`).
```

### `P5.3` – Cooldown, chống trùng alert, xử lý đến muộn và nạp lại cửa sổ khi khởi động `[ĐÃ XONG]`

```text
Phase 5, task 3. Đọc mục 9.0 và 9.5.

Việc cần làm:
1. Cooldown theo event-time:
   - `event_count`, `value_count`, `sequence`: `alert_key = rule_id + ":" + giá_trị_nhóm + ":" + (epoch_seconds(ts) // cooldown_seconds)`.
   - `match`: `alert_key = rule_id + ":" + event_uid` (không áp dụng cooldown).
   - Giới hạn tối đa 200 `event_uids` trên mỗi alert (giữ đầu/cuối cửa sổ) trong khi `event_count` ghi số thật.
2. Cửa sổ trượt xử lý sự kiện đến muộn (`ASP_ALLOWED_LATENESS`, mặc định `60s`): giữ trật tự theo `ts`, sự kiện trễ hơn `allowed_lateness` so với `ts` mới nhất của khóa vẫn cập nhật cửa sổ nhưng không phát alert mới.
3. Khi server khởi động (`Container.__init__` / startup): nếu dùng Postgres, lấy mốc `T = max(ts)` từ `events`, nạp các sự kiện có `ts >= T - (max_timespan + allowed_lateness)` theo thứ tự `ts` vào store ở chế độ **chỉ cập nhật cửa sổ (không phát alert)**, và nạp cooldown từ `alerts` có `window_end >= T - max_cooldown`.
4. Test: cooldown chặn alert trùng trong cùng ô; sự kiện trễ hơn `allowed_lateness` không nổ alert lại; khởi động lại server (khởi tạo lại `RuleEngine` + `store` từ Postgres) vẫn giữ đủ cửa sổ để sự kiện kế tiếp kích hoạt đúng mà không phát lại alert cũ.
```

### `P5.4` – Case có vòng đời (`case_idle_timeout`) `[ĐÃ XONG]`

```text
Phase 5, task 4. Đọc mục 9.5, quyết định 6 và DDL `cases` ở 8.3.

Việc cần làm:
1. Khóa case đúng mục 9.5: `ip:<source.ip>` -> fallback `host:<host.name>|user:<user.name>` -> fallback `alert:<alert_key>`.
2. Vòng đời theo event-time (`ASP_CASE_IDLE_TIMEOUT`, mặc định `6h`):
   - Tìm case `open` có cùng `case_key`.
   - Nếu có và `alert_window_end - case.last_activity_at <= case_idle_timeout`: gắn alert vào case đó, cập nhật `last_activity_at`, `level` (mức cao nhất), `updated_at`.
   - Nếu có nhưng đã quá `case_idle_timeout`: đóng case cũ (`status = 'closed'`) rồi mở case mới.
3. Bảo đảm đồng bộ trong `PostgresAlertRepository` / `IngestionService` (dưới `engine_lock` và xử lý index `cases_one_open_per_key`) để hai lô đồng thời không tạo hai case mở cùng khóa.
4. Test (cả `memory` và `postgres`): cùng IP trong 6h -> 1 case; vượt 6h -> case cũ `closed`, mở case mới `open`; gọi đồng thời nhiều thread không lỗi trùng `cases_one_open_per_key`.
```

### `P5.5` – Hoàn thiện API đọc (`alerts`, `events`, `cases`) `[ĐÃ XONG]`

```text
Phase 5, task 5. Đọc mục 8.1 và 11.

Việc cần làm:
1. Bổ sung vào `ILogRepository` / `IAlertRepository` (cài trên cả `memory.py` và `postgres.py`) và các router v1 (đều bảo vệ bằng `require_operator_scope("read")`, phân trang `limit` tối đa `1000`, `offset`):
   - `GET /api/v1/alerts`: lọc theo `rule_id`, `level`, `status`, `case_id`, `since`, `until`.
   - `GET /api/v1/events`: lọc theo `source_ip`, `user_name`, `action`, `dataset`, `parse_status`, `since`, `until`.
   - Giữ và rà soát `GET /api/v1/cases` (lọc `status`, `level`, `source_ip`) và `GET /api/v1/cases/{id}` (kèm danh sách alerts).
2. Giữ nguyên `POST /api/v1/cases/{id}/investigate` và trường Phase 6 tùy chọn trên `Case` để không làm gãy contract bàn giao.
3. Test: không token -> `401`, sai scope -> `403`, query lọc và phân trang chạy đúng trên cả `memory` và `postgres`, không ghép chuỗi SQL.
```

### `P5.6` – Công cụ `tools/asp_logtest.py` `[ĐÃ XONG]`

```text
Phase 5, task 6. Đọc mục 9.6.

Việc cần làm:
1. Viết `tools/asp_logtest.py`:
   - Chế độ dòng đơn: `python tools/asp_logtest.py "<dòng log>" --type auth [--rules-dir rules/] [--timezone Asia/Ho_Chi_Minh]` -> in JSON sự kiện chuẩn ECS và danh sách rule loại `match` khớp.
   - Chế độ file: `--file samples/rules/...` -> chạy cả file qua parser + `RuleEngine` với `InMemory` repository/store (không cần DB), in các alert sinh ra.
2. Test chạy được trên cả 6 rule YAML và bộ mẫu `samples/rules/`.
```

### `P5.G` – Cổng kiểm Phase 5 & Bàn giao Phase 6 `[ĐÃ XONG]`

```text
Cổng kiểm cuối Phase 5. KHÔNG viết tính năng mới ngoài sửa lỗi nhỏ.

Việc cần làm:
1. Chạy toàn bộ `pytest` trong `.venv` (có `ASP_DB_URL` trỏ `asp_db`) và dán nguyên văn output.
2. Chạy mô phỏng kiểm chứng cuối Phase 5 qua `asp_logtest.py` và endpoint thật: mỗi rule trong 6 rule nổ đúng 1 alert trên mẫu dương tính và 0 alert trên mẫu âm tính; restart server/container không mất cửa sổ; case đóng khi im lặng quá hạn.
3. Tạo `docs/handover-phase6.md` cho thành viên làm AI Agentic (Phase 6):
   - Mô tả chi tiết bảng `events`, `alerts`, `cases` (kèm các cột `ai_report`, `ai_investigated_at` và các trường tùy chọn trên `Case` schema).
   - Hướng dẫn tạo operator token phạm vi `investigate` bằng `tools/asp_admin.py`.
   - Hướng dẫn các endpoint đọc (`/api/v1/alerts`, `/api/v1/events`, `/api/v1/cases`, `/api/v1/cases/{id}`) và điểm nối `POST /api/v1/cases/{id}/investigate` + khung `server/src/agent/`.
   - Cung cấp sẵn đoạn SQL mẫu tạo role DB chỉ đọc `asp_ai_ro` (`GRANT SELECT ON events, alerts, cases TO asp_ai_ro`) để người làm Phase 6 bật khi cần.
   - Ghi rõ các giới hạn đã biết (single worker `--workers 1`, không tự đóng/xóa dữ liệu cũ...).
4. Đối chiếu DoD Phase 0–5 ở mục 13 và cập nhật bảng 3.1 cuối cùng trong `docs/phase0-report.md` (hoặc `ASP-thiet-ke-he-thong-v1.1.md` nếu được duyệt).
```

---

## Cuối cùng – Demo và Review báo cáo

### `F.1` – Kịch bản demo `[ĐÃ XONG]`

```text
Viết `scripts/demo_attack.py` (tương thích Windows/Linux, dùng `requests` hoặc `ssh`/TCP/HTTP tới lab target cấu hình qua tham số CLI/env, KHÔNG hardcode IP hay key) mô phỏng:
- Chuỗi đăng nhập SSH thất bại rồi thành công,
- Vài lệnh `sudo` thất bại và mở root shell,
- Quét HTTP 404 trên Apache (hoặc sinh log mẫu tương ứng).
Kèm `docs/demo.md`: các bước chạy migration, tạo agent/operator bằng `asp_admin.py`, khởi động server (`uvicorn server.main:app --workers 1`), chạy collector, chạy script demo, và các lệnh kiểm tra alert/case qua API.
```

### `F.2` – Review tổng và tài liệu báo cáo `[ĐÃ XONG]`

```text
KHÔNG viết code. Review toàn bộ repository so với mục 1.2, 4.4, 11, 14 của `ASP-thiet-ke-he-thong-v1.1.md` và xuất `docs/final-review.md` gồm:
1. Mức độ tuân thủ các nguyên tắc thiết kế (agent mỏng, raw append-only, idempotent, ECS, YAML rule, chỉ đọc ở giao diện AI).
2. Danh sách giới hạn đã biết cần đưa vào báo cáo đồ án (mục 4.4, 15).
3. Rủi ro bảo mật còn lại (vd: HTTP trong lab, chưa tạo role `asp_ai_ro` riêng ở giai đoạn SIEM, single-worker RAM state).
4. Các phần đã cắt/hoãn so với mục 13 (dashboard, `audit.log`, `psycopg[pool]`, Phase 6 bàn giao).
```

---

## Mẹo vận hành

| Tình huống | Cách xử lý |
| --- | --- |
| AI đề xuất đổi schema hoặc DDL | Dừng, chốt chung trong chat; cập nhật tài liệu thiết kế trước rồi mới cho sửa code |
| AI viết code ngoài phạm vi task | Nhắc: "Chỉ làm đúng task đã giao, hoàn tác phần ngoài phạm vi" |
| Test fail nhưng AI báo "xong" | Yêu cầu chạy lại trong `.venv` và dán nguyên văn output `pytest` |
| AI thêm thư viện ngoài danh sách mục 3 | Từ chối; nhắc lại `requirements.txt` đã chốt |
| Session quá dài, AI bắt đầu quên | Mở session mới: dán Prompt nền (mục A) + tóm tắt 4–5 dòng hiện trạng đã xong |
| Thiếu thời gian | Cắt theo thứ tự ở mục 13: dashboard, `audit.log`, mục N của Phase 3 (`head_hash`, `rejected/`, chia đôi 413), `asp_reparse.py`, `value_count`/`sequence` |
