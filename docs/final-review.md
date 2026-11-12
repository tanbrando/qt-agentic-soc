# Review Tổng thể Hệ thống ASP (SIEM Core Phase 0–5)

Ngày review: 2026-11-11  
Tài liệu đối chiếu: `ASP-thiet-ke-he-thong-v1.1.md` (Mục 1.2, 4.4, 11, 13, 14, 15)  
Trạng thái kiểm thử tự động: `114` unit/integration tests trên `.venv` (bao gồm cả PostgreSQL 17 local và InMemory).

---

## 1. Mức độ tuân thủ các nguyên tắc thiết kế (Mục 1.2 & Mục 14)

| Nguyên tắc / Quy ước | Đánh giá | Bằng chứng trong codebase |
| --- | --- | --- |
| **1. Agent mỏng (`client_parse: false`)** | Tuân thủ 100% | `client/config.yaml` đặt `client_parse: false`; `client/collector.py` đọc raw line kèm metadata file/agent qua `requests` đồng bộ; mọi chuẩn hóa diễn ra phía server. |
| **2. Lưu bản gốc trước, parse sau (`events_raw` append-only)** | Tuân thủ 100% | `migrations/002_events_raw_and_events.sql` tạo trigger `events_raw_immutable` chặn `UPDATE`; `PostgresLogRepository.save_batch_with_parser` ghi `events_raw` rồi mới parse trong transaction; `tools/asp_reparse.py` đọc `events_raw` để dựng lại `events`. |
| **3. At-least-once & Idempotent** | Tuân thủ 100% | `event_uid = sha1(agent_id\|device\|inode\|stream_id\|offset)`; collector chỉ commit `state.json` (temp + `fsync` + `os.replace`) sau khi nhận `2xx` hoặc ghi bền vào `spool_dir`; phát hiện rotation/truncate và ghi đè nhanh qua `head_hash` 64-byte (`seek(0)+read(64)` tương thích Windows/POSIX); server loại trùng bản ghi bằng `ON CONFLICT (event_uid) DO NOTHING` và không đưa bản trùng vào Rule Engine. |
| **4. Schema chuẩn tập con ECS** | Tuân thủ 100% | `server/src/common/schemas.py` là nguồn chân lý v1.1 (`ECSEvent` với `@timestamp`, `ecs.version`, `event.*`, `source.*`, `user.*`, `process.*`, `http.*`, `asp.*`; `Alert` và `Case` khớp DDL Mục 8.3). |
| **5. Rule Engine YAML + 4 class tổng quát** | Tuân thủ 100% | `server/src/engine/loader.py` validate YAML bằng Pydantic (rule lỗi bị bỏ qua có log); `generic_rules.py` cài `MatchRule`, `EventCountRule`, `ValueCountRule`, `SequenceRule`; 6 file rule trong `rules/*.yaml` kèm mẫu dương/âm trong `samples/rules/`; hỗ trợ cooldown theo event-time, cap 200 `event_uids`, `allowed_lateness`, reload từ Postgres khi khởi động, và CLI `tools/asp_logtest.py`. |
| **6. Coi log là đầu vào không đáng tin** | Tuân thủ 100% | Parser là hàm thuần, băm/cắt giới hạn độ dài chuỗi trước regex (`MAX_HEADER_INSPECT_BYTES`, `MAX_RULE_REGEX_INPUT_LEN = 4096`) chống ReDoS; giới hạn kích thước batch (500 events / 1 MB -> `413`); kẹp timestamp tương lai (`asp.ts_clamped`); dòng hỏng/rác ghi `unparsed` hoặc `error` không làm chết lô; mọi SQL tham số hóa (`%s`); kiểm tra định dạng IP qua `validate_optional_ip`. |
| **7. AI chỉ đọc & hợp đồng bàn giao Phase 6** | Tuân thủ phạm vi | Giữ nguyên khung `server/src/agent/` (`base.py`, `tools.py`, `workflow.py`), trường tùy chọn trên `Case`, và `POST /api/v1/cases/{id}/investigate` kèm `docs/handover-phase6.md`. |
| **8. Đồng bộ, thư viện cho phép & không hardcode bí mật** | Tuân thủ 100% | API/Service/Repository/Collector dùng `def` đồng bộ, `psycopg` v3 không pool, `requests`, `threading.Lock`, `uvicorn --workers 1`; không dùng `httpx`; `.env.example` và `scripts/demo_attack.py` dùng biến môi trường/CLI, không chứa mật khẩu/IP/key thật. |

---

## 2. Danh sách giới hạn đã biết (đưa vào báo cáo đồ án – Mục 4.4 & Mục 15)

1. **Giới hạn khi tailing & xoay vòng log (`client/collector.py`):**
   - Nếu file log xoay vòng và bị xóa nhanh hơn chu kỳ `poll_interval_seconds` hoặc trong lúc `spool_max_mb` đang đầy và server gián đoạn, dữ liệu chưa kịp đọc có thể bị mất.
   - Với cơ chế `copytruncate`: các byte mới ghi giữa lần poll cuối và thời điểm file bị truncate xuống 0 sẽ mất; phát hiện ghi đè nhanh qua `head_hash` chỉ hoạt động đáng tin cậy khi file đạt tối thiểu `64` byte và có thể trễ tối đa một chu kỳ `poll_interval_seconds`.
2. **Kiến trúc đơn tiến trình (`--workers 1`):**
   - Trạng thái cửa sổ trượt (`InMemorySlidingWindowStore`), danh sách cooldown ngắn hạn và `InMemoryRateLimiter` lưu trong RAM của một tiến trình Uvicorn duy nhất. Nếu chạy `--workers > 1` hoặc nhiều replica server, cửa sổ sự kiện và rate limit sẽ bị tách rời.
3. **Vòng đời đóng `Case` phụ thuộc sự kiện mới:**
   - `Case` hết hạn im lặng (`ASP_CASE_IDLE_TIMEOUT`, mặc định `6h` theo event-time) chỉ được đánh dấu `'closed'` khi có alert tiếp theo của cùng `case_key` được sinh ra; chưa có background reaper tự đóng các case đã nguội hoàn toàn.
4. **Phục hồi trạng thái sau khởi động lại & lỗi Engine sau commit:**
   - Khi khởi động lại, `reload_engine_state` nạp lại các sự kiện trong cửa sổ `[T - (max_timespan + allowed_lateness), T]` ở chế độ `replay_only=True`; các sự kiện đến muộn hơn ngưỡng nạp lại này sau khi restart sẽ không vào lại cửa sổ cũ.
   - Khi `RuleEngine` gặp ngoại lệ sau bước `COMMIT` transaction DB, hệ thống ghi log lỗi và vẫn trả HTTP `202` nhằm tránh agent lặp lại batch vô hạn; khả năng phát hiện cho đúng lô sự kiện đó bị mất (Mục 8.2 / 15).
5. **Chưa phát hiện agent im lặng & chưa tự dọn dữ liệu cũ:**
   - Bảng `agents` đã cập nhật `last_seen`, nhưng chưa cài rule/job cảnh báo khi một agent ngừng gửi heartbeat/log.
   - Toàn bộ bảng `events_raw`, `events`, `alerts`, `cases` chưa phân vùng theo tháng hoặc xóa tự động theo retention policy (Mục 8.4).

---

## 3. Rủi ro bảo mật còn lại (Mục 11 & Mục 15)

1. **Truyền tải HTTP trong môi trường lab:** mặc định `client/config.yaml` chạy `http://127.0.0.1:8000`; triển khai thực tế cần đặt TLS/HTTPS (reverse proxy Nginx/Caddy) và cấu hình `verify_tls: true` / `ca_file` trên agent.
2. **Tách quyền DB (`asp_app` vs `asp_ai_ro`) chưa bật ở Phase 1–5:** theo quyết định tối giản PostgreSQL 17 local (`ASP_DB_URL` duy nhất), kết nối hiện tại dùng chung quyền ứng dụng; khi tích hợp AI Agent thật ở Phase 6 cần tạo role chỉ đọc `asp_ai_ro` theo hướng dẫn SQL trong `docs/handover-phase6.md`.
3. **Giới hạn chi phí & Prompt Injection ở nhánh `investigate`:** `POST /api/v1/cases/{id}/investigate` hiện nối tới `DefaultAgentInvestigator` (chưa có cost ceiling/rate limit riêng cho LLM trả phí) và cần được thành viên Phase 6 bổ sung randomized delimiter quanh dữ liệu log + kiểm tra chéo `evidence_event_uids` với `FakeLLMClient`.
4. **Quản lý bí mật vận hành:** bất kỳ API key hoặc operator token nào từng xuất hiện trên terminal/log/tài liệu phải được xoay hoặc thu hồi ngay bằng `tools/asp_admin.py` (`rotate-agent-key`, `revoke-operator`).

---

## 4. Các phần đã cắt / hoãn so với Mục 13

- **Dashboard giao diện web (UI):** hoãn theo thứ tự ưu tiên Mục 13; toàn bộ dữ liệu đã sẵn sàng qua REST API `/api/v1/alerts`, `/api/v1/events`, `/api/v1/cases`, `/api/v1/cases/{id}`.
- **`audit.log` & parser `auditd` (`/var/log/audit/audit.log`):** hoãn vào phạm vi mở rộng sau Phase 5 (Mục 1.3 & Mục 13).
- **`psycopg[pool]` connection pooling:** chưa đưa vào sử dụng vì chưa có nhu cầu multi-connection concurrent pool ở quy mô lab một worker (Mục 3 & Phụ lục B).
- **Lớp AI Agentic hoàn chỉnh (Phase 6):** tích hợp LLM provider (`ILLMClient`), bổ sung đầy đủ AI read-only tools và workflow kiểm chứng -> bàn giao trọn vẹn tại `docs/handover-phase6.md`.

