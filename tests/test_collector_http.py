"""
HTTP delivery tests for P3.3 using stdlib http.server + requests.
Covers: 2xx commit, server down/5xx -> spool -> recovery FIFO order,
401/403 retain in spool without leaking API key in logs,
413 batch splitting, and 422 move to rejected/.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

from client.collector import LogCollector


class _MockIngestServer:
    def __init__(self) -> None:
        self.received_batches: List[Dict[str, Any]] = []
        self.auth_headers: List[str] = []
        self.next_responses: List[Tuple[int, str, Dict[str, str]]] = []
        self.default_status: int = 202
        self._lock = threading.Lock()
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):  # noqa: A002
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                with parent._lock:
                    parent.auth_headers.append(self.headers.get("Authorization", ""))
                    if parent.next_responses:
                        status_code, resp_text, extra_hdrs = parent.next_responses.pop(0)
                    else:
                        status_code, resp_text, extra_hdrs = (
                            parent.default_status,
                            '{"accepted":1,"duplicates":0,"unparsed":0,"parse_errors":0}',
                            {},
                        )
                    if 200 <= status_code < 300:
                        parent.received_batches.append(json.loads(body.decode("utf-8")))

                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                for k, v in extra_hdrs.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_text.encode("utf-8"))

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _write_cfg(tmp_path: Path, log_path: Path, server_url: str, max_events: int = 100) -> Path:
    cfg = [
        "agent_id: web-01",
        f"server_url: {server_url}",
        "ingest_path: /api/v1/ingest/logs",
        "api_key_env: TEST_COLLECTOR_KEY",
        "timezone: Asia/Ho_Chi_Minh",
        "start_position: beginning",
        f"state_file: {tmp_path / 'state.json'}",
        f"spool_dir: {tmp_path / 'spool'}",
        f"batch_max_events: {max_events}",
        "batch_max_seconds: 1",
        "http_timeout_seconds: 2",
        "sources:",
        f"  - path: {log_path}",
        "    log_type: auth",
    ]
    p = tmp_path / "config.yaml"
    p.write_text("\n".join(cfg), encoding="utf-8")
    return p


def test_http_spool_retry_fifo_order_when_server_dies_and_recovers(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TEST_COLLECTOR_KEY", "secret-agent-token-xyz")
    srv = _MockIngestServer()
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"first failed line\n")
    cfg = _write_cfg(tmp_path, log_file, srv.url)

    collector = LogCollector(str(cfg))
    try:
        # 1. Server returns 503 -> batch must be spooled AND offset committed
        srv.next_responses.append((503, '{"detail":"down"}', {}))
        collector.step(force_flush=True, now_mono=100.0)
        assert len(collector.spool.list_pending()) == 1
        assert len(srv.received_batches) == 0
        state1 = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        assert state1["sources"][str(log_file)]["offset"] == len(b"first failed line\n")

        # 2. Append second line while server is recovering; jump now_mono past backoff
        with open(log_file, "ab") as f:
            f.write(b"second line\n")
        collector.step(force_flush=True, now_mono=200.0)

        # Spooled batch MUST be delivered BEFORE the fresh second batch
        assert len(collector.spool.list_pending()) == 0
        assert len(srv.received_batches) == 2
        assert srv.received_batches[0]["events"][0]["message"] == "first failed line"
        assert srv.received_batches[1]["events"][0]["message"] == "second line"
        assert srv.auth_headers[0] == "Bearer secret-agent-token-xyz"
    finally:
        collector.close()
        srv.close()


def test_http_401_retains_spool_and_never_logs_api_key(tmp_path: Path, monkeypatch, caplog):
    secret = "super-secret-do-not-log-123456"
    monkeypatch.setenv("TEST_COLLECTOR_KEY", secret)
    srv = _MockIngestServer()
    srv.next_responses.append((401, '{"detail":"bad key"}', {}))

    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"auth line 1\n")
    cfg = _write_cfg(tmp_path, log_file, srv.url)

    collector = LogCollector(str(cfg))
    try:
        with caplog.at_level(logging.ERROR):
            collector.step(force_flush=True, now_mono=100.0)

        assert len(collector.spool.list_pending()) == 1
        assert "HTTP 401" in caplog.text
        assert secret not in caplog.text
    finally:
        collector.close()
        srv.close()


def test_http_413_splits_batch_and_422_moves_to_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TEST_COLLECTOR_KEY", "test-key")
    srv = _MockIngestServer()
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"line A\nline B\n")
    cfg = _write_cfg(tmp_path, log_file, srv.url)

    collector = LogCollector(str(cfg))
    try:
        # First attempt returns 413 -> splits 2-event batch into two 1-event batches (both succeed with 202)
        srv.next_responses.append((413, '{"detail":"too large"}', {}))
        collector.step(force_flush=True, now_mono=100.0)
        assert len(srv.received_batches) == 2
        assert srv.received_batches[0]["events"][0]["message"] == "line A"
        assert srv.received_batches[1]["events"][0]["message"] == "line B"

        # Next line triggers 422 -> moved into spool/rejected/ without blocking
        with open(log_file, "ab") as f:
            f.write(b"bad schema line\n")
        srv.next_responses.append((422, '{"detail":"invalid schema"}', {}))
        collector.step(force_flush=True, now_mono=105.0)
        rejected = list((tmp_path / "spool" / "rejected").glob("*.rejected.json"))
        assert len(rejected) == 1
        assert len(collector.spool.list_pending()) == 0
    finally:
        collector.close()
        srv.close()



def test_http_strips_key_whitespace_and_redacts_bearer_in_exception_logs(tmp_path: Path, monkeypatch, caplog):
    import requests as req_lib

    secret = "clean-token-secret-789"
    monkeypatch.setenv("TEST_COLLECTOR_KEY", f"{secret}\r\n")
    srv = _MockIngestServer()
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"line crlf key ok\n")
    cfg = _write_cfg(tmp_path, log_file, srv.url)

    collector = LogCollector(str(cfg))
    try:
        collector.step(force_flush=True, now_mono=100.0)
        assert len(srv.received_batches) == 1
        assert srv.auth_headers[0] == f"Bearer {secret}"

        with open(log_file, "ab") as f:
            f.write(b"line forcing exception\n")

        def _boom(*args, **kwargs):
            raise req_lib.exceptions.InvalidHeader(f"Invalid header value 'Bearer {secret}'")

        monkeypatch.setattr(collector._session, "post", _boom)
        with caplog.at_level(logging.WARNING):
            collector.step(force_flush=True, now_mono=200.0)

        assert "Bearer [REDACTED]" in caplog.text
        assert secret not in caplog.text
    finally:
        collector.close()
        srv.close()
