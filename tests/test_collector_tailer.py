"""
Unit tests for P3.1: collector config, timezone detection, (device, inode, stream_id),
start_position, rotation, truncate, head_hash change, incomplete lines, and max_line_bytes.
All tests run safely in tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path

from client.collector import LogCollector


def _write_cfg(tmp_path: Path, log_path: Path, **overrides) -> Path:
    cfg_lines = [
        f"agent_id: {overrides.get('agent_id', 'lab-agent-01')}",
        "server_url: http://127.0.0.1:8000",
        "ingest_path: /api/v1/ingest/logs",
        "api_key_env: TEST_ASP_KEY",
        f"timezone: {overrides.get('timezone', 'Asia/Ho_Chi_Minh')}",
        f"start_position: {overrides.get('start_position', 'beginning')}",
        f"state_file: {tmp_path / 'state.json'}",
        f"spool_dir: {tmp_path / 'spool'}",
        f"max_line_bytes: {overrides.get('max_line_bytes', 16384)}",
        "client_parse: false",
        "sources:",
        f"  - path: {log_path}",
        "    log_type: auth",
    ]
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("\n".join(cfg_lines), encoding="utf-8")
    return cfg_path


def test_collector_config_api_key_from_env_and_auto_timezone(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TEST_ASP_KEY", "dummy-env-token-for-test")
    log_file = tmp_path / "auth.log"
    cfg_path = _write_cfg(tmp_path, log_file, timezone="auto")

    collector = LogCollector(str(cfg_path))
    try:
        assert collector.api_key == "dummy-env-token-for-test"
        assert collector.client_parse is False
        assert len(collector.timezone) >= 3
    finally:
        collector.close()


def test_tailer_start_position_end_skips_history_and_buffers_only_complete_lines(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    initial_bytes = b"historical line 1\nhistorical line 2\n"
    log_file.write_bytes(initial_bytes)
    cfg_path = _write_cfg(tmp_path, log_file, start_position="end")

    collector = LogCollector(str(cfg_path))
    try:
        assert collector.poll_once() == []

        # Append partial line without trailing newline -> must not emit yet
        with open(log_file, "ab") as f:
            f.write(b"partial ")
        assert collector.poll_once() == []

        # Complete the line + add a second complete line
        with open(log_file, "ab") as f:
            f.write(b"completed\nsecond line\n")
        recs = collector.poll_once()
        assert [r.event.message for r in recs] == ["partial completed", "second line"]
        assert recs[0].event.file.offset < recs[1].event.file.offset

        # Offset in state.json has NOT advanced past initial EOF because we haven't committed yet
        state_data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        saved_offset = state_data["sources"][str(log_file)]["offset"]
        assert saved_offset == len(initial_bytes)
    finally:
        collector.close()


def test_tailer_truncate_changes_stream_id_and_resets_offset(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("line one\nline two\n", encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, log_file, start_position="beginning")

    collector = LogCollector(str(cfg_path))
    try:
        recs1 = collector.poll_once()
        assert len(recs1) == 2
        stream1 = recs1[0].event.file.stream_id
        collector.state_store.commit([r.commit_point for r in recs1])

        # Truncate file smaller and write a new line at offset 0
        log_file.write_text("fresh\n", encoding="utf-8")
        recs2 = collector.poll_once()
        assert len(recs2) == 1
        assert recs2[0].event.message == "fresh"
        assert recs2[0].event.file.offset == 0
        assert recs2[0].event.file.stream_id != stream1
    finally:
        collector.close()


def test_tailer_head_hash_detects_fast_overwrite_beyond_old_offset(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    initial_content = ("A" * 80 + "\n")
    log_file.write_text(initial_content, encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, log_file, start_position="beginning")

    collector = LogCollector(str(cfg_path))
    try:
        recs1 = collector.poll_once()
        assert len(recs1) == 1
        stream1 = recs1[0].event.file.stream_id
        collector.state_store.commit([recs1[-1].commit_point])

        # Overwrite same file with DIFFERENT first 64 bytes and LARGER size than old offset
        new_content = ("B" * 80 + "\n") + ("C" * 30 + "\n")
        log_file.write_text(new_content, encoding="utf-8")
        recs2 = collector.poll_once()
        assert len(recs2) == 2
        assert recs2[0].event.file.offset == 0
        assert recs2[0].event.file.stream_id != stream1
        assert recs2[0].event.message == "B" * 80
    finally:
        collector.close()


def test_tailer_rotation_drains_old_file_and_switches_stream(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    rotated_file = tmp_path / "auth.log.1"
    log_file.write_text("before rotation\n", encoding="utf-8")
    cfg_path = _write_cfg(tmp_path, log_file, start_position="beginning")

    collector = LogCollector(str(cfg_path))
    try:
        recs1 = collector.poll_once()
        assert [r.event.message for r in recs1] == ["before rotation"]
        stream1 = recs1[0].event.file.stream_id
        collector.state_store.commit([recs1[-1].commit_point])

        # Append one final partial line and rotate in-process (works on both Windows & POSIX)
        with open(log_file, "ab") as f:
            f.write(b"final line before rotate")
        log_file.rename(rotated_file)
        log_file.write_text("new file line\n", encoding="utf-8")

        recs2 = collector.poll_once()
        assert [r.event.message for r in recs2] == ["final line before rotate", "new file line"]
        assert recs2[0].event.file.stream_id == stream1
        assert recs2[1].event.file.stream_id != stream1
        assert recs2[1].event.file.offset == 0
    finally:
        collector.close()


def test_tailer_max_line_bytes_truncates_and_replaces_bad_utf8(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    with open(log_file, "wb") as f:
        f.write(b"1234567890ABCDEFGHIJ\n")
        f.write(b"bad \xff\xfe utf8\n")
    cfg_path = _write_cfg(tmp_path, log_file, start_position="beginning", max_line_bytes=10)

    collector = LogCollector(str(cfg_path))
    try:
        recs = collector.poll_once()
        assert len(recs) == 2
        assert recs[0].event.message == "1234567890"
        assert recs[0].event.message_truncated is True
        assert recs[1].event.message_truncated is True
        assert "\ufffd" in recs[1].event.message
    finally:
        collector.close()
