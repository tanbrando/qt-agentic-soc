"""
Unit tests for P3.2: disk spool durability, atomic state writes, FIFO order,
spool_max_mb pause behavior, and crash recovery between spool and state commit.
"""

from __future__ import annotations

import json
from pathlib import Path

from client.collector import LogCollector


def _write_cfg(tmp_path: Path, log_path: Path, spool_max_bytes: int = 10_000_000) -> Path:
    cfg = [
        "agent_id: spool-agent",
        "server_url: http://127.0.0.1:8000",
        "timezone: Asia/Ho_Chi_Minh",
        "start_position: beginning",
        f"state_file: {tmp_path / 'state' / 'state.json'}",
        f"spool_dir: {tmp_path / 'spool'}",
        f"spool_max_bytes: {spool_max_bytes}",
        "sources:",
        f"  - path: {log_path}",
        "    log_type: auth",
    ]
    p = tmp_path / "config.yaml"
    p.write_text("\n".join(cfg), encoding="utf-8")
    return p


def test_spool_fifo_ordering_and_no_leftover_tmp_files(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"line1\nline2\n")
    cfg = _write_cfg(tmp_path, log_file)
    collector = LogCollector(str(cfg))
    try:
        recs = collector.poll_once()
        b1 = collector.build_batch([recs[0]]).model_dump(mode="json")
        b2 = collector.build_batch([recs[1]]).model_dump(mode="json")
        p1 = collector.spool.enqueue(b1)
        p2 = collector.spool.enqueue(b2)

        pending = collector.spool.list_pending()
        assert pending == [p1, p2]
        assert not any(p.name.endswith(".tmp") for p in collector.spool_dir.iterdir())
        assert collector.spool.load_batch(pending[0])["batch_id"] == b1["batch_id"]
        assert collector.spool.load_batch(pending[1])["batch_id"] == b2["batch_id"]
    finally:
        collector.close()


def test_spool_full_pauses_collection_without_advancing_offset(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"first line\n")
    cfg = _write_cfg(tmp_path, log_file, spool_max_bytes=50)
    collector = LogCollector(str(cfg))
    try:
        recs = collector.poll_once()
        assert len(recs) == 1
        batch_dict = collector.build_batch(recs).model_dump(mode="json")
        sp_path = collector.spool.enqueue(batch_dict)
        collector.state_store.commit([recs[0].commit_point])
        assert collector.spool.is_full() is True

        # Append a new line while spool is full -> poll_once must pause and NOT lose or commit it
        with open(log_file, "ab") as f:
            f.write(b"second line while full\n")
        assert collector.poll_once() == []

        # Drain spool -> collector resumes reading exact next line
        collector.spool.remove(sp_path)
        assert collector.spool.is_full() is False
        resumed = collector.poll_once()
        assert [r.event.message for r in resumed] == ["second line while full"]
    finally:
        collector.close()


def test_crash_between_spool_write_and_state_commit_loses_zero_lines(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(b"important log line\n")
    cfg = _write_cfg(tmp_path, log_file)

    c1 = LogCollector(str(cfg))
    try:
        recs = c1.poll_once()
        assert len(recs) == 1
        sp = c1.spool.enqueue(c1.build_batch(recs).model_dump(mode="json"))
        assert sp.exists()
        # Simulate crash BEFORE calling state_store.commit(...)
    finally:
        c1.close()

    # After restart, state.json still does not have the committed offset -> re-reads safely (same event.id)
    c2 = LogCollector(str(cfg))
    try:
        reread = c2.poll_once()
        assert [r.event.message for r in reread] == ["important log line"]
        assert reread[0].event.file.offset == 0
        # Verify state_file json structure
        state_json = json.loads((tmp_path / "state" / "state.json").read_text(encoding="utf-8"))
        assert state_json["version"] == 1
    finally:
        c2.close()

