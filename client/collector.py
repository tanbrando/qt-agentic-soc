"""
Log Collector Agent Skeleton.
Tails monitored log files with persistent byte offset tracking and sends batches to the SOC ingest API.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
from uuid import uuid4

# Ensure root workspace is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import yaml
from client.parsers import ClientEdgeParser
from server.src.common.schemas import IngestBatchRequest, LogEventEnvelope, LogType


class FileTailer:
    """Tails a single log file and preserves read position."""

    def __init__(self, file_path: str, log_type: LogType, offset_dir: Path) -> None:
        self.file_path = Path(file_path)
        self.log_type = log_type
        self.offset_file = offset_dir / f"{self.file_path.name}.offset"
        self._current_offset: int = self._load_offset()

    def _load_offset(self) -> int:
        if self.offset_file.exists():
            try:
                return int(self.offset_file.read_text().strip())
            except Exception:
                return 0
        return 0

    def save_offset(self) -> None:
        try:
            self.offset_file.write_text(str(self._current_offset))
        except Exception as e:
            print(f"[Tailer] Failed to write offset file: {e}")

    def read_new_lines(self) -> List[str]:
        if not self.file_path.exists():
            return []

        lines = []
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._current_offset)
                for line in f:
                    stripped = line.strip("\r\n")
                    if stripped:
                        lines.append(stripped)
                self._current_offset = f.tell()
                self.save_offset()
        except Exception as e:
            print(f"[Tailer] Error reading {self.file_path}: {e}")

        return lines


class LogCollector:
    """
    Edge log collection agent.
    Gathers new log lines, applies edge parsing, and sends batches to the ingest server.
    """

    def __init__(self, config_path: str = "client/config.yaml") -> None:
        cfg = self._load_config(config_path)
        self.agent_id: str = cfg.get("agent_id", "agent-default")
        self.hostname: str = cfg.get("hostname", "localhost")
        self.server_url: str = cfg.get("server_url", "http://127.0.0.1:8000")
        self.batch_size: int = cfg.get("batch_size", 50)
        self.flush_interval: int = cfg.get("flush_interval_seconds", 5)

        self.offset_dir = Path(".agent_state")
        self.offset_dir.mkdir(exist_ok=True)

        self.tailers: List[FileTailer] = []
        for item in cfg.get("monitored_files", []):
            lt = LogType(item.get("log_type", "auth"))
            self.tailers.append(FileTailer(item["path"], lt, self.offset_dir))

        self.buffer: List[LogEventEnvelope] = []

    def _load_config(self, path_str: str) -> Dict[str, Any]:
        p = Path(path_str)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def collect_from_tailers(self) -> List[LogEventEnvelope]:
        """Reads latest lines from all monitored files and wraps into LogEventEnvelopes."""
        new_envelopes: List[LogEventEnvelope] = []
        for tailer in self.tailers:
            raw_lines = tailer.read_new_lines()
            for line in raw_lines:
                # Optional client-side edge parse
                edge_fields = {}
                if tailer.log_type == LogType.AUTH:
                    edge_fields = ClientEdgeParser.parse_auth_line_fast(line) or {}

                envelope = LogEventEnvelope(
                    event_id=uuid4(),
                    timestamp=datetime.now(timezone.utc),
                    agent_id=self.agent_id,
                    hostname=self.hostname,
                    log_type=tailer.log_type,
                    source_file=str(tailer.file_path),
                    raw=line,
                    fields=edge_fields,
                )
                new_envelopes.append(envelope)
        return new_envelopes

    async def flush_batch(self, force: bool = False) -> Optional[int]:
        """Flushes buffered envelopes to the server if batch_size is reached or forced."""
        if not self.buffer:
            return 0

        if not force and len(self.buffer) < self.batch_size:
            return 0

        batch_to_send = self.buffer[:self.batch_size]
        self.buffer = self.buffer[self.batch_size:]

        req = IngestBatchRequest(
            agent_id=self.agent_id,
            client_timestamp=datetime.now(timezone.utc),
            batch_size=len(batch_to_send),
            events=batch_to_send,
        )

        try:
            import httpx
            url = f"{self.server_url.rstrip('/')}/api/v1/ingest/logs"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=req.model_dump(mode="json"))
                if res.status_code == 200:
                    print(f"[Collector] Successfully sent batch of {len(batch_to_send)} events.")
                    return len(batch_to_send)
                else:
                    print(f"[Collector] Ingest returned error {res.status_code}: {res.text}")
                    # Requeue on failure
                    self.buffer = batch_to_send + self.buffer
                    return None
        except Exception as e:
            print(f"[Collector] Failed to reach ingest server at {self.server_url}: {e}")
            self.buffer = batch_to_send + self.buffer
            return None

    async def run_loop(self) -> None:
        """Continuous background collection loop."""
        print(f"[Collector] Starting agent {self.agent_id} targeting {self.server_url}...")
        while True:
            new_events = self.collect_from_tailers()
            if new_events:
                self.buffer.extend(new_events)
                await self.flush_batch()

            await asyncio.sleep(self.flush_interval)
            await self.flush_batch(force=True)


if __name__ == "__main__":
    collector = LogCollector()
    asyncio.run(collector.run_loop())

