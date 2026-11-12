"""
Thin Linux Log Collector Agent (Sections 4.1, 4.2, 4.3, 5).
Tails log files by (device, inode, stream_id, byte offset), tracks head_hash,
supports disk spooling and synchronous `requests` batch delivery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import requests
import yaml

from server.src.common.schemas import (
    AgentMetadata,
    IngestBatchRequest,
    LogType,
    RawEventFileMeta,
    RawLogEvent,
)

HEAD_HASH_BYTES = 64
AGENT_VERSION = "0.1.0"
logger = logging.getLogger(__name__)
_BEARER_RE = re.compile(r"(?i)Bearer\s+\S+")


def _redact_secrets(text: str, secret: Optional[str] = None) -> str:
    cleaned = _BEARER_RE.sub("Bearer [REDACTED]", text)
    if secret:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _ensure_secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def detect_local_iana_timezone() -> str:
    """Best-effort cross-platform detection of local IANA timezone name."""
    tz_env = os.environ.get("TZ")
    if tz_env:
        try:
            ZoneInfo(tz_env)
            return tz_env
        except (ZoneInfoNotFoundError, ValueError):
            pass

    etc_tz = Path("/etc/timezone")
    if etc_tz.exists():
        try:
            name = etc_tz.read_text(encoding="utf-8").strip()
            ZoneInfo(name)
            return name
        except Exception:
            pass

    localtime = Path("/etc/localtime")
    if localtime.is_symlink():
        try:
            target = str(localtime.resolve())
            if "zoneinfo/" in target:
                candidate = target.split("zoneinfo/", 1)[1]
                ZoneInfo(candidate)
                return candidate
        except Exception:
            pass

    local_tz = datetime.now().astimezone().tzinfo
    key = getattr(local_tz, "key", None)
    if key:
        return str(key)

    offset = datetime.now().astimezone().utcoffset()
    if offset is not None and int(offset.total_seconds()) == 7 * 3600:
        return "Asia/Ho_Chi_Minh"
    return "UTC"


def resolve_timezone(configured_tz: str) -> str:
    if not configured_tz or configured_tz == "auto":
        return detect_local_iana_timezone()
    ZoneInfo(configured_tz)
    return configured_tz


def _compute_head_hash(fp: BinaryIO, length: int = HEAD_HASH_BYTES) -> Tuple[int, Optional[str]]:
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    if size < length:
        return 0, None
    fp.seek(0, os.SEEK_SET)
    data = fp.read(length)
    if len(data) < length:
        return 0, None
    return length, hashlib.sha1(data).hexdigest()


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_secure_dir(path.parent)
    tmp_path = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    data = json.dumps(payload, indent=2).encode("utf-8")
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


class SpoolManager:
    """
    Durable disk spool for unsent batches (Section 4.3).
    Writes batches atomically (temp -> fsync -> replace) and reads oldest-first.
    """

    def __init__(self, spool_dir: Path, max_bytes: int = 500 * 1024 * 1024) -> None:
        self.spool_dir = spool_dir
        self.rejected_dir = spool_dir / "rejected"
        self.max_bytes = max(1, max_bytes)
        self._seq = 0
        _ensure_secure_dir(self.spool_dir)

    def list_pending(self) -> List[Path]:
        if not self.spool_dir.exists():
            return []
        files = [
            p
            for p in self.spool_dir.iterdir()
            if p.is_file() and p.suffix == ".json" and not p.name.startswith(".")
        ]
        return sorted(files, key=lambda p: p.name)

    def total_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.list_pending() if p.exists())

    def is_full(self) -> bool:
        return self.total_bytes() >= self.max_bytes

    def enqueue(self, batch_payload: Dict[str, Any]) -> Path:
        self._seq += 1
        ts_ns = time.time_ns()
        batch_id = str(batch_payload.get("batch_id", "batch")).replace("/", "_")
        filename = f"{ts_ns:020d}_{self._seq:06d}_{batch_id}.json"
        dest = self.spool_dir / filename
        _atomic_write_json(dest, batch_payload)
        return dest

    def load_batch(self, spool_path: Path) -> Dict[str, Any]:
        return json.loads(spool_path.read_text(encoding="utf-8"))

    def remove(self, spool_path: Path) -> None:
        if spool_path.exists():
            spool_path.unlink()

    def reject(
        self,
        batch_payload: Dict[str, Any],
        reason: str,
        spool_path: Optional[Path] = None,
    ) -> Path:
        _ensure_secure_dir(self.rejected_dir)
        self._seq += 1
        ts_ns = time.time_ns()
        batch_id = str(batch_payload.get("batch_id", "rejected")).replace("/", "_")
        dest = self.rejected_dir / f"{ts_ns:020d}_{self._seq:06d}_{batch_id}.rejected.json"
        _atomic_write_json(dest, {"reason": reason, "batch": batch_payload})
        if spool_path is not None:
            self.remove(spool_path)
        return dest


@dataclass
class SourceState:
    device: int
    inode: int
    stream_id: str
    offset: int
    head_len: int = 0
    head_hash: Optional[str] = None
    pending_rotated: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device,
            "inode": self.inode,
            "stream_id": self.stream_id,
            "offset": self.offset,
            "head_len": self.head_len,
            "head_hash": self.head_hash,
            "pending_rotated": list(self.pending_rotated),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SourceState:
        return cls(
            device=int(data["device"]),
            inode=int(data["inode"]),
            stream_id=str(data["stream_id"]),
            offset=int(data["offset"]),
            head_len=int(data.get("head_len", 0)),
            head_hash=data.get("head_hash"),
            pending_rotated=list(data.get("pending_rotated", [])),
        )


@dataclass
class CommitPoint:
    path: str
    state: SourceState


@dataclass
class CollectedRecord:
    event: RawLogEvent
    commit_point: CommitPoint


class AgentStateStore:
    """Manages persistent committed positions in state.json (Section 4.2)."""

    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.sources: Dict[str, SourceState] = {}
        self.load()

    def load(self) -> None:
        if not self.state_file.exists():
            self.sources = {}
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.sources = {
                path: SourceState.from_dict(st)
                for path, st in (raw.get("sources") or {}).items()
            }
        except Exception:
            self.sources = {}

    def save(self) -> None:
        payload = {
            "version": 1,
            "sources": {path: st.to_dict() for path, st in self.sources.items()},
        }
        _atomic_write_json(self.state_file, payload)

    def commit(self, commit_points: List[CommitPoint]) -> None:
        if not commit_points:
            return
        for cp in commit_points:
            self.sources[cp.path] = cp.state
        self.save()


class FileTailer:
    """
    Tails a single log source with rotation, truncate, head_hash,
    incomplete trailing line buffering, and max_line_bytes truncation.
    """

    def __init__(
        self,
        file_path: str,
        log_type: LogType,
        state_store: AgentStateStore,
        start_position: str = "end",
        max_line_bytes: int = 16384,
    ) -> None:
        self.file_path = Path(file_path)
        self.path_key = str(file_path)
        self.log_type = log_type
        self.state_store = state_store
        self.start_position = start_position
        self.max_line_bytes = max_line_bytes

        self._fp: Optional[BinaryIO] = None
        self._active_state: Optional[SourceState] = None
        self._read_offset: int = 0

        self._initialize()

    def _new_stream_id(self) -> str:
        return secrets.token_hex(4)

    def _initialize(self) -> None:
        saved = self.state_store.sources.get(self.path_key)
        if saved is not None:
            self._active_state = SourceState.from_dict(saved.to_dict())
            self._read_offset = saved.offset
            # Try opening current inode if it matches saved state
            if self.file_path.exists():
                st = os.stat(self.file_path)
                if (st.st_dev, st.st_ino) == (saved.device, saved.inode):
                    fp = open(self.file_path, "rb")
                    if saved.head_len == 0 and st.st_size >= HEAD_HASH_BYTES:
                        hlen, hhash = _compute_head_hash(fp)
                        self._active_state.head_len = hlen
                        self._active_state.head_hash = hhash
                    if os.name == "posix":
                        self._fp = fp
                    else:
                        fp.close()
            return

        # First run without prior state
        if self.file_path.exists():
            st = os.stat(self.file_path)
            fp = open(self.file_path, "rb")
            hlen, hhash = _compute_head_hash(fp)
            start_off = st.st_size if self.start_position == "end" else 0
            initial = SourceState(
                device=st.st_dev,
                inode=st.st_ino,
                stream_id=self._new_stream_id(),
                offset=start_off,
                head_len=hlen,
                head_hash=hhash,
            )
            if os.name == "posix":
                self._fp = fp
            else:
                fp.close()
            self._active_state = initial
            self._read_offset = start_off
            self.state_store.sources[self.path_key] = SourceState.from_dict(initial.to_dict())
            self.state_store.save()

    def close(self) -> None:
        if self._fp is not None:
            try:
                self._fp.close()
            finally:
                self._fp = None

    def _find_rotated_file_by_inode(self, device: int, inode: int) -> Optional[Path]:
        parent = self.file_path.parent
        if not parent.exists():
            return None
        for entry in parent.iterdir():
            if entry.name.endswith(".gz") or not entry.is_file():
                continue
            try:
                st = os.stat(entry)
                if (st.st_dev, st.st_ino) == (device, inode):
                    return entry
            except OSError:
                continue
        return None

    def _read_lines_from_fp(
        self,
        fp: BinaryIO,
        start_offset: int,
        state_snapshot: SourceState,
        flush_trailing_partial: bool = False,
    ) -> Tuple[List[CollectedRecord], int]:
        fp.seek(0, os.SEEK_END)
        file_size = fp.tell()
        if file_size <= start_offset:
            return [], start_offset

        fp.seek(start_offset, os.SEEK_SET)
        chunk = fp.read(file_size - start_offset)
        if not chunk:
            return [], start_offset

        records: List[CollectedRecord] = []
        cursor = 0
        chunk_len = len(chunk)

        while cursor < chunk_len:
            nl_idx = chunk.find(b"\n", cursor)
            if nl_idx == -1:
                if not flush_trailing_partial:
                    break
                raw_bytes = chunk[cursor:]
                next_offset = start_offset + chunk_len
            else:
                raw_bytes = chunk[cursor:nl_idx]
                next_offset = start_offset + nl_idx + 1

            line_offset = start_offset + cursor
            if raw_bytes.endswith(b"\r"):
                raw_bytes = raw_bytes[:-1]

            truncated = False
            if len(raw_bytes) > self.max_line_bytes:
                raw_bytes = raw_bytes[: self.max_line_bytes]
                truncated = True

            message = raw_bytes.decode("utf-8", errors="replace")
            collected_at = datetime.now(timezone.utc)

            ev = RawLogEvent(
                log_type=self.log_type,
                file=RawEventFileMeta(
                    path=self.path_key,
                    device=state_snapshot.device,
                    inode=state_snapshot.inode,
                    stream_id=state_snapshot.stream_id,
                    offset=line_offset,
                ),
                collected_at=collected_at,
                message=message,
                message_truncated=truncated,
            )

            cp_state = SourceState(
                device=state_snapshot.device,
                inode=state_snapshot.inode,
                stream_id=state_snapshot.stream_id,
                offset=next_offset,
                head_len=state_snapshot.head_len,
                head_hash=state_snapshot.head_hash,
            )
            records.append(CollectedRecord(event=ev, commit_point=CommitPoint(self.path_key, cp_state)))
            cursor = next_offset - start_offset

        return records, start_offset + cursor

    def poll(self) -> List[CollectedRecord]:
        """Reads newly appended complete lines without committing state to disk."""
        if not self.file_path.exists():
            return []

        try:
            st = os.stat(self.file_path)
        except OSError:
            return []

        records: List[CollectedRecord] = []

        # Case A: File appeared for the first time after startup
        if self._active_state is None:
            self._fp = open(self.file_path, "rb")
            hlen, hhash = _compute_head_hash(self._fp)
            self._active_state = SourceState(
                device=st.st_dev,
                inode=st.st_ino,
                stream_id=self._new_stream_id(),
                offset=0,
                head_len=hlen,
                head_hash=hhash,
            )
            self._read_offset = 0

        # Case B: Log rotation detected (device or inode changed)
        elif (st.st_dev, st.st_ino) != (self._active_state.device, self._active_state.inode):
            old_fp = self._fp
            opened_rotated = False
            if old_fp is None:
                rotated_path = self._find_rotated_file_by_inode(
                    self._active_state.device,
                    self._active_state.inode,
                )
                if rotated_path is not None:
                    old_fp = open(rotated_path, "rb")
                    opened_rotated = True

            if old_fp is not None:
                try:
                    tail_records, _ = self._read_lines_from_fp(
                        old_fp,
                        self._read_offset,
                        self._active_state,
                        flush_trailing_partial=True,
                    )
                    records.extend(tail_records)
                finally:
                    if opened_rotated or old_fp is self._fp:
                        old_fp.close()
                self._fp = None

            # Switch to the new file at offset 0 with new stream_id
            self._fp = open(self.file_path, "rb")
            hlen, hhash = _compute_head_hash(self._fp)
            self._active_state = SourceState(
                device=st.st_dev,
                inode=st.st_ino,
                stream_id=self._new_stream_id(),
                offset=0,
                head_len=hlen,
                head_hash=hhash,
            )
            self._read_offset = 0

        else:
            # Same (device, inode): ensure handle open
            if self._fp is None:
                self._fp = open(self.file_path, "rb")

            # Case C: Truncate detected (file shrank below read_offset)
            if st.st_size < self._read_offset:
                hlen, hhash = _compute_head_hash(self._fp)
                self._active_state = SourceState(
                    device=st.st_dev,
                    inode=st.st_ino,
                    stream_id=self._new_stream_id(),
                    offset=0,
                    head_len=hlen,
                    head_hash=hhash,
                )
                self._read_offset = 0
            # Case D: Head hash changed (copytruncate or inode reuse)
            elif self._active_state.head_len > 0 and st.st_size >= self._active_state.head_len:
                cur_len, cur_hash = _compute_head_hash(self._fp, self._active_state.head_len)
                if cur_len == self._active_state.head_len and cur_hash != self._active_state.head_hash:
                    hlen, hhash = _compute_head_hash(self._fp)
                    self._active_state = SourceState(
                        device=st.st_dev,
                        inode=st.st_ino,
                        stream_id=self._new_stream_id(),
                        offset=0,
                        head_len=hlen,
                        head_hash=hhash,
                    )
                    self._read_offset = 0
            elif self._active_state.head_len == 0 and st.st_size >= HEAD_HASH_BYTES:
                hlen, hhash = _compute_head_hash(self._fp)
                self._active_state.head_len = hlen
                self._active_state.head_hash = hhash

        assert self._fp is not None and self._active_state is not None
        new_recs, next_offset = self._read_lines_from_fp(
            self._fp,
            self._read_offset,
            self._active_state,
            flush_trailing_partial=False,
        )
        self._read_offset = next_offset
        records.extend(new_recs)
        if os.name != "posix":
            self.close()
        return records


class LogCollector:
    """
    Thin Linux collector agent holding FileTailers and an in-memory pending queue.
    """

    def __init__(self, config_path: str = "client/config.yaml") -> None:
        cfg = self._load_config(config_path)
        self.agent_id: str = str(cfg.get("agent_id", "web-01"))
        self.hostname: str = str(cfg.get("hostname") or socket.gethostname())
        self.server_url: str = str(cfg.get("server_url", "http://127.0.0.1:8000"))
        self.ingest_path: str = str(cfg.get("ingest_path", "/api/v1/ingest/logs"))
        self.api_key_env: str = str(cfg.get("api_key_env", "ASP_AGENT_API_KEY"))
        raw_env_key = os.environ.get(self.api_key_env)
        self.api_key: Optional[str] = raw_env_key.strip() if raw_env_key else None
        self.verify_tls: bool = bool(cfg.get("verify_tls", True))
        self.ca_file: Optional[str] = cfg.get("ca_file")
        self.timezone: str = resolve_timezone(str(cfg.get("timezone", "auto")))
        self.start_position: str = str(cfg.get("start_position", "end"))
        self.state_file = Path(str(cfg.get("state_file", ".agent_state/state.json")))
        self.spool_dir = Path(str(cfg.get("spool_dir", ".agent_state/spool")))
        self.spool_max_mb: float = float(cfg.get("spool_max_mb", 500))
        spool_max_bytes = int(cfg.get("spool_max_bytes", self.spool_max_mb * 1024 * 1024))
        self.poll_interval_seconds: float = float(cfg.get("poll_interval_seconds", 0.5))
        self.batch_max_events: int = int(cfg.get("batch_max_events", cfg.get("batch_size", 100)))
        self.batch_max_bytes: int = int(cfg.get("batch_max_bytes", 900000))
        self.batch_max_seconds: float = float(
            cfg.get("batch_max_seconds", cfg.get("flush_interval_seconds", 2))
        )
        self.max_line_bytes: int = int(cfg.get("max_line_bytes", 16384))
        self.http_timeout_seconds: float = float(cfg.get("http_timeout_seconds", 10))
        self.client_parse: bool = bool(cfg.get("client_parse", False))

        _ensure_secure_dir(self.state_file.parent)
        self.state_store = AgentStateStore(self.state_file)
        self.spool = SpoolManager(self.spool_dir, max_bytes=spool_max_bytes)
        self.tailers: List[FileTailer] = []
        source_items = cfg.get("sources") or cfg.get("monitored_files") or []
        for item in source_items:
            lt = LogType(item.get("log_type", "auth"))
            self.tailers.append(
                FileTailer(
                    file_path=str(item["path"]),
                    log_type=lt,
                    state_store=self.state_store,
                    start_position=self.start_position,
                    max_line_bytes=self.max_line_bytes,
                )
            )

        self.pending_records: List[CollectedRecord] = []
        self._last_flush_at: float = time.monotonic()
        self._consecutive_failures: int = 0
        self._next_retry_at: float = 0.0
        self._session = requests.Session()

    def _load_config(self, path_str: str) -> Dict[str, Any]:
        p = Path(path_str)
        if p.exists():
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return {}

    def poll_once(self) -> List[CollectedRecord]:
        """Polls all configured sources and buffers newly read lines in RAM.
        Pauses reading if disk spool is full so lines are never dropped or committed prematurely."""
        if self.spool.is_full():
            logger.warning("Spool directory is full; pausing log collection until space frees.")
            return []

        collected: List[CollectedRecord] = []
        for tailer in self.tailers:
            recs = tailer.poll()
            if recs:
                collected.extend(recs)
                self.pending_records.extend(recs)
        return collected

    def build_batch(self, records: List[CollectedRecord]) -> IngestBatchRequest:
        """Wraps collected RawLogEvents into a v1.1 IngestBatchRequest."""
        return IngestBatchRequest(
            schema_version="1.1",
            batch_id=str(uuid4()),
            sent_at=datetime.now(timezone.utc),
            agent=AgentMetadata(
                id=self.agent_id,
                hostname=self.hostname,
                version=AGENT_VERSION,
                ip=[],
                timezone=self.timezone,
            ),
            events=[r.event for r in records],
        )

    def _compute_backoff(self, retry_after_header: Optional[str] = None) -> float:
        base = min(60.0, float(2 ** max(0, self._consecutive_failures - 1)))
        jitter = random.uniform(0.0, base * 0.2)
        delay = min(60.0, base + jitter)
        if retry_after_header:
            try:
                delay = max(delay, float(retry_after_header))
            except ValueError:
                pass
        return delay

    def _post_payload(self, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.server_url.rstrip('/')}/{self.ingest_path.lstrip('/')}"
        headers = {"Content-Type": "application/json"}
        raw_key = os.environ.get(self.api_key_env) or self.api_key
        api_key = raw_key.strip() if raw_key else None
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        verify: Any = self.ca_file if self.ca_file else self.verify_tls
        return self._session.post(
            url,
            json=payload,
            headers=headers,
            timeout=self.http_timeout_seconds,
            verify=verify,
        )

    def _split_payload_halves(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        events = list(payload["events"])
        mid = len(events) // 2
        left = dict(payload, batch_id=str(uuid4()), events=events[:mid])
        right = dict(payload, batch_id=str(uuid4()), events=events[mid:])
        return left, right

    def _send_payload(
        self,
        payload: Dict[str, Any],
        spool_path: Optional[Path] = None,
        commit_points: Optional[List[CommitPoint]] = None,
        now_mono: Optional[float] = None,
    ) -> bool:
        """
        Sends one batch payload per Section 4.3 rules.
        Returns True if batch reached a terminal state (2xx or rejected or split-resolved),
        False if caller should back off and keep retrying.
        """
        cur_mono = now_mono if now_mono is not None else time.monotonic()

        try:
            resp = self._post_payload(payload)
        except requests.RequestException as exc:
            cur_key = (os.environ.get(self.api_key_env) or self.api_key or "").strip() or None
            logger.warning(
                "Network error sending batch %s: %s",
                payload.get("batch_id"),
                _redact_secrets(str(exc), cur_key),
            )
            if spool_path is None:
                self.spool.enqueue(payload)
                if commit_points:
                    self.state_store.commit(commit_points)
            self._consecutive_failures += 1
            self._next_retry_at = cur_mono + self._compute_backoff()
            return False

        code = resp.status_code

        if 200 <= code < 300:
            if spool_path is not None:
                self.spool.remove(spool_path)
            if commit_points:
                self.state_store.commit(commit_points)
            self._consecutive_failures = 0
            self._next_retry_at = 0.0
            return True

        if code == 413:
            events = payload.get("events") or []
            if len(events) <= 1:
                self.spool.reject(payload, "HTTP 413 single event too large", spool_path=spool_path)
                if commit_points:
                    self.state_store.commit(commit_points)
                return True
            left, right = self._split_payload_halves(payload)
            if spool_path is not None:
                # Replace oversized spooled batch with two smaller batches preserving FIFO order
                p_left = self.spool.enqueue(left)
                p_right = self.spool.enqueue(right)
                self.spool.remove(spool_path)
                ok1 = self._send_payload(left, spool_path=p_left, now_mono=cur_mono)
                if not ok1:
                    return False
                return self._send_payload(right, spool_path=p_right, now_mono=cur_mono)

            ok1 = self._send_payload(left, now_mono=cur_mono)
            if not ok1:
                self.spool.enqueue(right)
                if commit_points:
                    self.state_store.commit(commit_points)
                return False
            return self._send_payload(right, commit_points=commit_points, now_mono=cur_mono)

        if code in (400, 422):
            reason = f"HTTP {code}: {resp.text[:300]}"
            logger.error("Permanent client error for batch %s (%s); moving to rejected/", payload.get("batch_id"), code)
            self.spool.reject(payload, reason, spool_path=spool_path)
            if commit_points:
                self.state_store.commit(commit_points)
            self._consecutive_failures = 0
            return True

        if code in (401, 403):
            logger.error(
                "Ingest rejected with HTTP %s (check agent API key or agent.id); retaining batch in spool.",
                code,
            )
            if spool_path is None:
                self.spool.enqueue(payload)
                if commit_points:
                    self.state_store.commit(commit_points)
            self._consecutive_failures += 1
            self._next_retry_at = cur_mono + self._compute_backoff()
            return False

        # 429, 5xx, or unexpected retriable status
        logger.warning("Retriable HTTP %s for batch %s", code, payload.get("batch_id"))
        if spool_path is None:
            self.spool.enqueue(payload)
            if commit_points:
                self.state_store.commit(commit_points)
        self._consecutive_failures += 1
        retry_after = resp.headers.get("Retry-After")
        self._next_retry_at = cur_mono + self._compute_backoff(retry_after)
        return False

    def drain_spool(self, now_mono: Optional[float] = None) -> bool:
        """Sends spooled batches oldest-first. Returns True if all spooled batches cleared."""
        cur_mono = now_mono if now_mono is not None else time.monotonic()
        if cur_mono < self._next_retry_at:
            return False
        for sp_path in self.spool.list_pending():
            payload = self.spool.load_batch(sp_path)
            if not self._send_payload(payload, spool_path=sp_path, now_mono=cur_mono):
                return False
        return True

    def _estimate_pending_bytes(self, count: int) -> int:
        return sum(len(r.event.message.encode("utf-8")) + 200 for r in self.pending_records[:count])

    def flush_pending(self, force: bool = False, now_mono: Optional[float] = None) -> int:
        """Flushes pending RAM records if limits reached or forced. Returns count of events processed."""
        cur_mono = now_mono if now_mono is not None else time.monotonic()
        if cur_mono < self._next_retry_at:
            return 0
        if not self.drain_spool(now_mono=cur_mono):
            return 0
        if not self.pending_records:
            return 0

        sent_events = 0
        while self.pending_records:
            time_due = (cur_mono - self._last_flush_at) >= self.batch_max_seconds
            take_count = min(len(self.pending_records), self.batch_max_events)
            # Shrink slice if estimated byte size exceeds batch_max_bytes
            while take_count > 1 and self._estimate_pending_bytes(take_count) > self.batch_max_bytes:
                take_count = max(1, take_count // 2)

            size_due = (
                len(self.pending_records) >= self.batch_max_events
                or self._estimate_pending_bytes(take_count) >= self.batch_max_bytes
            )
            if not (force or size_due or time_due):
                break

            chunk = self.pending_records[:take_count]
            self.pending_records = self.pending_records[take_count:]
            payload = self.build_batch(chunk).model_dump(mode="json")
            commit_points = [r.commit_point for r in chunk]
            self._last_flush_at = cur_mono
            sent_events += len(chunk)
            if not self._send_payload(payload, commit_points=commit_points, now_mono=cur_mono):
                break

        return sent_events

    def step(self, force_flush: bool = False, now_mono: Optional[float] = None) -> None:
        """One collector iteration: drain spool, poll files, flush batches."""
        cur_mono = now_mono if now_mono is not None else time.monotonic()
        self.drain_spool(now_mono=cur_mono)
        self.poll_once()
        self.flush_pending(force=force_flush, now_mono=cur_mono)

    def run_loop(self, stop_event: Optional[threading.Event] = None) -> None:
        """Continuous synchronous collector loop."""
        logger.info("Starting ASP collector agent_id=%s target=%s", self.agent_id, self.server_url)
        while stop_event is None or not stop_event.is_set():
            self.step(force_flush=False)
            if stop_event is not None:
                if stop_event.wait(self.poll_interval_seconds):
                    break
            else:
                time.sleep(self.poll_interval_seconds)

    def close(self) -> None:
        for t in self.tailers:
            t.close()
        self._session.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ASP thin Linux log collector agent.")
    parser.add_argument(
        "--config",
        default="client/config.yaml",
        help="Path to collector YAML configuration file (default: client/config.yaml).",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    collector = LogCollector(config_path=args.config)
    try:
        collector.run_loop()
    except KeyboardInterrupt:
        pass
    finally:
        collector.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
