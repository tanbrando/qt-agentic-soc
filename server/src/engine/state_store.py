"""
Sliding window state storage abstractions and in-memory implementation.
Supports event-time sliding windows, out-of-order insertion, allowed_lateness,
cooldown tracking, and bounded RAM usage (max_window_events, LRU max_keys).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class WindowEntry:
    timestamp: datetime
    event_id: str
    value: Optional[str] = None


@dataclass(frozen=True)
class WindowResult:
    entries: List[WindowEntry]
    max_timestamp: datetime
    is_late: bool


class ISlidingWindowStore(ABC):
    """Abstract contract for sliding window tracking."""

    @abstractmethod
    def add_and_get_window(
        self,
        bucket_key: str,
        event_id: str,
        timestamp: datetime,
        window_seconds: int,
    ) -> List[str]:
        """Records an event and returns active event IDs currently within the window."""
        pass

    @abstractmethod
    def add_entry_and_get_window(
        self,
        bucket_key: str,
        event_id: str,
        timestamp: datetime,
        window_seconds: int,
        value: Optional[str] = None,
        allowed_lateness_seconds: int = 60,
    ) -> WindowResult:
        """
        Records an entry (with optional distinct-count value), maintains event-time order,
        evicts entries older than window_seconds from the bucket's max timestamp,
        and reports whether the event arrived later than `allowed_lateness_seconds`.
        """
        pass

    @abstractmethod
    def get_window_events(
        self,
        bucket_key: str,
        current_time: datetime,
        window_seconds: int,
    ) -> List[str]:
        """Returns all event IDs within the specified window without adding a new event."""
        pass

    @abstractmethod
    def get_window_entries(
        self,
        bucket_key: str,
        current_time: datetime,
        window_seconds: int,
    ) -> List[WindowEntry]:
        """Returns all WindowEntry items within the window without adding a new event."""
        pass

    @abstractmethod
    def clear_bucket(self, bucket_key: str) -> None:
        """Flushes state for the specified bucket."""
        pass

    @abstractmethod
    def is_in_cooldown(self, cooldown_key: str, event_ts: datetime, cooldown_seconds: int) -> bool:
        """Checks whether an alert bucket is currently within cooldown for event_ts."""
        pass

    @abstractmethod
    def record_cooldown(self, cooldown_key: str, event_ts: datetime, cooldown_seconds: int) -> None:
        """Records that an alert fired for cooldown_key at event_ts."""
        pass

    @abstractmethod
    def record_cooldown_slot(self, cooldown_key: str, slot: int) -> None:
        """Records that an alert fired for an explicit cooldown slot integer."""
        pass


class InMemorySlidingWindowStore(ISlidingWindowStore):
    """
    Bounded in-memory sliding window using OrderedDict (LRU keys) and deque (maxlen).
    Handles out-of-order events by event-time (supporting log replay and server reload).
    """

    def __init__(
        self,
        max_window_events: int = 10_000,
        max_keys: int = 100_000,
    ) -> None:
        self.max_window_events = max(1, max_window_events)
        self.max_keys = max(1, max_keys)
        self._buckets: OrderedDict[str, Deque[WindowEntry]] = OrderedDict()
        self._max_ts: Dict[str, datetime] = {}
        self._cooldowns: OrderedDict[str, int] = OrderedDict()

    def _ensure_utc(self, dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _evict_expired(self, q: Deque[WindowEntry], cutoff: datetime) -> None:
        while q and q[0].timestamp <= cutoff:
            q.popleft()

    def _touch_bucket(self, bucket_key: str) -> Deque[WindowEntry]:
        if bucket_key in self._buckets:
            self._buckets.move_to_end(bucket_key)
            return self._buckets[bucket_key]
        while len(self._buckets) >= self.max_keys:
            evicted_key, _ = self._buckets.popitem(last=False)
            self._max_ts.pop(evicted_key, None)
        q: Deque[WindowEntry] = deque(maxlen=self.max_window_events)
        self._buckets[bucket_key] = q
        return q

    def _insert_sorted(self, q: Deque[WindowEntry], entry: WindowEntry) -> None:
        if not q or entry.timestamp >= q[-1].timestamp:
            q.append(entry)
            return
        # Out-of-order insert preserving ascending timestamp order
        items = list(q)
        inserted = False
        for idx, existing in enumerate(items):
            if entry.timestamp < existing.timestamp:
                items.insert(idx, entry)
                inserted = True
                break
        if not inserted:
            items.append(entry)
        q.clear()
        for item in items[-self.max_window_events :]:
            q.append(item)

    def add_entry_and_get_window(
        self,
        bucket_key: str,
        event_id: str,
        timestamp: datetime,
        window_seconds: int,
        value: Optional[str] = None,
        allowed_lateness_seconds: int = 60,
    ) -> WindowResult:
        ts = self._ensure_utc(timestamp)
        q = self._touch_bucket(bucket_key)

        prev_max = self._max_ts.get(bucket_key)
        is_late = False
        if prev_max is not None and ts < prev_max - timedelta(seconds=allowed_lateness_seconds):
            is_late = True

        max_ts = ts if (prev_max is None or ts > prev_max) else prev_max
        self._max_ts[bucket_key] = max_ts

        self._insert_sorted(q, WindowEntry(timestamp=ts, event_id=event_id, value=value))
        cutoff = max_ts - timedelta(seconds=window_seconds)
        self._evict_expired(q, cutoff)

        return WindowResult(entries=list(q), max_timestamp=max_ts, is_late=is_late)

    def add_and_get_window(
        self,
        bucket_key: str,
        event_id: str,
        timestamp: datetime,
        window_seconds: int,
    ) -> List[str]:
        res = self.add_entry_and_get_window(
            bucket_key=bucket_key,
            event_id=event_id,
            timestamp=timestamp,
            window_seconds=window_seconds,
        )
        return [item.event_id for item in res.entries]

    def get_window_entries(
        self,
        bucket_key: str,
        current_time: datetime,
        window_seconds: int,
    ) -> List[WindowEntry]:
        q = self._buckets.get(bucket_key)
        if q is None:
            return []
        ts = self._ensure_utc(current_time)
        max_ts = max(ts, self._max_ts.get(bucket_key, ts))
        cutoff = max_ts - timedelta(seconds=window_seconds)
        self._evict_expired(q, cutoff)
        return list(q)

    def get_window_events(
        self,
        bucket_key: str,
        current_time: datetime,
        window_seconds: int,
    ) -> List[str]:
        return [e.event_id for e in self.get_window_entries(bucket_key, current_time, window_seconds)]

    def clear_bucket(self, bucket_key: str) -> None:
        self._buckets.pop(bucket_key, None)
        self._max_ts.pop(bucket_key, None)

    def key_count(self) -> int:
        return len(self._buckets)

    def _cooldown_slot(self, event_ts: datetime, cooldown_seconds: int) -> int:
        epoch = int(self._ensure_utc(event_ts).timestamp())
        return epoch // cooldown_seconds

    def is_in_cooldown(self, cooldown_key: str, event_ts: datetime, cooldown_seconds: int) -> bool:
        if cooldown_seconds <= 0:
            return False
        slot = self._cooldown_slot(event_ts, cooldown_seconds)
        last_slot = self._cooldowns.get(cooldown_key)
        if last_slot is not None:
            self._cooldowns.move_to_end(cooldown_key)
            return last_slot >= slot
        return False

    def record_cooldown(self, cooldown_key: str, event_ts: datetime, cooldown_seconds: int) -> None:
        if cooldown_seconds <= 0:
            return
        slot = self._cooldown_slot(event_ts, cooldown_seconds)
        self.record_cooldown_slot(cooldown_key, slot)

    def record_cooldown_slot(self, cooldown_key: str, slot: int) -> None:
        if cooldown_key in self._cooldowns:
            self._cooldowns.move_to_end(cooldown_key)
            if slot > self._cooldowns[cooldown_key]:
                self._cooldowns[cooldown_key] = slot
            return
        while len(self._cooldowns) >= self.max_keys:
            self._cooldowns.popitem(last=False)
        self._cooldowns[cooldown_key] = slot
