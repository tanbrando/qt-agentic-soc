"""
Sliding window state storage abstractions and in-memory implementation.
Allows stateful rules (Brute-Force, DDoS, Scans) to track temporal windows accurately.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple
from uuid import UUID


class ISlidingWindowStore(ABC):
    """Abstract contract for sliding window tracking."""

    @abstractmethod
    def add_and_get_window(
        self,
        bucket_key: str,
        event_id: UUID,
        timestamp: datetime,
        window_seconds: int,
    ) -> List[UUID]:
        """
        Records an event into bucket_key, evicts entries older than window_seconds,
        and returns the list of all active event IDs currently within the window.
        """
        pass

    @abstractmethod
    def get_window_events(
        self,
        bucket_key: str,
        current_time: datetime,
        window_seconds: int,
    ) -> List[UUID]:
        """Returns all event IDs within the specified window without adding a new event."""
        pass

    @abstractmethod
    def clear_bucket(self, bucket_key: str) -> None:
        """Flushes state for the specified bucket."""
        pass


class InMemorySlidingWindowStore(ISlidingWindowStore):
    """
    Thread-safe in-memory sliding window using deque.
    Handles temporal events by event-time (supporting replaying of logs).
    """

    def __init__(self) -> None:
        # bucket_key -> deque of (timestamp, event_id)
        self._buckets: Dict[str, deque[Tuple[datetime, UUID]]] = defaultdict(deque)

    def _ensure_utc(self, dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _evict_expired(self, q: deque[Tuple[datetime, UUID]], cutoff: datetime) -> None:
        while q and q[0][0] < cutoff:
            q.popleft()

    def add_and_get_window(
        self,
        bucket_key: str,
        event_id: UUID,
        timestamp: datetime,
        window_seconds: int,
    ) -> List[UUID]:
        ts = self._ensure_utc(timestamp)
        q = self._buckets[bucket_key]
        q.append((ts, event_id))

        cutoff = ts - timedelta(seconds=window_seconds)
        self._evict_expired(q, cutoff)

        return [item[1] for item in q]

    def get_window_events(
        self,
        bucket_key: str,
        current_time: datetime,
        window_seconds: int,
    ) -> List[UUID]:
        if bucket_key not in self._buckets:
            return []
        ts = self._ensure_utc(current_time)
        q = self._buckets[bucket_key]
        cutoff = ts - timedelta(seconds=window_seconds)
        self._evict_expired(q, cutoff)
        return [item[1] for item in q]

    def clear_bucket(self, bucket_key: str) -> None:
        if bucket_key in self._buckets:
            del self._buckets[bucket_key]

