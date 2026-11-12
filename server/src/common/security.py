"""
Security helpers for token hashing and per-agent ingest rate limiting.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict


def hash_secret(raw_token: str) -> str:
    """Computes SHA-256 hex digest of an API key or operator token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_secret_hash(raw_token: str, stored_hash: str) -> bool:
    """Constant-time verification of a raw token against a stored SHA-256 hex digest."""
    return hmac.compare_digest(hash_secret(raw_token), stored_hash)


def generate_token() -> str:
    """Generates a cryptographically random URL-safe token (>= 32 bytes entropy)."""
    return secrets.token_urlsafe(32)


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class InMemoryRateLimiter:
    """
    Thread-safe per-agent token bucket rate limiter (batches per minute).
    """

    def __init__(self, rate_per_minute: int = 120) -> None:
        self.rate_per_minute = max(1, rate_per_minute)
        self._rate_per_second = self.rate_per_minute / 60.0
        self._capacity = float(self.rate_per_minute)
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        """Consumes 1 token for key; returns True if allowed, False if rate limited."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._buckets[key] = _Bucket(tokens=self._capacity - 1.0, last_refill=ts)
                return True

            elapsed = max(0.0, ts - bucket.last_refill)
            bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._rate_per_second)
            bucket.last_refill = ts

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False

