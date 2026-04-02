"""src/utils/cache.py — Thread-safe LRU cache with TTL for redaction results."""
from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from threading import RLock
from typing import Optional


class TTLCache:
    """
    Thread-safe LRU cache with per-entry TTL.
    Used to avoid re-processing identical texts in high-traffic scenarios.
    """

    def __init__(self, max_size: int = 10_000, ttl_seconds: int = 300):
        self._max = max_size
        self._ttl = ttl_seconds
        self._store: OrderedDict[str, tuple[object, float]] = OrderedDict()
        self._lock = RLock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(text: str, entities: tuple[str, ...]) -> str:
        raw = f"{text}::{','.join(sorted(entities))}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, text: str, entities: tuple[str, ...] = ()) -> Optional[object]:
        key = self._key(text, entities)
        with self._lock:
            if key not in self._store:
                self._misses += 1
                return None
            value, expiry = self._store[key]
            if time.monotonic() > expiry:
                del self._store[key]
                self._misses += 1
                return None
            # Move to end (LRU)
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set(self, text: str, entities: tuple[str, ...], value: object) -> None:
        key = self._key(text, entities)
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.monotonic() + self._ttl)
            if len(self._store) > self._max:
                self._store.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size": self.size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 4) if total else 0.0,
        }
