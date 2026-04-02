"""tests/unit/test_cache.py — TTL cache unit tests."""

from __future__ import annotations

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import pytest
from src.utils.cache import TTLCache


class TestTTLCache:
    def test_set_and_get(self):
        c = TTLCache(max_size=100, ttl_seconds=60)
        c.set("hello world", (), "result_obj")
        assert c.get("hello world", ()) == "result_obj"

    def test_miss_returns_none(self):
        c = TTLCache()
        assert c.get("not here", ()) is None

    def test_ttl_expiry(self):
        c = TTLCache(ttl_seconds=1)
        c.set("expiring", (), "value")
        assert c.get("expiring", ()) == "value"
        time.sleep(1.1)
        assert c.get("expiring", ()) is None

    def test_lru_eviction(self):
        c = TTLCache(max_size=3, ttl_seconds=60)
        c.set("a", (), 1)
        c.set("b", (), 2)
        c.set("c", (), 3)
        # Access a to make it recently used
        c.get("a", ())
        # Add d — should evict b (LRU)
        c.set("d", (), 4)
        assert c.get("a", ()) == 1   # still present
        assert c.get("c", ()) == 3   # still present
        assert c.get("d", ()) == 4   # newly added
        assert c.size <= 3

    def test_different_entity_filters_separate_keys(self):
        c = TTLCache()
        c.set("text", ("EMAIL",), "result_email")
        c.set("text", ("PHONE",), "result_phone")
        assert c.get("text", ("EMAIL",)) == "result_email"
        assert c.get("text", ("PHONE",)) == "result_phone"

    def test_hit_rate_tracking(self):
        c = TTLCache()
        c.set("x", (), "v")
        c.get("x", ())   # hit
        c.get("y", ())   # miss
        stats = c.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5

    def test_clear(self):
        c = TTLCache()
        c.set("a", (), 1)
        c.clear()
        assert c.size == 0
        assert c.get("a", ()) is None

    def test_thread_safety(self):
        import threading
        c = TTLCache(max_size=1000, ttl_seconds=60)
        errors = []

        def writer(n):
            try:
                for i in range(50):
                    c.set(f"key-{n}-{i}", (), f"val-{n}-{i}")
            except Exception as e:
                errors.append(e)

        def reader(n):
            try:
                for i in range(50):
                    c.get(f"key-{n}-{i}", ())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(5)]
        threads += [threading.Thread(target=reader, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == [], f"Thread errors: {errors}"
