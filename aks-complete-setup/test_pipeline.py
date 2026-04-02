"""tests/unit/test_pipeline.py — Async pipeline unit tests."""

from __future__ import annotations

import asyncio
import sys
import os
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from src.redactor.pipeline import (
        CircuitBreaker, CircuitState,
        InMemoryHandler, LLMSample,
        RedactionPipeline,
    )
    from src.redactor.engine import RedactionEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

try:
    from redactor.pipeline import (
        RedactionPipeline as LegacyPipeline,
        LLMSample as LegacySample,
        InMemoryHandler as LegacyHandler,
    )
    LEGACY_AVAILABLE = True
except ImportError:
    LEGACY_AVAILABLE = False

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def pipeline():
    if PRESIDIO_AVAILABLE:
        engine = RedactionEngine.get_instance()
        p = RedactionPipeline(engine=engine, concurrency=4)
    elif LEGACY_AVAILABLE:
        from redactor import Redactor
        r = Redactor(use_spacy=False)
        p = LegacyPipeline(redactor=r, concurrency=4)
    else:
        pytest.skip("No pipeline available")
    await p.start()
    yield p
    await p.stop()


class TestSingleSample:
    async def test_basic_redaction(self, pipeline):
        if PRESIDIO_AVAILABLE:
            sample = LLMSample.new("My email is foo@example.com")
        else:
            sample = LegacySample(sample_id="t1", prompt="My email is foo@example.com")

        result = await pipeline.process(sample)
        assert "foo@example.com" not in result.redacted_prompt

    async def test_prompt_and_response_redacted(self, pipeline):
        if PRESIDIO_AVAILABLE:
            sample = LLMSample.new(
                prompt="My SSN is 456-78-9012",
                response="Got it, SSN 456-78-9012 noted."
            )
        else:
            sample = LegacySample(
                sample_id="t2",
                prompt="My SSN is 456-78-9012",
                response="Got it, SSN 456-78-9012 noted."
            )
        result = await pipeline.process(sample)
        assert "456-78-9012" not in result.redacted_prompt
        assert "456-78-9012" not in (result.redacted_response or "")

    async def test_annotator_view_safe(self, pipeline):
        if PRESIDIO_AVAILABLE:
            sample = LLMSample.new("SSN: 456-78-9012, card 4532015112830366")
        else:
            sample = LegacySample(sample_id="t3", prompt="SSN: 456-78-9012")

        result = await pipeline.process(sample)
        view = result.to_annotator_dict()
        assert "token_map" not in view
        assert "prompt" in view or "redacted_prompt" in view


class TestBatchProcessing:
    async def test_batch_10(self, pipeline):
        if PRESIDIO_AVAILABLE:
            samples = [LLMSample.new(f"Email {i}@test.com, SSN 456-78-{9000+i:04d}")
                       for i in range(10)]
        else:
            samples = [LegacySample(sample_id=f"b{i}", prompt=f"Email {i}@test.com")
                       for i in range(10)]
        results = await pipeline.process_batch(samples)
        assert len(results) == 10

    async def test_batch_concurrent_performance(self, pipeline):
        """100 samples should process in under 30 seconds."""
        if PRESIDIO_AVAILABLE:
            samples = [LLMSample.new(f"test{i}@example.com") for i in range(100)]
        else:
            samples = [LegacySample(sample_id=f"p{i}", prompt=f"test{i}@example.com")
                       for i in range(100)]
        t0 = time.perf_counter()
        results = await pipeline.process_batch(samples)
        elapsed = time.perf_counter() - t0
        assert elapsed < 30.0, f"Batch too slow: {elapsed:.1f}s"
        assert len(results) == 100

    async def test_empty_text_handled(self, pipeline):
        if PRESIDIO_AVAILABLE:
            sample = LLMSample.new("   ")
        else:
            sample = LegacySample(sample_id="empty", prompt="   ")
        result = await pipeline.process(sample)
        assert result is not None


class TestStreamProcessing:
    async def test_stream_drains_queue(self, pipeline):
        queue = asyncio.Queue()
        stop = asyncio.Event()

        count = 5
        if PRESIDIO_AVAILABLE:
            for i in range(count):
                await queue.put(LLMSample.new(f"email{i}@test.com"))
        else:
            for i in range(count):
                await queue.put(LegacySample(sample_id=f"s{i}", prompt=f"email{i}@test.com"))

        task = asyncio.create_task(pipeline.process_stream(queue, stop_event=stop))
        await asyncio.sleep(5.0)
        stop.set()
        await asyncio.wait_for(task, timeout=10.0)
        assert queue.empty()

    async def test_stats_tracked(self, pipeline):
        if PRESIDIO_AVAILABLE:
            await pipeline.process(LLMSample.new("test@example.com"))
        else:
            await pipeline.process(LegacySample(sample_id="stat1", prompt="test@example.com"))

        stats = pipeline.stats
        assert stats["processed"] >= 1
        assert "error_rate" in stats or "errors" in stats


@pytest.mark.skipif(not PRESIDIO_AVAILABLE, reason="Presidio not installed")
class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
        assert not cb.is_open()

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=100.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open()

    def test_success_resets_failures(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(3):
            cb.record_failure()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb.is_open()
        time.sleep(0.05)
        assert cb.state == CircuitState.HALF_OPEN

    def test_closes_after_half_open_successes(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, half_open_max=2)
        cb.record_failure()
        time.sleep(0.05)
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
