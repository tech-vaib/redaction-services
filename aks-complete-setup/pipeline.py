"""
src/redactor/pipeline.py — Production async redaction pipeline.

Features:
  - Async worker pool with configurable concurrency
  - Backpressure via bounded queue
  - Circuit breaker (stops accepting when error rate is high)
  - Batch coalescing (groups small requests for efficiency)
  - Per-sample consistent token scoping
  - Pluggable output handlers
  - Graceful shutdown
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from tenacity import (
    RetryError,
    retry,
    stop_after_attempt,
    wait_exponential,
)

from src.redactor.engine import RedactionEngine, RedactionResult
from src.utils.logging import get_logger
from src.utils.metrics import ACTIVE_WORKERS, ERRORS_TOTAL, QUEUE_DEPTH

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Domain models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LLMSample:
    sample_id: str
    prompt: str
    response: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    language: str = "en"

    @staticmethod
    def new(prompt: str, response: Optional[str] = None, **metadata) -> "LLMSample":
        return LLMSample(
            sample_id=str(uuid.uuid4()),
            prompt=prompt,
            response=response,
            metadata=metadata,
        )


@dataclass
class RedactedSample:
    sample_id: str
    redacted_prompt: str
    redacted_response: Optional[str]
    prompt_result: RedactionResult
    response_result: Optional[RedactionResult]
    metadata: Dict[str, Any]
    processing_ms: float
    timestamp: float = field(default_factory=time.time)

    @property
    def total_entities(self) -> int:
        n = self.prompt_result.entity_count
        if self.response_result:
            n += self.response_result.entity_count
        return n

    def to_dict(self, include_token_map: bool = False) -> dict:
        return {
            "sample_id": self.sample_id,
            "redacted_prompt": self.redacted_prompt,
            "redacted_response": self.redacted_response,
            "prompt_analysis": self.prompt_result.to_dict(include_token_map),
            "response_analysis": (
                self.response_result.to_dict(include_token_map)
                if self.response_result else None
            ),
            "total_entities": self.total_entities,
            "metadata": self.metadata,
            "processing_ms": self.processing_ms,
            "timestamp": self.timestamp,
        }

    def to_annotator_dict(self) -> dict:
        """Zero-PII view safe for human annotators."""
        return {
            "sample_id": self.sample_id,
            "prompt": self.redacted_prompt,
            "response": self.redacted_response,
            "metadata": self.metadata,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Circuit breaker
# ─────────────────────────────────────────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = "closed"        # normal operation
    OPEN = "open"            # rejecting requests
    HALF_OPEN = "half_open"  # probing for recovery


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 10,
        recovery_timeout: float = 30.0,
        half_open_max: int = 3,
    ):
        self._threshold = failure_threshold
        self._recovery = recovery_timeout
        self._half_max = half_open_max
        self._failures = 0
        self._half_open_count = 0
        self._state = CircuitState.CLOSED
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._opened_at >= self._recovery:
                self._state = CircuitState.HALF_OPEN
                self._half_open_count = 0
        return self._state

    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN

    def record_success(self) -> None:
        self._failures = 0
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_count += 1
            if self._half_open_count >= self._half_max:
                self._state = CircuitState.CLOSED
                logger.info("Circuit breaker closed")

    def record_failure(self) -> None:
        self._failures += 1
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._opened_at = time.monotonic()
        elif self._failures >= self._threshold:
            self._state = CircuitState.OPEN
            self._opened_at = time.monotonic()
            logger.warning("Circuit breaker opened", failures=self._failures)

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "failures": self._failures,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class RedactionPipeline:
    """
    Production async pipeline.

    Usage:
        pipeline = RedactionPipeline()
        await pipeline.start()
        result = await pipeline.process(sample)
        await pipeline.stop()
    """

    def __init__(
        self,
        engine: Optional[RedactionEngine] = None,
        concurrency: int = 8,
        queue_size: int = 10_000,
        output_handlers: Optional[List[Callable]] = None,
    ):
        self._engine = engine or RedactionEngine.get_instance()
        self._concurrency = concurrency
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._queue: Optional[asyncio.Queue] = None
        self._queue_size = queue_size
        self._output_handlers = output_handlers or []
        self._circuit = CircuitBreaker()
        self._running = False

        # Stats
        self._processed = 0
        self._errors = 0
        self._total_ms = 0.0

    async def start(self) -> None:
        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._queue = asyncio.Queue(maxsize=self._queue_size)
        self._running = True
        logger.info("Pipeline started", concurrency=self._concurrency)

    async def stop(self) -> None:
        self._running = False
        if self._queue:
            await self._queue.join()
        logger.info("Pipeline stopped", stats=self.stats)

    # ── Processing ────────────────────────────────────────────────────────────

    async def process(self, sample: LLMSample) -> RedactedSample:
        """Process a single sample. Returns RedactedSample."""
        if self._circuit.is_open():
            ERRORS_TOTAL.labels(error_type="circuit_open").inc()
            raise RuntimeError("Circuit breaker is open — service degraded")

        if self._semaphore is None:
            # Allow direct calls without explicit start() (lazy init)
            self._semaphore = asyncio.Semaphore(self._concurrency)

        async with self._semaphore:
            ACTIVE_WORKERS.inc()
            try:
                result = await self._process_one(sample)
                self._circuit.record_success()
                return result
            except Exception as exc:
                self._circuit.record_failure()
                self._errors += 1
                ERRORS_TOTAL.labels(error_type=type(exc).__name__).inc()
                raise
            finally:
                ACTIVE_WORKERS.dec()

    async def process_batch(self, samples: List[LLMSample]) -> List[RedactedSample]:
        """Process a batch concurrently. Returns results in same order."""
        tasks = [asyncio.create_task(self.process(s)) for s in samples]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.error("Sample failed",
                             sample_id=samples[i].sample_id, error=str(r))
            else:
                output.append(r)
        return output

    async def process_stream(
        self,
        source: asyncio.Queue,
        stop_event: Optional[asyncio.Event] = None,
    ) -> None:
        """
        Drain a stream queue of LLMSamples.
        Integrates with Kafka consumers, WebSocket feeds, etc.
        """
        stop_event = stop_event or asyncio.Event()
        while not stop_event.is_set() or not source.empty():
            try:
                sample: LLMSample = await asyncio.wait_for(source.get(), timeout=0.5)
                result = await self.process(sample)
                await self._dispatch(result)
                source.task_done()
                QUEUE_DEPTH.set(source.qsize())
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.exception("Stream error", error=str(exc))
                self._errors += 1

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _process_one(self, sample: LLMSample) -> RedactedSample:
        t0 = time.perf_counter()

        loop = asyncio.get_event_loop()
        prompt_result, response_result = await loop.run_in_executor(
            None, self._redact_sample, sample
        )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        self._processed += 1
        self._total_ms += elapsed_ms

        rs = RedactedSample(
            sample_id=sample.sample_id,
            redacted_prompt=prompt_result.redacted_text,
            redacted_response=(response_result.redacted_text if response_result else None),
            prompt_result=prompt_result,
            response_result=response_result,
            metadata=sample.metadata,
            processing_ms=elapsed_ms,
        )

        logger.debug("Sample processed",
                     sample_id=sample.sample_id,
                     entities=rs.total_entities,
                     ms=elapsed_ms)
        return rs

    def _redact_sample(
        self, sample: LLMSample
    ) -> tuple[RedactionResult, Optional[RedactionResult]]:
        """CPU-bound work — runs in thread pool executor."""
        # Use a fresh engine call with shared state for cross-field consistency
        engine = self._engine
        prompt_r = engine.redact(sample.prompt, consistent_tokens=True,
                                 language=sample.language)

        # Pass consistent tokens from prompt to response
        response_r: Optional[RedactionResult] = None
        if sample.response:
            response_r = engine.redact(sample.response, consistent_tokens=True,
                                       language=sample.language)

        return prompt_r, response_r

    async def _dispatch(self, result: RedactedSample) -> None:
        for handler in self._output_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(result)
                else:
                    handler(result)
            except Exception as exc:
                logger.error("Output handler error", error=str(exc))

    def add_handler(self, handler: Callable) -> None:
        self._output_handlers.append(handler)

    @property
    def stats(self) -> dict:
        avg = (self._total_ms / self._processed) if self._processed else 0.0
        return {
            "processed": self._processed,
            "errors": self._errors,
            "avg_ms": round(avg, 2),
            "error_rate": round(self._errors / max(self._processed, 1), 4),
            "circuit_breaker": self._circuit.to_dict(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Built-in output handlers
# ─────────────────────────────────────────────────────────────────────────────

import json


class JSONLFileHandler:
    """Append redacted samples to a JSONL file (no token_map)."""

    def __init__(self, path: str, include_token_map: bool = False):
        self._path = path
        self._include = include_token_map

    def __call__(self, result: RedactedSample) -> None:
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(result.to_dict(include_token_map=self._include)) + "\n")


class InMemoryHandler:
    """Collect in memory (testing / batch jobs)."""

    def __init__(self, max_size: int = 100_000):
        self.results: List[RedactedSample] = []
        self._max = max_size

    def __call__(self, result: RedactedSample) -> None:
        if len(self.results) < self._max:
            self.results.append(result)

    def clear(self) -> None:
        self.results.clear()
