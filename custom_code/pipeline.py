"""
pipeline.py — High-throughput async redaction pipeline.

Designed for:
  - LLM traffic sampling interception
  - Async processing (no blocking the annotation queue)
  - Configurable concurrency and batching
  - Optional Kafka / Redis Queue integration hooks
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .engine import Redactor, RedactionResult

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LLMSample:
    """Represents one sampled LLM interaction."""
    sample_id: str
    prompt: str
    response: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class RedactedSample:
    """Redacted version of an LLMSample, safe for annotators."""
    sample_id: str
    redacted_prompt: str
    redacted_response: Optional[str]
    prompt_result: Optional[RedactionResult]
    response_result: Optional[RedactionResult]
    metadata: Dict[str, Any]
    processing_time_ms: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "redacted_prompt": self.redacted_prompt,
            "redacted_response": self.redacted_response,
            "prompt_entities": (
                self.prompt_result.to_dict()["entities"] if self.prompt_result else []
            ),
            "response_entities": (
                self.response_result.to_dict()["entities"] if self.response_result else []
            ),
            "token_maps": {
                "prompt": self.prompt_result.token_map if self.prompt_result else {},
                "response": self.response_result.token_map if self.response_result else {},
            },
            "metadata": self.metadata,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp,
        }

    def to_annotator_view(self) -> dict:
        """Safe view for human annotators — no token_maps exposed."""
        return {
            "sample_id": self.sample_id,
            "prompt": self.redacted_prompt,
            "response": self.redacted_response,
            "metadata": self.metadata,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Async pipeline
# ─────────────────────────────────────────────────────────────────────────────

class RedactionPipeline:
    """
    Async pipeline that:
      1. Accepts LLMSample objects
      2. Runs redaction in a thread pool (CPU-bound)
      3. Calls registered output handlers (e.g. push to queue, write to DB)
    """

    def __init__(
        self,
        redactor: Optional[Redactor] = None,
        concurrency: int = 8,
        output_handlers: Optional[List[Callable]] = None,
    ):
        self.redactor = redactor or Redactor()
        self.concurrency = concurrency
        self.output_handlers = output_handlers or []
        self._semaphore = asyncio.Semaphore(concurrency)
        self._loop = None
        self._executor = None

        # Metrics
        self._processed = 0
        self._errors = 0
        self._total_ms = 0.0

    # ── Public interface ────────────────────────────────────────────────────

    async def process(self, sample: LLMSample) -> RedactedSample:
        """Process a single sample asynchronously."""
        async with self._semaphore:
            return await self._process_one(sample)

    async def process_batch(self, samples: List[LLMSample]) -> List[RedactedSample]:
        """Process a batch of samples concurrently."""
        tasks = [self.process(s) for s in samples]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.error("Sample %s failed: %s", samples[i].sample_id, r)
                self._errors += 1
            else:
                output.append(r)
        return output

    async def process_stream(
        self,
        source: asyncio.Queue,
        stop_event: Optional[asyncio.Event] = None,
    ) -> None:
        """
        Continuously drain a queue of LLMSamples.
        Useful for hooking into Kafka consumer or websocket feed.
        """
        stop_event = stop_event or asyncio.Event()
        while not stop_event.is_set():
            try:
                sample = await asyncio.wait_for(source.get(), timeout=1.0)
                result = await self.process(sample)
                await self._dispatch(result)
                source.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.exception("Stream processing error: %s", exc)
                self._errors += 1

    def add_output_handler(self, handler: Callable) -> None:
        """Register a callback for processed results."""
        self.output_handlers.append(handler)

    @property
    def stats(self) -> dict:
        avg = (self._total_ms / self._processed) if self._processed else 0
        return {
            "processed": self._processed,
            "errors": self._errors,
            "avg_processing_ms": round(avg, 2),
        }

    # ── Internals ────────────────────────────────────────────────────────────

    async def _process_one(self, sample: LLMSample) -> RedactedSample:
        t0 = time.perf_counter()

        # Run CPU-bound redaction in thread pool
        loop = asyncio.get_event_loop()
        prompt_result, response_result = await loop.run_in_executor(
            None, self._redact_sample, sample
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000
        self._processed += 1
        self._total_ms += elapsed_ms

        rs = RedactedSample(
            sample_id=sample.sample_id,
            redacted_prompt=prompt_result.redacted_text,
            redacted_response=(
                response_result.redacted_text if response_result else None
            ),
            prompt_result=prompt_result,
            response_result=response_result,
            metadata=sample.metadata,
            processing_time_ms=round(elapsed_ms, 2),
        )

        logger.debug(
            "Processed %s in %.1fms — %d entities",
            sample.sample_id,
            elapsed_ms,
            (prompt_result.entity_count + (response_result.entity_count if response_result else 0)),
        )

        return rs

    def _redact_sample(
        self, sample: LLMSample
    ) -> tuple[RedactionResult, Optional[RedactionResult]]:
        """Synchronous redaction (runs in thread pool)."""
        # Use a per-sample redactor so tokens are consistent within a sample
        r = Redactor(
            use_spacy=self.redactor.use_spacy,
            consistent_tokens=True,
        )
        prompt_result = r.redact(sample.prompt)
        response_result = (
            r.redact(sample.response) if sample.response else None
        )
        return prompt_result, response_result

    async def _dispatch(self, result: RedactedSample) -> None:
        """Call all registered output handlers."""
        for handler in self.output_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(result)
                else:
                    handler(result)
            except Exception as exc:
                logger.error("Output handler failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Built-in output handlers
# ─────────────────────────────────────────────────────────────────────────────

class JSONFileHandler:
    """Append redacted samples to a JSONL file."""

    def __init__(self, path: str):
        self.path = path

    def __call__(self, result: RedactedSample) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(result.to_dict()) + "\n")


class InMemoryHandler:
    """Collect results in memory (useful for testing / batch jobs)."""

    def __init__(self):
        self.results: List[RedactedSample] = []

    def __call__(self, result: RedactedSample) -> None:
        self.results.append(result)

    def clear(self) -> None:
        self.results.clear()


class PrintHandler:
    """Print redacted text to stdout (debug)."""

    def __call__(self, result: RedactedSample) -> None:
        print(f"\n[{result.sample_id}] {result.processing_time_ms}ms")
        print("PROMPT:", result.redacted_prompt[:120])
        if result.redacted_response:
            print("RESPONSE:", result.redacted_response[:120])
