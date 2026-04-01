"""tests/test_pipeline.py — Async pipeline tests."""

import asyncio
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from redactor import (
    InMemoryHandler,
    LLMSample,
    Redactor,
    RedactionPipeline,
)


@pytest.fixture
def pipeline():
    handler = InMemoryHandler()
    p = RedactionPipeline(
        redactor=Redactor(use_spacy=False),
        concurrency=4,
        output_handlers=[handler],
    )
    return p, handler


@pytest.mark.asyncio
async def test_single_sample(pipeline):
    p, handler = pipeline
    sample = LLMSample(
        sample_id="test-001",
        prompt="My email is foo@example.com",
        response="Got it, I'll reach out to foo@example.com",
    )
    result = await p.process(sample)
    assert result.sample_id == "test-001"
    assert "foo@example.com" not in result.redacted_prompt
    assert "foo@example.com" not in result.redacted_response
    assert "[EMAIL_1]" in result.redacted_prompt
    assert "[EMAIL_1]" in result.redacted_response  # consistent token


@pytest.mark.asyncio
async def test_batch_processing(pipeline):
    p, handler = pipeline
    samples = [
        LLMSample(sample_id=f"batch-{i}", prompt=f"SSN: {i}23-45-6789")
        for i in range(1, 6)
    ]
    results = await p.process_batch(samples)
    assert len(results) == 5
    for r in results:
        assert "SSN" not in r.redacted_prompt or "[SSN_" in r.redacted_prompt


@pytest.mark.asyncio
async def test_pipeline_stats(pipeline):
    p, _ = pipeline
    sample = LLMSample(sample_id="stat-test", prompt="test@example.com")
    await p.process(sample)
    stats = p.stats
    assert stats["processed"] >= 1
    assert stats["avg_processing_ms"] >= 0


@pytest.mark.asyncio
async def test_annotator_view_no_token_map(pipeline):
    p, _ = pipeline
    sample = LLMSample(
        sample_id="anno-test",
        prompt="Patient John Smith SSN 123-45-6789",
    )
    result = await p.process(sample)
    annotator_view = result.to_annotator_view()
    assert "token_map" not in annotator_view
    assert "sample_id" in annotator_view
    assert "prompt" in annotator_view


@pytest.mark.asyncio
async def test_stream_processing():
    """Test the streaming queue interface."""
    handler = InMemoryHandler()
    p = RedactionPipeline(
        redactor=Redactor(use_spacy=False),
        concurrency=2,
        output_handlers=[handler],
    )
    queue = asyncio.Queue()
    stop = asyncio.Event()

    # Put some items
    for i in range(3):
        await queue.put(LLMSample(sample_id=f"stream-{i}", prompt=f"email{i}@test.com"))

    # Run stream processor briefly
    stop_after = asyncio.create_task(asyncio.sleep(0.5))

    async def runner():
        await p.process_stream(queue, stop_event=stop)

    task = asyncio.create_task(runner())
    await stop_after
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)

    # All items should be processed
    assert queue.empty()
