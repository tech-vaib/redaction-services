"""
api/server.py — FastAPI REST service for the redaction pipeline.

Endpoints:
  POST /redact              — Redact a single text string
  POST /redact/batch        — Redact a list of strings
  POST /redact/sample       — Redact a full LLM prompt+response sample
  GET  /health              — Health check
  GET  /stats               — Pipeline processing statistics
  GET  /patterns            — List all registered patterns
  POST /patterns/{name}/disable
  POST /patterns/{name}/enable
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Import our library
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from redactor import (
    InMemoryHandler,
    LLMSample,
    Redactor,
    RedactionPipeline,
    disable_pattern,
    enable_pattern,
    get_enabled_patterns,
    list_categories,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="LLM Redaction Service",
    description="Automated PII/PHI redaction for LLM traffic sampling",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared resources (initialized at startup)
_redactor: Optional[Redactor] = None
_pipeline: Optional[RedactionPipeline] = None
_start_time: float = time.time()


@app.on_event("startup")
async def startup():
    global _redactor, _pipeline
    logger.info("Starting redaction service…")
    _redactor = Redactor(use_spacy=True, consistent_tokens=True)
    _pipeline = RedactionPipeline(redactor=_redactor, concurrency=16)
    logger.info("Service ready. Patterns loaded: %d", len(get_enabled_patterns()))


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response schemas
# ─────────────────────────────────────────────────────────────────────────────

class RedactTextRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text to redact")
    categories: Optional[List[str]] = Field(None, description="Limit to these categories")
    skip_categories: Optional[List[str]] = Field(None, description="Skip these categories")
    include_entities: bool = Field(True, description="Return entity list in response")
    include_token_map: bool = Field(
        False,
        description="Return token→original map (ADMIN only — keep off for annotators)",
    )


class RedactTextResponse(BaseModel):
    request_id: str
    redacted_text: str
    entity_count: int
    categories_found: List[str]
    entities: Optional[List[dict]] = None
    token_map: Optional[Dict[str, str]] = None
    processing_ms: float


class RedactBatchRequest(BaseModel):
    texts: List[str] = Field(..., min_items=1, max_items=500)
    include_token_map: bool = False


class RedactSampleRequest(BaseModel):
    sample_id: Optional[str] = None
    prompt: str
    response: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    annotator_view: bool = Field(
        True,
        description="If true, returns safe view without token_map",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "patterns_loaded": len(get_enabled_patterns()),
    }


@app.get("/stats")
async def stats():
    return {
        "pipeline": _pipeline.stats if _pipeline else {},
        "uptime_seconds": round(time.time() - _start_time, 1),
    }


@app.get("/patterns")
async def list_patterns():
    patterns = get_enabled_patterns()
    return {
        "count": len(patterns),
        "categories": list_categories(),
        "patterns": [
            {
                "name": p.name,
                "category": p.category,
                "priority": p.priority,
                "description": p.description,
                "enabled": p.enabled,
            }
            for p in patterns
        ],
    }


@app.post("/patterns/{name}/disable")
async def disable(name: str):
    disable_pattern(name)
    return {"status": "disabled", "pattern": name}


@app.post("/patterns/{name}/enable")
async def enable(name: str):
    enable_pattern(name)
    return {"status": "enabled", "pattern": name}


@app.post("/redact", response_model=RedactTextResponse)
async def redact_text(req: RedactTextRequest):
    t0 = time.perf_counter()
    request_id = str(uuid.uuid4())

    try:
        r = Redactor(
            use_spacy=True,
            consistent_tokens=True,
            redact_categories=req.categories,
            skip_categories=req.skip_categories,
        )
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, r.redact, req.text)
    except Exception as exc:
        logger.exception("Redaction failed for %s", request_id)
        raise HTTPException(status_code=500, detail=str(exc))

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return RedactTextResponse(
        request_id=request_id,
        redacted_text=result.redacted_text,
        entity_count=result.entity_count,
        categories_found=result.categories_found,
        entities=(
            result.to_dict()["entities"] if req.include_entities else None
        ),
        token_map=result.token_map if req.include_token_map else None,
        processing_ms=round(elapsed_ms, 2),
    )


@app.post("/redact/batch")
async def redact_batch(req: RedactBatchRequest):
    t0 = time.perf_counter()
    samples = [
        LLMSample(sample_id=str(uuid.uuid4()), prompt=t, response=None)
        for t in req.texts
    ]
    results = await _pipeline.process_batch(samples)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    return {
        "count": len(results),
        "processing_ms": round(elapsed_ms, 2),
        "results": [
            {
                "sample_id": r.sample_id,
                "redacted_text": r.redacted_prompt,
                "entity_count": (
                    r.prompt_result.entity_count if r.prompt_result else 0
                ),
                "token_map": r.prompt_result.token_map if req.include_token_map and r.prompt_result else None,
            }
            for r in results
        ],
    }


@app.post("/redact/sample")
async def redact_sample(req: RedactSampleRequest):
    sample = LLMSample(
        sample_id=req.sample_id or str(uuid.uuid4()),
        prompt=req.prompt,
        response=req.response,
        metadata=req.metadata,
    )
    result = await _pipeline.process(sample)

    if req.annotator_view:
        return result.to_annotator_view()
    return result.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )
