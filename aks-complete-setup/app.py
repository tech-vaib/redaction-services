"""
src/api/app.py — Production FastAPI application.

Endpoints:
  POST /v1/redact              — Redact single text (sync + async path)
  POST /v1/redact/batch        — Redact list of texts
  POST /v1/redact/sample       — Redact LLM prompt+response sample
  GET  /v1/entities            — List all supported entity types
  GET  /health                 — Liveness probe
  GET  /ready                  — Readiness probe
  GET  /metrics                — Prometheus metrics
  GET  /docs                   — Swagger UI (disable in prod if needed)
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, field_validator

from src.config.settings import get_settings
from src.redactor.engine import ENTITY_CATEGORY, RedactionEngine
from src.redactor.pipeline import (
    InMemoryHandler,
    LLMSample,
    RedactionPipeline,
    RedactedSample,
)
from src.utils.cache import TTLCache
from src.utils.logging import configure_logging, get_logger
from src.utils.metrics import (
    ERRORS_TOTAL,
    REQUEST_LATENCY,
    REQUESTS_TOTAL,
    BATCH_SIZE,
    CACHE_SIZE,
    init_metrics,
)

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Application lifecycle
# ─────────────────────────────────────────────────────────────────────────────

_engine: Optional[RedactionEngine] = None
_pipeline: Optional[RedactionPipeline] = None
_cache: Optional[TTLCache] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown."""
    global _engine, _pipeline, _cache
    configure_logging()
    settings = get_settings()

    init_metrics(settings.service_name, settings.service_version, settings.environment)

    logger.info("Starting service",
                version=settings.service_version,
                environment=settings.environment)

    _engine = RedactionEngine.get_instance()
    _pipeline = RedactionPipeline(
        engine=_engine,
        concurrency=settings.pipeline_workers,
        queue_size=settings.pipeline_queue_size,
    )
    await _pipeline.start()

    if settings.result_cache_enabled:
        _cache = TTLCache(
            max_size=settings.result_cache_max_size,
            ttl_seconds=settings.result_cache_ttl_seconds,
        )

    logger.info("Service ready")
    yield

    logger.info("Shutting down")
    await _pipeline.stop()


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="PII/PHI Redaction Service",
        description="Production-grade LLM traffic redaction — GDPR/CCPA/HIPAA aligned",
        version=settings.service_version,
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ── Request ID + latency middleware ──────────────────────────────────────
    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        request_id = str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(request_id=request_id)
        t0 = time.perf_counter()
        try:
            response = await call_next(request)
            elapsed = time.perf_counter() - t0
            path = request.url.path
            REQUEST_LATENCY.labels(endpoint=path).observe(elapsed)
            REQUESTS_TOTAL.labels(endpoint=path, status=response.status_code).inc()
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{elapsed:.4f}"
            return response
        finally:
            structlog.contextvars.unbind_contextvars("request_id")

    # ── Routes ───────────────────────────────────────────────────────────────
    app.include_router(health_router)
    app.include_router(redact_router, prefix="/v1")
    app.include_router(meta_router, prefix="/v1")

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Dependency injection
# ─────────────────────────────────────────────────────────────────────────────

def get_engine() -> RedactionEngine:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialised")
    return _engine


def get_pipeline() -> RedactionPipeline:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialised")
    return _pipeline


def get_cache() -> Optional[TTLCache]:
    return _cache


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────

class RedactRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500_000)
    entities: Optional[List[str]] = Field(None, description="Limit to specific entity types")
    language: str = Field("en", pattern=r"^[a-z]{2}$")
    consistent_tokens: bool = True
    include_entities: bool = True
    include_token_map: bool = Field(False, description="Admin only — never for annotators")

    @field_validator("text")
    @classmethod
    def strip_text(cls, v: str) -> str:
        return v.strip()


class RedactResponse(BaseModel):
    request_id: str
    redacted_text: str
    entity_count: int
    categories_found: List[str]
    processing_ms: float
    cached: bool = False
    entities: Optional[List[dict]] = None
    token_map: Optional[Dict[str, str]] = None


class BatchRedactRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=500)
    language: str = "en"
    include_token_map: bool = False


class SampleRedactRequest(BaseModel):
    sample_id: Optional[str] = None
    prompt: str = Field(..., min_length=1, max_length=500_000)
    response: Optional[str] = Field(None, max_length=500_000)
    language: str = "en"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    annotator_view: bool = Field(True, description="Safe view — no token_map")
    include_token_map: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────

from fastapi import APIRouter

health_router = APIRouter(tags=["Health"])
redact_router = APIRouter(tags=["Redaction"])
meta_router = APIRouter(tags=["Metadata"])


# ── Health ────────────────────────────────────────────────────────────────────

@health_router.get("/health")
async def liveness():
    return {"status": "ok", "timestamp": time.time()}


@health_router.get("/ready")
async def readiness(engine: RedactionEngine = Depends(get_engine)):
    return {
        "status": "ready",
        "engine": "ok",
        "timestamp": time.time(),
    }


@health_router.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    if _cache:
        CACHE_SIZE.set(_cache.size)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── Redaction ─────────────────────────────────────────────────────────────────

@redact_router.post("/redact", response_model=RedactResponse)
async def redact_text(
    req: RedactRequest,
    engine: RedactionEngine = Depends(get_engine),
    cache: Optional[TTLCache] = Depends(get_cache),
):
    request_id = str(uuid.uuid4())

    # Cache lookup
    cached_result = None
    cache_key_entities = tuple(req.entities or [])
    if cache:
        cached_result = cache.get(req.text, cache_key_entities)

    if cached_result is not None:
        result = cached_result
        was_cached = True
    else:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: engine.redact(
                    req.text,
                    entities=req.entities,
                    consistent_tokens=req.consistent_tokens,
                    language=req.language,
                ),
            )
        except Exception as exc:
            logger.exception("Redaction error", error=str(exc))
            ERRORS_TOTAL.labels(error_type="redact_error").inc()
            raise HTTPException(status_code=500, detail="Redaction failed")

        if cache:
            cache.set(req.text, cache_key_entities, result)
        was_cached = False

    return RedactResponse(
        request_id=request_id,
        redacted_text=result.redacted_text,
        entity_count=result.entity_count,
        categories_found=result.categories_found,
        processing_ms=result.processing_ms,
        cached=was_cached,
        entities=result.to_dict()["entities"] if req.include_entities else None,
        token_map=result.token_map if req.include_token_map else None,
    )


@redact_router.post("/redact/batch")
async def redact_batch(
    req: BatchRedactRequest,
    pipeline: RedactionPipeline = Depends(get_pipeline),
):
    BATCH_SIZE.observe(len(req.texts))
    t0 = time.perf_counter()

    samples = [
        LLMSample(
            sample_id=str(uuid.uuid4()),
            prompt=text,
            language=req.language,
        )
        for text in req.texts
    ]

    results = await pipeline.process_batch(samples)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "count": len(results),
        "total_processing_ms": elapsed_ms,
        "results": [
            {
                "sample_id": r.sample_id,
                "redacted_text": r.redacted_prompt,
                "entity_count": r.prompt_result.entity_count if r.prompt_result else 0,
                "categories_found": r.prompt_result.categories_found if r.prompt_result else [],
                "token_map": r.prompt_result.token_map if req.include_token_map and r.prompt_result else None,
            }
            for r in results
        ],
    }


@redact_router.post("/redact/sample")
async def redact_sample(
    req: SampleRedactRequest,
    pipeline: RedactionPipeline = Depends(get_pipeline),
):
    sample = LLMSample(
        sample_id=req.sample_id or str(uuid.uuid4()),
        prompt=req.prompt,
        response=req.response,
        metadata=req.metadata,
        language=req.language,
    )

    try:
        result = await pipeline.process(sample)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if req.annotator_view:
        return result.to_annotator_dict()
    return result.to_dict(include_token_map=req.include_token_map)


# ── Metadata ──────────────────────────────────────────────────────────────────

@meta_router.get("/entities")
async def list_entities():
    categories: Dict[str, List[str]] = {}
    for entity, category in ENTITY_CATEGORY.items():
        categories.setdefault(category, []).append(entity)
    return {
        "total": len(ENTITY_CATEGORY),
        "by_category": categories,
    }


@meta_router.get("/pipeline/stats")
async def pipeline_stats(pipeline: RedactionPipeline = Depends(get_pipeline)):
    settings = get_settings()
    return {
        "pipeline": pipeline.stats,
        "cache": _cache.stats if _cache else None,
        "settings": {
            "concurrency": settings.pipeline_workers,
            "spacy_model": settings.spacy_model.value,
            "score_threshold": settings.presidio_score_threshold,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

app = create_app()
