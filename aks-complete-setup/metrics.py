"""src/utils/metrics.py — Prometheus metrics."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# ── Counters ────────────────────────────────────────────────────────────────
REQUESTS_TOTAL = Counter(
    "redaction_requests_total",
    "Total redaction requests",
    ["endpoint", "status"],
)

ENTITIES_DETECTED_TOTAL = Counter(
    "redaction_entities_detected_total",
    "Total entities detected by type",
    ["entity_type", "category"],
)

ERRORS_TOTAL = Counter(
    "redaction_errors_total",
    "Total errors",
    ["error_type"],
)

# ── Histograms ───────────────────────────────────────────────────────────────
REQUEST_LATENCY = Histogram(
    "redaction_request_duration_seconds",
    "Request duration",
    ["endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

BATCH_SIZE = Histogram(
    "redaction_batch_size",
    "Batch size distribution",
    buckets=(1, 5, 10, 25, 50, 100, 250, 500),
)

TEXT_LENGTH = Histogram(
    "redaction_text_length_chars",
    "Input text length",
    buckets=(100, 500, 1000, 5000, 10000, 50000),
)

# ── Gauges ───────────────────────────────────────────────────────────────────
QUEUE_DEPTH = Gauge(
    "redaction_queue_depth",
    "Current async pipeline queue depth",
)

ACTIVE_WORKERS = Gauge(
    "redaction_active_workers",
    "Currently active pipeline workers",
)

CACHE_SIZE = Gauge(
    "redaction_cache_entries",
    "Current result cache size",
)

# ── Info ─────────────────────────────────────────────────────────────────────
SERVICE_INFO = Info(
    "redaction_service",
    "Service metadata",
)


def init_metrics(service_name: str, version: str, environment: str) -> None:
    SERVICE_INFO.info({
        "service_name": service_name,
        "version": version,
        "environment": environment,
    })
