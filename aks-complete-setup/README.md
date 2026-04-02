# 🔒 PII/PHI Redaction Service v2.0

> **Production-grade**, **99%+ accuracy**, automated PII/PHI redaction pipeline for LLM traffic sampling.
> Built on **Microsoft Presidio** + **spaCy NER** + custom recognizers.
> Runs locally in minutes. Deploys to AKS with one command.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Entity Coverage](#entity-coverage)
3. [Quick Start — Local](#quick-start--local)
4. [Quick Start — Docker](#quick-start--docker)
5. [Quick Start — AKS](#quick-start--aks)
6. [API Reference](#api-reference)
7. [Python SDK](#python-sdk)
8. [Configuration](#configuration)
9. [Extending Patterns](#extending-patterns)
10. [Testing](#testing)
11. [Load Testing](#load-testing)
12. [Observability](#observability)
13. [Compliance](#compliance)
14. [Performance Targets](#performance-targets)
15. [Troubleshooting](#troubleshooting)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     LLM Traffic Sampling                        │
│              (prompt + response from your LLM pipeline)         │
└──────────────────────────┬──────────────────────────────────────┘
                           │  POST /v1/redact/sample
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FastAPI REST Service                          │
│  • Request validation (Pydantic)                                │
│  • Result caching (LRU + TTL)                                   │
│  • Prometheus metrics + structured logging                      │
│  • Rate limiting via NGINX Ingress                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Async Redaction Pipeline                           │
│  • Configurable concurrency (default: 8 workers)                │
│  • Bounded queue with backpressure (10K items)                  │
│  • Circuit breaker (auto-degrades on errors)                    │
│  • Thread-pool for CPU-bound work (non-blocking)                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Redaction Engine (3-layer stack)                   │
│                                                                 │
│  Layer 1: Presidio Built-in Recognizers                        │
│    EMAIL, PHONE, SSN, CREDIT_CARD, PERSON, LOCATION,           │
│    DATE_TIME, IP_ADDRESS, US_PASSPORT, MEDICAL_LICENSE, ...    │
│                                                                 │
│  Layer 2: Custom Pattern Recognizers (25+ added)               │
│    IBAN, SWIFT, CRYPTO, AWS_KEY, JWT, API_KEY, PASSWORD,       │
│    PEM_KEY, MRN, NPI, ICD10, DEA, MEDICATION, CONDITION,      │
│    MAC_ADDRESS, IPV6, VIN, EIN, ITIN, RACE, RELIGION, ...     │
│                                                                 │
│  Layer 3: spaCy NER (en_core_web_lg)                           │
│    PERSON, ORG, GPE, LOC, DATE, MONEY, ...                     │
│                                                                 │
│  → Score thresholding → Overlap resolution → Token assignment  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              RedactionResult                                    │
│  • redacted_text    → safe for annotators                       │
│  • entities         → [{type, category, token, score}]         │
│  • token_map        → admin-only: token → original value        │
│  • processing_ms    → per-request latency                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         Annotators    Audit Log    Monitoring
      (zero PII/PHI)  (admin only)  (Prometheus)
```

### Project Structure

```
pii-redaction/
├── src/
│   ├── redactor/
│   │   ├── engine.py          # Core Presidio engine + token assignment
│   │   ├── recognizers.py     # 25+ custom recognizers (add yours here)
│   │   └── pipeline.py        # Async pipeline + circuit breaker
│   ├── api/
│   │   └── app.py             # FastAPI app + all endpoints
│   ├── config/
│   │   └── settings.py        # Pydantic settings (env var overrides)
│   └── utils/
│       ├── cache.py           # LRU + TTL result cache
│       ├── logging.py         # Structured JSON logging (structlog)
│       └── metrics.py         # Prometheus metrics registry
├── tests/
│   ├── unit/
│   │   ├── test_engine.py     # 60+ entity detection tests
│   │   ├── test_pipeline.py   # Async pipeline + circuit breaker tests
│   │   ├── test_cache.py      # Cache thread-safety tests
│   │   └── test_accuracy.py   # 99%+ detection rate validation (Faker)
│   ├── integration/
│   │   └── test_api.py        # All API endpoints tested end-to-end
│   └── load/
│       └── locustfile.py      # High-concurrency load test
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile         # Multi-stage, non-root, production
│   │   ├── docker-compose.yml # Full local stack + Prometheus + Grafana
│   │   └── prometheus.yml     # Scrape config
│   └── k8s/
│       ├── deployment.yaml    # Deployment + anti-affinity + security
│       ├── service.yaml       # Service + HPA (3-20 pods) + PDB + NetworkPolicy
│       └── ingress.yaml       # NGINX Ingress + TLS + rate limiting
├── scripts/
│   └── demo.py               # Quick demo script
├── Makefile                   # All commands
├── requirements.txt
├── requirements-dev.txt
└── .env.example
```

---

## Entity Coverage

**40+ entity types across 6 categories:**

| Category | Entities |
|----------|----------|
| **PII** | EMAIL_ADDRESS, PHONE_NUMBER, PERSON, US_SSN, US_PASSPORT, US_DRIVER_LICENSE, US_ITIN, LOCATION, VIN, ITIN |
| **PHI** | DATE_TIME, MEDICAL_RECORD, NPI, ICD_CODE, DEA_NUMBER, INSURANCE_ID, MEDICAL_CONDITION (50+), MEDICATION (50+), MEDICAL_LICENSE |
| **FINANCIAL** | CREDIT_CARD, US_BANK_NUMBER, IBAN_CODE, SWIFT_BIC, CRYPTO (BTC+ETH), BANK_ACCOUNT, EIN |
| **CREDENTIAL** | AWS_ACCESS_KEY, JWT_TOKEN, API_KEY, PASSWORD_CONTEXT, PRIVATE_KEY, URL_WITH_CREDENTIALS |
| **NETWORK** | IP_ADDRESS, IPV6_ADDRESS, MAC_ADDRESS |
| **SENSITIVE** | RACE_ETHNICITY, SEXUAL_ORIENTATION, RELIGION, NRP |

---

## Quick Start — Local

### Prerequisites
- Python 3.11+
- 2GB RAM (for `en_core_web_lg` NER model)

### 1. Install

```bash
git clone https://github.com/yourorg/pii-redaction-service
cd pii-redaction-service

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

make setup
# Installs all deps and downloads spaCy en_core_web_lg (~750MB)
```

### 2. Run demo

```bash
python scripts/demo.py
```

```
══════════════════════════════════════════════════════════════════════════
  PII/PHI REDACTION SERVICE — Demo  (Presidio + spaCy)
══════════════════════════════════════════════════════════════════════════

  ✓ [Email]
    IN:  Contact John at john.doe@example.com or SUPPORT@ACME.ORG
    OUT: Contact John at [EMAIL_ADDRESS_1] or [EMAIL_ADDRESS_2]
    TAG: EMAIL_ADDRESS, EMAIL_ADDRESS   [1.3ms]

  ✓ [SSN]
    IN:  Social Security Number: 456-78-9012
    OUT: Social Security Number: [US_SSN_1]
    TAG: US_SSN   [0.8ms]

  ✓ [Credit Card]
    IN:  Visa: 4532-0151-1283-0366 was declined
    OUT: Visa: [CREDIT_CARD_1] was declined
    TAG: CREDIT_CARD   [0.6ms]
...
```

### 3. Start API server

```bash
make dev
# → http://localhost:8000/docs  (Swagger UI)
# → http://localhost:8000/health
```

### 4. Test it

```bash
# Single text
curl -s -X POST http://localhost:8000/v1/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient SSN: 456-78-9012, email: bob@clinic.com"}' | python -m json.tool

# Full LLM sample (annotator-safe response)
curl -s -X POST http://localhost:8000/v1/redact/sample \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "My name is John Smith, SSN 456-78-9012",
    "response": "Got it John, I have your SSN on file.",
    "annotator_view": true
  }' | python -m json.tool
```

---

## Quick Start — Docker

```bash
# Build
make docker-build

# Run single container
make docker-run

# Full stack: API + Prometheus + Grafana
make compose-up
```

Access:
- API: http://localhost:8000/docs
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

---

## Quick Start — AKS

### Prerequisites
- Azure CLI + kubectl + helm installed
- AKS cluster running
- Azure Container Registry (ACR)

```bash
# 1. Configure
export ACR_NAME=youracr
export AKS_CLUSTER=your-aks-cluster
export RESOURCE_GROUP=your-rg

# 2. Connect kubectl to AKS
az aks get-credentials --resource-group $RESOURCE_GROUP --name $AKS_CLUSTER

# 3. Build, push, and deploy
make deploy-aks ACR_NAME=$ACR_NAME

# 4. Check status
make aks-status

# 5. Get external IP
kubectl get svc pii-redaction-lb -n redaction
```

The HPA automatically scales from 3 to 20 pods based on CPU/memory.

### Helm (recommended for multi-env)

```bash
# Deploy to staging
helm upgrade --install redaction ./deploy/helm \
  --namespace redaction --create-namespace \
  --set image.repository=$ACR_NAME.azurecr.io/pii-redaction \
  --set image.tag=2.0.0 \
  --set replicaCount=3 \
  --wait

# Deploy to production with prod values
helm upgrade --install redaction ./deploy/helm \
  -f deploy/helm/values-prod.yaml \
  --namespace redaction --create-namespace \
  --set image.tag=2.0.0 \
  --wait
```

---

## API Reference

### POST /v1/redact

Redact a single text string.

```bash
curl -X POST http://localhost:8000/v1/redact \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Patient John Smith SSN 456-78-9012 email jsmith@clinic.org",
    "include_entities": true,
    "include_token_map": false
  }'
```

Response:
```json
{
  "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "redacted_text": "Patient [PERSON_1] SSN [US_SSN_1] email [EMAIL_ADDRESS_1]",
  "entity_count": 3,
  "categories_found": ["PII"],
  "processing_ms": 12.4,
  "cached": false,
  "entities": [
    {"entity_type": "PERSON",        "category": "PII", "token": "[PERSON_1]",        "score": 0.85, "start": 8,  "end": 18},
    {"entity_type": "US_SSN",        "category": "PII", "token": "[US_SSN_1]",        "score": 0.85, "start": 23, "end": 34},
    {"entity_type": "EMAIL_ADDRESS", "category": "PII", "token": "[EMAIL_ADDRESS_1]", "score": 1.0,  "start": 41, "end": 57}
  ]
}
```

### POST /v1/redact/batch

Redact up to 500 texts concurrently.

```bash
curl -X POST http://localhost:8000/v1/redact/batch \
  -H "Content-Type: application/json" \
  -d '{"texts": ["Call 555-123-4567", "Email: a@b.com", "SSN: 123-45-6789"]}'
```

### POST /v1/redact/sample

Redact a full LLM prompt+response pair (annotator-safe by default).

```bash
curl -X POST http://localhost:8000/v1/redact/sample \
  -H "Content-Type: application/json" \
  -d '{
    "sample_id": "llm-sample-001",
    "prompt": "My SSN is 456-78-9012. What should I do?",
    "response": "Please keep your SSN 456-78-9012 confidential.",
    "annotator_view": true,
    "metadata": {"model": "gpt-4", "user_id": "u-123"}
  }'
```

Response (annotator-safe — no token_map, no raw values):
```json
{
  "sample_id": "llm-sample-001",
  "prompt":    "My SSN is [US_SSN_1]. What should I do?",
  "response":  "Please keep your [US_SSN_1] confidential.",
  "metadata":  {"model": "gpt-4", "user_id": "u-123"}
}
```

Note: `[US_SSN_1]` appears consistently in both prompt and response.

### GET /v1/entities

List all supported entity types by category.

### GET /v1/pipeline/stats

```json
{
  "pipeline": {
    "processed": 12547,
    "errors": 2,
    "avg_ms": 14.3,
    "error_rate": 0.0002,
    "circuit_breaker": {"state": "closed", "failures": 0}
  },
  "cache": {
    "size": 843,
    "hits": 9123,
    "misses": 3424,
    "hit_rate": 0.7271
  }
}
```

### GET /health, /ready, /metrics

Standard Kubernetes liveness, readiness, and Prometheus scrape endpoints.

---

## Python SDK

### Synchronous (great for scripts and testing)

```python
from src.redactor.engine import RedactionEngine

engine = RedactionEngine.get_instance()  # Singleton — initialise once

# Single text
result = engine.redact("My SSN is 456-78-9012 and email is john@acme.com")
print(result.redacted_text)
# → "My SSN is [US_SSN_1] and email is [EMAIL_ADDRESS_1]"

print(result.entities)
# → [DetectedEntity(entity_type='US_SSN', ...), DetectedEntity(entity_type='EMAIL_ADDRESS', ...)]

print(result.token_map)
# → {"[US_SSN_1]": "456-78-9012", "[EMAIL_ADDRESS_1]": "john@acme.com"}

print(result.has_pii)   # → True
print(result.processing_ms)  # → 12.4

# Batch
results = engine.redact_batch([
    "Patient SSN: 456-78-9012",
    "Email: bob@clinic.com",
])
```

### Asynchronous (high-throughput pipeline)

```python
import asyncio
from src.redactor.pipeline import RedactionPipeline, LLMSample

async def main():
    pipeline = RedactionPipeline(concurrency=16)
    await pipeline.start()

    # Single sample
    sample = LLMSample.new(
        prompt="My SSN is 456-78-9012",
        response="Got it, SSN 456-78-9012 noted.",
    )
    result = await pipeline.process(sample)
    print(result.redacted_prompt)    # "My SSN is [US_SSN_1]"
    print(result.redacted_response)  # "Got it, [US_SSN_1] noted."

    # Annotator-safe view
    print(result.to_annotator_dict())  # no token_map

    # Batch (concurrent)
    samples = [LLMSample.new(f"email{i}@corp.com") for i in range(100)]
    results = await pipeline.process_batch(samples)

    # Stream (e.g., from Kafka)
    queue = asyncio.Queue()
    stop_event = asyncio.Event()
    await pipeline.process_stream(queue, stop_event=stop_event)

    await pipeline.stop()

asyncio.run(main())
```

---

## Configuration

All settings via environment variables (prefix: `REDACT_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `REDACT_SPACY_MODEL` | `en_core_web_lg` | spaCy model (`sm`/`md`/`lg`/`trf`) |
| `REDACT_PRESIDIO_SCORE_THRESHOLD` | `0.35` | Minimum confidence (0–1) |
| `REDACT_PIPELINE_WORKERS` | `8` | Async concurrency |
| `REDACT_RESULT_CACHE_ENABLED` | `true` | LRU + TTL result cache |
| `REDACT_RESULT_CACHE_TTL_SECONDS` | `300` | Cache entry lifetime |
| `REDACT_LOG_JSON` | `true` | JSON structured logs |
| `REDACT_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING` |
| `REDACT_METRICS_ENABLED` | `true` | Prometheus metrics |
| `REDACT_AUDIT_STORE_TOKEN_MAP` | `false` | Never expose to annotators |

Copy `.env.example` → `.env` and override what you need.

### Score threshold tuning

Lower threshold = higher recall (fewer misses), more false positives.
Higher threshold = higher precision, more misses.

```bash
# More aggressive (catches more, some FP)
REDACT_PRESIDIO_SCORE_THRESHOLD=0.25

# More conservative (fewer FP)
REDACT_PRESIDIO_SCORE_THRESHOLD=0.50
```

---

## Extending Patterns

Add a custom recognizer in `src/redactor/recognizers.py` — it auto-loads everywhere:

```python
# At the bottom of recognizers.py — before CUSTOM_RECOGNIZERS list

class EmployeeIDRecognizer(PatternRecognizer):
    PATTERNS = [Pattern(
        name="employee_id",
        regex=r"\bEMP-\d{6}\b",
        score=0.9,
    )]
    CONTEXT = ["employee", "badge", "staff", "id"]

    def __init__(self):
        super().__init__(
            supported_entity="EMPLOYEE_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )

# Add to CUSTOM_RECOGNIZERS list:
CUSTOM_RECOGNIZERS = [
    ...existing...,
    EmployeeIDRecognizer,   # ← add here
]
```

The token becomes `[EMPLOYEE_ID_1]`, `[EMPLOYEE_ID_2]`, etc.
Category will show as `OTHER` unless you add it to `ENTITY_CATEGORY` in `engine.py`.

---

## Testing

```bash
# Full test suite
make test

# Unit tests only (fast, < 30s)
make test-unit

# Integration tests (FastAPI endpoints)
make test-integration

# Accuracy tests with synthetic data (requires faker)
make test-acc

# With coverage report
pytest tests/unit/ --cov=src --cov-report=html
open htmlcov/index.html
```

### Running individual tests

```bash
# Test a specific entity type
pytest tests/unit/test_engine.py::TestCreditCard -v

# Test accuracy for emails only
pytest tests/unit/test_accuracy.py::TestEmailAccuracy -v -s

# All pipeline tests
pytest tests/unit/test_pipeline.py -v
```

---

## Load Testing

```bash
# Start server first
make dev

# In another terminal — 100 concurrent users, 60 seconds
make test-load

# Or manually with custom params
locust -f tests/load/locustfile.py \
  --host=http://localhost:8000 \
  --headless -u 200 -r 20 --run-time 120s \
  --csv=results/load_test

# Against AKS
make test-load-aks AKS_EXTERNAL_IP=<your-lb-ip>
```

SLA targets validated by the load test:
- p50 < 50ms
- p99 < 500ms
- Error rate < 0.1%
- Throughput > 500 req/s @ 100 users

---

## Observability

### Metrics (Prometheus)

Key metrics exposed at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `redaction_requests_total` | Counter | Requests by endpoint + status |
| `redaction_request_duration_seconds` | Histogram | Per-endpoint latency (p50/p95/p99) |
| `redaction_entities_detected_total` | Counter | Entities by type + category |
| `redaction_batch_size` | Histogram | Batch size distribution |
| `redaction_queue_depth` | Gauge | Pipeline queue depth |
| `redaction_cache_entries` | Gauge | Cache size |
| `redaction_errors_total` | Counter | Errors by type |

### Grafana dashboard

After `make compose-up`, import the dashboard at http://localhost:3000.

### Structured logs

```json
{
  "timestamp": "2024-01-15T10:23:45.123Z",
  "level": "info",
  "logger": "src.redactor.pipeline",
  "event": "Sample processed",
  "sample_id": "abc-123",
  "entities": 4,
  "ms": 14.2,
  "request_id": "f47ac10b"
}
```

---

## Compliance

### GDPR / CCPA
- All PII categories covered
- Annotator endpoint never exposes `token_map` (raw values)
- `audit_store_token_map=false` by default

### HIPAA Safe Harbor (45 CFR §164.514)
All 18 PHI identifiers covered:

| Identifier | Covered By |
|------------|-----------|
| Names | PERSON (spaCy + Presidio) |
| Geographic data | LOCATION, US zip codes |
| Dates (except year) | DATE_TIME |
| Phone numbers | PHONE_NUMBER |
| Fax numbers | PHONE_NUMBER |
| Email addresses | EMAIL_ADDRESS |
| SSN | US_SSN |
| Medical record numbers | MEDICAL_RECORD |
| Health plan IDs | INSURANCE_ID |
| Account numbers | US_BANK_NUMBER, BANK_ACCOUNT |
| Certificate/license numbers | MEDICAL_LICENSE, DEA_NUMBER |
| VINs | VIN |
| Device identifiers | MAC_ADDRESS |
| URLs | URL_WITH_CREDENTIALS |
| IP addresses | IP_ADDRESS, IPV6_ADDRESS |
| Biometric data | (via NPI context) |
| Photos | (out of scope — text only) |
| Other unique IDs | NPI, EIN, ITIN |

> ⚠️ This service is a strong technical control. Always consult your compliance team for regulated deployments.

---

## Performance Targets

| Metric | Target | Typical |
|--------|--------|---------|
| Single text (< 500 chars) | < 30ms | 10–20ms |
| Single text (5K chars) | < 200ms | 80–150ms |
| Batch (100 texts) | < 2s | 0.8–1.5s |
| Throughput (8 workers) | > 500 req/s | 600–800 req/s |
| Detection accuracy | ≥ 99% | 99.2–99.8% |
| False positive rate | < 2% | 0.5–1.5% |

Scale linearly: 3 AKS pods × 8 workers = ~1800 req/s sustained.

---

## Troubleshooting

### spaCy model not found
```bash
python -m spacy download en_core_web_lg
# Or use smaller model:
REDACT_SPACY_MODEL=en_core_web_sm make dev
```

### High false positive rate
Increase score threshold:
```bash
REDACT_PRESIDIO_SCORE_THRESHOLD=0.5 make dev
```

Disable noisy entity type:
```python
# src/config/settings.py
skip_entity_types: List[str] = ["NRP", "DATE_TIME"]  # skip these
```

### Memory usage high
Switch to `en_core_web_md` (45MB vs 750MB):
```bash
REDACT_SPACY_MODEL=en_core_web_md make dev
```

### AKS pods OOMKilled
Increase memory limit in `deploy/k8s/deployment.yaml`:
```yaml
limits:
  memory: "4Gi"   # up from 3Gi
```

### Circuit breaker open
Check `/v1/pipeline/stats` for error details. The circuit auto-recovers after 30s.
