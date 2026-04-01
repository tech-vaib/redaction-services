# 🔒 LLM Redaction Service

> Automated PII/PHI redaction pipeline for LLM traffic sampling — designed for Trust & Safety teams, annotation pipelines, and ML engineers.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Entity Coverage](#entity-coverage)
- [Usage](#usage)
  - [Python Library](#python-library)
  - [CLI](#cli)
  - [REST API](#rest-api)
- [Extending Patterns](#extending-patterns)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Compliance Notes](#compliance-notes)

---

## Overview

This service intercepts sampled LLM prompts and responses, detects sensitive data, and replaces it with stable, consistent tokens before the data reaches human annotators.

```
LLM Traffic
    │
    ▼
┌─────────────────────────────────┐
│   Redaction Pipeline (async)    │
│                                 │
│  1. Regex Engine (30+ patterns) │
│  2. spaCy NER (names/orgs/locs) │
│  3. Overlap Resolution          │
│  4. Token Assignment            │
└─────────────┬───────────────────┘
              │
              ▼
    "John called 555-1234"
    → "[PERSON_1] called [PHONE_1]"
              │
              ▼
       Annotation Queue
     (zero raw PII/PHI visible)
```

**Guarantees:**
- ✅ No raw PII/PHI visible to annotators
- ✅ Consistent tokens: same value → same token within a document
- ✅ Structure + semantic meaning preserved
- ✅ GDPR / CCPA / HIPAA Safe Harbor aligned
- ✅ Async, non-blocking — no bottleneck before annotation system

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/yourorg/llm-redaction-service
cd llm-redaction-service

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy NER model (recommended for name/org/location detection)
python -m spacy download en_core_web_sm
# Or for better accuracy:
python -m spacy download en_core_web_lg
```

### 2. Run the demo

```bash
python scripts/redact_cli.py demo
```

Output:
```
══════════════════════════════════════════════════════════════════════
  LLM REDACTION SERVICE — Entity Detection Demo
══════════════════════════════════════════════════════════════════════

  ✓ [Email]
    IN:  Contact John at john.doe@example.com
    OUT: Contact John at [EMAIL_1]
    TAG: EMAIL

  ✓ [SSN]
    IN:  Social Security Number: 456-78-9012
    OUT: Social Security Number: [SSN_1]
    TAG: SSN

  ✓ [Credit Card]
    IN:  Visa ending in 4532-0151-1283-0366
    OUT: Visa ending in [CREDIT_CARD_1]
    TAG: CREDIT_CARD
...
```

### 3. Start the API

```bash
python scripts/redact_cli.py serve
# → http://localhost:8000/docs
```

---

## Architecture

```
redaction-service/
├── redactor/
│   ├── __init__.py          # Public API
│   ├── patterns.py          # 🔑 All detection patterns (add yours here)
│   ├── engine.py            # Redactor class — regex + spaCy + overlap resolution
│   └── pipeline.py          # Async pipeline — batching, concurrency, handlers
├── api/
│   └── server.py            # FastAPI REST endpoints
├── scripts/
│   └── redact_cli.py        # CLI interface
├── tests/
│   ├── test_redactor.py     # Unit tests for all entity types
│   └── test_pipeline.py     # Async pipeline tests
├── config/
│   └── settings.yaml        # Configuration
└── requirements.txt
```

### Detection Pipeline

```
Input text
    │
    ├─► Regex pass (patterns.py)
    │       All PatternDef entries with compiled regex
    │       Runs in O(n × patterns) — very fast
    │
    ├─► spaCy NER pass (if enabled)
    │       Catches names, organizations, locations
    │       not covered by regex heuristics
    │
    ▼
Overlap Resolution
    │   When spans overlap, higher-priority pattern wins
    │   Priority defined per PatternDef (0–10)
    │
    ▼
Token Assignment
    │   [LABEL_N] tokens — consistent within a document
    │   PERSON_1, PERSON_2, EMAIL_1, etc.
    │
    ▼
RedactionResult
    ├── redacted_text   (safe for annotators)
    ├── entities        (metadata: label, position, token)
    └── token_map       (token → original — admin only)
```

---

## Entity Coverage

| Category | Entities Detected |
|----------|-------------------|
| **PII** | Email, Phone (US/Intl), SSN, Full name, Honorific name, Street address, ZIP code, City/State, Passport, Driver's license, ITIN, VIN, License plate, Geo coordinates |
| **PHI** | Date (month+day), Medical record number, NPI, ICD-10 code, Medical conditions (30+), Medications (30+), DEA number, Insurance member ID, Age |
| **FINANCIAL** | Credit card (Visa/MC/Amex/Discover), Bank account/routing, IBAN, EIN, SWIFT/BIC, Crypto wallet (BTC/ETH) |
| **NETWORK** | IPv4, IPv6, MAC address, URL with credentials, Domain |
| **CREDENTIAL** | API key/token, AWS key, Private key (PEM), Password, JWT token |
| **SENSITIVE** | Race/ethnicity, Religion, Sexual orientation, Political affiliation |

**Total: 40+ pattern definitions out of the box.**

---

## Usage

### Python Library

```python
from redactor import Redactor

# Basic usage
r = Redactor()
result = r.redact("Call me at 555-123-4567 or email jane@acme.com")

print(result.redacted_text)
# → "Call me at [PHONE_1] or email [EMAIL_1]"

print(result.entities)
# → [DetectedEntity(label='PHONE', ...), DetectedEntity(label='EMAIL', ...)]

print(result.token_map)
# → {"[PHONE_1]": "555-123-4567", "[EMAIL_1]": "jane@acme.com"}
```

#### Batch redaction

```python
results = r.redact_batch([
    "Patient John Smith, SSN 456-78-9012",
    "Dr. Jane Doe, NPI: 1234567890",
])
for res in results:
    print(res.redacted_text)
```

#### Category filtering

```python
# Only redact financial data
r = Redactor(redact_categories=["FINANCIAL"])

# Skip sensitive categories (race, religion, etc.)
r = Redactor(skip_categories=["SENSITIVE"])

# Combine
r = Redactor(
    redact_categories=["PII", "PHI", "FINANCIAL"],
    skip_categories=["SENSITIVE"],
)
```

#### Consistent tokens (default: on)

```python
r = Redactor(consistent_tokens=True)
result = r.redact("Contact john@x.com — reply to john@x.com")
# → "Contact [EMAIL_1] — reply to [EMAIL_1]"  (same value = same token)
```

### Async Pipeline

```python
import asyncio
from redactor import RedactionPipeline, LLMSample, JSONFileHandler

async def main():
    pipeline = RedactionPipeline(
        concurrency=16,
        output_handlers=[JSONFileHandler("redacted.jsonl")],
    )

    # Process a single sample
    sample = LLMSample(
        sample_id="abc-123",
        prompt="My SSN is 456-78-9012",
        response="Got it, I'll keep your SSN 456-78-9012 safe.",
    )
    result = await pipeline.process(sample)

    print(result.redacted_prompt)    # "My SSN is [SSN_1]"
    print(result.redacted_response)  # "Got it, I'll keep your [SSN_1] safe."

    # Annotator-safe view (no token_map)
    print(result.to_annotator_view())

asyncio.run(main())
```

#### Stream processing (e.g., Kafka integration hook)

```python
import asyncio
from redactor import RedactionPipeline, LLMSample

async def kafka_consumer_loop(pipeline, consumer):
    queue = asyncio.Queue()
    stop = asyncio.Event()

    async def feed():
        async for msg in consumer:
            sample = LLMSample(**msg.value)
            await queue.put(sample)

    await asyncio.gather(
        feed(),
        pipeline.process_stream(queue, stop_event=stop),
    )
```

### CLI

```bash
# Redact a string
python scripts/redact_cli.py text "My SSN is 456-78-9012"

# Redact a JSONL file
python scripts/redact_cli.py file samples.jsonl --output redacted.jsonl

# Only redact PII and PHI
python scripts/redact_cli.py text "..." --categories PII PHI

# List all patterns
python scripts/redact_cli.py patterns

# Run demo
python scripts/redact_cli.py demo
```

### REST API

```bash
# Start server
python scripts/redact_cli.py serve

# Redact text
curl -X POST http://localhost:8000/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient SSN: 123-45-6789, email: bob@clinic.com"}'

# Response:
{
  "request_id": "...",
  "redacted_text": "Patient SSN: [SSN_1], email: [EMAIL_1]",
  "entity_count": 2,
  "categories_found": ["PII"],
  "entities": [
    {"label": "SSN",   "token": "[SSN_1]",   "start": 13, "end": 24},
    {"label": "EMAIL", "token": "[EMAIL_1]", "start": 33, "end": 47}
  ],
  "processing_ms": 1.4
}

# Redact a full LLM sample
curl -X POST http://localhost:8000/redact/sample \
  -H "Content-Type: application/json" \
  -d '{
    "sample_id": "sample-001",
    "prompt": "My name is John Smith, DOB 03/15/1982",
    "response": "Hello John Smith, how can I help?",
    "annotator_view": true
  }'

# List patterns
curl http://localhost:8000/patterns

# Disable a noisy pattern
curl -X POST http://localhost:8000/patterns/PERSON_FULL/disable

# Health check
curl http://localhost:8000/health

# Pipeline stats
curl http://localhost:8000/stats
```

---

## Extending Patterns

All patterns live in **`redactor/patterns.py`**. Adding a new one is 5 lines:

```python
# At the bottom of PATTERN_REGISTRY in patterns.py:

PatternDef(
    name="EMPLOYEE_ID",          # → token becomes [EMPLOYEE_ID_1]
    category="ENTERPRISE",       # your custom category
    priority=9,                  # 0–10, higher wins on overlap
    description="Internal badge IDs formatted EMP-XXXXXX",
    pattern=_re(r"EMP-\d{6}", re.IGNORECASE),
),
```

That's it. The pattern auto-loads everywhere — CLI, API, pipeline, tests.

### Custom callable (for complex logic)

```python
import re

def detect_custom_ids(text):
    """Returns list of match objects or (start, end, value) tuples."""
    results = []
    # Your complex detection logic here
    for m in re.finditer(r"CUST-[A-Z]{2}\d{8}", text):
        results.append(m)
    return results

PatternDef(
    name="CUSTOMER_ID",
    category="ENTERPRISE",
    priority=9,
    description="Custom customer IDs: CUST-XX00000000",
    pattern=detect_custom_ids,   # callable works too
),
```

### Disable a pattern at runtime

```python
from redactor import disable_pattern, enable_pattern

disable_pattern("PERSON_FULL")   # Too many false positives
enable_pattern("PERSON_FULL")    # Re-enable
```

---

## Configuration

Edit `config/settings.yaml` or set environment variables:

```bash
export REDACT_PIPELINE_CONCURRENCY=16
export REDACT_API_PORT=9000
```

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `pipeline.concurrency` | 8 | Parallel redaction workers |
| `pipeline.use_spacy` | true | Enable NER model |
| `pipeline.consistent_tokens` | true | Same value = same token |
| `detection.skip_categories` | [DOMAIN] | Categories to skip |
| `detection.disabled_patterns` | [PERSON_FULL] | Patterns to disable (noisy) |

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# Unit tests only (fast, no spaCy)
pytest tests/test_redactor.py -v

# Async pipeline tests
pytest tests/test_pipeline.py -v

# With coverage
pip install pytest-cov
pytest tests/ --cov=redactor --cov-report=term-missing
```

---

## Compliance Notes

### GDPR / CCPA
- All PII categories covered (names, emails, phones, addresses, IDs)
- Token map (reverse lookup) stored separately from annotator view
- Annotator endpoint (`/redact/sample?annotator_view=true`) never exposes raw values

### HIPAA Safe Harbor (45 CFR §164.514)
- All 18 PHI identifiers covered:
  - Names ✅ Dates (except year) ✅ Phone ✅ Email ✅ SSN ✅
  - Medical record numbers ✅ Health plan IDs ✅ Account numbers ✅
  - Certificates/licenses ✅ VINs ✅ Device identifiers ✅
  - URLs ✅ IP addresses ✅ Biometric data (via NPI/DEA) ✅
  - Geographic data ✅ Age >89 ✅ Diagnosis codes ✅

### Important
> ⚠️ This service is a strong technical control but is not a substitute for legal review. Consult your compliance team before deploying in a regulated environment.

---

## License

Apache 2.0 — free for commercial and open-source use.
