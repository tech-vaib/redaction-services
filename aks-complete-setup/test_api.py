"""
tests/integration/test_api.py — FastAPI integration tests.

Tests every endpoint with realistic payloads.
Uses httpx AsyncClient for true async testing.
"""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import pytest
import pytest_asyncio

try:
    from httpx import AsyncClient, ASGITransport
    from src.api.app import create_app
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI/httpx not installed"),
]


@pytest_asyncio.fixture(scope="module")
async def client():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    async def test_liveness(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    async def test_readiness(self, client):
        r = await client.get("/ready")
        assert r.status_code == 200
        assert r.json()["status"] == "ready"

    async def test_metrics_endpoint(self, client):
        r = await client.get("/metrics")
        assert r.status_code == 200
        assert "redaction_requests_total" in r.text or "redaction" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# /v1/redact
# ─────────────────────────────────────────────────────────────────────────────

class TestRedactEndpoint:
    async def test_basic_email(self, client):
        r = await client.post("/v1/redact", json={"text": "email: john@example.com"})
        assert r.status_code == 200
        data = r.json()
        assert "john@example.com" not in data["redacted_text"]
        assert data["entity_count"] >= 1

    async def test_ssn_redacted(self, client):
        r = await client.post("/v1/redact", json={"text": "SSN: 456-78-9012"})
        assert r.status_code == 200
        assert "456-78-9012" not in r.json()["redacted_text"]

    async def test_credit_card(self, client):
        r = await client.post("/v1/redact", json={"text": "Card: 4532015112830366"})
        assert r.status_code == 200
        assert "4532015112830366" not in r.json()["redacted_text"]

    async def test_response_structure(self, client):
        r = await client.post("/v1/redact", json={"text": "test@x.com"})
        data = r.json()
        assert "request_id" in data
        assert "redacted_text" in data
        assert "entity_count" in data
        assert "categories_found" in data
        assert "processing_ms" in data

    async def test_token_map_not_exposed_by_default(self, client):
        r = await client.post("/v1/redact", json={"text": "test@x.com"})
        assert "token_map" not in r.json() or r.json().get("token_map") is None

    async def test_token_map_exposed_when_requested(self, client):
        r = await client.post("/v1/redact", json={
            "text": "test@x.com",
            "include_token_map": True,
        })
        data = r.json()
        assert data.get("token_map") is not None
        assert any("test@x.com" in v for v in data["token_map"].values())

    async def test_entities_included(self, client):
        r = await client.post("/v1/redact", json={
            "text": "email test@x.com",
            "include_entities": True,
        })
        data = r.json()
        assert data.get("entities") is not None
        assert len(data["entities"]) >= 1

    async def test_empty_text_rejected(self, client):
        r = await client.post("/v1/redact", json={"text": ""})
        assert r.status_code == 422

    async def test_whitespace_only_text(self, client):
        r = await client.post("/v1/redact", json={"text": "   "})
        assert r.status_code == 200
        assert r.json()["entity_count"] == 0

    async def test_caching(self, client):
        payload = {"text": "Cache test: john@example.com, SSN 456-78-9012"}
        r1 = await client.post("/v1/redact", json=payload)
        r2 = await client.post("/v1/redact", json=payload)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["redacted_text"] == r2.json()["redacted_text"]
        # Second request should be cached
        assert r2.json().get("cached", False) is True

    async def test_complex_text(self, client):
        text = (
            "Patient John Smith DOB 01/15/1982 SSN 456-78-9012 "
            "email jsmith@clinic.org phone (555) 123-4567 "
            "Visa card 4532-0151-1283-0366 diagnosis diabetes"
        )
        r = await client.post("/v1/redact", json={"text": text})
        assert r.status_code == 200
        data = r.json()
        assert data["entity_count"] >= 4
        assert "456-78-9012" not in data["redacted_text"]
        assert "jsmith@clinic.org" not in data["redacted_text"]

    async def test_request_id_in_header(self, client):
        r = await client.post("/v1/redact", json={"text": "test@x.com"})
        assert "x-request-id" in r.headers

    async def test_process_time_in_header(self, client):
        r = await client.post("/v1/redact", json={"text": "test@x.com"})
        assert "x-process-time" in r.headers


# ─────────────────────────────────────────────────────────────────────────────
# /v1/redact/batch
# ─────────────────────────────────────────────────────────────────────────────

class TestBatchEndpoint:
    async def test_batch_basic(self, client):
        r = await client.post("/v1/redact/batch", json={
            "texts": [
                "email: a@x.com",
                "SSN: 123-45-6789",
                "Card: 4532015112830366",
            ]
        })
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 3
        assert len(data["results"]) == 3

    async def test_batch_results_redacted(self, client):
        r = await client.post("/v1/redact/batch", json={
            "texts": ["a@test.com", "b@test.com", "c@test.com"]
        })
        for result in r.json()["results"]:
            assert "@test.com" not in result["redacted_text"]

    async def test_batch_empty_list_rejected(self, client):
        r = await client.post("/v1/redact/batch", json={"texts": []})
        assert r.status_code == 422

    async def test_batch_large(self, client):
        texts = [f"User {i} email{i}@corp.com SSN {i}56-78-9012" for i in range(50)]
        r = await client.post("/v1/redact/batch", json={"texts": texts})
        assert r.status_code == 200
        assert r.json()["count"] == 50


# ─────────────────────────────────────────────────────────────────────────────
# /v1/redact/sample
# ─────────────────────────────────────────────────────────────────────────────

class TestSampleEndpoint:
    async def test_sample_annotator_view(self, client):
        r = await client.post("/v1/redact/sample", json={
            "prompt": "My SSN is 456-78-9012",
            "response": "I see your SSN is 456-78-9012",
            "annotator_view": True,
        })
        assert r.status_code == 200
        data = r.json()
        # Annotator view: no token_map
        assert "token_map" not in data
        assert "456-78-9012" not in data.get("prompt", "")
        assert "456-78-9012" not in data.get("response", "")

    async def test_sample_full_view(self, client):
        r = await client.post("/v1/redact/sample", json={
            "prompt": "Email: bob@test.com",
            "annotator_view": False,
            "include_token_map": True,
        })
        assert r.status_code == 200
        data = r.json()
        assert "prompt_analysis" in data or "redacted_prompt" in data

    async def test_sample_with_metadata(self, client):
        r = await client.post("/v1/redact/sample", json={
            "sample_id": "test-abc-123",
            "prompt": "test@x.com",
            "metadata": {"source": "gpt-4", "user_id": "u-999"},
            "annotator_view": True,
        })
        assert r.status_code == 200

    async def test_sample_prompt_only(self, client):
        r = await client.post("/v1/redact/sample", json={
            "prompt": "test@x.com",
        })
        assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# /v1/entities
# ─────────────────────────────────────────────────────────────────────────────

class TestEntitiesEndpoint:
    async def test_list_entities(self, client):
        r = await client.get("/v1/entities")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 20
        assert "by_category" in data
        cats = data["by_category"]
        for expected_cat in ("PII", "PHI", "FINANCIAL", "CREDENTIAL"):
            assert expected_cat in cats

    async def test_pipeline_stats(self, client):
        r = await client.get("/v1/pipeline/stats")
        assert r.status_code == 200
        data = r.json()
        assert "pipeline" in data


# ─────────────────────────────────────────────────────────────────────────────
# Error handling
# ─────────────────────────────────────────────────────────────────────────────

class TestErrorHandling:
    async def test_invalid_json_400(self, client):
        r = await client.post(
            "/v1/redact",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422

    async def test_missing_text_field(self, client):
        r = await client.post("/v1/redact", json={"language": "en"})
        assert r.status_code == 422
