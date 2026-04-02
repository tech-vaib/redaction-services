"""
tests/load/locustfile.py — Load test with Locust.

Simulates high-concurrency LLM traffic redaction.

Run locally:
    locust -f tests/load/locustfile.py --host=http://localhost:8000 --headless \
           -u 100 -r 10 --run-time 60s

AKS load test:
    locust -f tests/load/locustfile.py --host=http://<AKS_EXTERNAL_IP> \
           --headless -u 500 -r 50 --run-time 300s \
           --csv=results/load_test

Targets:
  - p50 latency < 50ms
  - p99 latency < 500ms
  - Throughput > 500 req/s at 100 concurrent users
  - Error rate < 0.1%
"""

from __future__ import annotations

import json
import random
import uuid

try:
    from locust import HttpUser, between, task, events
    from locust.runners import MasterRunner
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False
    # Provide stubs so the file is importable for testing
    class HttpUser:
        pass
    def task(w=1):
        return lambda f: f
    def between(a, b):
        return (a, b)

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic payload pools
# ─────────────────────────────────────────────────────────────────────────────

EMAILS = [f"user{i}@corp{i % 10}.com" for i in range(200)]
SSNS = [f"{random.randint(100,899)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
        for _ in range(100)]
CARDS = ["4532015112830366", "5425233430109903", "374251018720955", "6011000990139424"]
IPS = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
       for _ in range(100)]
PHONES = ["555-123-4567", "(800) 555-0100", "+1 415 555 2671", "800.555.0199"]
NAMES = ["John Smith", "Jane Doe", "Robert Johnson", "Maria Garcia", "Wei Chen"]


def _pick(*pool):
    return random.choice(pool[0] if len(pool) == 1 else pool)


def make_short_payload() -> dict:
    """< 200 chars — simulates single-turn message."""
    return {
        "text": (
            f"Hi, I'm {_pick(NAMES)}. "
            f"Email me at {_pick(EMAILS)} or call {_pick(PHONES)}."
        )
    }


def make_medium_payload() -> dict:
    """~500 chars — typical LLM prompt."""
    return {
        "text": (
            f"Patient: {_pick(NAMES)} (SSN: {_pick(SSNS)})\n"
            f"Contact: {_pick(EMAILS)} | {_pick(PHONES)}\n"
            f"IP Address: {_pick(IPS)}\n"
            f"Credit Card: {_pick(CARDS)}\n"
            f"Diagnosis: Type 2 diabetes. Medication: metformin 500mg.\n"
            f"Notes: Patient presents with elevated blood pressure. "
            f"Recommend follow-up within 30 days."
        )
    }


def make_large_payload() -> dict:
    """~2000 chars — long document redaction."""
    lines = []
    for i in range(10):
        lines.append(
            f"Record {i+1}: {_pick(NAMES)}, SSN {_pick(SSNS)}, "
            f"email {_pick(EMAILS)}, card {_pick(CARDS)}, IP {_pick(IPS)}, "
            f"phone {_pick(PHONES)}. Diagnosis: diabetes. Prescribed: metformin."
        )
    return {"text": "\n".join(lines)}


def make_batch_payload(size: int = 20) -> dict:
    texts = []
    for _ in range(size):
        texts.append(
            f"{_pick(NAMES)} emailed {_pick(EMAILS)} from {_pick(IPS)}"
        )
    return {"texts": texts}


def make_sample_payload() -> dict:
    return {
        "sample_id": str(uuid.uuid4()),
        "prompt": (
            f"My name is {_pick(NAMES)} and my SSN is {_pick(SSNS)}. "
            f"Please call me at {_pick(PHONES)}."
        ),
        "response": (
            f"Thank you {_pick(NAMES)}. I've noted your SSN and will call {_pick(PHONES)}."
        ),
        "annotator_view": True,
        "metadata": {"model": "gpt-4", "temperature": 0.7},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Locust user classes
# ─────────────────────────────────────────────────────────────────────────────

class RedactionUser(HttpUser):
    """
    Primary load user — weighted mix of all endpoints.
    Simulates realistic annotation pipeline traffic.
    """
    wait_time = between(0.01, 0.1)  # 10–100ms think time

    @task(50)
    def redact_short(self):
        """Most common — short single texts."""
        self.client.post(
            "/v1/redact",
            json=make_short_payload(),
            name="/v1/redact [short]",
        )

    @task(30)
    def redact_medium(self):
        self.client.post(
            "/v1/redact",
            json=make_medium_payload(),
            name="/v1/redact [medium]",
        )

    @task(10)
    def redact_large(self):
        self.client.post(
            "/v1/redact",
            json=make_large_payload(),
            name="/v1/redact [large]",
        )

    @task(20)
    def redact_batch(self):
        self.client.post(
            "/v1/redact/batch",
            json=make_batch_payload(size=random.randint(5, 25)),
            name="/v1/redact/batch",
        )

    @task(15)
    def redact_sample(self):
        self.client.post(
            "/v1/redact/sample",
            json=make_sample_payload(),
            name="/v1/redact/sample",
        )

    @task(5)
    def health_check(self):
        self.client.get("/health", name="/health")


class AnnotatorUser(HttpUser):
    """
    Simulates human annotator workload — lighter, reads annotator-safe views.
    """
    wait_time = between(0.5, 2.0)  # slower — humans think

    @task(80)
    def get_sample_annotator_view(self):
        self.client.post(
            "/v1/redact/sample",
            json={**make_sample_payload(), "annotator_view": True},
            name="/v1/redact/sample [annotator]",
        )

    @task(20)
    def get_entities_list(self):
        self.client.get("/v1/entities", name="/v1/entities")


class SpikeUser(HttpUser):
    """
    Spike test user — sends large batches to stress the pipeline.
    Use sparingly: --users 10
    """
    wait_time = between(0.1, 0.5)

    @task
    def large_batch_spike(self):
        self.client.post(
            "/v1/redact/batch",
            json=make_batch_payload(size=100),
            name="/v1/redact/batch [spike]",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Custom event hooks for SLA tracking
# ─────────────────────────────────────────────────────────────────────────────

if LOCUST_AVAILABLE:
    SLA_P99_MS = 500
    SLA_ERROR_RATE = 0.001  # 0.1%

    @events.quitting.add_listener
    def on_quitting(environment, **kwargs):
        stats = environment.runner.stats.total
        p99 = stats.get_response_time_percentile(0.99)
        error_rate = stats.fail_ratio

        print(f"\n{'='*60}")
        print(f"  LOAD TEST RESULTS")
        print(f"{'='*60}")
        print(f"  Total requests: {stats.num_requests:,}")
        print(f"  Failures:       {stats.num_failures:,} ({error_rate:.2%})")
        print(f"  p50 latency:    {stats.get_response_time_percentile(0.5):.0f}ms")
        print(f"  p95 latency:    {stats.get_response_time_percentile(0.95):.0f}ms")
        print(f"  p99 latency:    {p99:.0f}ms")
        print(f"  Throughput:     {stats.total_rps:.1f} req/s")
        print(f"{'='*60}")

        sla_met = True
        if p99 > SLA_P99_MS:
            print(f"  ❌ SLA BREACH: p99 {p99:.0f}ms > {SLA_P99_MS}ms target")
            sla_met = False
        else:
            print(f"  ✅ p99 SLA met: {p99:.0f}ms ≤ {SLA_P99_MS}ms")

        if error_rate > SLA_ERROR_RATE:
            print(f"  ❌ SLA BREACH: error rate {error_rate:.2%} > {SLA_ERROR_RATE:.2%}")
            sla_met = False
        else:
            print(f"  ✅ Error rate SLA met: {error_rate:.2%} ≤ {SLA_ERROR_RATE:.2%}")

        if not sla_met:
            environment.process_exit_code = 1
