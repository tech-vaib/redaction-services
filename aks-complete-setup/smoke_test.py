#!/usr/bin/env python3
"""
scripts/smoke_test.py — Post-deployment smoke tests.

Validates the service is working correctly after any deployment.
Exits 0 on success, 1 on failure.

Usage:
    python scripts/smoke_test.py --url http://localhost:8000
    python scripts/smoke_test.py --url https://redaction.yourdomain.com
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
import urllib.error


def get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def post(url: str, body: dict, timeout: int = 30) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def check(condition: bool, name: str, detail: str = "") -> bool:
    if condition:
        print(f"  ✓ {name}")
        return True
    else:
        print(f"  ✗ {name}" + (f": {detail}" if detail else ""))
        return False


def run_smoke_tests(base_url: str) -> bool:
    base_url = base_url.rstrip("/")
    failures = 0

    print(f"\n{'═'*60}")
    print(f"  Smoke Tests → {base_url}")
    print(f"{'═'*60}\n")

    # ── 1. Liveness ───────────────────────────────────────────────────────────
    print("  [Health]")
    try:
        r = get(f"{base_url}/health")
        failures += 0 if check(r.get("status") == "ok", "Liveness /health") else 1
    except Exception as e:
        failures += 1
        check(False, "Liveness /health", str(e))

    # ── 2. Readiness ──────────────────────────────────────────────────────────
    try:
        r = get(f"{base_url}/ready")
        failures += 0 if check(r.get("status") == "ready", "Readiness /ready") else 1
    except Exception as e:
        failures += 1
        check(False, "Readiness /ready", str(e))

    # ── 3. Metrics endpoint ───────────────────────────────────────────────────
    try:
        req = urllib.request.Request(f"{base_url}/metrics")
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode()
        failures += 0 if check(
            "redaction" in body, "Metrics /metrics"
        ) else 1
    except Exception as e:
        failures += 1
        check(False, "Metrics /metrics", str(e))

    print()

    # ── 4. Redact endpoint ────────────────────────────────────────────────────
    print("  [Redaction]")
    SENSITIVE_VALUES = {
        "email":   ("test@example.com",  "Contact test@example.com"),
        "ssn":     ("456-78-9012",       "SSN: 456-78-9012"),
        "card":    ("4532015112830366",  "Card: 4532015112830366"),
        "phone":   ("555-123-4567",      "Call 555-123-4567"),
        "ip":      ("192.168.1.100",     "Server 192.168.1.100"),
        "aws_key": ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    }

    for name, (sensitive, text) in SENSITIVE_VALUES.items():
        try:
            r = post(f"{base_url}/v1/redact", {"text": text, "include_entities": True})
            redacted = r.get("redacted_text", "")
            not_leaked = sensitive not in redacted
            has_entity = r.get("entity_count", 0) >= 1
            failures += 0 if check(
                not_leaked and has_entity,
                f"Redact [{name}]",
                f"redacted='{redacted[:60]}', entities={r.get('entity_count', 0)}"
            ) else 1
        except Exception as e:
            failures += 1
            check(False, f"Redact [{name}]", str(e))

    print()

    # ── 5. Token map not exposed by default ───────────────────────────────────
    print("  [Security]")
    try:
        r = post(f"{base_url}/v1/redact", {"text": "test@x.com"})
        failures += 0 if check(
            r.get("token_map") is None,
            "Token map NOT in default response"
        ) else 1
    except Exception as e:
        failures += 1
        check(False, "Token map security", str(e))

    # ── 6. Annotator view safety ──────────────────────────────────────────────
    try:
        r = post(f"{base_url}/v1/redact/sample", {
            "prompt": "SSN: 456-78-9012",
            "annotator_view": True,
        })
        failures += 0 if check(
            "token_map" not in r and "456-78-9012" not in str(r),
            "Annotator view has no PII"
        ) else 1
    except Exception as e:
        failures += 1
        check(False, "Annotator view safety", str(e))

    print()

    # ── 7. Batch endpoint ─────────────────────────────────────────────────────
    print("  [Batch]")
    try:
        texts = [f"email{i}@corp.com SSN {i}56-78-9012" for i in range(10)]
        r = post(f"{base_url}/v1/redact/batch", {"texts": texts})
        failures += 0 if check(
            r.get("count") == 10 and len(r.get("results", [])) == 10,
            "Batch 10 texts → 10 results"
        ) else 1
    except Exception as e:
        failures += 1
        check(False, "Batch endpoint", str(e))

    print()

    # ── 8. Latency check ─────────────────────────────────────────────────────
    print("  [Performance]")
    try:
        t0 = time.perf_counter()
        r = post(f"{base_url}/v1/redact", {
            "text": "Patient John Smith SSN 456-78-9012 email j@x.com card 4532015112830366"
        })
        elapsed_ms = (time.perf_counter() - t0) * 1000
        failures += 0 if check(
            elapsed_ms < 500,
            f"Single redact latency < 500ms",
            f"actual={elapsed_ms:.0f}ms"
        ) else 1
    except Exception as e:
        failures += 1
        check(False, "Latency check", str(e))

    # ── 9. Entities endpoint ──────────────────────────────────────────────────
    try:
        r = get(f"{base_url}/v1/entities")
        failures += 0 if check(
            r.get("total", 0) >= 20,
            f"Entity catalog has ≥20 types ({r.get('total', 0)} found)"
        ) else 1
    except Exception as e:
        failures += 1
        check(False, "Entities endpoint", str(e))

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    if failures == 0:
        print(f"  ✅  All smoke tests PASSED")
    else:
        print(f"  ❌  {failures} smoke test(s) FAILED")
    print(f"{'═'*60}\n")

    return failures == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Post-deploy smoke tests")
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Service base URL",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Retry failed tests N times",
    )
    args = parser.parse_args()

    for attempt in range(1, args.retries + 1):
        if attempt > 1:
            print(f"\nRetry {attempt}/{args.retries} in 5s...")
            time.sleep(5)
        success = run_smoke_tests(args.url)
        if success:
            sys.exit(0)

    sys.exit(1)
