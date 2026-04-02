#!/usr/bin/env python3
"""
scripts/demo.py — Interactive demo of the redaction service.

Works with Presidio engine (full install) and legacy regex engine.
Run: python scripts/demo.py
"""

from __future__ import annotations

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Try Presidio first
try:
    from src.redactor.engine import RedactionEngine
    engine = RedactionEngine.get_instance()
    def do_redact(text):
        return engine.redact(text)
    ENGINE_NAME = "Presidio + spaCy"
    print(f"✅  Using {ENGINE_NAME} engine")
except Exception as e:
    # Fall back to legacy regex engine
    try:
        from redactor.engine import Redactor
        r = Redactor(use_spacy=False)
        def do_redact(text):
            return r.redact(text)
        ENGINE_NAME = "Custom regex (legacy)"
        print(f"⚠️   Falling back to {ENGINE_NAME}: {e}")
    except ImportError:
        print("❌  No engine available. Run: pip install -r requirements.txt")
        sys.exit(1)

DEMOS = [
    # (Category, text)
    ("Email",            "Contact John at john.doe@example.com or SUPPORT@ACME.ORG"),
    ("Phone",            "Call (800) 555-0100 or +1 415-555-2671 anytime"),
    ("SSN",              "Social Security Number: 456-78-9012"),
    ("Credit Card",      "Visa: 4532-0151-1283-0366 was declined"),
    ("Bank Account",     "Account #1234567890, Routing #021000021"),
    ("IBAN",             "Wire to IBAN GB29NWBK60161331926819"),
    ("IPv4",             "Server at 192.168.1.100 is unreachable"),
    ("IPv6",             "Device: 2001:0db8:85a3::8a2e:0370:7334"),
    ("MAC Address",      "Hardware: 00:1A:2B:3C:4D:5E"),
    ("Date (PHI)",       "DOB: March 15th, 1982"),
    ("Medical Record",   "MRN: A9876543, NPI: 1234567890"),
    ("ICD Code",         "Diagnosis: E11.9 (Type 2 Diabetes), F32.1"),
    ("Condition",        "Patient has diabetes and severe depression"),
    ("Medication",       "Prescribed metformin and sertraline 50mg"),
    ("Insurance",        "Insurance member ID: XYZ-9876543"),
    ("AWS Key",          "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    ("API Key",          "api_key=sk-abc123def456ghi789jkl012mno345"),
    ("Password",         "password: MyS3cr3tP@ss!"),
    ("JWT Token",        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123"),
    ("Passport",         "Passport number: A12345678"),
    ("Driver License",   "DL: D1234567"),
    ("EIN",              "EIN: 12-3456789"),
    ("VIN",              "Vehicle VIN: 1HGBH41JXMN109186"),
    ("BTC Wallet",       "Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ("ETH Wallet",       "ETH: 0x742d35Cc6634C0532925a3b8D4C9Db96590c6C87"),
    ("Race/Ethnicity",   "Patient race: Hispanic"),
    ("Religion",         "He is Catholic and attends weekly services"),
    ("Sexual Orient.",   "She identifies as bisexual"),
    ("Dr. Name",         "Dr. Sarah Johnson requested the records"),
    ("Address",          "Ships to 123 Main St, Anytown, CA 90210"),
    ("URL w/creds",      "postgres://admin:s3cr3t@db.prod.example.com/app"),
    ("Complex Record",   (
        "Patient: Jane Smith (DOB: 01/15/1982)\n"
        "SSN: 456-78-9012 | Email: jsmith@clinic.org\n"
        "Insurance member ID: XYZ123456\n"
        "Diagnosis: E11.9 (diabetes)\n"
        "Medication: metformin 500mg\n"
        "Card: 4532-0151-1283-0366"
    )),
]


def run_demo():
    W = 72
    print("\n" + "═" * W)
    print(f"  PII/PHI REDACTION SERVICE — Demo  ({ENGINE_NAME})")
    print("═" * W)

    total_entities = 0
    total_ms = 0.0

    for category, text in DEMOS:
        t0 = time.perf_counter()
        result = do_redact(text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        total_entities += result.entity_count
        total_ms += elapsed_ms

        status = "✓" if result.entity_count > 0 else "○"
        print(f"\n  {status} [{category}]")

        # For multiline, show indented
        for i, line in enumerate(text.splitlines()):
            if i == 0:
                print(f"    IN:  {line[:75]}")
            else:
                print(f"         {line[:75]}")

        for i, line in enumerate(result.redacted_text.splitlines()):
            if i == 0:
                print(f"    OUT: {line[:75]}")
            else:
                print(f"         {line[:75]}")

        entity_labels = ", ".join(
            getattr(e, 'entity_type', getattr(e, 'label', '?'))
            for e in result.entities
        ) or "(none)"
        print(f"    TAG: {entity_labels[:70]}   [{elapsed_ms:.1f}ms]")

    print("\n" + "─" * W)
    print(f"  Total entities detected : {total_entities}")
    print(f"  Total processing time   : {total_ms:.1f}ms")
    print(f"  Average per text        : {total_ms/len(DEMOS):.1f}ms")
    print("═" * W + "\n")


if __name__ == "__main__":
    run_demo()
