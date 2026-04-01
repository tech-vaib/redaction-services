#!/usr/bin/env python3
"""
scripts/redact_cli.py — Command-line interface for the redaction service.

Examples:
    # Redact a string
    python scripts/redact_cli.py --text "Call John at 555-123-4567 or john@x.com"

    # Redact a file (JSONL with {prompt, response} per line)
    python scripts/redact_cli.py --file samples.jsonl --output redacted.jsonl

    # Show all loaded patterns
    python scripts/redact_cli.py --list-patterns

    # Redact only specific categories
    python scripts/redact_cli.py --text "..." --categories PII PHI

    # Run the API server
    python scripts/redact_cli.py --serve
"""

import argparse
import json
import sys
import os
import time
import asyncio
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from redactor import (
    InMemoryHandler,
    JSONFileHandler,
    LLMSample,
    Redactor,
    RedactionPipeline,
    get_enabled_patterns,
    list_categories,
)


def cmd_list_patterns(args):
    patterns = get_enabled_patterns()
    print(f"\n{'─'*60}")
    print(f"  Loaded patterns: {len(patterns)}")
    print(f"  Categories: {', '.join(list_categories())}")
    print(f"{'─'*60}")
    for cat in list_categories():
        cat_patterns = [p for p in patterns if p.category == cat]
        print(f"\n  [{cat}]")
        for p in cat_patterns:
            print(f"    {p.name:<25} (priority={p.priority}) — {p.description}")
    print()


def cmd_redact_text(args):
    r = Redactor(
        use_spacy=not args.no_spacy,
        consistent_tokens=True,
        redact_categories=args.categories or None,
        skip_categories=args.skip_categories or [],
    )
    t0 = time.perf_counter()
    result = r.redact(args.text)
    elapsed = (time.perf_counter() - t0) * 1000

    print(f"\n{'─'*60}")
    print(f"  ORIGINAL:  {args.text}")
    print(f"  REDACTED:  {result.redacted_text}")
    print(f"{'─'*60}")
    print(f"  Entities found: {result.entity_count}")
    print(f"  Categories: {result.categories_found}")
    print(f"  Time: {elapsed:.1f}ms")

    if result.entities:
        print("\n  Entity detail:")
        for e in result.entities:
            print(f"    [{e.label}] '{e.value}' → {e.token}")
    print()


def cmd_redact_file(args):
    infile = Path(args.file)
    outfile = Path(args.output) if args.output else infile.with_suffix(".redacted.jsonl")

    if not infile.exists():
        print(f"Error: file not found: {infile}")
        sys.exit(1)

    pipeline = RedactionPipeline(
        redactor=Redactor(use_spacy=not args.no_spacy),
        concurrency=args.concurrency,
    )
    handler = JSONFileHandler(str(outfile))
    pipeline.add_output_handler(handler)

    async def run():
        samples = []
        with open(infile, encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    samples.append(LLMSample(
                        sample_id=obj.get("id", f"line-{i}"),
                        prompt=obj.get("prompt", obj.get("text", "")),
                        response=obj.get("response"),
                        metadata=obj.get("metadata", {}),
                    ))
                except json.JSONDecodeError:
                    # Treat plain text lines as prompts
                    samples.append(LLMSample(sample_id=f"line-{i}", prompt=line))

        t0 = time.perf_counter()
        results = await pipeline.process_batch(samples)
        elapsed = time.perf_counter() - t0

        print(f"\n{'─'*60}")
        print(f"  Processed:  {len(results)} samples")
        print(f"  Output:     {outfile}")
        print(f"  Total time: {elapsed:.2f}s")
        print(f"  Throughput: {len(results)/elapsed:.0f} samples/sec")
        print(f"  Stats:      {pipeline.stats}")
        print()

    asyncio.run(run())


def cmd_serve(args):
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Run: pip install uvicorn")
        sys.exit(1)

    print(f"\nStarting redaction API on http://{args.host}:{args.port}")
    print("Docs: http://{}:{}/docs\n".format(args.host, args.port))

    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level="info",
    )


def cmd_demo(args):
    """Run a built-in demo showcasing all entity types."""
    demos = [
        ("Email", "Contact John at john.doe@example.com or SUPPORT@ACME.ORG"),
        ("Phone", "Call us at (800) 555-0100 or +1 415-555-2671"),
        ("SSN", "Social Security Number: 456-78-9012"),
        ("Credit Card", "Visa ending in 4532-0151-1283-0366"),
        ("Bank", "Account #1234567890 Routing #021000021"),
        ("IBAN", "Please wire to GB29NWBK60161331926819"),
        ("IP", "Server IP: 192.168.10.55 and IPv6: 2001:db8::1"),
        ("MAC", "Device MAC: 00:1A:2B:3C:4D:5E"),
        ("Date (PHI)", "DOB: March 15th, 1982"),
        ("Medical Record", "MRN: A9876543, NPI: 1234567890"),
        ("ICD Code", "Diagnosis: E11.9, F32.1"),
        ("Condition", "Patient has diabetes and severe depression"),
        ("Medication", "Prescribed metformin and sertraline"),
        ("Insurance", "Insurance member ID: XYZ-9876543"),
        ("API Key", "api_key=sk-abc123def456ghi789jkl012mno345"),
        ("AWS Key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
        ("Password", "password: MyS3cr3tP@ss!"),
        ("JWT", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123"),
        ("Passport", "Passport number: A12345678"),
        ("Driver License", "DL: D1234567"),
        ("VIN", "Vehicle: 1HGBH41JXMN109186"),
        ("Geo Coords", "Location: lat 37.7749, lon -122.4194"),
        ("Crypto", "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na"),
        ("Race/Ethnicity", "Patient identified as Hispanic"),
        ("Religion", "He is Catholic"),
        ("Name (honorific)", "Dr. Sarah Johnson requested the records"),
        ("Address", "Ships to 123 Main St, Anytown, CA 90210"),
    ]

    r = Redactor(use_spacy=False, consistent_tokens=False)
    print("\n" + "═"*70)
    print("  LLM REDACTION SERVICE — Entity Detection Demo")
    print("═"*70)
    for entity_type, text in demos:
        result = r.redact(text)
        label_str = ", ".join(f"{e.label}" for e in result.entities) or "(none)"
        status = "✓" if result.entity_count > 0 else "○"
        print(f"\n  {status} [{entity_type}]")
        print(f"    IN:  {text}")
        print(f"    OUT: {result.redacted_text}")
        print(f"    TAG: {label_str}")
    print("\n" + "═"*70 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="redact",
        description="LLM PII/PHI Redaction Service CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # redact text
    p_text = sub.add_parser("text", help="Redact a single text string")
    p_text.add_argument("text", help="Text to redact")
    p_text.add_argument("--no-spacy", action="store_true")
    p_text.add_argument("--categories", nargs="+", metavar="CAT")
    p_text.add_argument("--skip-categories", nargs="+", metavar="CAT")

    # redact file
    p_file = sub.add_parser("file", help="Redact a JSONL file")
    p_file.add_argument("file", help="Input JSONL file")
    p_file.add_argument("--output", "-o", help="Output file path")
    p_file.add_argument("--no-spacy", action="store_true")
    p_file.add_argument("--concurrency", type=int, default=8)

    # list patterns
    sub.add_parser("patterns", help="List all loaded detection patterns")

    # demo
    sub.add_parser("demo", help="Run built-in detection demo")

    # serve
    p_serve = sub.add_parser("serve", help="Start the REST API server")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.add_argument("--workers", type=int, default=1)

    args = parser.parse_args()

    if args.command == "text":
        cmd_redact_text(args)
    elif args.command == "file":
        cmd_redact_file(args)
    elif args.command == "patterns":
        cmd_list_patterns(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "serve":
        cmd_serve(args)
    else:
        # Default: run demo
        cmd_demo(args)


if __name__ == "__main__":
    main()
