#!/usr/bin/env python3
"""
scripts/redact_cli.py — Command-line redaction tool.

Works with full Presidio stack or falls back to lightweight regex engine.

Usage:
    # Redact a string
    python scripts/redact_cli.py text "My SSN is 456-78-9012"

    # Redact a JSONL file (each line: {"prompt": "...", "response": "..."})
    python scripts/redact_cli.py file input.jsonl --output redacted.jsonl

    # Start REST API server
    python scripts/redact_cli.py serve --port 8000

    # List all entity types
    python scripts/redact_cli.py entities

    # Run built-in demo
    python scripts/redact_cli.py demo

    # Post-deploy smoke test
    python scripts/redact_cli.py smoke --url http://localhost:8000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ── Engine selection ─────────────────────────────────────────────────────────
def get_engine():
    try:
        os.environ.setdefault("REDACT_LOG_JSON", "false")
        os.environ.setdefault("REDACT_LOG_LEVEL", "WARNING")
        from src.redactor.engine import RedactionEngine
        return RedactionEngine.get_instance(), "Presidio + spaCy"
    except Exception:
        try:
            from redactor.engine import Redactor
            return Redactor(use_spacy=False), "Custom regex"
        except ImportError:
            print("❌  No engine found. Run: pip install -r requirements.txt")
            sys.exit(1)


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_text(args):
    engine, engine_name = get_engine()
    print(f"\nEngine: {engine_name}\n{'─'*60}")

    t0 = time.perf_counter()
    result = engine.redact(args.text)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"ORIGINAL:  {args.text}")
    print(f"REDACTED:  {result.redacted_text}")
    print(f"{'─'*60}")
    print(f"Entities : {result.entity_count}")
    print(f"Time     : {elapsed_ms:.1f}ms")

    if result.entities:
        print("\nEntity details:")
        for e in result.entities:
            label = getattr(e, 'entity_type', getattr(e, 'label', '?'))
            score = getattr(e, 'score', None)
            score_str = f" (score={score:.2f})" if score is not None else ""
            print(f"  [{label}]{score_str} → {e.token}  original='{e.value}'")
    print()


def cmd_file(args):
    engine, engine_name = get_engine()
    infile = args.file
    outfile = args.output or infile.replace(".jsonl", ".redacted.jsonl")

    if not os.path.exists(infile):
        print(f"❌  File not found: {infile}")
        sys.exit(1)

    print(f"Engine: {engine_name}")
    print(f"Input:  {infile}")
    print(f"Output: {outfile}")

    count = 0
    t0 = time.perf_counter()

    with open(infile, encoding="utf-8") as fin, \
         open(outfile, "w", encoding="utf-8") as fout:

        for i, line in enumerate(fin):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = {"prompt": line}

            prompt = obj.get("prompt", obj.get("text", ""))
            response = obj.get("response")

            r_prompt = engine.redact(prompt)
            r_response = engine.redact(response) if response else None

            out = {
                "sample_id": obj.get("id", f"line-{i}"),
                "redacted_prompt": r_prompt.redacted_text,
                "redacted_response": r_response.redacted_text if r_response else None,
                "entity_count": r_prompt.entity_count + (r_response.entity_count if r_response else 0),
                "metadata": obj.get("metadata", {}),
            }
            fout.write(json.dumps(out) + "\n")
            count += 1

            if count % 100 == 0:
                print(f"  Processed {count} lines...")

    elapsed = time.perf_counter() - t0
    print(f"\n✅  Done: {count} samples in {elapsed:.1f}s "
          f"({count/elapsed:.0f} samples/sec)")
    print(f"   Output: {outfile}\n")


def cmd_entities(args):
    try:
        from src.redactor.engine import ENTITY_CATEGORY
        cats: dict = {}
        for e, c in ENTITY_CATEGORY.items():
            cats.setdefault(c, []).append(e)
        print(f"\n{'═'*60}")
        print(f"  Supported Entity Types ({len(ENTITY_CATEGORY)} total)")
        print(f"{'═'*60}")
        for cat, entities in sorted(cats.items()):
            print(f"\n  [{cat}]")
            for e in sorted(entities):
                print(f"    {e}")
        print()
    except ImportError:
        print("Install presidio: pip install -r requirements.txt")


def cmd_demo(args):
    import subprocess
    script = os.path.join(os.path.dirname(__file__), "demo.py")
    subprocess.run([sys.executable, script], check=True)


def cmd_serve(args):
    try:
        import uvicorn
    except ImportError:
        print("Install uvicorn: pip install uvicorn")
        sys.exit(1)

    print(f"\nStarting PII Redaction Service")
    print(f"  URL:  http://{args.host}:{args.port}")
    print(f"  Docs: http://{args.host}:{args.port}/docs\n")

    uvicorn.run(
        "src.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


def cmd_smoke(args):
    script = os.path.join(os.path.dirname(__file__), "smoke_test.py")
    import subprocess
    result = subprocess.run(
        [sys.executable, script, "--url", args.url, "--retries", str(args.retries)],
        check=False,
    )
    sys.exit(result.returncode)


# ── CLI parser ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="redact",
        description="PII/PHI Redaction Service CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # text
    p = sub.add_parser("text", help="Redact a single text string")
    p.add_argument("text", help="Text to redact")

    # file
    p = sub.add_parser("file", help="Redact a JSONL file")
    p.add_argument("file", help="Input JSONL file path")
    p.add_argument("--output", "-o", help="Output file path")

    # entities
    sub.add_parser("entities", help="List all supported entity types")

    # demo
    sub.add_parser("demo", help="Run detection demo")

    # serve
    p = sub.add_parser("serve", help="Start REST API server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")

    # smoke
    p = sub.add_parser("smoke", help="Run post-deploy smoke tests")
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--retries", type=int, default=3)

    args = parser.parse_args()
    dispatch = {
        "text":     cmd_text,
        "file":     cmd_file,
        "entities": cmd_entities,
        "demo":     cmd_demo,
        "serve":    cmd_serve,
        "smoke":    cmd_smoke,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
