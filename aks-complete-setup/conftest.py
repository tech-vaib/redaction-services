# tests/conftest.py — shared pytest configuration
import os
import sys

# Ensure src is importable from any test location
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Set test environment
os.environ.setdefault("REDACT_ENVIRONMENT", "test")
os.environ.setdefault("REDACT_LOG_JSON", "false")
os.environ.setdefault("REDACT_LOG_LEVEL", "WARNING")
os.environ.setdefault("REDACT_METRICS_ENABLED", "false")
os.environ.setdefault("REDACT_RESULT_CACHE_ENABLED", "true")
os.environ.setdefault("REDACT_AUDIT_STORE_TOKEN_MAP", "false")
