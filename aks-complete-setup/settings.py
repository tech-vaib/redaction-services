"""
src/config/settings.py — Centralised settings via pydantic-settings.

All values are overridable by environment variables prefixed REDACT_.
Example:  REDACT_API_PORT=9000  REDACT_PIPELINE_WORKERS=16

Priority: env vars > .env file > defaults below.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class SpacyModel(str, Enum):
    SM = "en_core_web_sm"
    MD = "en_core_web_md"
    LG = "en_core_web_lg"
    TRF = "en_core_web_trf"   # transformer — highest accuracy, needs GPU


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="REDACT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Service identity ────────────────────────────────────────────────────
    service_name: str = "pii-redaction-service"
    service_version: str = "2.0.0"
    environment: str = "production"        # local | staging | production

    # ── API ─────────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 1                   # gunicorn workers (overridden by k8s)
    api_timeout: int = 30                  # per-request timeout seconds
    api_max_request_size_bytes: int = 1_048_576  # 1 MB

    # ── Pipeline ────────────────────────────────────────────────────────────
    pipeline_workers: int = Field(default=8, ge=1, le=256)
    pipeline_batch_size: int = Field(default=100, ge=1, le=1000)
    pipeline_queue_size: int = Field(default=10_000, ge=100)

    # ── Detection ───────────────────────────────────────────────────────────
    spacy_model: SpacyModel = SpacyModel.LG
    presidio_score_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    enable_transformer_model: bool = False   # set True with en_core_web_trf
    default_language: str = "en"

    # Tuning: lower threshold = more recall (fewer misses), higher = more precision
    entity_score_overrides: dict = Field(default_factory=lambda: {
        "PERSON":         0.5,   # higher — names have false positives
        "EMAIL_ADDRESS":  0.9,   # very precise regex
        "PHONE_NUMBER":   0.4,
        "US_SSN":         0.85,
        "CREDIT_CARD":    0.85,
        "IP_ADDRESS":     0.6,
        "DATE_TIME":      0.4,
        "MEDICAL_LICENSE":0.6,
        "US_PASSPORT":    0.7,
        "IBAN_CODE":      0.85,
        "CRYPTO":         0.85,
        "AWS_ACCESS_KEY": 0.95,
        "JWT_TOKEN":      0.95,
        "PASSWORD_CONTEXT":0.8,
    })

    # ── Categories to always skip (e.g. domain = too noisy in some corpora)
    skip_entity_types: List[str] = Field(default_factory=list)

    # ── Observability ────────────────────────────────────────────────────────
    log_level: LogLevel = LogLevel.INFO
    log_json: bool = True                  # structured JSON logs for prod
    metrics_enabled: bool = True
    tracing_enabled: bool = False
    otlp_endpoint: Optional[str] = None   # e.g. http://otel-collector:4317

    # ── Health / readiness ───────────────────────────────────────────────────
    health_check_path: str = "/health"
    readiness_path: str = "/ready"

    # ── CORS ────────────────────────────────────────────────────────────────
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])

    # ── Cache ────────────────────────────────────────────────────────────────
    result_cache_enabled: bool = True
    result_cache_ttl_seconds: int = 300
    result_cache_max_size: int = 10_000

    # ── Audit ────────────────────────────────────────────────────────────────
    audit_log_enabled: bool = True
    audit_store_token_map: bool = False    # NEVER expose raw→token map in annotator path
    audit_log_path: Optional[Path] = None

    @field_validator("api_workers", mode="before")
    @classmethod
    def clamp_workers(cls, v: int) -> int:
        import os
        cpu = os.cpu_count() or 1
        return min(int(v), cpu * 2)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
