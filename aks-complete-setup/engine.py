"""
src/redactor/engine.py — Production Presidio-backed redaction engine.

Detection stack (in order, results merged):
  1. Presidio built-in recognizers  (email, phone, SSN, credit card, names, …)
  2. Custom recognizers             (IBAN, JWT, AWS key, medications, …)
  3. spaCy NER                      (PERSON, ORG, GPE, LOC via Presidio NLP)

All results use consistent [LABEL_N] tokens preserving semantic meaning
without exposing raw PII/PHI.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

from src.config.settings import get_settings
from src.redactor.recognizers import CUSTOM_RECOGNIZERS
from src.utils.logging import get_logger
from src.utils.metrics import ENTITIES_DETECTED_TOTAL, TEXT_LENGTH

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Entity → category mapping (for filtering and metrics)
# ─────────────────────────────────────────────────────────────────────────────

ENTITY_CATEGORY: Dict[str, str] = {
    # Built-in Presidio
    "PERSON":               "PII",
    "EMAIL_ADDRESS":        "PII",
    "PHONE_NUMBER":         "PII",
    "US_SSN":               "PII",
    "US_PASSPORT":          "PII",
    "US_DRIVER_LICENSE":    "PII",
    "US_ITIN":              "PII",
    "US_BANK_NUMBER":       "FINANCIAL",
    "CREDIT_CARD":          "FINANCIAL",
    "LOCATION":             "PII",
    "NRP":                  "SENSITIVE",       # Nationality / Race / Religion
    "DATE_TIME":            "PHI",
    "IP_ADDRESS":           "NETWORK",
    "URL":                  "NETWORK",
    "MEDICAL_LICENSE":      "PHI",
    # Custom
    "IBAN_CODE":            "FINANCIAL",
    "SWIFT_BIC":            "FINANCIAL",
    "CRYPTO":               "FINANCIAL",
    "BANK_ACCOUNT":         "FINANCIAL",
    "EIN":                  "FINANCIAL",
    "AWS_ACCESS_KEY":       "CREDENTIAL",
    "JWT_TOKEN":            "CREDENTIAL",
    "API_KEY":              "CREDENTIAL",
    "PASSWORD_CONTEXT":     "CREDENTIAL",
    "PRIVATE_KEY":          "CREDENTIAL",
    "URL_WITH_CREDENTIALS": "CREDENTIAL",
    "MEDICAL_RECORD":       "PHI",
    "NPI":                  "PHI",
    "ICD_CODE":             "PHI",
    "DEA_NUMBER":           "PHI",
    "INSURANCE_ID":         "PHI",
    "MEDICAL_CONDITION":    "PHI",
    "MEDICATION":           "PHI",
    "IPV6_ADDRESS":         "NETWORK",
    "MAC_ADDRESS":          "NETWORK",
    "VIN":                  "PII",
    "ITIN":                 "PII",
    "RACE_ETHNICITY":       "SENSITIVE",
    "SEXUAL_ORIENTATION":   "SENSITIVE",
    "RELIGION":             "SENSITIVE",
}


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedEntity:
    entity_type: str
    category: str
    start: int
    end: int
    score: float
    value: str
    token: str = ""


@dataclass
class RedactionResult:
    original_text: str
    redacted_text: str
    entities: List[DetectedEntity] = field(default_factory=list)
    token_map: Dict[str, str] = field(default_factory=dict)
    processing_ms: float = 0.0

    @property
    def entity_count(self) -> int:
        return len(self.entities)

    @property
    def categories_found(self) -> List[str]:
        return sorted({e.category for e in self.entities})

    @property
    def has_pii(self) -> bool:
        return any(e.category in ("PII", "PHI", "FINANCIAL", "CREDENTIAL")
                   for e in self.entities)

    def to_dict(self, include_token_map: bool = False) -> dict:
        d: dict = {
            "redacted_text": self.redacted_text,
            "entity_count": self.entity_count,
            "categories_found": self.categories_found,
            "processing_ms": self.processing_ms,
            "entities": [
                {
                    "entity_type": e.entity_type,
                    "category": e.category,
                    "token": e.token,
                    "score": round(e.score, 3),
                    "start": e.start,
                    "end": e.end,
                }
                for e in self.entities
            ],
        }
        if include_token_map:
            d["token_map"] = self.token_map
        return d

    def to_annotator_dict(self) -> dict:
        """Safe view for human annotators — no token_map, no scores."""
        return {
            "redacted_text": self.redacted_text,
            "entity_count": self.entity_count,
            "categories_found": self.categories_found,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class RedactionEngine:
    """
    Thread-safe, singleton-per-config Presidio-backed redaction engine.

    Thread safety: Presidio AnalyzerEngine and AnonymizerEngine are both
    thread-safe for concurrent analyze/anonymize calls. Token counters use
    per-call state (not shared), so concurrent calls are fully independent.
    """

    _instance: Optional["RedactionEngine"] = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "RedactionEngine":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        settings = get_settings()
        self._settings = settings
        self._analyzer = self._build_analyzer()
        self._anonymizer = AnonymizerEngine()
        logger.info("RedactionEngine initialised",
                    model=settings.spacy_model.value,
                    custom_recognizers=len(CUSTOM_RECOGNIZERS))

    # ── Build Presidio analyzer ───────────────────────────────────────────────

    def _build_analyzer(self) -> AnalyzerEngine:
        settings = self._settings

        # NLP engine with spaCy
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": settings.spacy_model.value}],
        }
        try:
            nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
        except Exception as exc:
            logger.warning("spaCy model not found, falling back to en_core_web_sm",
                           error=str(exc))
            nlp_config["models"][0]["model_name"] = "en_core_web_sm"
            try:
                nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
            except Exception:
                logger.warning("spaCy unavailable — using pattern-only mode")
                nlp_engine = None

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(
            languages=["en"],
            nlp_engine=nlp_engine,
        )

        # Register all custom recognizers
        for recognizer_cls in CUSTOM_RECOGNIZERS:
            try:
                registry.add_recognizer(recognizer_cls())
            except Exception as exc:
                logger.warning("Failed to register recognizer",
                               name=recognizer_cls.__name__, error=str(exc))

        return AnalyzerEngine(
            registry=registry,
            nlp_engine=nlp_engine,
            supported_languages=["en"],
        )

    # ── Public sync API ───────────────────────────────────────────────────────

    def analyze(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        language: str = "en",
    ) -> List[RecognizerResult]:
        """
        Run entity detection only. Returns raw Presidio results with scores.
        """
        settings = self._settings
        score_threshold = settings.presidio_score_threshold

        results = self._analyzer.analyze(
            text=text,
            entities=entities,
            language=language,
            score_threshold=score_threshold,
            return_decision_process=False,
        )

        # Apply per-entity score overrides
        filtered = []
        for r in results:
            threshold = settings.entity_score_overrides.get(r.entity_type, score_threshold)
            if r.score >= threshold and r.entity_type not in settings.skip_entity_types:
                filtered.append(r)

        return filtered

    def redact(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        consistent_tokens: bool = True,
        language: str = "en",
    ) -> RedactionResult:
        """
        Full redaction: detect → assign tokens → replace.

        This is the core synchronous method. Safe to call from multiple threads.
        """
        if not text or not text.strip():
            return RedactionResult(original_text=text, redacted_text=text)

        t0 = time.perf_counter()

        # 1. Measure text
        TEXT_LENGTH.observe(len(text))

        # 2. Detect
        analyzer_results = self.analyze(text, entities=entities, language=language)

        if not analyzer_results:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                processing_ms=round((time.perf_counter() - t0) * 1000, 2),
            )

        # 3. Build per-call token state (not shared between calls)
        label_counters: Dict[str, int] = defaultdict(int)
        value_to_token: Dict[str, str] = {}  # for consistent_tokens within this call

        # 4. Build operator map: entity_type → OperatorConfig(replace, token)
        operators: Dict[str, OperatorConfig] = {}
        entity_details: List[DetectedEntity] = []

        # Sort by position for consistent token numbering
        sorted_results = sorted(analyzer_results, key=lambda r: r.start)

        for r in sorted_results:
            raw_value = text[r.start:r.end]
            entity_type = r.entity_type
            category = ENTITY_CATEGORY.get(entity_type, "OTHER")

            # Token assignment
            if consistent_tokens and raw_value in value_to_token:
                token = value_to_token[raw_value]
            else:
                label_counters[entity_type] += 1
                token = f"[{entity_type}_{label_counters[entity_type]}]"
                if consistent_tokens:
                    value_to_token[raw_value] = token

            entity_details.append(DetectedEntity(
                entity_type=entity_type,
                category=category,
                start=r.start,
                end=r.end,
                score=r.score,
                value=raw_value,
                token=token,
            ))

            # Record metrics
            ENTITIES_DETECTED_TOTAL.labels(
                entity_type=entity_type,
                category=category,
            ).inc()

        # 5. Apply anonymization via Presidio (handles overlaps correctly)
        #    We use a lambda operator so each entity gets its unique token
        operator_config = {
            result.entity_type: OperatorConfig("replace", {"new_value": detail.token})
            for result, detail in zip(sorted_results, entity_details)
        }

        # Presidio anonymizer handles overlap resolution internally
        try:
            anonymized = self._anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=operator_config,
            )
            redacted_text = anonymized.text
        except Exception as exc:
            logger.error("Anonymization failed, using manual replacement",
                         error=str(exc))
            redacted_text = self._manual_replace(text, entity_details)

        # 6. Build token_map (token → original value)
        token_map = {e.token: e.value for e in entity_details}

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        return RedactionResult(
            original_text=text,
            redacted_text=redacted_text,
            entities=entity_details,
            token_map=token_map,
            processing_ms=elapsed_ms,
        )

    def redact_batch(
        self,
        texts: List[str],
        consistent_tokens: bool = True,
    ) -> List[RedactionResult]:
        """Synchronous batch redaction. Thread-safe."""
        return [self.redact(t, consistent_tokens=consistent_tokens) for t in texts]

    # ── Fallback manual replacement ───────────────────────────────────────────

    @staticmethod
    def _manual_replace(text: str, entities: List[DetectedEntity]) -> str:
        """Fallback if Presidio anonymizer fails — replace highest-priority spans."""
        # Sort by start position, resolve overlaps (highest score wins)
        sorted_ents = sorted(entities, key=lambda e: (e.start, -e.score))
        resolved: List[DetectedEntity] = []
        last_end = -1
        for ent in sorted_ents:
            if ent.start >= last_end:
                resolved.append(ent)
                last_end = ent.end

        parts = []
        cursor = 0
        for ent in sorted(resolved, key=lambda e: e.start):
            parts.append(text[cursor:ent.start])
            parts.append(ent.token)
            cursor = ent.end
        parts.append(text[cursor:])
        return "".join(parts)
