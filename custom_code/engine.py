"""
engine.py — Core redaction engine.

Detection pipeline:
  1. Regex patterns (from patterns.py) — fast, deterministic
  2. spaCy NER (if available) — catches names, orgs, locations
  3. Overlap resolution — higher-priority span wins
  4. Token assignment — PERSON_1, PERSON_2, EMAIL_1, etc.
  5. Text reconstruction with token substitution
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .patterns import (
    PATTERN_REGISTRY,
    DetectedEntity,
    PatternDef,
    get_enabled_patterns,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# spaCy optional import
# ─────────────────────────────────────────────────────────────────────────────

try:
    import spacy

    _NLP = None

    def _get_nlp():
        global _NLP
        if _NLP is None:
            # Try best available model (largest first)
            for model in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
                try:
                    _NLP = spacy.load(model)
                    logger.info("spaCy model loaded: %s", model)
                    break
                except OSError:
                    continue
            if _NLP is None:
                logger.warning("No spaCy model found — NER disabled. "
                               "Run: python -m spacy download en_core_web_sm")
        return _NLP

    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    logger.warning("spaCy not installed — NER disabled.")

    def _get_nlp():
        return None


# ─────────────────────────────────────────────────────────────────────────────
# spaCy label → our label mapping
# ─────────────────────────────────────────────────────────────────────────────

SPACY_LABEL_MAP: Dict[str, Tuple[str, str]] = {
    "PERSON":   ("PERSON",  "PII"),
    "ORG":      ("ORG",     "PII"),
    "GPE":      ("LOCATION","PII"),   # geo-political entity
    "LOC":      ("LOCATION","PII"),
    "FAC":      ("LOCATION","PII"),   # facility
    "DATE":     ("DATE",    "PHI"),
    "TIME":     ("TIME",    "PHI"),
    "MONEY":    ("MONEY",   "FINANCIAL"),
    "CARDINAL": ("NUMBER",  "PII"),   # can be ID-like
}

# spaCy entity types that should skip if already caught by regex
SPACY_SKIP_IF_REGEX_HANDLED = {"DATE", "CARDINAL", "MONEY"}


# ─────────────────────────────────────────────────────────────────────────────
# Redactor
# ─────────────────────────────────────────────────────────────────────────────

class Redactor:
    """
    Main redaction engine.

    Usage:
        r = Redactor()
        result = r.redact("Call me at 555-123-4567 or email jane@acme.com")
        print(result.redacted_text)
        # → "Call me at [PHONE_1] or email [EMAIL_1]"
    """

    def __init__(
        self,
        use_spacy: bool = True,
        consistent_tokens: bool = True,
        redact_categories: Optional[List[str]] = None,
        skip_categories: Optional[List[str]] = None,
    ):
        """
        Args:
            use_spacy:          Enable spaCy NER pass.
            consistent_tokens:  Same value always → same token (cross-document).
            redact_categories:  Whitelist of categories (None = all enabled).
            skip_categories:    Blacklist of categories to skip.
        """
        self.use_spacy = use_spacy and SPACY_AVAILABLE
        self.consistent_tokens = consistent_tokens
        self.redact_categories = set(redact_categories) if redact_categories else None
        self.skip_categories = set(skip_categories) if skip_categories else set()

        # Global value→token map (for consistent_tokens across calls)
        self._global_token_map: Dict[str, str] = {}
        self._label_counters: Dict[str, int] = defaultdict(int)

    # ── Public API ──────────────────────────────────────────────────────────

    def redact(self, text: str) -> "RedactionResult":
        """Redact a single string. Returns RedactionResult."""
        entities = self._detect(text)
        redacted, token_map = self._apply(text, entities)
        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            entities=entities,
            token_map=token_map,
        )

    def redact_batch(self, texts: List[str]) -> List["RedactionResult"]:
        """Redact multiple strings, sharing token counters."""
        return [self.redact(t) for t in texts]

    def reset_counters(self) -> None:
        """Reset token counters and global map (start fresh)."""
        self._global_token_map.clear()
        self._label_counters.clear()

    # ── Detection ────────────────────────────────────────────────────────────

    def _detect(self, text: str) -> List[DetectedEntity]:
        """Run all detectors and return deduplicated, sorted entities."""
        candidates: List[DetectedEntity] = []

        # 1. Regex pass
        candidates.extend(self._detect_regex(text))

        # 2. spaCy NER pass
        if self.use_spacy:
            candidates.extend(self._detect_spacy(text, candidates))

        # 3. Overlap resolution (highest priority wins)
        resolved = self._resolve_overlaps(candidates)

        # 4. Sort by position
        resolved.sort(key=lambda e: e.start)

        return resolved

    def _detect_regex(self, text: str) -> List[DetectedEntity]:
        entities = []
        patterns = get_enabled_patterns()

        # Filter by category allow/skip lists
        patterns = self._filter_patterns(patterns)

        for pat in patterns:
            try:
                if callable(pat.pattern) and not hasattr(pat.pattern, "finditer"):
                    # Custom callable
                    matches = pat.pattern(text)
                else:
                    matches = pat.pattern.finditer(text)

                for m in matches:
                    entities.append(
                        DetectedEntity(
                            label=pat.name,
                            category=pat.category,
                            value=m.group(0),
                            start=m.start(),
                            end=m.end(),
                        )
                    )
            except Exception as exc:
                logger.warning("Pattern %s failed: %s", pat.name, exc)

        return entities

    def _detect_spacy(
        self, text: str, existing: List[DetectedEntity]
    ) -> List[DetectedEntity]:
        nlp = _get_nlp()
        if nlp is None:
            return []

        # Build set of already-covered spans to avoid duplicates
        covered = {(e.start, e.end) for e in existing}

        entities = []
        try:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ not in SPACY_LABEL_MAP:
                    continue
                if ent.label_ in SPACY_SKIP_IF_REGEX_HANDLED:
                    # Skip if a regex already caught this exact span
                    if (ent.start_char, ent.end_char) in covered:
                        continue
                our_label, our_cat = SPACY_LABEL_MAP[ent.label_]
                if not self._category_allowed(our_cat):
                    continue
                entities.append(
                    DetectedEntity(
                        label=our_label,
                        category=our_cat,
                        value=ent.text,
                        start=ent.start_char,
                        end=ent.end_char,
                    )
                )
        except Exception as exc:
            logger.warning("spaCy failed: %s", exc)

        return entities

    # ── Overlap resolution ───────────────────────────────────────────────────

    @staticmethod
    def _resolve_overlaps(entities: List[DetectedEntity]) -> List[DetectedEntity]:
        """
        For overlapping spans: keep the one with higher priority.
        Priority comes from the PatternDef; spaCy entities get priority=5.
        """
        # Map label→priority from registry
        priority_map: Dict[str, int] = {p.name: p.priority for p in PATTERN_REGISTRY}
        default_priority = 5

        def priority(e: DetectedEntity) -> int:
            return priority_map.get(e.label, default_priority)

        # Sort by start, then by descending priority
        sorted_ents = sorted(entities, key=lambda e: (e.start, -priority(e)))

        result: List[DetectedEntity] = []
        last_end = -1

        for ent in sorted_ents:
            if ent.start >= last_end:
                result.append(ent)
                last_end = ent.end
            else:
                # Overlap: check if current is higher priority than what's there
                if result and priority(ent) > priority(result[-1]):
                    result[-1] = ent
                    last_end = ent.end

        return result

    # ── Token assignment & text reconstruction ───────────────────────────────

    def _apply(
        self, text: str, entities: List[DetectedEntity]
    ) -> Tuple[str, Dict[str, str]]:
        """Replace detected spans with tokens. Returns (redacted_text, token_map)."""
        token_map: Dict[str, str] = {}  # token → original value
        parts = []
        cursor = 0

        for ent in entities:
            # Text before this entity
            parts.append(text[cursor : ent.start])

            # Assign token
            token = self._assign_token(ent)
            ent.token = token
            token_map[token] = ent.value

            parts.append(token)
            cursor = ent.end

        # Remainder
        parts.append(text[cursor:])

        return "".join(parts), token_map

    def _assign_token(self, ent: DetectedEntity) -> str:
        """
        Return a stable [LABEL_N] token for this entity value.
        If consistent_tokens=True, same raw value always gets same token.
        """
        key = f"{ent.label}:{ent.value}"
        if self.consistent_tokens and key in self._global_token_map:
            return self._global_token_map[key]

        self._label_counters[ent.label] += 1
        token = f"[{ent.label}_{self._label_counters[ent.label]}]"

        if self.consistent_tokens:
            self._global_token_map[key] = token

        return token

    # ── Category filtering helpers ────────────────────────────────────────────

    def _filter_patterns(self, patterns: List[PatternDef]) -> List[PatternDef]:
        return [p for p in patterns if self._category_allowed(p.category)]

    def _category_allowed(self, category: str) -> bool:
        if category in self.skip_categories:
            return False
        if self.redact_categories is not None:
            return category in self.redact_categories
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Result object
# ─────────────────────────────────────────────────────────────────────────────

class RedactionResult:
    __slots__ = ("original_text", "redacted_text", "entities", "token_map")

    def __init__(
        self,
        original_text: str,
        redacted_text: str,
        entities: List[DetectedEntity],
        token_map: Dict[str, str],
    ):
        self.original_text = original_text
        self.redacted_text = redacted_text
        self.entities = entities
        self.token_map = token_map

    @property
    def entity_count(self) -> int:
        return len(self.entities)

    @property
    def categories_found(self) -> List[str]:
        return sorted(set(e.category for e in self.entities))

    def to_dict(self) -> dict:
        return {
            "redacted_text": self.redacted_text,
            "entity_count": self.entity_count,
            "categories_found": self.categories_found,
            "entities": [
                {
                    "label": e.label,
                    "category": e.category,
                    "token": e.token,
                    "start": e.start,
                    "end": e.end,
                }
                for e in self.entities
            ],
            "token_map": self.token_map,
        }

    def __repr__(self) -> str:
        return (
            f"RedactionResult(entities={self.entity_count}, "
            f"categories={self.categories_found})"
        )
