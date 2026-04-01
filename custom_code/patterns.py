"""
patterns.py — Centralized, extensible pattern registry for PII/PHI detection.

Each PatternDef has:
  - name:        Unique entity label (used as [LABEL_N] token)
  - category:    Grouping (PII, PHI, FINANCIAL, NETWORK, etc.)
  - pattern:     Compiled regex OR callable(text) → list[re.Match|Span]
  - priority:    Higher wins when spans overlap (0 = lowest)
  - description: Human-readable note

To add a new pattern:
  1. Define a PatternDef at the bottom of PATTERN_REGISTRY.
  2. That's it — it auto-loads everywhere.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern, Union


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PatternDef:
    name: str
    category: str
    pattern: Union[Pattern, Callable]          # regex or callable
    priority: int = 5                          # higher = preferred on overlap
    description: str = ""
    enabled: bool = True


@dataclass
class DetectedEntity:
    label: str          # e.g. PERSON, EMAIL
    category: str
    value: str          # original sensitive text
    start: int
    end: int
    token: str = ""     # filled in by redactor  e.g. [PERSON_1]


# ─────────────────────────────────────────────────────────────────────────────
# Helper: compile with verbose flag for readability
# ─────────────────────────────────────────────────────────────────────────────

def _re(pattern: str, flags: int = 0) -> Pattern:
    return re.compile(pattern, flags)


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

PATTERN_REGISTRY: List[PatternDef] = [

    # ── EMAIL ────────────────────────────────────────────────────────────────
    PatternDef(
        name="EMAIL",
        category="PII",
        priority=9,
        description="Standard email addresses",
        pattern=_re(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        ),
    ),

    # ── PHONE NUMBERS ────────────────────────────────────────────────────────
    PatternDef(
        name="PHONE",
        category="PII",
        priority=8,
        description="US/international phone numbers in common formats",
        pattern=_re(
            r"""
            (?<!\d)                         # not preceded by digit
            (?:\+?1[-.\s]?)?                # optional country code
            (?:\(?\d{3}\)?[-.\s]?)          # area code
            \d{3}[-.\s]?\d{4}              # 7-digit local
            (?!\d)                          # not followed by digit
            """,
            re.VERBOSE,
        ),
    ),

    PatternDef(
        name="PHONE_INTL",
        category="PII",
        priority=8,
        description="International phone numbers with + prefix",
        pattern=_re(
            r"\+(?:[0-9]\s?){6,14}[0-9]"
        ),
    ),

    # ── SSN ──────────────────────────────────────────────────────────────────
    PatternDef(
        name="SSN",
        category="PII",
        priority=10,
        description="US Social Security Numbers (dashes or spaces)",
        pattern=_re(
            r"(?<!\d)(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}(?!\d)"
        ),
    ),

    # ── CREDIT CARDS ─────────────────────────────────────────────────────────
    PatternDef(
        name="CREDIT_CARD",
        category="FINANCIAL",
        priority=10,
        description="Visa, MC, Amex, Discover card numbers",
        pattern=_re(
            r"""
            (?<!\d)
            (?:
                4\d{3}                      # Visa
              | 5[1-5]\d{2}                 # MC
              | 3[47]\d{2}                  # Amex
              | 6(?:011|5\d{2})             # Discover
            )
            (?:[-\s]?\d{4}){2,3}            # remaining groups
            (?!\d)
            """,
            re.VERBOSE,
        ),
    ),

    # ── BANK ACCOUNT ─────────────────────────────────────────────────────────
    PatternDef(
        name="BANK_ACCOUNT",
        category="FINANCIAL",
        priority=9,
        description="Bank account / routing numbers preceded by keyword",
        pattern=_re(
            r"(?:account|acct|routing|aba)[:\s#]*\d{6,17}",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="IBAN",
        category="FINANCIAL",
        priority=9,
        description="International Bank Account Numbers",
        pattern=_re(
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"
        ),
    ),

    # ── IP ADDRESSES ─────────────────────────────────────────────────────────
    PatternDef(
        name="IP_ADDRESS",
        category="NETWORK",
        priority=7,
        description="IPv4 addresses",
        pattern=_re(
            r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
        ),
    ),

    PatternDef(
        name="IPV6_ADDRESS",
        category="NETWORK",
        priority=7,
        description="IPv6 addresses",
        pattern=_re(
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
            r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
            r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
        ),
    ),

    PatternDef(
        name="MAC_ADDRESS",
        category="NETWORK",
        priority=7,
        description="MAC / hardware addresses",
        pattern=_re(
            r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"
        ),
    ),

    # ── DATES (PHI — except year-only) ───────────────────────────────────────
    PatternDef(
        name="DATE",
        category="PHI",
        priority=6,
        description="Dates that include month/day (HIPAA safe-harbor: year alone ok)",
        pattern=_re(
            r"""
            (?<!\d)
            (?:
                \d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}   # 01/12/2024
              | (?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|
                   Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|
                   Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)
                \s+\d{1,2}(?:st|nd|rd|th)?,?\s*\d{4}     # January 5th, 2024
              | \d{1,2}\s+
                (?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|
                   Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|
                   Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)
                \s+\d{4}                                  # 5 January 2024
            )
            (?!\d)
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
    ),

    # ── MEDICAL RECORD / PATIENT ID ──────────────────────────────────────────
    PatternDef(
        name="MEDICAL_RECORD",
        category="PHI",
        priority=9,
        description="Medical record numbers, patient IDs",
        pattern=_re(
            r"(?:MRN|medical\s+record|patient\s+(?:id|number|#))[:\s#]*[A-Z0-9\-]{4,20}",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="NPI",
        category="PHI",
        priority=9,
        description="National Provider Identifier (10-digit)",
        pattern=_re(
            r"(?:NPI)[:\s#]*\d{10}",
            re.IGNORECASE,
        ),
    ),

    # ── DIAGNOSIS / MEDICAL CODES ────────────────────────────────────────────
    PatternDef(
        name="ICD_CODE",
        category="PHI",
        priority=8,
        description="ICD-10 diagnosis codes",
        pattern=_re(
            r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b"
        ),
    ),

    PatternDef(
        name="MEDICAL_CONDITION",
        category="PHI",
        priority=6,
        description="Common sensitive medical condition keywords",
        pattern=_re(
            r"\b(?:diabetes|hypertension|hiv|aids|cancer|tumor|seizure|"
            r"depression|anxiety|schizophrenia|bipolar|hepatitis|"
            r"cirrhosis|alzheimer[s']?|dementia|epilepsy|"
            r"substance\s+abuse|addiction|overdose|opioid|"
            r"pregnancy|pregnant|miscarriage|abortion)\b",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="MEDICATION",
        category="PHI",
        priority=6,
        description="Common prescription medication names",
        pattern=_re(
            r"\b(?:metformin|lisinopril|atorvastatin|levothyroxine|metoprolol|"
            r"amlodipine|omeprazole|losartan|gabapentin|sertraline|"
            r"zoloft|prozac|xanax|adderall|ritalin|oxycodone|hydrocodone|"
            r"tramadol|fentanyl|morphine|insulin|warfarin|eliquis|"
            r"ozempic|wegovy|humira|keytruda)\b",
            re.IGNORECASE,
        ),
    ),

    # ── NAMES — regex heuristic (NLP fallback via spaCy if available) ─────────
    PatternDef(
        name="PERSON",
        category="PII",
        priority=5,
        description="Honorific + capitalized name pattern",
        pattern=_re(
            r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Sir|Rev\.?)\s+"
            r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b"
        ),
    ),

    PatternDef(
        name="PERSON_FULL",
        category="PII",
        priority=4,
        description="Two+ capitalized words (name heuristic, lower priority)",
        pattern=_re(
            r"\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20})?\b"
        ),
    ),

    # ── ADDRESS ──────────────────────────────────────────────────────────────
    PatternDef(
        name="STREET_ADDRESS",
        category="PII",
        priority=8,
        description="US street addresses",
        pattern=_re(
            r"\d{1,5}\s+[A-Z][a-zA-Z0-9\s]{3,40}"
            r"\b(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|"
            r"Ln|Lane|Ct|Court|Pl|Place|Way|Pkwy|Hwy|Highway)\b",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="ZIP_CODE",
        category="PII",
        priority=7,
        description="US ZIP codes (5 or 9 digit)",
        pattern=_re(
            r"(?<!\d)\d{5}(?:-\d{4})?(?!\d)"
        ),
    ),

    PatternDef(
        name="CITY_STATE",
        category="PII",
        priority=5,
        description="City, State abbreviation patterns",
        pattern=_re(
            r"\b[A-Z][a-zA-Z\s]{2,25},\s*"
            r"(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|"
            r"MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|"
            r"SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b"
        ),
    ),

    # ── PASSPORT / NATIONAL IDs ───────────────────────────────────────────────
    PatternDef(
        name="PASSPORT",
        category="PII",
        priority=9,
        description="Passport numbers (US format)",
        pattern=_re(
            r"(?:passport(?:\s+(?:number|no|#))?)[:\s]*[A-Z]{1,2}\d{6,9}",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="DRIVERS_LICENSE",
        category="PII",
        priority=9,
        description="Driver's license preceded by keyword",
        pattern=_re(
            r"(?:driver[s']?\s+licen[sc]e|dl|d\.l\.)[:\s#]*[A-Z0-9\-]{5,15}",
            re.IGNORECASE,
        ),
    ),

    # ── GOVERNMENT IDs ───────────────────────────────────────────────────────
    PatternDef(
        name="EIN",
        category="FINANCIAL",
        priority=9,
        description="Employer Identification Numbers",
        pattern=_re(
            r"(?:EIN|employer\s+id(?:entification)?)[:\s#]*\d{2}-\d{7}",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="ITIN",
        category="PII",
        priority=9,
        description="Individual Taxpayer Identification Numbers",
        pattern=_re(
            r"(?:ITIN)[:\s#]*9\d{2}-[78]\d-\d{4}",
            re.IGNORECASE,
        ),
    ),

    # ── FINANCIAL ────────────────────────────────────────────────────────────
    PatternDef(
        name="SWIFT_BIC",
        category="FINANCIAL",
        priority=8,
        description="SWIFT / BIC codes",
        pattern=_re(
            r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"
        ),
    ),

    PatternDef(
        name="CRYPTO_ADDRESS",
        category="FINANCIAL",
        priority=8,
        description="Bitcoin and Ethereum wallet addresses",
        pattern=_re(
            r"(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}"           # Bitcoin
            r"|0x[a-fA-F0-9]{40}"                               # Ethereum
        ),
    ),

    # ── CREDENTIALS / SECRETS ────────────────────────────────────────────────
    PatternDef(
        name="API_KEY",
        category="CREDENTIAL",
        priority=10,
        description="Generic API keys / tokens preceded by keyword",
        pattern=_re(
            r"(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key)"
            r"[:\s='\"`]+[A-Za-z0-9\-_\.]{20,}",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="AWS_KEY",
        category="CREDENTIAL",
        priority=10,
        description="AWS access key IDs",
        pattern=_re(
            r"(?:AKIA|AIPA|ASIA)[0-9A-Z]{16}"
        ),
    ),

    PatternDef(
        name="PRIVATE_KEY",
        category="CREDENTIAL",
        priority=10,
        description="PEM private key blocks",
        pattern=_re(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
    ),

    PatternDef(
        name="PASSWORD",
        category="CREDENTIAL",
        priority=10,
        description="Passwords preceded by keyword",
        pattern=_re(
            r"(?:password|passwd|pwd|pass)[:\s='\"`]+\S{6,}",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="JWT_TOKEN",
        category="CREDENTIAL",
        priority=9,
        description="JSON Web Tokens",
        pattern=_re(
            r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
        ),
    ),

    # ── NETWORK / DEVICE ─────────────────────────────────────────────────────
    PatternDef(
        name="URL_WITH_CREDENTIALS",
        category="CREDENTIAL",
        priority=10,
        description="URLs with embedded username/password",
        pattern=_re(
            r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^@\s]+@[^\s]+"
        ),
    ),

    PatternDef(
        name="DOMAIN",
        category="NETWORK",
        priority=3,
        description="Fully-qualified domain names (low priority, context-dependent)",
        pattern=_re(
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|edu|gov|io|co)\b",
            re.IGNORECASE,
        ),
    ),

    # ── VEHICLE ──────────────────────────────────────────────────────────────
    PatternDef(
        name="VIN",
        category="PII",
        priority=9,
        description="Vehicle Identification Numbers",
        pattern=_re(
            r"\b[A-HJ-NPR-Z0-9]{17}\b"
        ),
    ),

    PatternDef(
        name="LICENSE_PLATE",
        category="PII",
        priority=7,
        description="US vehicle license plates preceded by keyword",
        pattern=_re(
            r"(?:license\s+plate|plate\s+(?:number|no|#))[:\s]*[A-Z0-9]{2,8}",
            re.IGNORECASE,
        ),
    ),

    # ── BIOMETRIC / HEALTH IDs ────────────────────────────────────────────────
    PatternDef(
        name="DEA_NUMBER",
        category="PHI",
        priority=9,
        description="DEA prescriber numbers",
        pattern=_re(
            r"\b(?:DEA)[:\s#]*[A-Z]{2}\d{7}\b",
            re.IGNORECASE,
        ),
    ),

    PatternDef(
        name="INSURANCE_ID",
        category="PHI",
        priority=8,
        description="Health insurance member IDs preceded by keyword",
        pattern=_re(
            r"(?:insurance|member|subscriber|policy)\s*(?:id|number|no|#)[:\s]*[A-Z0-9\-]{6,20}",
            re.IGNORECASE,
        ),
    ),

    # ── GEOGRAPHIC (PHI HIPAA small geo) ─────────────────────────────────────
    PatternDef(
        name="GEO_COORDS",
        category="PII",
        priority=7,
        description="Latitude/longitude coordinate pairs",
        pattern=_re(
            r"(?:lat(?:itude)?|lon(?:gitude)?)?[-+]?\d{1,3}\.\d{4,}[,\s]+[-+]?\d{1,3}\.\d{4,}",
            re.IGNORECASE,
        ),
    ),

    # ── AGE ───────────────────────────────────────────────────────────────────
    PatternDef(
        name="AGE",
        category="PHI",
        priority=5,
        description="Ages of individuals (especially > 89 is PHI under HIPAA)",
        pattern=_re(
            r"(?:age[d]?|years?\s+old)[:\s]*\d{1,3}",
            re.IGNORECASE,
        ),
    ),

    # ── RACE / ETHNICITY (SENSITIVE) ──────────────────────────────────────────
    PatternDef(
        name="RACE_ETHNICITY",
        category="SENSITIVE",
        priority=5,
        description="Self-reported race/ethnicity labels",
        pattern=_re(
            r"\b(?:caucasian|african[- ]american|hispanic|latino(?:\/a)?|"
            r"asian[- ]american|native\s+american|pacific\s+islander|"
            r"middle\s+eastern|multiracial)\b",
            re.IGNORECASE,
        ),
    ),

    # ── RELIGION ──────────────────────────────────────────────────────────────
    PatternDef(
        name="RELIGION",
        category="SENSITIVE",
        priority=4,
        description="Religious affiliations",
        pattern=_re(
            r"\b(?:christian|muslim|jewish|hindu|buddhist|sikh|atheist|"
            r"agnostic|catholic|protestant|evangelical|orthodox|sunni|shia)\b",
            re.IGNORECASE,
        ),
    ),

    # ── POLITICAL ─────────────────────────────────────────────────────────────
    PatternDef(
        name="POLITICAL_AFFILIATION",
        category="SENSITIVE",
        priority=4,
        description="Political party membership explicit statements",
        pattern=_re(
            r"(?:registered|lifelong|proud|devout)\s+"
            r"(?:democrat|republican|libertarian|green|socialist|communist)",
            re.IGNORECASE,
        ),
    ),

    # ── SEXUAL ORIENTATION ────────────────────────────────────────────────────
    PatternDef(
        name="SEXUAL_ORIENTATION",
        category="SENSITIVE",
        priority=4,
        description="Sexual orientation self-identifications",
        pattern=_re(
            r"\b(?:gay|lesbian|bisexual|transgender|queer|non[-\s]binary|"
            r"pansexual|asexual)\b",
            re.IGNORECASE,
        ),
    ),

    # ── CUSTOM ENTERPRISE ────────────────────────────────────────────────────
    # ↓ Add your own patterns here — they auto-load. Example:
    #
    # PatternDef(
    #     name="EMPLOYEE_ID",
    #     category="ENTERPRISE",
    #     priority=9,
    #     description="Internal employee badge IDs",
    #     pattern=_re(r"EMP-\d{6}", re.IGNORECASE),
    # ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Registry helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_enabled_patterns() -> List[PatternDef]:
    return [p for p in PATTERN_REGISTRY if p.enabled]


def get_patterns_by_category(category: str) -> List[PatternDef]:
    return [p for p in PATTERN_REGISTRY if p.category == category and p.enabled]


def disable_pattern(name: str) -> None:
    for p in PATTERN_REGISTRY:
        if p.name == name:
            p.enabled = False


def enable_pattern(name: str) -> None:
    for p in PATTERN_REGISTRY:
        if p.name == name:
            p.enabled = True


def list_categories() -> List[str]:
    return sorted(set(p.category for p in PATTERN_REGISTRY))
