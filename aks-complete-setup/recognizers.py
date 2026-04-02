"""
src/redactor/recognizers.py — Custom Presidio recognizers.

These extend Presidio's built-in coverage for entity types not included
or with insufficient accuracy in the default recognizer registry.

Each recognizer is a PatternRecognizer or EntityRecognizer subclass.
Add new ones at the bottom — they are auto-registered in engine.py.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _r(name: str, regex: str, score: float, context: list[str] | None = None) -> Pattern:
    return Pattern(name=name, regex=regex, score=score)


# ─────────────────────────────────────────────────────────────────────────────
# Financial
# ─────────────────────────────────────────────────────────────────────────────

class IBANRecognizer(PatternRecognizer):
    PATTERNS = [_r("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b", 0.85)]
    CONTEXT = ["iban", "international bank", "account number", "wire", "transfer"]

    def __init__(self):
        super().__init__(
            supported_entity="IBAN_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SWIFTRecognizer(PatternRecognizer):
    PATTERNS = [_r("swift", r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", 0.7)]
    CONTEXT = ["swift", "bic", "bank", "wire"]

    def __init__(self):
        super().__init__(
            supported_entity="SWIFT_BIC",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class CryptoAddressRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("bitcoin", r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b", 0.85),
        _r("ethereum", r"\b0x[a-fA-F0-9]{40}\b", 0.9),
    ]
    CONTEXT = ["btc", "bitcoin", "eth", "ethereum", "wallet", "crypto", "address"]

    def __init__(self):
        super().__init__(
            supported_entity="CRYPTO",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class BankAccountRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("account_kw", r"(?:account|acct|routing|aba)[:\s#]*\d{6,17}", 0.75),
    ]
    CONTEXT = ["account", "bank", "routing", "checking", "savings"]

    def __init__(self):
        super().__init__(
            supported_entity="BANK_ACCOUNT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class EINRecognizer(PatternRecognizer):
    PATTERNS = [_r("ein", r"(?:EIN|employer\s+id(?:entification)?)[:\s#]*\d{2}-\d{7}", 0.85)]
    CONTEXT = ["ein", "employer", "tax id", "federal"]

    def __init__(self):
        super().__init__(
            supported_entity="EIN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Credentials & Secrets
# ─────────────────────────────────────────────────────────────────────────────

class AWSKeyRecognizer(PatternRecognizer):
    PATTERNS = [_r("aws_key", r"(?:AKIA|AIPA|ASIA)[0-9A-Z]{16}", 0.95)]
    CONTEXT = ["aws", "amazon", "access", "key", "secret"]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_ACCESS_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class JWTRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("jwt", r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", 0.95)
    ]
    CONTEXT = ["bearer", "token", "authorization", "jwt", "auth"]

    def __init__(self):
        super().__init__(
            supported_entity="JWT_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class APIKeyRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("api_key_kw",
           r"(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key)"
           r"[:\s='\"`]+[A-Za-z0-9\-_\.]{20,}",
           0.85),
    ]
    CONTEXT = ["api", "key", "token", "secret", "authorization"]

    def __init__(self):
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class PasswordContextRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("password_kw",
           r"(?:password|passwd|pwd|pass)[:\s='\"`]+\S{6,}",
           0.85),
    ]
    CONTEXT = ["password", "passwd", "credential", "login", "secret"]

    def __init__(self):
        super().__init__(
            supported_entity="PASSWORD_CONTEXT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class PEMKeyRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("pem",
           r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?"
           r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
           0.99),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PRIVATE_KEY",
            patterns=self.PATTERNS,
        )


class URLWithCredentialsRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("url_creds",
           r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^@\s]+@[^\s]+",
           0.9),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="URL_WITH_CREDENTIALS",
            patterns=self.PATTERNS,
        )


# ─────────────────────────────────────────────────────────────────────────────
# PHI
# ─────────────────────────────────────────────────────────────────────────────

class MedicalRecordRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("mrn",
           r"(?:MRN|medical\s+record|patient\s+(?:id|number|#))[:\s#]*[A-Z0-9\-]{4,20}",
           0.85),
    ]
    CONTEXT = ["mrn", "medical record", "patient id", "record number"]

    def __init__(self):
        super().__init__(
            supported_entity="MEDICAL_RECORD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class NPIRecognizer(PatternRecognizer):
    PATTERNS = [_r("npi", r"(?:NPI)[:\s#]*\d{10}", 0.9)]
    CONTEXT = ["npi", "provider", "national provider"]

    def __init__(self):
        super().__init__(
            supported_entity="NPI",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class ICD10Recognizer(PatternRecognizer):
    PATTERNS = [_r("icd10", r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b", 0.6)]
    CONTEXT = ["diagnosis", "icd", "code", "condition", "disorder"]

    def __init__(self):
        super().__init__(
            supported_entity="ICD_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class DEARecognizer(PatternRecognizer):
    PATTERNS = [_r("dea", r"\b(?:DEA)[:\s#]*[A-Z]{2}\d{7}\b", 0.9)]
    CONTEXT = ["dea", "prescriber", "prescription", "controlled"]

    def __init__(self):
        super().__init__(
            supported_entity="DEA_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class InsuranceIDRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("ins_id",
           r"(?:insurance|member|subscriber|policy)\s*(?:id|number|no|#)"
           r"[:\s]*[A-Z0-9\-]{6,20}",
           0.75),
    ]
    CONTEXT = ["insurance", "member", "subscriber", "policy", "health plan"]

    def __init__(self):
        super().__init__(
            supported_entity="INSURANCE_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class MedicalConditionRecognizer(PatternRecognizer):
    # 50+ sensitive medical conditions per HIPAA
    _CONDITIONS = (
        r"diabetes|hypertension|hiv\b|aids\b|cancer|tumor|seizure|epilepsy|"
        r"depression|anxiety|schizophrenia|bipolar|hepatitis|cirrhosis|"
        r"alzheimer[s']?|dementia|parkinson[s']?|multiple\s+sclerosis|"
        r"substance\s+abuse|addiction|overdose|opioid|"
        r"pregnancy|pregnant|miscarriage|abortion|"
        r"anorexia|bulimia|eating\s+disorder|"
        r"ptsd|post[\-\s]traumatic|suicidal|self[\-\s]harm|"
        r"lupus|rheumatoid|crohn[s']?|colitis|celiac|"
        r"asthma|copd|emphysema|tuberculosis|tb\b|"
        r"stroke|heart\s+attack|myocardial\s+infarction|"
        r"kidney\s+disease|renal\s+failure|dialysis|"
        r"liver\s+disease|fatty\s+liver|"
        r"sickle\s+cell|hemophilia|leukemia|lymphoma"
    )
    PATTERNS = [_r("condition", rf"\b(?:{_CONDITIONS})\b", 0.65)]
    CONTEXT = ["patient", "diagnosis", "condition", "history", "medical", "treatment"]

    def __init__(self):
        super().__init__(
            supported_entity="MEDICAL_CONDITION",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class MedicationRecognizer(PatternRecognizer):
    _MEDS = (
        r"metformin|lisinopril|atorvastatin|levothyroxine|metoprolol|"
        r"amlodipine|omeprazole|losartan|gabapentin|sertraline|"
        r"zoloft|prozac|xanax|adderall|ritalin|oxycodone|hydrocodone|"
        r"tramadol|fentanyl|morphine|codeine|insulin|warfarin|eliquis|"
        r"ozempic|wegovy|humira|keytruda|remicade|enbrel|"
        r"prednisone|methylprednisolone|dexamethasone|"
        r"amoxicillin|azithromycin|doxycycline|ciprofloxacin|"
        r"abilify|seroquel|risperdal|lithium|valium|klonopin|"
        r"vyvanse|concerta|strattera|wellbutrin|effexor|lexapro|"
        r"crestor|lipitor|zocor|plavix|aspirin|ibuprofen|acetaminophen"
    )
    PATTERNS = [_r("medication", rf"\b(?:{_MEDS})\b", 0.7)]
    CONTEXT = ["prescribed", "medication", "drug", "dose", "mg", "tablet", "rx"]

    def __init__(self):
        super().__init__(
            supported_entity="MEDICATION",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Network
# ─────────────────────────────────────────────────────────────────────────────

class IPv6Recognizer(PatternRecognizer):
    PATTERNS = [
        _r("ipv6",
           r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
           r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
           r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}",
           0.75),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IPV6_ADDRESS",
            patterns=self.PATTERNS,
        )


class MACAddressRecognizer(PatternRecognizer):
    PATTERNS = [
        _r("mac", r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", 0.75)
    ]
    CONTEXT = ["mac", "hardware", "device", "address", "interface"]

    def __init__(self):
        super().__init__(
            supported_entity="MAC_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Government / Identity
# ─────────────────────────────────────────────────────────────────────────────

class VINRecognizer(PatternRecognizer):
    PATTERNS = [_r("vin", r"\b[A-HJ-NPR-Z0-9]{17}\b", 0.75)]
    CONTEXT = ["vin", "vehicle", "car", "identification", "number"]

    def __init__(self):
        super().__init__(
            supported_entity="VIN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class ITINRecognizer(PatternRecognizer):
    PATTERNS = [_r("itin", r"(?:ITIN)[:\s#]*9\d{2}-[78]\d-\d{4}", 0.9)]
    CONTEXT = ["itin", "individual taxpayer", "tax"]

    def __init__(self):
        super().__init__(
            supported_entity="ITIN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive
# ─────────────────────────────────────────────────────────────────────────────

class RaceEthnicityRecognizer(PatternRecognizer):
    _RACES = (
        r"caucasian|african[- ]american|hispanic|latino(?:\/a)?|"
        r"asian[- ]american|native\s+american|pacific\s+islander|"
        r"middle\s+eastern|multiracial|biracial"
    )
    PATTERNS = [_r("race", rf"\b(?:{_RACES})\b", 0.6)]
    CONTEXT = ["race", "ethnicity", "identifies", "background", "heritage"]

    def __init__(self):
        super().__init__(
            supported_entity="RACE_ETHNICITY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SexualOrientationRecognizer(PatternRecognizer):
    _ORIENT = (
        r"gay|lesbian|bisexual|transgender|queer|non[-\s]binary|"
        r"pansexual|asexual|lgbtq\+?"
    )
    PATTERNS = [_r("orientation", rf"\b(?:{_ORIENT})\b", 0.6)]
    CONTEXT = ["identifies", "orientation", "gender", "sexuality", "lgbtq"]

    def __init__(self):
        super().__init__(
            supported_entity="SEXUAL_ORIENTATION",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class ReligionRecognizer(PatternRecognizer):
    _REL = (
        r"christian|muslim|jewish|hindu|buddhist|sikh|atheist|"
        r"agnostic|catholic|protestant|evangelical|orthodox|"
        r"sunni|shia|mormon|jehovah[s']?\s+witness"
    )
    PATTERNS = [_r("religion", rf"\b(?:{_REL})\b", 0.55)]
    CONTEXT = ["religion", "faith", "church", "mosque", "temple", "belief", "worship"]

    def __init__(self):
        super().__init__(
            supported_entity="RELIGION",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Registry — all custom recognizers auto-loaded by engine.py
# ─────────────────────────────────────────────────────────────────────────────

CUSTOM_RECOGNIZERS = [
    # Financial
    IBANRecognizer,
    SWIFTRecognizer,
    CryptoAddressRecognizer,
    BankAccountRecognizer,
    EINRecognizer,
    # Credentials
    AWSKeyRecognizer,
    JWTRecognizer,
    APIKeyRecognizer,
    PasswordContextRecognizer,
    PEMKeyRecognizer,
    URLWithCredentialsRecognizer,
    # PHI
    MedicalRecordRecognizer,
    NPIRecognizer,
    ICD10Recognizer,
    DEARecognizer,
    InsuranceIDRecognizer,
    MedicalConditionRecognizer,
    MedicationRecognizer,
    # Network
    IPv6Recognizer,
    MACAddressRecognizer,
    # Identity
    VINRecognizer,
    ITINRecognizer,
    # Sensitive
    RaceEthnicityRecognizer,
    SexualOrientationRecognizer,
    ReligionRecognizer,
]
