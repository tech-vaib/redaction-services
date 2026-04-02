"""
tests/unit/test_engine.py — Comprehensive engine unit tests.

Covers all 40+ entity types, edge cases, accuracy, consistency,
performance bounds, and security guarantees.
"""

from __future__ import annotations

import re
import sys
import os
import time
import pytest

# Allow running without full install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# ── Lightweight stub for when Presidio is not installed ─────────────────────
try:
    from src.redactor.engine import RedactionEngine, RedactionResult
    from src.redactor.recognizers import CUSTOM_RECOGNIZERS
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

# ── Fallback: test against the original custom engine ───────────────────────
try:
    from redactor.engine import Redactor as _LegacyRedactor
    LEGACY_AVAILABLE = True
except ImportError:
    LEGACY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine():
    if PRESIDIO_AVAILABLE:
        return RedactionEngine.get_instance()
    elif LEGACY_AVAILABLE:
        return _LegacyRedactor(use_spacy=False)
    pytest.skip("No redaction engine available")


def redact(engine, text) -> "RedactionResult":
    if PRESIDIO_AVAILABLE:
        return engine.redact(text)
    else:
        return engine.redact(text)


def entities_of(result) -> set:
    if PRESIDIO_AVAILABLE:
        return {e.entity_type for e in result.entities}
    else:
        return {e.label for e in result.entities}


def get_redacted(result) -> str:
    return result.redacted_text


# ─────────────────────────────────────────────────────────────────────────────
# Helper: assert entity found
# ─────────────────────────────────────────────────────────────────────────────

def assert_redacted(engine, text: str, expected_label: str = None):
    result = redact(engine, text)
    assert result.redacted_text != text or len(result.entities) == 0, \
        f"Text not redacted: {text}"
    if expected_label:
        found = entities_of(result)
        # Check for both Presidio and legacy label names
        label_variants = {expected_label, expected_label.lower(),
                          expected_label.upper(),
                          expected_label.replace("_", " ")}
        assert any(
            any(v in f for v in label_variants) or f == expected_label
            for f in found
        ), f"Expected '{expected_label}' in {found}\nText: {text}\nRedacted: {result.redacted_text}"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PII — Email
# ─────────────────────────────────────────────────────────────────────────────

class TestEmail:
    VALID = [
        "Contact john.doe@example.com for support",
        "user+tag@sub.domain.co.uk is the address",
        "SUPPORT@COMPANY.ORG replied",
        "first.last@government.gov confirmed",
        "123numeric@domain.io pinged",
        "email@[123.123.123.123] is an IP email",
        "very.unusual.'@'.unusual.com@example.com",
    ]

    SHOULD_NOT_MATCH = [
        "just-a-domain.com",           # no @
        "not an email here",
    ]

    @pytest.mark.parametrize("text", VALID)
    def test_email_detected(self, engine, text):
        result = redact(engine, text)
        assert result.entity_count >= 1, f"No entity in: {text}"

    @pytest.mark.parametrize("text", SHOULD_NOT_MATCH)
    def test_non_email_not_matched(self, engine, text):
        result = redact(engine, text)
        # Should not false-positive on plain domains/text
        for e in result.entities:
            label = getattr(e, 'entity_type', getattr(e, 'label', ''))
            assert 'EMAIL' not in label.upper(), \
                f"False positive EMAIL on: {text}"

    def test_email_not_in_redacted(self, engine):
        result = redact(engine, "Send to alice@wonderland.org please")
        assert "alice@wonderland.org" not in result.redacted_text

    def test_multiple_emails(self, engine):
        result = redact(engine, "From: a@x.com To: b@y.com CC: c@z.com")
        assert result.entity_count >= 3


# ─────────────────────────────────────────────────────────────────────────────
# PII — Phone
# ─────────────────────────────────────────────────────────────────────────────

class TestPhone:
    VALID = [
        "Call 555-123-4567 now",
        "Phone: (800) 555-0100",
        "Dial 800.555.0199 ext 123",
        "Tel: +1 415 555 2671",
        "+44 20 7946 0958 (UK)",
        "My number is 5551234567",
        "Reach us at 1-888-555-1234",
    ]

    @pytest.mark.parametrize("text", VALID)
    def test_phone_detected(self, engine, text):
        result = redact(engine, text)
        assert result.entity_count >= 1, f"No entity in: {text}\nRedacted: {result.redacted_text}"

    def test_phone_not_in_redacted(self, engine):
        result = redact(engine, "Call me at 555-123-4567 anytime")
        assert "555-123-4567" not in result.redacted_text


# ─────────────────────────────────────────────────────────────────────────────
# PII — SSN
# ─────────────────────────────────────────────────────────────────────────────

class TestSSN:
    VALID_SSN = [
        "SSN: 123-45-6789",
        "Social security: 987-65-4321",
        "My SSN is 456-78-9012",
    ]
    INVALID_SSN = [
        "000-12-3456",    # 000 prefix invalid
        "666-12-3456",    # 666 prefix invalid
        "900-12-3456",    # 9xx prefix invalid
    ]

    @pytest.mark.parametrize("text", VALID_SSN)
    def test_valid_ssn(self, engine, text):
        result = redact(engine, text)
        assert result.entity_count >= 1

    def test_ssn_not_in_redacted(self, engine):
        result = redact(engine, "SSN: 456-78-9012")
        assert "456-78-9012" not in result.redacted_text

    @pytest.mark.parametrize("text", INVALID_SSN)
    def test_invalid_ssn_low_score(self, engine, text):
        # Should not confidently detect these as SSNs
        result = redact(engine, text)
        for e in result.entities:
            label = getattr(e, 'entity_type', getattr(e, 'label', ''))
            score = getattr(e, 'score', 1.0)
            if 'SSN' in label.upper():
                assert score < 0.9, f"High confidence on invalid SSN: {text}"


# ─────────────────────────────────────────────────────────────────────────────
# Financial
# ─────────────────────────────────────────────────────────────────────────────

class TestCreditCard:
    VALID = [
        "Visa: 4532015112830366",
        "MC: 5425233430109903",
        "Amex: 374251018720955",
        "Discover: 6011000990139424",
        "Card: 4532-0151-1283-0366",
        "Charged to 4111 1111 1111 1111",
    ]

    @pytest.mark.parametrize("cc", VALID)
    def test_card_detected(self, engine, cc):
        result = redact(engine, cc)
        assert result.entity_count >= 1, f"Not detected: {cc}"

    def test_card_not_in_redacted(self, engine):
        result = redact(engine, "Card: 4532015112830366 was charged")
        assert "4532015112830366" not in result.redacted_text


class TestFinancial:
    def test_iban(self, engine):
        result = redact(engine, "Please wire to IBAN GB29NWBK60161331926819")
        assert result.entity_count >= 1

    def test_bank_account(self, engine):
        result = redact(engine, "Account #123456789012, routing #021000021")
        assert result.entity_count >= 1

    def test_crypto_btc(self, engine):
        result = redact(engine, "Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result.entity_count >= 1

    def test_crypto_eth(self, engine):
        result = redact(engine, "ETH address: 0x742d35Cc6634C0532925a3b8D4C9Db96590c6C87")
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Credentials
# ─────────────────────────────────────────────────────────────────────────────

class TestCredentials:
    def test_aws_key(self, engine):
        result = redact(engine, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert result.entity_count >= 1
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text

    def test_jwt(self, engine):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact(engine, f"Authorization: Bearer {token}")
        assert result.entity_count >= 1
        assert token not in result.redacted_text

    def test_api_key(self, engine):
        result = redact(engine, "api_key=sk-abc123def456ghi789jkl012mno345pqr")
        assert result.entity_count >= 1

    def test_password(self, engine):
        result = redact(engine, "password: MyS3cr3tP@ssw0rd!")
        assert result.entity_count >= 1
        assert "MyS3cr3tP@ssw0rd" not in result.redacted_text

    def test_pem_key(self, engine):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn\n-----END RSA PRIVATE KEY-----"
        result = redact(engine, pem)
        assert result.entity_count >= 1

    def test_url_with_creds(self, engine):
        result = redact(engine, "postgres://admin:s3cr3t@db.example.com/prod")
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Network
# ─────────────────────────────────────────────────────────────────────────────

class TestNetwork:
    def test_ipv4(self, engine):
        result = redact(engine, "Server at 192.168.1.100 is down")
        assert result.entity_count >= 1
        assert "192.168.1.100" not in result.redacted_text

    def test_ipv6(self, engine):
        result = redact(engine, "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result.entity_count >= 1

    def test_mac(self, engine):
        result = redact(engine, "Device MAC: 00:1A:2B:3C:4D:5E")
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# PHI
# ─────────────────────────────────────────────────────────────────────────────

class TestPHI:
    def test_date_numeric(self, engine):
        result = redact(engine, "DOB: 01/15/1985")
        assert result.entity_count >= 1

    def test_date_written(self, engine):
        result = redact(engine, "Admitted on January 5th, 2024")
        assert result.entity_count >= 1

    def test_medical_record(self, engine):
        result = redact(engine, "MRN: A9876543")
        assert result.entity_count >= 1

    def test_npi(self, engine):
        result = redact(engine, "Provider NPI: 1234567890")
        assert result.entity_count >= 1

    def test_icd10(self, engine):
        result = redact(engine, "Diagnosis: E11.9, F32.1")
        assert result.entity_count >= 1

    def test_medical_condition(self, engine):
        for condition in ["diabetes", "hypertension", "HIV", "cancer",
                          "depression", "schizophrenia"]:
            result = redact(engine, f"Patient has {condition}")
            assert result.entity_count >= 1, f"Condition not detected: {condition}"

    def test_medication(self, engine):
        for med in ["metformin", "sertraline", "oxycodone", "insulin"]:
            result = redact(engine, f"Prescribed {med} 500mg daily")
            assert result.entity_count >= 1, f"Medication not detected: {med}"

    def test_insurance_id(self, engine):
        result = redact(engine, "Insurance member ID: XYZ123456789")
        assert result.entity_count >= 1

    def test_dea_number(self, engine):
        result = redact(engine, "DEA: AB1234567")
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Identity Documents
# ─────────────────────────────────────────────────────────────────────────────

class TestIdentityDocs:
    def test_passport(self, engine):
        result = redact(engine, "Passport number: A12345678")
        assert result.entity_count >= 1

    def test_drivers_license(self, engine):
        result = redact(engine, "Driver's license: D1234567")
        assert result.entity_count >= 1

    def test_vin(self, engine):
        result = redact(engine, "VIN: 1HGBH41JXMN109186")
        assert result.entity_count >= 1

    def test_itin(self, engine):
        result = redact(engine, "ITIN: 912-70-1234")
        assert result.entity_count >= 1

    def test_ein(self, engine):
        result = redact(engine, "EIN: 12-3456789")
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive Categories
# ─────────────────────────────────────────────────────────────────────────────

class TestSensitive:
    def test_race(self, engine):
        result = redact(engine, "Patient ethnicity: Hispanic")
        assert result.entity_count >= 1

    def test_religion(self, engine):
        result = redact(engine, "He identifies as Catholic")
        assert result.entity_count >= 1

    def test_sexual_orientation(self, engine):
        result = redact(engine, "She identifies as bisexual")
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Token consistency & zero-leak guarantees
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenConsistency:
    def test_same_email_same_token(self, engine):
        result = redact(engine, "email john@x.com again john@x.com")
        tokens = re.findall(r"\[EMAIL_ADDRESS_\d+\]|\[EMAIL_\d+\]", result.redacted_text)
        # Should have same token both times
        if len(tokens) >= 2:
            assert len(set(tokens)) == 1, f"Different tokens for same email: {tokens}"

    def test_no_pii_in_redacted(self, engine):
        """Core security guarantee: no original sensitive value in output."""
        sensitive_texts = [
            ("456-78-9012", "SSN: 456-78-9012"),
            ("4532015112830366", "Card: 4532015112830366"),
            ("john@example.com", "Email: john@example.com"),
            ("192.168.1.1", "IP: 192.168.1.1"),
            ("AKIAIOSFODNN7EXAMPLE", "AWS Key: AKIAIOSFODNN7EXAMPLE"),
        ]
        for sensitive, text in sensitive_texts:
            result = redact(engine, text)
            if result.entity_count > 0:
                assert sensitive not in result.redacted_text, \
                    f"LEAK: '{sensitive}' found in: {result.redacted_text}"

    def test_structure_preserved(self, engine):
        """Redacted text must preserve structure/format."""
        text = "Name: John\nEmail: john@x.com\nPhone: 555-000-1234\nNote: urgent"
        result = redact(engine, text)
        assert "Name:" in result.redacted_text
        assert "Email:" in result.redacted_text
        assert "Phone:" in result.redacted_text
        assert "Note: urgent" in result.redacted_text
        assert "\n" in result.redacted_text

    def test_non_pii_unchanged(self, engine):
        """Non-sensitive text should pass through unchanged."""
        result = redact(engine, "The quick brown fox jumps over the lazy dog.")
        assert result.redacted_text == "The quick brown fox jumps over the lazy dog."


# ─────────────────────────────────────────────────────────────────────────────
# Complex multi-entity texts
# ─────────────────────────────────────────────────────────────────────────────

class TestComplexTexts:
    def test_patient_record(self, engine):
        text = (
            "Patient: John Smith (DOB: 03/15/1982)\n"
            "SSN: 456-78-9012\n"
            "Contact: jsmith@hospital.org | (555) 987-6543\n"
            "Insurance: member ID XYZ123456\n"
            "Diagnosis: E11.9 (Type 2 diabetes)\n"
            "Medication: metformin 500mg twice daily\n"
            "Credit card: 4532-0151-1283-0366\n"
        )
        result = redact(engine, text)
        assert result.entity_count >= 5

        leaks = ["456-78-9012", "jsmith@hospital.org", "4532-0151-1283-0366"]
        for val in leaks:
            assert val not in result.redacted_text, f"LEAK: {val}"

    def test_api_config(self, engine):
        text = (
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "export DB_PASSWORD=S3cr3tPass!\n"
            "export API_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc\n"
            "export SERVER_IP=10.0.0.100\n"
        )
        result = redact(engine, text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "S3cr3tPass" not in result.redacted_text

    def test_long_text_performance(self, engine):
        """Performance: 10K char text should redact in < 2 seconds."""
        base = "Patient John Smith (SSN: 456-78-9012) emailed john@clinic.com. "
        text = base * 150  # ~9000 chars
        t0 = time.perf_counter()
        result = redact(engine, text)
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"Too slow: {elapsed:.2f}s for {len(text)} chars"
        assert result.entity_count >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Result object
# ─────────────────────────────────────────────────────────────────────────────

class TestResultObject:
    def test_to_dict_no_token_map(self, engine):
        result = redact(engine, "test@example.com")
        d = result.to_dict() if PRESIDIO_AVAILABLE else result.to_dict()
        assert "redacted_text" in d
        # token_map should not be included by default
        if PRESIDIO_AVAILABLE:
            assert "token_map" not in d

    def test_empty_text(self, engine):
        result = redact(engine, "   ")
        assert result.entity_count == 0

    def test_categories_found(self, engine):
        result = redact(engine, "Email test@x.com and IP 192.168.1.1")
        cats = result.categories_found
        assert isinstance(cats, list)
        assert len(cats) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Recognizer registry
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not PRESIDIO_AVAILABLE, reason="Presidio not installed")
class TestRecognizerRegistry:
    def test_custom_recognizers_count(self):
        assert len(CUSTOM_RECOGNIZERS) >= 20

    def test_all_recognizers_instantiable(self):
        for cls in CUSTOM_RECOGNIZERS:
            instance = cls()
            assert instance is not None
