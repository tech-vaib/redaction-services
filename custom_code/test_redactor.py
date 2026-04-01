"""
tests/test_redactor.py — Comprehensive test suite for the redaction engine.

Run with:
    pytest tests/ -v
    pytest tests/ -v --tb=short
"""

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from redactor import Redactor, get_enabled_patterns, list_categories
from redactor.engine import RedactionResult


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def redactor():
    """Shared redactor instance (no spaCy for speed in unit tests)."""
    return Redactor(use_spacy=False, consistent_tokens=True)


@pytest.fixture(scope="module")
def fresh():
    """New redactor per test group needing clean counters."""
    return Redactor(use_spacy=False, consistent_tokens=False)


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def redacts(redactor, text, label=None):
    result = redactor.redact(text)
    if label:
        found_labels = {e.label for e in result.entities}
        assert label in found_labels, (
            f"Expected label '{label}' in {found_labels}\nText: {text}\n"
            f"Redacted: {result.redacted_text}"
        )
    assert result.redacted_text != text or result.entity_count == 0
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PII — Email
# ─────────────────────────────────────────────────────────────────────────────

class TestEmail:
    cases = [
        "Contact john.doe@example.com for info",
        "Email: user+tag@sub.domain.co.uk",
        "SUPPORT@COMPANY.ORG",
        "first.last@government.gov",
    ]

    @pytest.mark.parametrize("text", cases)
    def test_email_detected(self, redactor, text):
        redacts(redactor, text, "EMAIL")

    def test_token_format(self, redactor):
        r = Redactor(use_spacy=False, consistent_tokens=False)
        result = r.redact("john@example.com and jane@example.com")
        assert "[EMAIL_1]" in result.redacted_text
        assert "[EMAIL_2]" in result.redacted_text

    def test_same_email_same_token(self, redactor):
        r = Redactor(use_spacy=False, consistent_tokens=True)
        result = r.redact("john@x.com called, reply to john@x.com")
        tokens = [t for t in result.token_map if "EMAIL" in t]
        assert len(tokens) == 1, "Same email should get same token"


# ─────────────────────────────────────────────────────────────────────────────
# PII — Phone
# ─────────────────────────────────────────────────────────────────────────────

class TestPhone:
    cases = [
        "Call 555-123-4567",
        "Phone: (800) 555-0100",
        "Reach me at 800.555.0199",
        "Tel: +1 415 555 2671",
        "+44 20 7946 0958",
    ]

    @pytest.mark.parametrize("text", cases)
    def test_phone_detected(self, redactor, text):
        redacts(redactor, text, "PHONE")


# ─────────────────────────────────────────────────────────────────────────────
# PII — SSN
# ─────────────────────────────────────────────────────────────────────────────

class TestSSN:
    valid = [
        "SSN: 123-45-6789",
        "Social: 987 65 4320",
        "My number is 456-78-9012",
    ]
    invalid = [
        "000-12-3456",   # invalid group
        "666-12-3456",   # invalid group
        "900-12-3456",   # invalid group
    ]

    @pytest.mark.parametrize("text", valid)
    def test_ssn_valid(self, redactor, text):
        redacts(redactor, text, "SSN")

    @pytest.mark.parametrize("text", invalid)
    def test_ssn_invalid_not_matched(self, redactor, text):
        result = redactor.redact(text)
        labels = {e.label for e in result.entities}
        assert "SSN" not in labels


# ─────────────────────────────────────────────────────────────────────────────
# Financial
# ─────────────────────────────────────────────────────────────────────────────

class TestCreditCard:
    cases = [
        ("4532015112830366", "CREDIT_CARD"),      # Visa
        ("5425233430109903", "CREDIT_CARD"),      # MC
        ("374251018720955",  "CREDIT_CARD"),      # Amex
        ("6011000990139424", "CREDIT_CARD"),      # Discover
        ("4532-0151-1283-0366", "CREDIT_CARD"),   # With dashes
    ]

    @pytest.mark.parametrize("number,label", cases)
    def test_card_detected(self, redactor, number, label):
        redacts(redactor, f"Card: {number}", label)


class TestBankAccount:
    def test_account_keyword(self, redactor):
        redacts(redactor, "Account: 123456789012", "BANK_ACCOUNT")

    def test_routing_keyword(self, redactor):
        redacts(redactor, "Routing #021000021", "BANK_ACCOUNT")

    def test_iban(self, redactor):
        redacts(redactor, "IBAN: GB29NWBK60161331926819", "IBAN")


# ─────────────────────────────────────────────────────────────────────────────
# Network
# ─────────────────────────────────────────────────────────────────────────────

class TestNetwork:
    def test_ipv4(self, redactor):
        redacts(redactor, "Server at 192.168.1.100", "IP_ADDRESS")

    def test_ipv6(self, redactor):
        redacts(redactor, "Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IPV6_ADDRESS")

    def test_mac(self, redactor):
        redacts(redactor, "MAC: 00:1A:2B:3C:4D:5E", "MAC_ADDRESS")

    def test_url_with_creds(self, redactor):
        redacts(redactor, "postgres://admin:s3cr3t@db.example.com/mydb", "URL_WITH_CREDENTIALS")


# ─────────────────────────────────────────────────────────────────────────────
# PHI
# ─────────────────────────────────────────────────────────────────────────────

class TestPHI:
    def test_date(self, redactor):
        redacts(redactor, "DOB: 01/15/1985", "DATE")

    def test_date_long(self, redactor):
        redacts(redactor, "Admitted January 5th, 2024", "DATE")

    def test_medical_record(self, redactor):
        redacts(redactor, "MRN: A1234567", "MEDICAL_RECORD")

    def test_icd_code(self, redactor):
        redacts(redactor, "Diagnosis: E11.9", "ICD_CODE")

    def test_medical_condition(self, redactor):
        redacts(redactor, "Patient has diabetes and hypertension", "MEDICAL_CONDITION")

    def test_medication(self, redactor):
        redacts(redactor, "Prescribed metformin 500mg", "MEDICATION")

    def test_insurance_id(self, redactor):
        redacts(redactor, "Insurance member ID: XYZ123456", "INSURANCE_ID")

    def test_npi(self, redactor):
        redacts(redactor, "NPI: 1234567890", "NPI")


# ─────────────────────────────────────────────────────────────────────────────
# Credentials
# ─────────────────────────────────────────────────────────────────────────────

class TestCredentials:
    def test_api_key(self, redactor):
        redacts(redactor, "api_key=sk-abc123def456ghi789jkl012", "API_KEY")

    def test_aws_key(self, redactor):
        redacts(redactor, "Key: AKIAIOSFODNN7EXAMPLE", "AWS_KEY")

    def test_password(self, redactor):
        redacts(redactor, "password: Sup3rS3cr3t!", "PASSWORD")

    def test_jwt(self, redactor):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        redacts(redactor, f"Bearer {token}", "JWT_TOKEN")

    def test_private_key(self, redactor):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        redacts(redactor, pem, "PRIVATE_KEY")


# ─────────────────────────────────────────────────────────────────────────────
# Government IDs
# ─────────────────────────────────────────────────────────────────────────────

class TestGovIDs:
    def test_passport(self, redactor):
        redacts(redactor, "Passport number: A12345678", "PASSPORT")

    def test_drivers_license(self, redactor):
        redacts(redactor, "DL: D1234567", "DRIVERS_LICENSE")

    def test_ein(self, redactor):
        redacts(redactor, "EIN: 12-3456789", "EIN")

    def test_vin(self, redactor):
        redacts(redactor, "VIN: 1HGBH41JXMN109186", "VIN")


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive categories
# ─────────────────────────────────────────────────────────────────────────────

class TestSensitive:
    def test_race(self, redactor):
        redacts(redactor, "Patient identified as African-American", "RACE_ETHNICITY")

    def test_religion(self, redactor):
        redacts(redactor, "He is Catholic and attends weekly", "RELIGION")

    def test_sexual_orientation(self, redactor):
        redacts(redactor, "She identifies as bisexual", "SEXUAL_ORIENTATION")


# ─────────────────────────────────────────────────────────────────────────────
# Token consistency
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenConsistency:
    def test_consistent_tokens(self):
        r = Redactor(use_spacy=False, consistent_tokens=True)
        text = "Email john@x.com, also john@x.com"
        result = r.redact(text)
        assert result.redacted_text.count("[EMAIL_1]") == 2

    def test_different_values_different_tokens(self):
        r = Redactor(use_spacy=False, consistent_tokens=False)
        result = r.redact("john@x.com and jane@y.com")
        assert "[EMAIL_1]" in result.redacted_text
        assert "[EMAIL_2]" in result.redacted_text

    def test_no_original_in_redacted(self):
        r = Redactor(use_spacy=False)
        cases = [
            "SSN 123-45-6789",
            "email@test.com",
            "Card 4532015112830366",
        ]
        for text in cases:
            result = r.redact(text)
            for ent in result.entities:
                assert ent.value not in result.redacted_text


# ─────────────────────────────────────────────────────────────────────────────
# Category filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestCategoryFiltering:
    def test_redact_only_financial(self):
        r = Redactor(use_spacy=False, redact_categories=["FINANCIAL"])
        text = "Email me at john@x.com, card 4532015112830366"
        result = r.redact(text)
        assert "john@x.com" in result.redacted_text  # email NOT redacted
        assert "4532015112830366" not in result.redacted_text  # card IS redacted

    def test_skip_sensitive_category(self):
        r = Redactor(use_spacy=False, skip_categories=["SENSITIVE"])
        text = "Patient is Catholic and has SSN 123-45-6789"
        result = r.redact(text)
        assert "Catholic" in result.redacted_text  # religion NOT redacted
        assert "123-45-6789" not in result.redacted_text  # SSN IS redacted


# ─────────────────────────────────────────────────────────────────────────────
# Overlap resolution
# ─────────────────────────────────────────────────────────────────────────────

class TestOverlapResolution:
    def test_no_duplicate_tokens(self):
        r = Redactor(use_spacy=False)
        # SSN pattern should win over generic number patterns
        result = r.redact("SSN: 123-45-6789 and email foo@bar.com")
        labels = [e.label for e in result.entities]
        # No duplicated spans
        positions = [(e.start, e.end) for e in result.entities]
        assert len(positions) == len(set(positions)), "Duplicate spans detected"


# ─────────────────────────────────────────────────────────────────────────────
# Multi-entity text
# ─────────────────────────────────────────────────────────────────────────────

class TestMultiEntity:
    def test_complex_paragraph(self):
        r = Redactor(use_spacy=False)
        text = (
            "Patient John Smith (DOB: 03/15/1982, SSN: 456-78-9012) "
            "was admitted on 01/10/2024. "
            "Contact: jsmith@hospital.org or (555) 987-6543. "
            "Insurance member ID: ABC123456. "
            "Credit card on file: 4532015112830366. "
            "Diagnosis: E11.9 (Type 2 Diabetes)."
        )
        result = r.redact(text)
        assert result.entity_count >= 5
        # Verify none of the sensitive values appear in redacted text
        sensitive = ["456-78-9012", "jsmith@hospital.org", "555) 987-6543",
                     "4532015112830366"]
        for val in sensitive:
            assert val not in result.redacted_text, f"Value not redacted: {val}"

    def test_structure_preserved(self):
        r = Redactor(use_spacy=False)
        text = "Name: John Smith\nEmail: john@x.com\nPhone: 555-000-1234"
        result = r.redact(text)
        assert "Name:" in result.redacted_text
        assert "Email:" in result.redacted_text
        assert "Phone:" in result.redacted_text
        assert "\n" in result.redacted_text


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistry:
    def test_patterns_loaded(self):
        patterns = get_enabled_patterns()
        assert len(patterns) > 20

    def test_categories_present(self):
        cats = list_categories()
        expected = {"PII", "PHI", "FINANCIAL", "NETWORK", "CREDENTIAL"}
        assert expected.issubset(set(cats))

    def test_result_to_dict(self):
        r = Redactor(use_spacy=False)
        result = r.redact("email@test.com")
        d = result.to_dict()
        assert "redacted_text" in d
        assert "entities" in d
        assert "token_map" in d
