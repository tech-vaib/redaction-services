Instructions to Run Locally
1. Install Python 3.8+
##2. Install dependencies:
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_sm

Optional Google DLP fallback:
pip install google-cloud-dlp
export GOOGLE_PROJECT_ID="your-google-project-id"
gcloud auth application-default login

If you don’t want Google fallback, keep GOOGLE_DLP_FALLBACK_ENABLED = False and no Google setup is needed.
# 3. Run the script:
python pii_redaction_service.py

You should see:

Original text
Redacted text (tokens like [PERSON_1], [ORDER_ID_1])
Detected entities with original value

###How to Add Missing PII / PHI Patterns

#Open CUSTOM_ENTITIES list in the script:

CUSTOM_ENTITIES = [
    {"label": "ORDER_ID", "pattern": r"\bORD-\d{5}\b"},
    {"label": "PRODUCT_CODE", "pattern": r"\bPROD-[A-Z0-9]{4,6}\b"},
]

#Add new patterns as dictionary entries:
{"label": "SSN", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"},
{"label": "LICENSE_PLATE", "pattern": r"\b[A-Z]{3}-\d{3}\b"},

label → token name prefix (e.g., [SSN_1])
pattern → regex to match entity in text
Run the script — new entities will be detected and replaced.


✅ This setup lets you fully test Presidio + SpaCy + custom regex entities locally, with optional Google DLP fallback, and token replacement for all detected entities.
