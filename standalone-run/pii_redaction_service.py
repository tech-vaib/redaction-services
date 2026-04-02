import re
from collections import defaultdict

# Presidio imports
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, OperatorConfig

# SpaCy imports
import spacy

# Optional Google DLP imports
try:
    from google.cloud import dlp_v2
    google_dlp_available = True
except ImportError:
    google_dlp_available = False

# ------------------- CONFIGURATION -------------------
GOOGLE_DLP_FALLBACK_ENABLED = False  # Set True to enable Google DLP fallback
CUSTOM_ENTITIES = [
    # Add custom regex patterns for missing PII/PHI here
    {"label": "ORDER_ID", "pattern": r"\bORD-\d{5}\b"},
    {"label": "PRODUCT_CODE", "pattern": r"\bPROD-[A-Z0-9]{4,6}\b"},
]

CONFIDENCE_THRESHOLD = 0.85  # Placeholder for fallback trigger
GOOGLE_PROJECT_ID = ""  # Add your project id if using Google DLP

# ------------------- INITIALIZATION -------------------
# Presidio
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# SpaCy
nlp = spacy.load("en_core_web_sm")

# Token mapping
token_counter = defaultdict(int)

def get_token_for_entity(entity_type):
    token_counter[entity_type] += 1
    return f"[{entity_type.upper()}_{token_counter[entity_type]}]"

# ------------------- STEP 1: Presidio -------------------
def anonymize_with_presidio(text):
    results = analyzer.analyze(text=text, language="en")
    if not results:
        return text, []

    entities = []
    for res in results:
        token = get_token_for_entity(res.entity_type)
        entities.append({
            "start": res.start,
            "end": res.end,
            "entity_type": res.entity_type,
            "token": token,
            "original_text": text[res.start:res.end]
        })

    operators = {}
    for ent in entities:
        operators[ent["entity_type"]] = OperatorConfig("replace", {"new_value": ent["token"]})

    anonymized_text = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text
    return anonymized_text, entities

# ------------------- STEP 2: SpaCy -------------------
def detect_custom_entities_spacy(text):
    doc = nlp(text)
    entities = []
    for ent in doc.ents:
        entities.append({
            "start": ent.start_char,
            "end": ent.end_char,
            "entity_type": ent.label_,
            "text": ent.text
        })
    return entities

def anonymize_spacy_entities(text, spacy_entities, existing_entities):
    new_entities = []
    anonymized_text = text
    offset = 0
    for ent in spacy_entities:
        overlap = any(not (ent["end"] <= e["start"] or ent["start"] >= e["end"]) for e in existing_entities)
        if overlap:
            continue
        token = get_token_for_entity(ent["entity_type"])
        start = ent["start"] + offset
        end = ent["end"] + offset
        anonymized_text = anonymized_text[:start] + token + anonymized_text[end:]
        offset += len(token) - (end - start)
        new_entities.append({
            "start": start,
            "end": start + len(token),
            "entity_type": ent["entity_type"],
            "token": token,
            "original_text": ent["text"]
        })
    return anonymized_text, new_entities

# ------------------- STEP 3: Custom Regex Entities -------------------
def detect_custom_entities_config(text, existing_entities):
    new_entities = []
    offset = 0
    for ent_conf in CUSTOM_ENTITIES:
        for match in re.finditer(ent_conf["pattern"], text):
            start, end = match.start(), match.end()
            overlap = any(not (start >= e["end"] or end <= e["start"]) for e in existing_entities)
            if overlap:
                continue
            token = get_token_for_entity(ent_conf["label"])
            text = text[:start] + token + text[end:]
            offset += len(token) - (end - start)
            new_entities.append({
                "start": start,
                "end": start + len(token),
                "entity_type": ent_conf["label"],
                "token": token,
                "original_text": match.group()
            })
    return text, new_entities

# ------------------- STEP 4: Optional Google DLP -------------------
def google_dlp_redact(text):
    if not google_dlp_available or not GOOGLE_PROJECT_ID:
        print("[INFO] Google DLP unavailable or project ID missing. Skipping fallback.")
        return text, []

    client = dlp_v2.DlpServiceClient()
    parent = f"projects/{GOOGLE_PROJECT_ID}"

    info_types = [{"name": "PERSON_NAME"}, {"name": "EMAIL_ADDRESS"}, {"name": "PHONE_NUMBER"}, {"name": "CREDIT_CARD_NUMBER"}, {"name": "DATE"}]

    inspect_config = {"info_types": info_types, "min_likelihood": dlp_v2.Likelihood.POSSIBLE}
    deidentify_config = {
        "info_type_transformations": {"transformations": [{"info_types": info_types, "primitive_transformation": {"replace_with_info_type_config": {}}}]}
    }

    response = client.deidentify_content(
        request={"parent": parent, "deidentify_config": deidentify_config, "inspect_config": inspect_config, "item": {"value": text}}
    )
    return response.item.value, []

# ------------------- REDACTION PIPELINE -------------------
def redact_text_pipeline(text, enable_google_fallback=False, custom_entities_config=True):
    global token_counter
    token_counter.clear()

    # Step 1: Presidio
    presidio_text, presidio_entities = anonymize_with_presidio(text)

    # Step 2: SpaCy
    spacy_entities = detect_custom_entities_spacy(presidio_text)
    combined_text, spacy_new_entities = anonymize_spacy_entities(presidio_text, spacy_entities, presidio_entities)
    all_entities = presidio_entities + spacy_new_entities

    # Step 3: Custom regex entities
    if custom_entities_config:
        combined_text, custom_new_entities = detect_custom_entities_config(combined_text, all_entities)
        all_entities += custom_new_entities

    # Step 4: Optional Google fallback
    if enable_google_fallback:
        if len(all_entities) < 1:
            fallback_text, _ = google_dlp_redact(text)
            if fallback_text != text:
                combined_text = fallback_text

    return combined_text, all_entities

# ------------------- SAMPLE RUN -------------------
if __name__ == "__main__":
    sample_text = """
    Hello, my name is John Doe and my email is john.doe@example.com.
    I live in Seattle and my phone number is 555-123-4567.
    My credit card number is 4111 1111 1111 1111.
    My order ID is ORD-12345 and product code PROD-AB12.
    """

    print("===== Input Text =====")
    print(sample_text)

    redacted_text, entities = redact_text_pipeline(sample_text, enable_google_fallback=GOOGLE_DLP_FALLBACK_ENABLED, custom_entities_config=True)

    print("\n===== Redacted Text =====")
    print(redacted_text)

    print("\n===== Detected Entities =====")
    for ent in entities:
        print(f"{ent['token']} -> {ent['entity_type']} : '{ent['original_text']}'")
