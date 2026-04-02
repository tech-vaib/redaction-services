from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re
from collections import defaultdict

# Presidio imports
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, OperatorConfig

# SpaCy
import spacy

# Optional Google DLP
try:
    from google.cloud import dlp_v2
    google_dlp_available = True
except ImportError:
    google_dlp_available = False

# ------------------- CONFIGURATION -------------------
GOOGLE_DLP_FALLBACK_ENABLED = False  # Set True to enable Google DLP fallback
CUSTOM_ENTITIES = [
    {"label": "ORDER_ID", "pattern": r"\bORD-\d{5}\b"},
    {"label": "PRODUCT_CODE", "pattern": r"\bPROD-[A-Z0-9]{4,6}\b"},
]
GOOGLE_PROJECT_ID = ""  # Set if using Google DLP

# ------------------- INITIALIZATION -------------------
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
nlp = spacy.load("en_core_web_sm")
token_counter = defaultdict(int)

# ------------------- UTILITIES -------------------
def get_token_for_entity(entity_type):
    token_counter[entity_type] += 1
    return f"[{entity_type.upper()}_{token_counter[entity_type]}]"

# Presidio anonymization
def anonymize_with_presidio(text):
    results = analyzer.analyze(text=text, language="en")
    entities = []
    if results:
        for res in results:
            token = get_token_for_entity(res.entity_type)
            entities.append({
                "start": res.start,
                "end": res.end,
                "entity_type": res.entity_type,
                "token": token,
                "original_text": text[res.start:res.end]
            })
        operators = {ent["entity_type"]: OperatorConfig("replace", {"new_value": ent["token"]}) for ent in entities}
        anonymized_text = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text
        return anonymized_text, entities
    return text, []

# SpaCy entity detection
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
        if overlap: continue
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

# Custom regex entities
def detect_custom_entities_config(text, existing_entities):
    new_entities = []
    offset = 0
    for ent_conf in CUSTOM_ENTITIES:
        for match in re.finditer(ent_conf["pattern"], text):
            start, end = match.start(), match.end()
            overlap = any(not (start >= e["end"] or end <= e["start"]) for e in existing_entities)
            if overlap: continue
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

# Google DLP fallback
def google_dlp_redact(text):
    if not google_dlp_available or not GOOGLE_PROJECT_ID:
        return text, []
    client = dlp_v2.DlpServiceClient()
    parent = f"projects/{GOOGLE_PROJECT_ID}"
    info_types = [{"name": "PERSON_NAME"}, {"name": "EMAIL_ADDRESS"}, {"name": "PHONE_NUMBER"}, {"name": "CREDIT_CARD_NUMBER"}, {"name": "DATE"}]
    inspect_config = {"info_types": info_types, "min_likelihood": dlp_v2.Likelihood.POSSIBLE}
    deidentify_config = {"info_type_transformations":{"transformations":[{"info_types":info_types,"primitive_transformation":{"replace_with_info_type_config":{}}}]}}
    response = client.deidentify_content(request={"parent": parent, "deidentify_config": deidentify_config, "inspect_config": inspect_config, "item":{"value": text}})
    return response.item.value, []

# ------------------- PIPELINE -------------------
def redact_text_pipeline(text, enable_google_fallback=False, custom_entities_config=True):
    global token_counter
    token_counter.clear()
    # Step1: Presidio
    presidio_text, presidio_entities = anonymize_with_presidio(text)
    # Step2: SpaCy
    spacy_entities = detect_custom_entities_spacy(presidio_text)
    combined_text, spacy_new_entities = anonymize_spacy_entities(presidio_text, spacy_entities, presidio_entities)
    all_entities = presidio_entities + spacy_new_entities
    # Step3: Custom regex
    if custom_entities_config:
        combined_text, custom_new_entities = detect_custom_entities_config(combined_text, all_entities)
        all_entities += custom_new_entities
    # Step4: Optional Google fallback
    if enable_google_fallback:
        if len(all_entities) < 1:
            fallback_text, _ = google_dlp_redact(text)
            if fallback_text != text:
                combined_text = fallback_text
    return combined_text, all_entities

# ------------------- FASTAPI SERVICE -------------------
app = FastAPI(title="PII/PHI Redaction Service")

class TextInput(BaseModel):
    text: str
    enable_google_fallback: bool = GOOGLE_DLP_FALLBACK_ENABLED
    custom_entities_config: bool = True

@app.post("/redact")
def redact(input: TextInput):
    try:
        redacted_text, entities = redact_text_pipeline(
            input.text, input.enable_google_fallback, input.custom_entities_config
        )
        return {"redacted_text": redacted_text, "entities": entities}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
