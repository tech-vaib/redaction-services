How to Run the FastAPI Service
1. Install dependencies
   pip install fastapi uvicorn presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_sm
#Optional for Google DLP:
pip install google-cloud-dlp
export GOOGLE_PROJECT_ID="your-google-project-id"
gcloud auth application-default login

2. Run the service
   uvicorn app:app --reload

   Service will start at: http://127.0.0.1:8000
Interactive docs: http://127.0.0.1:8000/docs
You can paste text and see redacted output + detected entities

3. Test with CURL or Python

   curl -X POST "http://127.0.0.1:8000/redact" -H "Content-Type: application/json" -d '{"text": "My email is john.doe@example.com and order ID is ORD-12345."}'

   4. Add missing PII / PHI patterns
      Edit CUSTOM_ENTITIES in app.py:
      
      CUSTOM_ENTITIES = [
    {"label": "SSN", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"},
    {"label": "LICENSE_PLATE", "pattern": r"\b[A-Z]{3}-\d{3}\b"},
]

Save the file and restart the FastAPI service.
New entities will automatically be detected and replaced with consistent tokens.
With this, you now have a fully functional local API service for testing PII/PHI redaction with:

Configurable custom entities
Optional Google DLP fallback
Token replacement
Presidio + SpaCy detection
