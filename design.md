# PII / PHI Redaction Service – Requirements, Questions, and Tool Evaluation

## 📌 Objective
Build and integrate an automated redaction service that:
- Intercepts sampled LLM traffic
- Masks Personally Identifiable Information (PII) and Protected Health Information (PHI)
- Ensures no human annotator sees sensitive data
- Preserves structure and semantic meaning of text

---

# ❓ 1. Clarification Questions for PM

## 🔹 Product & Usage

### Interaction Model
- Is this:
  - API service?
  - Internal UI tool?
  - Middleware in pipeline?
- Who are the consumers?
  - LLM systems?
  - Logging systems?
  - Annotation platforms?

---

### Input / Output Format

**Questions:**
- Input types:
  - Single message?
  - Batch JSON?
  - Files (PDF, CSV)?
  - Streaming (Kafka)?
- Output:
  - Redacted text only?
  - With entity metadata?
  - Reversible mapping needed?

**Example:**
```json
{
  "input": "My name is John and I live in Seattle",
  "output": "My name is [PERSON_1] and I live in [LOCATION_1]",
  "entities": [
    {"type": "PERSON", "value": "John", "token": "PERSON_1"}
  ]
}
Real-Time vs Async
Is this blocking LLM responses?
Or batch processing?

Ask:

Expected latency?
Sync vs async?

Scale
Requests per second?
Daily volume?
Avg text size?

Accuracy
How is recall measured?
What dataset?
Acceptable false positives?

Compliance
GDPR / HIPAA / CCPA scope?
Audit logs needed?
Explainability required?
Reversible redaction?
Entity Definitions
What qualifies as:
Name?
Address?
Date?

Token Rules
Consistency within request?
Across requests?

Storage & Security
Can raw text be logged?
Can mappings be stored?

Human Feedback
Is there a learning loop?

| Type        | Support |
| ----------- | ------- |
| Single text | ✅       |
| Batch JSON  | ✅       |
| Files       | 🔜      |
| Streaming   | 🔜      |

🧠 3. Tool Comparison
Summary
Best compliance: Google DLP
Best AWS integration: Amazon Comprehend
Best customizable/free: Presidio + SpaCy
Best overall: Hybrid approach

## Comparison Table:
| Feature           | Presidio        | SpaCy           | AWS Comprehend | Google DLP  |
| ----------------- | --------------- | --------------- | -------------- | ----------- |
| Type              | Open-source     | NLP library     | Managed API    | Managed DLP |
| PII Detection     | ✅               | ❌               | ✅              | ✅           |
| PHI Support       | ⚠️              | ❌               | ✅              | ✅           |
| Customization     | ✅               | ✅               | ⚠️             | ✅           |
| Setup Effort      | Medium          | High            | Low            | Low         |
| Accuracy          | Medium-High     | Variable        | High           | Very High   |
| Token Replacement | ✅               | ❌               | ❌              | ✅           |
| Cost              | Free            | Free            | Pay-per-use    | Pay-per-use |
| Latency           | Low             | Low             | Medium         | Medium      |
| Scalability       | Infra dependent | Infra dependent | High           | High        |
| Compliance        | ❌               | ❌               | ✅              | ✅           |


⚠️ 4. Limitations
Presidio
Needs tuning
Limited PHI support
SpaCy
No built-in PII detection
Requires ML expertise
AWS Comprehend
Limited customization
Cost scales with usage
Google DLP
Expensive
Vendor lock-in
Latency concerns

💰 5. Cost Considerations
| Tool             | Cost Level |
| ---------------- | ---------- |
| Presidio / SpaCy | Low        |
| AWS Comprehend   | Medium     |
| Google DLP       | High       |

## Tool Selection Guide:

| Scenario          | Recommendation   |
| ----------------- | ---------------- |
| Strict compliance | Google DLP       |
| AWS ecosystem     | AWS Comprehend   |
| Cost sensitive    | Presidio + SpaCy |
| Custom needs      | Presidio         |

# FLOW:
1. Presidio detects PII
2. SpaCy adds custom entities
3. Cloud API fallback for misses
4. Token replacement layer


## When to Call the Cloud API Fallback?
1. Selective Fallback Triggered by Confidence or Coverage Gaps
Don’t call the cloud API for every request! That would be costly and increase latency.
Instead, use Presidio + SpaCy as the primary detectors.
For each entity detection, you get a confidence score or coverage information.
Fallback triggers only when:
Presidio + SpaCy confidence is below a threshold for critical entities.
Some entity types are not supported or poorly detected by Presidio + SpaCy.
You detect suspicious patterns or uncertain redactions (e.g., ambiguous tokens).

Example:
If Presidio says, “I’m 98% confident this is a PERSON entity,” accept it directly.
If it says, “I’m 60% confident,” then call the cloud API to double-check.

2. Periodic Sampling / Spot Checks
Instead of calling fallback every time, sample 5-10% of traffic for fallback verification.
Helps detect degradation or blind spots in your own models without heavy cost.
3. Batch Post-processing for Quality Assurance
Run fallback offline asynchronously on sampled logs or annotations.
Update models or rules based on these results to reduce fallback calls over time.
4. Entity-Type-Based Fallback
For entities that Presidio + SpaCy struggle with (e.g., PHI like medical codes), always send those specific fields to the cloud API.
For others (like emails, phone numbers), rely only on Presidio.
Why Not Always Call Cloud API?
Cost: Cloud APIs charge per character or request — heavy usage is expensive.
Latency: Adds delay if you wait on fallback every time.
Complexity: More calls mean more failure points.

## Summary: Efficient Fallback Design
| Scenario                      | Action                        |
| ----------------------------- | ----------------------------- |
| High confidence from Presidio | Use primary detection only    |
| Low confidence / unknown type | Call cloud API fallback       |
| Periodic QA                   | Sampled fallback verification |
| PHI detection                 | Always use fallback for those |

