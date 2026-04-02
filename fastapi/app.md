PII/PHI Redaction Requirements:


| Category                        | Gap / Ambiguity           | Questions to PM                                                                                            | Notes / Options                                 |
| ------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| **Users & Interaction**         | Who will use the service? | Who are the intended users? Internal analysts, external clients, automated pipelines?                      | Clarify user personas                           |
|                                 | Interaction mode unclear  | How will users interact? Web portal, API, command line, batch jobs?                                        | Impacts design choices                          |
|                                 | User roles                | Are there different user roles or access levels to support?                                                | Role-based access may affect redaction policies |
| **Input & Output**              | Input type not specified  | What type of data will users provide? Text messages, documents, logs, API payloads?                        | Determines preprocessing and ingestion          |
|                                 | Input size                | Are there max input size limits?                                                                           | Impacts performance and tool selection          |
|                                 | Output requirements       | Should output include only redacted text or also PII/PHI metadata (positions/types)?                       | Guides API response format                      |
|                                 | Output format             | Preferred output format: JSON, plain text, CSV?                                                            | Affects integration with downstream systems     |
| **Scope of PII/PHI Detection**  | Missing entity types      | Which types of PII/PHI need detection? Names, emails, SSNs, medical data, custom IDs?                      | Need a complete list                            |
|                                 | Domain-specific entities  | Are there internal/custom entities critical for detection?                                                 | E.g., order IDs, product codes                  |
|                                 | Exclusions                | Any data types to ignore for redaction?                                                                    | Avoid over-redaction                            |
| **Tools & Technologies**        | Tool selection unclear    | PM mentioned Presidio, SpaCy, AWS Comprehend, Google DLP — do we implement all or evaluate & pick?         | Helps define scope and PoC                      |
|                                 | Pipeline combination      | Should multiple tools be combined or just one?                                                             | Accuracy vs performance tradeoff                |
|                                 | Latency/performance       | Are there performance constraints for multi-tool pipelines?                                                | Guides architecture decisions                   |
|                                 | Google fallback           | Is Google DLP fallback optional or mandatory?                                                              | Affects local testing and deployment            |
|                                 | Cost / licensing          | Are there budget constraints for cloud tools?                                                              | AWS/GCP costs need approval                     |
| **Redaction & Tokenization**    | Token consistency         | Should tokens be consistent across multiple requests/documents?                                            | Impacts token mapping design                    |
|                                 | Token configuration       | Are replacement tokens configurable or fixed?                                                              | Customization for compliance                    |
|                                 | Logging / auditing        | Do we need logs of original vs redacted data?                                                              | Required for compliance reporting               |
| **Integration & Deployment**    | Deployment environment    | On-prem, cloud, or hybrid?                                                                                 | Affects architecture                            |
|                                 | API / system integration  | Should it be exposed as API or embedded internally?                                                        | Impacts service design                          |
|                                 | Security / compliance     | Encryption at rest, HIPAA/GDPR requirements?                                                               | Critical for sensitive data                     |
| **Reporting & Monitoring**      | Metrics & dashboards      | Do we need detection accuracy, failure rates, or tool performance metrics?                                 | Monitoring & reporting                          |
|                                 | False negatives           | How should we handle misses?                                                                               | Fallback mechanism required?                    |
|                                 | Dynamic pattern updates   | Can new PII/PHI patterns be added without redeploy?                                                        | Impacts flexibility of system                   |
| **Evaluation & Recommendation** | Tool comparison           | Any preferred criteria for choosing Presidio, SpaCy, AWS, Google? Accuracy, speed, cost, integration ease? | Helps recommend best option                     |
|                                 | Deliverables              | Should we provide a comparison table with pros/cons, cost, limitations?                                    | Clear recommendation for PM                     |





1. Users & Interaction
Who are the intended users of this service? (internal analysts, external clients, automated pipelines, etc.)
How will they interact with the system? (web portal, API, command line, app, batch jobs, etc.)
Are there different user roles or access levels that we need to support?
2. Input & Output
What type of data will users provide?
Single text messages, documents (PDF, Word, CSV), logs, or API payloads?
Are there any maximum size limits for the input data?
Should the output be just redacted text or also include metadata like detected PII/PHI positions and types?
What format should the output be in? (plain text, JSON, CSV, etc.)
3. Scope of PII/PHI Detection
Which types of PII/PHI need to be detected? (names, emails, SSNs, medical data, custom IDs, etc.)
Are there any domain-specific entities that are critical but may not be standard (e.g., internal order IDs, product codes, license numbers)?
Are there any types of data that should not be detected or redacted?
4. Tools & Technologies
PM mentioned exploring Microsoft Presidio, SpaCy, Amazon Comprehend, Google Cloud Sensitive Data Protection — do we need to implement all of these or just evaluate and pick the best?
Should the pipeline combine multiple tools for higher accuracy, or is one tool sufficient?
Are there performance or latency constraints for using multiple detection engines?
Should we support optional Google DLP fallback or make it mandatory?
Are there licensing or cost constraints for using cloud-based tools (AWS, GCP)?
5. Redaction & Tokenization
Should we replace detected PII/PHI with consistent tokens across multiple requests/documents?
Do we need configurable custom replacement tokens or fixed patterns?
Is there a requirement to log or audit original vs redacted data for compliance?
6. Integration & Deployment
Will this run on-premise, cloud, or hybrid?
Should it be exposed as an API service, or integrated directly into an internal system?
Are there security or compliance requirements for handling the data (encryption at rest, GDPR/HIPAA compliance)?
7. Reporting & Monitoring
Do we need metrics or dashboards for detection accuracy, failures, or tool performance?
How should we handle false negatives or misses?
Should there be a way to update or add new PII/PHI patterns dynamically without redeploying?
8. Evaluation & Recommendation
Are there preferred evaluation criteria for choosing between Presidio, SpaCy, AWS, and Google?
Accuracy, coverage, speed, cost, ease of integration, scalability?
Should we provide a comparison table with pros/cons, cost, and limitations for all tools?
