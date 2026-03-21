# Sphinx — AI Mesh Firewall

## Sprint Implementation Plan v2.0

| **Field**         | **Detail**                                                           |
|-------------------|----------------------------------------------------------------------|
| Product           | Sphinx AI Mesh Firewall                                              |
| Plan Version      | 2.0                                                                  |
| Total Sprints     | 30 Sprints across 8 Phases                                           |
| Total Duration    | ~60 Weeks (2-week sprints)                                           |
| Sprint Length     | 2 weeks                                                              |
| Team Composition  | 3 BE Engineers, 2 FE Engineers, 1 DevOps/Infra, 1 QA, 1 Security SME |
| Story Point Scale | Fibonacci (1, 2, 3, 5, 8, 13)                                        |
| Document Status   | Draft — Engineering Review                                           |

## 1. Plan Overview
This document defines the 20-sprint implementation plan for the Sphinx AI Mesh Firewall, organized into 6 phases. Each sprint is 2 weeks, for a total project duration of approximately 40 weeks. Phases are sequenced to deliver governance value incrementally, starting with the gateway foundation and ending with enterprise-grade compliance tooling.

| **Phase**   | **Name**                                    | **Sprints**   | **Weeks**   | **Key Deliverable**                                                                         |
|-------------|---------------------------------------------|---------------|-------------|---------------------------------------------------------------------------------------------|
| **Phase 1** | Gateway Foundation & Auth                   | Sprints 1–3   | Weeks 1–6   | Working gateway with API key auth, policy cache, rate limiting                              |
| **Phase 2** | Input Firewall & RAG Firewall               | Sprints 4–7   | Weeks 7–14  | Prompt injection detection, PII redaction, RAG pipeline controls                            |
| **Phase 3** | Vector DB Firewall                          | Sprints 8–10  | Weeks 15–20 | Pre-retrieval namespace isolation, ChromaDB/Pinecone/Milvus support                         |
| **Phase 4** | Multi-Model Routing & Kill-Switch           | Sprints 11–13 | Weeks 21–26 | Sensitivity-based routing, per-model kill-switch with fallback                              |
| **Phase 5** | Output Guardrails & MCP Governance          | Sprints 14–17 | Weeks 27–34 | Streaming output scanning, MCP tool inventory, agent scope enforcement                      |
| **Phase 6** | Compliance, Audit & Dashboard               | Sprints 18–20 | Weeks 35–40 | Full audit trail, compliance dashboards, policy versioning, GA hardening                    |
| **Phase 7** | Agentic Security Enhancements (P0/P1)       | Sprints 21–27 | Weeks 41–54 | Multilingual detection, Red teaming, Memory security, A2A firewall, HITL, Cascading failure |
| **Phase 8** | Enterprise & Strategic Enhancements (P1/P2) | Sprints 28–30 | Weeks 55–60 | ML model scanning, EU AI Act, Multi-turn security, AI-SPM integration, Semantic caching     |

## 2. Phase 1 — Gateway Foundation & Auth (Sprints 1–3)
Establish the core proxy gateway infrastructure: request ingestion, API key authentication, tenant context injection, token budget enforcement, rate limiting, policy cache loading, and the initial control plane management API. This phase delivers a working gateway that routes traffic to LLM providers with basic access controls.

### Sprint 1 — Gateway Skeleton & API Key Auth \[Weeks 1–2\]
| **Task**                           | **Description**                                                                                                                           | **Points** |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Gateway proxy core                 | Implement reverse proxy in Python (FastAPI/ASGI) that forwards requests to configured LLM provider endpoints                              | 8          |
| API key model + storage            | Design and implement API key schema: allowed models, TPM rate limit, risk score, expiry, project/tenant fields. PostgreSQL + Redis cache. | 5          |
| Key validation middleware          | Inline middleware: extract key from Authorization header, validate against cache, inject tenant context into request context              | 5          |
| Provider credential store          | Encrypted credential vault for LLM provider API keys; per-provider enable/disable flag                                                    | 3          |
| Health check + readiness endpoints | GET /health and GET /ready for load balancer and Kubernetes probes                                                                        | 2          |
| Docker Compose dev stack           | Gateway + Redis + Postgres + mock LLM endpoint for local development                                                                      | 3          |

### Sprint 1 Acceptance Criteria
- API key validated from Redis cache on every request; invalid keys return 401 within 5 ms

- Tenant context (project ID, tenant ID) injected into request context and visible in request logs

- Gateway successfully proxies requests to OpenAI-compatible endpoint in local dev environment

- Docker Compose stack starts cleanly with one command

### Sprint 2 — Rate Limiting, Token Budgets & Kill-Switch Foundation \[Weeks 3–4\]
| **Task**                           | **Description**                                                                                                                | **Points** |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|------------|
| Token-per-minute rate limiter      | Redis-backed sliding window rate limiter keyed by API key. Enforce TPM limit; return 429 with Retry-After header on breach.    | 8          |
| Token budget tracking              | Track cumulative token consumption per key per period. Persist to Postgres asynchronously; serve budget state from Redis.      | 5          |
| Kill-switch data model             | Per-model kill-switch record: model name, action (Block/Reroute), fallback model, activated-by, reason, timestamp              | 3          |
| Kill-switch check at ingress       | Check kill-switch state from cache at earliest pipeline stage. Return 503 or reroute transparently.                            | 5          |
| Policy cache loader                | Background process: pull compiled policy objects from control plane on startup and on push notification. TTL + forced refresh. | 5          |
| Control plane API — key management | REST API: create/read/update/delete API keys, set rate limits, assign tenants                                                  | 5          |

### Sprint 2 Acceptance Criteria
- Rate limiter enforces TPM limit; 429 returned on the request that exceeds the limit within the sliding window

- Kill-switch activation propagates to gateway within 5 seconds; next request returns 503 or routes to fallback

- Policy cache loaded from control plane on gateway startup; in-memory lookup completes in under 1 ms

- API key CRUD operations available via authenticated control plane REST API

### Sprint 3 — Multi-Provider Routing Foundation & Audit Skeleton \[Weeks 5–6\]
| **Task**                 | **Description**                                                                                                                       | **Points** |
|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------|------------|
| LLM provider adapters    | Provider-specific adapter layer: OpenAI, Anthropic Claude, Google Gemini. Normalize request/response format to unified schema.        | 8          |
| Basic routing engine     | Route request to configured provider based on API key allowed-models policy. Select provider from weighted list.                      | 5          |
| Async audit event writer | Write enforcement events to Kafka queue asynchronously. Event schema: timestamp, request hash, tenant, model, action, policy version. | 5          |
| Audit Postgres consumer  | Kafka consumer writes audit events to Postgres audit table. Idempotent insert by request hash.                                        | 3          |
| Streaming proxy support  | Pass-through streaming (SSE / chunked transfer) from provider to client without buffering entire response                             | 5          |
| Basic admin UI scaffold  | React 19 scaffold: login, API key management page, basic dashboard layout                                                             | 5          |

### Sprint 3 Acceptance Criteria
- Requests successfully proxied to OpenAI, Anthropic, and Gemini via unified gateway endpoint

- Streaming responses from all three providers pass through to client with no buffering delay

- Every proxied request generates an audit event in Kafka and persists to Postgres within 2 seconds

- Admin UI login and API key list page functional

## 3. Phase 2 — Input Firewall & RAG Firewall (Sprints 4–7)
Implement the input-side security layer: prompt injection and jailbreak detection (Tier 1 heuristic, Tier 2 ML), PII/PHI redaction, credential pattern scanning, and the pipeline-aware RAG firewall with per-stage controls.

### Sprint 4 — Tier 1 Threat Detection Engine \[Weeks 7–8\]
| **Task**                             | **Description**                                                                                                                   | **Points** |
|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|------------|
| Threat pattern library               | Curated regex + keyword pattern library for: prompt injection, jailbreak templates, OWASP LLM Top 10 patterns. YAML-configurable. | 8          |
| Heuristic injection scorer           | Score prompt text against pattern library. Return risk level (Critical/High/Medium/Low) + matched patterns. Target p99 \< 80 ms.  | 8          |
| Policy action engine                 | Map risk level to configured action: Allow / Block / Rewrite / Downgrade. Actions configurable per policy rule.                   | 5          |
| Rewrite capability                   | For Rewrite action: apply configured substitution template to prompt before forwarding to model                                   | 3          |
| Policy builder UI — rule creation    | Admin UI: create security policy rules with keyword/regex patterns, severity, action, stage assignment                            | 5          |
| Unit test suite — injection patterns | Test 200+ injection and jailbreak patterns; assert correct detection and action. \< 2% false positive target.                     | 5          |

### Sprint 4 Acceptance Criteria
- Tier 1 engine detects standard OWASP LLM Top 10 injection patterns with \< 2% false positive rate on test suite

- Policy actions (Block, Rewrite, Allow, Downgrade) apply correctly per configured rule severity

- Detection latency p99 \< 80 ms on 1000-token prompt

- Policy rules creatable via admin UI and immediately active after save

### Sprint 5 — PII/PHI Detection & Redaction (Data Shield) \[Weeks 9–10\]
| **Task**                               | **Description**                                                                                                                | **Points** |
|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|------------|
| PII entity recognizer                  | Named entity recognition for: names, email addresses, phone numbers, SSNs, dates-of-birth, addresses. Spacy + custom rules.    | 8          |
| PHI extension                          | HIPAA PHI extensions: patient IDs, diagnosis codes, medication names, provider names, MRNs                                     | 5          |
| Credential pattern scanner             | Regex patterns for: API keys (OpenAI, AWS, GitHub, etc.), credit card numbers, private keys, connection strings                | 5          |
| Redaction engine                       | Replace detected entities with placeholder tokens (e.g., \[REDACTED-EMAIL\]). Preserve sentence structure for model coherence. | 5          |
| Reversible redaction (tokenized vault) | Optional: store original value in tenant-scoped vault; replace with reversible token for post-response de-tokenization         | 8          |
| PII scanning parallelism               | Run PII scan concurrently with threat engine; combine results before applying action                                           | 3          |

### Sprint 5 Acceptance Criteria
- PII/PHI entities correctly detected and redacted in test prompts across all supported entity types

- Credential patterns (API keys, card numbers) detected with zero false negatives on standard formats

- PII scan runs in parallel with threat engine; combined latency overhead \< 30 ms

- Reversible redaction: original values recoverable from vault for the request session

### Sprint 6 — RAG Pipeline Classification & Query Firewall \[Weeks 11–12\]
| **Task**                        | **Description**                                                                                                                   | **Points** |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|------------|
| RAG request classifier          | Classify inbound request as: Standard Chat, RAG Query, or MCP Tool Call. Route to appropriate enforcement branch.                 | 5          |
| Query-stage injection detection | Apply Tier 1 + Tier 2 detection specifically to RAG query stage; block retrieval before it reaches vector DB on critical findings | 8          |
| Query-stage PII redaction       | Apply Data Shield to RAG queries; mask PII before query reaches vector store                                                      | 5          |
| Intent classification           | Lightweight classifier for query intent: data extraction attempt, normal retrieval, sensitive topic. Flag high-risk intents.      | 5          |
| RAG policy configuration UI     | Admin UI: configure per-stage policies for RAG pipelines — different rules for Query vs Retrieval vs Generator stages             | 5          |
| Integration test — RAG flow     | End-to-end test: RAG query through gateway → classification → query firewall → mock vector DB → context assembly → model → output | 5          |

### Sprint 6 Acceptance Criteria
- RAG queries correctly classified and routed to RAG enforcement branch vs standard chat branch

- Injection in RAG query blocked before reaching vector DB in test scenarios

- PII in RAG query redacted before vector store receives the query

- End-to-end RAG flow test passes with policy enforcement active at each stage

### Sprint 7 — Tier 2 ML Scanner & Policy Versioning \[Weeks 13–14\]
| **Task**                    | **Description**                                                                                                                                          | **Points** |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Tier 2 ML semantic analyzer | Semantic embedding model for ambiguous prompts that pass Tier 1. Cosine similarity against threat embedding index. Run only on Tier 1 escalations.       | 13         |
| Escalation gate             | Logic: if Tier 1 returns Medium risk with no pattern match → escalate to Tier 2. If Tier 1 returns High/Critical → act immediately without Tier 2 delay. | 5          |
| Policy version management   | Each policy publish creates a versioned snapshot. Every audit event records policy version at time of enforcement.                                       | 5          |
| Policy diff + rollback      | Admin UI: view diff between policy versions; rollback to previous version with one click; rollback propagates to gateway in \< 5 s                       | 5          |
| Policy simulation mode      | Dry-run new policy against recent request log; preview which requests would be blocked/rewritten before activation                                       | 8          |

### Sprint 7 Acceptance Criteria
- Tier 2 ML scanner correctly classifies ambiguous prompts that evade Tier 1 keyword detection

- Tier 2 only invoked on Tier 1 escalations; Tier 1 High/Critical actions applied without Tier 2 delay

- Policy version recorded in every audit event; rollback restores previous version within 5 seconds

- Policy simulation produces accurate preview of enforcement impact on recent request history

## 4. Phase 3 — Vector DB Firewall (Sprints 8–10)
Build the pre-retrieval Vector DB Firewall: namespace isolation enforcement, per-collection access policies, anomaly detection on query embeddings, and retrieved chunk scanning before context assembly. Deliver support for ChromaDB, Pinecone, and Milvus.

### Sprint 8 — Vector DB Proxy & Namespace Isolation \[Weeks 15–16\]
| **Task**                         | **Description**                                                                                                                            | **Points** |
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Vector DB proxy layer            | Intercept vector DB queries from RAG pipelines. Support ChromaDB, Pinecone, Milvus client libraries via transparent proxy.                 | 13         |
| Collection access policy model   | Per-collection policy: default action (Deny/Allow/Monitor), allowed operations (Query/Insert/Update/Delete), sensitive fields, max results | 5          |
| Namespace isolation injector     | Inject authenticated tenant's namespace identifier as mandatory filter on every retrieval query. Non-bypassable.                           | 8          |
| Collection allowlist enforcement | Unlisted collections return access-denied error. All governed collections must have explicit policy.                                       | 3          |
| Max results cap                  | Enforce configured max results per query (1–100). Trim response if provider returns excess documents.                                      | 3          |
| Vector DB admin UI               | Admin UI: register vector collections, configure per-collection policy, assign namespace field name                                        | 5          |

### Sprint 8 Acceptance Criteria
- Tenant namespace filter injected on every retrieval query; test confirms cross-tenant documents never returned

- Unlisted collections return access-denied; listed collections enforce operation allowlist

- Max results cap enforced across ChromaDB, Pinecone, and Milvus in integration tests

### Sprint 9 — Chunk Scanning & Indirect Injection Prevention \[Weeks 17–18\]
| **Task**                           | **Description**                                                                                                                                  | **Points** |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Retrieval chunk scanner            | Scan every retrieved document chunk for hidden instructions before it enters context assembly. Apply Tier 1 injection patterns to chunk content. | 8          |
| Sensitive field block policy       | If 'Block Sensitive Documents' enabled on collection: auto-block chunks where sensitive field matches configured patterns                        | 5          |
| Anomaly distance threshold monitor | Compute cosine distance of query embedding from collection centroid. Alert + log when distance exceeds configured threshold (embedding anomaly). | 8          |
| Context minimization               | Apply configurable max-chunks and max-tokens-per-chunk limits during context assembly to reduce over-retrieval exposure                          | 3          |
| Indirect injection incident log    | Create an Incident record when retrieved chunk contains hidden instruction. Include chunk content hash, collection, and tenant.                  | 3          |
| Chunk scan test suite              | Automated tests: poisoned documents in mock collections; assert chunks blocked before reaching context assembly                                  | 5          |

### Sprint 9 Acceptance Criteria
- Retrieved chunks containing injection patterns blocked before context assembly in all test scenarios

- Sensitive field block policy removes matching documents from retrieval response before model sees content

- Embedding anomaly detection fires alert on statistically outlier queries in test scenarios

### Sprint 10 — Vector DB Firewall Hardening & Observability \[Weeks 19–20\]
| **Task**                               | **Description**                                                                                                                  | **Points** |
|----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|------------|
| Milvus full integration                | Complete Milvus proxy support: metadata filter injection, partition-based namespace isolation, gRPC proxy support                | 8          |
| Vector DB policy compliance tagging    | Tag retrieved chunks with compliance labels (PII / IP / Regulated) before assembly. Labels used in downstream routing decisions. | 5          |
| Collection-level audit log             | Per-collection audit log: query hash, namespace filter applied, chunks returned, chunks blocked, anomaly score                   | 5          |
| Vector DB dashboard                    | Admin UI: collection policy health, query volume per tenant, blocked query count, anomaly event timeline                         | 5          |
| Penetration test — namespace isolation | Structured test: 10 cross-tenant extraction scenarios; assert zero escapes with policy active                                    | 8          |

### Sprint 10 Acceptance Criteria
- All three vector DBs (ChromaDB, Pinecone, Milvus) pass namespace isolation penetration test suite with zero escapes

- Compliance tags on retrieved chunks correctly trigger routing policy in downstream pipeline

- Collection audit log populated for every governed query; accessible via admin dashboard

## 5. Phase 4 — Multi-Model Routing & Kill-Switch (Sprints 11–13)
Implement the full multi-model governance layer: sensitivity-based routing, budget-triggered model downgrade, AWS Bedrock and Azure OpenAI adapter support, and the production-grade kill-switch with fallback routing and immutable audit trail.

### Sprint 11 — Sensitivity-Based Routing & Budget Downgrade \[Weeks 21–22\]
| **Task**                     | **Description**                                                                                                                                | **Points** |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Routing policy evaluator     | Evaluate routing decision based on: compliance tags, data sensitivity score, active kill-switch state, budget status, configured routing rules | 8          |
| Sensitivity-to-model mapping | Policy: if request carries PII/PHI/IP tag → route to configured private/on-premise model; else → route to configured public model              | 5          |
| Budget-triggered downgrade   | When token budget for current tier exceeded → downgrade to configured cheaper model tier. Log downgrade event.                                 | 5          |
| Self-hosted Llama adapter    | Adapter for Llama-compatible local/on-premise deployment (Ollama, vLLM). Support both OpenAI-compatible and native APIs.                       | 8          |
| Routing rules UI             | Admin UI: define routing rules — if \[condition\] then route to \[model\]. Support multiple ordered rules with fallthrough.                    | 5          |
| Routing decision audit log   | Record routing decision in audit event: which rules evaluated, which model selected, reason for selection                                      | 3          |

### Sprint 11 Acceptance Criteria
- Requests tagged with PII/PHI route to on-premise model; clean requests route to public model in integration tests

- Budget-exceeded requests downgrade to cheaper tier model; downgrade event logged in audit trail

- Llama self-hosted adapter proxies requests successfully in local integration test

### Sprint 12 — Kill-Switch Production Hardening \[Weeks 23–24\]
| **Task**                      | **Description**                                                                                                                              | **Points** |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Kill-switch cache propagation | Kill-switch state changes in control plane publish to Redis pub/sub. Gateway subscribers update local state within 5 seconds.                | 8          |
| Block mode                    | When action=Block: return 503 with configured error message. Log: model, activating admin, reason, timestamp.                                | 3          |
| Reroute mode                  | When action=Reroute: transparently redirect request to fallback model without client-visible error. Log reroute event.                       | 5          |
| AWS Bedrock adapter           | Adapter for AWS Bedrock: Claude via Bedrock, Titan, Llama via Bedrock. Handle Bedrock's InvokeModel/InvokeModelWithResponseStream APIs.      | 8          |
| Azure OpenAI adapter          | Adapter for Azure OpenAI: handle deployment names, API version headers, Azure AD authentication                                              | 5          |
| Kill-switch UI                | Admin UI: per-model kill-switch toggle. Select action (Block/Reroute), fallback model, mandatory reason field. Activation log visible in UI. | 5          |

### Sprint 12 Acceptance Criteria
- Kill-switch activated in control plane; next request to target model returns 503 or routes to fallback within 5 seconds

- Kill-switch audit record immutable: includes admin username, timestamp, reason — cannot be deleted via API

- AWS Bedrock and Azure OpenAI adapters successfully proxy requests in integration tests

### Sprint 13 — Provider Health Monitoring & Failover \[Weeks 25–26\]
| **Task**                     | **Description**                                                                                                                                    | **Points** |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Provider health probe        | Periodic health check for each registered provider. Detect latency spikes, error rate increases, and provider outages.                             | 5          |
| Automatic failover policy    | Configurable policy: if provider error rate exceeds threshold → automatically activate kill-switch reroute to fallback. Human confirmation option. | 8          |
| Circuit breaker per provider | Per-provider circuit breaker: open on consecutive failures, half-open probe, close on recovery. State visible in dashboard.                        | 8          |
| Cost tracking per provider   | Track token consumption and estimated cost per provider per tenant. Expose via dashboard and API.                                                  | 5          |
| Multi-model dashboard        | Admin UI: model registry, health status, cost breakdown, active kill-switches, routing rule summary                                                | 5          |

### Sprint 13 Acceptance Criteria
- Provider health probe detects simulated error rate spike and fires alert within 60 seconds

- Circuit breaker opens on 5 consecutive failures; closes after successful probe with no traffic lost

- Cost dashboard shows accurate per-provider, per-tenant token consumption in real time

## 6. Phase 5 — Output Guardrails & MCP Governance (Sprints 14–17)
Implement streaming output scanning with PII/credential redaction before response delivery, and the full MCP server governance layer: automated tool server discovery, risk scoring, per-agent scope enforcement, and field-level context redaction.

### Sprint 14 — Streaming Output Scanner \[Weeks 27–28\]
| **Task**                         | **Description**                                                                                                                  | **Points** |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------|------------|
| Streaming chunk interceptor      | Intercept SSE stream chunks from LLM provider. Buffer minimal context window (sliding window) to detect multi-chunk patterns.    | 8          |
| Output PII redaction             | Apply Data Shield to output stream. Redact PII/PHI tokens in chunks before forwarding to client. Preserve stream coherence.      | 8          |
| Output credential detection      | Detect API key patterns, connection strings, private keys in output stream. Block chunk and substitute with \[REDACTED\] marker. | 5          |
| Output policy evaluation         | Evaluate compiled policy rules against output content. Apply: Stream / Redact / Block / Rewrite / Incident Log actions.          | 5          |
| Regulated data leakage detection | Match output content against compliance tags from input pipeline. If regulated data appears in output → redact + log incident.   | 5          |
| Output guardrail test suite      | Test: model response containing SSN, API key, PII — assert correctly redacted in streamed output delivered to test client        | 5          |

### Sprint 14 Acceptance Criteria
- PII entities in model output redacted in stream before reaching client in all test scenarios

- API key patterns in model output blocked; client receives \[REDACTED\] in place of credential

- Streaming performance maintained: no increase in time-to-first-token vs pass-through baseline

### Sprint 15 — MCP Server Discovery & Risk Scoring \[Weeks 29–30\]
| **Task**                       | **Description**                                                                                                                                 | **Points** |
|--------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| MCP server registry            | Inventory store for MCP server connections: server name, URL, protocol version, connected agents, capabilities list                             | 5          |
| Automated capability discovery | On agent connection: enumerate MCP server capabilities via protocol introspection. Extract tool names, parameter schemas, required permissions. | 8          |
| Risk scoring engine            | Score each tool based on: capability category (read/write/outbound), data access scope, external network access, destructive operations flag.   | 8          |
| Risk score model               | Risk model: Critical (outbound HTTP, write+delete), High (write access, external data), Medium (read + sensitive fields), Low (read only)       | 5          |
| MCP scanner UI                 | Admin UI: MCP server inventory table. Per-server: risk score badge, connected agents, capability list, last-seen timestamp                      | 5          |
| Risk score alert               | Alert on: new MCP server registration, Critical-risk capability discovered, agent connected to unreviewed server                                | 3          |

### Sprint 15 Acceptance Criteria
- MCP server capabilities automatically discovered and inventoried on first agent connection

- Risk scores correctly assigned based on capability categories in test scenario suite

- Admin receives alert within 60 seconds of new Critical-risk capability appearing in inventory

### Sprint 16 — Per-Agent Scope Enforcement \[Weeks 31–32\]
| **Task**                         | **Description**                                                                                                                               | **Points** |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Agent service account model      | Each AI agent authenticates via a dedicated service account. Service account carries: allowed MCP servers, allowed tool names, context scope. | 5          |
| Tool access enforcement          | Before forwarding MCP tool call: validate tool name is in agent service account allowlist. Block and log if not permitted.                    | 8          |
| Context scope enforcement        | Filter context assembly output to documents within agent's context scope. Agents cannot access context outside their configured scope.        | 8          |
| Field-level redaction for agents | Apply field-level redaction to context chunks before agent sees content. Strip PII, IP-tagged, regulated fields per scope policy.             | 5          |
| Agent service account UI         | Admin UI: create/manage agent service accounts. Configure allowed tools, MCP servers, context scope, field redaction policy.                  | 5          |
| Agent governance test suite      | End-to-end test: agent attempting out-of-scope tool call → blocked. Agent requesting out-of-scope document → filtered.                        | 5          |

### Sprint 16 Acceptance Criteria
- Out-of-scope tool calls blocked and logged; agent receives access-denied response

- Context assembly filtered to agent scope; out-of-scope documents absent from agent context

- Field-level redaction removes configured sensitive fields from agent-visible content in all test cases

### Sprint 17 — MCP Guardrails Dashboard & Compliance Tagging \[Weeks 33–34\]
| **Task**                          | **Description**                                                                                                              | **Points** |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------|------------|
| MCP guardrail status dashboard    | Live dashboard: per-agent connectivity status, violation counts (last 24h), kill-switch events, tool call volume by agent    | 8          |
| Compliance tagging for MCP output | Tag MCP tool responses with compliance labels based on content scan. Labels flow into routing and audit pipeline.            | 5          |
| MCP tool call audit log           | Per-call audit: agent ID, tool name, MCP server, input hash, output hash, action taken, compliance tags, timestamp           | 5          |
| Bulk scope policy import          | Import agent scope policies via JSON/YAML for bulk onboarding of large agent fleets                                          | 3          |
| Agent risk score                  | Aggregate risk score per agent based on: connected tool risk scores, violation history, scope breadth. Display in dashboard. | 5          |

### Sprint 17 Acceptance Criteria
- MCP guardrail dashboard populates real-time from live agent traffic in staging environment

- Every MCP tool call produces a complete audit record with all required fields

- Agent risk scores update dynamically as tool connections and violation history change

## 7. Phase 6 — Compliance, Audit & Dashboard (Sprints 18–20)
Deliver the full compliance and audit package: complete audit trail with tamper-evident log, compliance dashboards mapped to GDPR/HIPAA/SOC 2/PCI-DSS, policy export and reporting, performance hardening, and general availability preparation.

### Sprint 18 — Audit Trail Hardening & Compliance Reports \[Weeks 35–36\]
| **Task**                        | **Description**                                                                                                                                                | **Points** |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Full audit schema enforcement   | Validate every audit event has required fields: timestamp, request hash, tenant ID, model used, policy version, risk score, action taken, enforcement duration | 5          |
| Tamper-evident log              | Hash chaining on audit records: each record includes hash of previous record. Verification API to detect tampering.                                            | 8          |
| Audit log query API             | REST API: query audit records by tenant, date range, model, action, risk level, policy version. Paginated response.                                            | 5          |
| GDPR compliance report          | Generate GDPR report: PII detected/redacted count, data lineage evidence, retention policy status, exportable as PDF                                           | 5          |
| HIPAA compliance report         | Generate HIPAA report: PHI encounter log, access events, redaction evidence per patient encounter (anonymized record IDs)                                      | 5          |
| SOC 2 / PCI-DSS evidence export | Export audit records in SOC 2 / PCI-DSS evidence format: access controls log, policy change log, incident log. ZIP archive download.                           | 5          |

### Sprint 18 Acceptance Criteria
- Hash chain on audit log verified by validation API; simulated record deletion detected as tamper event

- GDPR/HIPAA/SOC 2/PCI-DSS reports generate successfully from 30-day audit data in staging

- Audit query API returns correct filtered results with pagination within 2 seconds on 1M record dataset

### Sprint 19 — Enterprise Dashboard & Alerting \[Weeks 37–38\]
| **Task**                      | **Description**                                                                                                                                               | **Points** |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Security operations dashboard | Unified dashboard: request volume, block rate, top threats, top tenants, token budget consumption, active kill-switches, recent incidents                     | 8          |
| Policy coverage map           | Visualize policy coverage: which OWASP LLM Top 10 items have active rules. Coverage gaps highlighted.                                                         | 5          |
| Incident management           | Incident records for: Critical threat detections, namespace isolation breaches (attempted), kill-switch activations, Tier 2 ML findings                       | 5          |
| Real-time alert engine        | Configurable alerts: block rate spike, budget exhaustion, new Critical-risk MCP tool, kill-switch activation, anomaly score breach. Email + webhook delivery. | 8          |
| Tenant usage dashboard        | Per-tenant: request volume, block rate, token usage, policy violations, cost estimate. Accessible to tenant admins (scoped view).                             | 5          |
| Onboarding wizard             | Step-by-step onboarding: register first model, issue first API key, point test request at gateway, verify first audit log entry.                              | 3          |

### Sprint 19 Acceptance Criteria
- Security dashboard populates from production-equivalent load in staging environment

- Alerts fire within 60 seconds of trigger condition in alert integration test

- Onboarding wizard completes in \< 30 minutes in user test with a new engineer unfamiliar with the product

### Sprint 20 — Performance Hardening, Security Review & GA \[Weeks 39–40\]
| **Task**                        | **Description**                                                                                                                   | **Points** |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|------------|
| Load test — 1000 RPS            | Load test at 1000 requests/second sustained. Target: p99 latency \< 80 ms on keyword + PII path. Profile and optimize hotspots.   | 8          |
| Memory and CPU profiling        | Profile gateway under load. Identify and resolve memory leaks, inefficient regex compilation, cache eviction issues.              | 5          |
| Security penetration test       | External pentest engagement: gateway API, admin UI, audit log API, vector DB firewall. Report and remediate findings.             | 13         |
| Kubernetes production manifests | Production-grade K8s deployment: HPA, PodDisruptionBudget, NetworkPolicy, secrets management (Vault integration), resource limits | 5          |
| On-premise deployment guide     | Documentation: self-hosted gateway deployment with air-gapped vector DB and Llama. Docker Compose and K8s variants.               | 3          |
| GA release checklist            | Complete GA checklist: security review sign-off, performance sign-off, compliance report generation verified, runbook complete.   | 3          |

### Sprint 20 Acceptance Criteria
- Gateway sustains 1000 RPS with p99 latency \< 80 ms (keyword + PII path) in load test

- Zero Critical / High findings unresolved after pentest remediation cycle

- Production K8s manifests deploy cleanly to staging; HPA scales gateway pods under simulated load

- GA release checklist signed off by Engineering Lead, Security Lead, and Product Owner

## 8. Phase 7 — Agentic Security Enhancements P0/P1 (Sprints 21–27)
Addresses the critical and high-priority competitive gaps identified in the enhancement analysis. Covers: multilingual detection (E1), EU AI Act compliance (E8, parallel track), AI red teaming (E2), agent memory store security (E3), inter-agent A2A firewall (E4), HITL enforcement checkpoints (E5), and cascading failure detection (E6).

### Sprint 21 — Multilingual Threat Detection + EU AI Act Controls \[Weeks 41–42\]
| **Task**                            | **Description**                                                                                                                                                                     | **Points** |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Unicode normalization pre-processor | Normalize Unicode variants, homoglyphs, and character substitutions in prompts before pattern matching. Defeats encoding-based evasion.                                             | 5          |
| Multilingual model integration      | Integrate multilingual transformer model (mBERT or XLM-R) for injection/jailbreak detection across 100+ languages. Run as Tier 2 parallel to English Tier 1.                        | 13         |
| Language detection + routing        | Detect prompt language, apply language-appropriate detection model, record detected language in audit event.                                                                        | 3          |
| EU AI Act risk classification       | Risk classification schema for AI systems governed by Sphinx. Dashboard: display each registered AI application's EU AI Act risk tier (Prohibited / High-Risk / Limited / Minimal). | 5          |
| Transparency event logging          | Log AI-generated content markers per EU AI Act Article 50. Record model, generation timestamp, and output hash for transparency evidence.                                           | 3          |

### Sprint 21 Acceptance Criteria
- Multilingual model detects injection in French, Spanish, Chinese, Arabic, and Russian test prompts with \< 5% false positive rate

- Unicode obfuscation attacks (homoglyph substitution, zero-width characters) normalized and detected correctly

- EU AI Act risk tier assigned to each registered AI application; transparency event logged for every model response

### Sprint 22 — Language Pack Expansion + EU AI Act Human Oversight Docs \[Weeks 43–44\]
| **Task**                                 | **Description**                                                                                                                                                               | **Points** |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Language-specific threat pattern packs   | Curated injection and jailbreak patterns for top 20 non-English languages. Extend Tier 1 keyword library with translated and transliterated variants.                         | 8          |
| Cross-language attack detection          | Detect attacks that mix languages within a single prompt (e.g., English system prompt + Mandarin injection suffix).                                                           | 5          |
| EU AI Act human oversight documentation  | Generate Article 14 human oversight documentation: which agents have HITL checkpoints, who is designated as human overseer, audit of oversight events.                        | 5          |
| EU AI Act technical documentation export | Article 11 technical documentation package: system architecture summary, training data description (for fine-tuned models), accuracy and robustness measures. Exportable PDF. | 5          |
| Multilingual performance benchmark       | Regression test: detection latency p99 \< 120 ms across all supported languages. Publish language coverage matrix in admin UI.                                                | 3          |

### Sprint 22 Acceptance Criteria
- Language coverage matrix shows detection support for 50+ languages in admin UI

- Cross-language attack (English + non-English mixed prompt) detected correctly in test suite

- EU AI Act Article 11 technical documentation package generates successfully for a sample AI application

### Sprint 23 — Red Teaming Engine: Attack Probe Library \[Weeks 45–46\]
| **Task**                            | **Description**                                                                                                                                                   | **Points** |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Red team runner infrastructure      | Asynchronous job runner for attack simulation campaigns. Target: customer-provided AI application endpoint. Result storage per campaign.                          | 5          |
| Injection probe suite (100+ probes) | Automated probe library: direct injection, indirect injection (via document content), system prompt extraction, OWASP LLM Top 10 coverage.                        | 8          |
| Jailbreak probe suite               | DAN variants, role-play bypasses, many-shot jailbreaks, obfuscated instruction probes. Each probe returns: detected/not detected, risk score, bypass technique.   | 8          |
| PII extraction probes               | Probes designed to induce the model to reveal PII, training data, or system prompt content. Validates that Data Shield and output guardrails catch the responses. | 5          |
| Campaign results dashboard          | Admin UI: create red team campaign, view probe results, filter by technique/severity, export findings report.                                                     | 5          |

### Sprint 23 Acceptance Criteria
- Red team campaign runs 100+ probes against target endpoint and returns results within 10 minutes

- Campaign results correctly flag known-vulnerable endpoints in test scenarios; known-secure endpoints show zero critical findings

- Findings report exportable as PDF from admin UI

### Sprint 24 — Red Teaming: Agentic Probes + Policy Feedback Loop \[Weeks 47–48\]
| **Task**                                | **Description**                                                                                                                                            | **Points** |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Agentic attack probe suite              | Probes targeting agentic applications: tool call injection, memory poisoning simulation, privilege escalation via agent context, multi-step attack chains. | 13         |
| Red team → policy recommendation engine | Analyze probe results; generate recommended policy rules that would have blocked detected vulnerabilities. One-click policy import from recommendation.    | 8          |
| Continuous red team scheduling          | Schedule recurring red team campaigns (daily/weekly). Alert on regression: new vulnerability detected that was not present in prior campaign.              | 5          |
| Red team API                            | REST API for CI/CD integration: trigger campaign, poll results, fail build on Critical findings. Enables security-gated deployment pipelines.              | 5          |

### Sprint 24 Acceptance Criteria
- Agentic probe suite detects tool call injection and memory poisoning in test scenarios

- Policy recommendation generated from red team findings imports correctly and blocks the detected attack in regression test

- Red team API integrates with GitHub Actions CI/CD pipeline in reference integration test

### Sprint 25 — Agent Memory Store Firewall: Write Interception \[Weeks 49–50\]
| **Task**                                      | **Description**                                                                                                                                                                           | **Points** |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Memory store proxy                            | Intercept agent memory write operations to Redis, PostgreSQL (pgvector), and vector stores used as agent memory. Support LangChain, AutoGen, CrewAI memory abstractions.                  | 13         |
| Instruction-pattern scanner for memory writes | Scan content being written to agent memory for instruction-like patterns (imperative commands, policy override language, future-tense directives). Block or quarantine suspicious writes. | 8          |
| Memory write audit log                        | Per-write audit: agent ID, session, content hash, scanner verdict, action taken. Immutable record.                                                                                        | 3          |
| Memory write policy configuration             | Admin UI: configure per-agent memory write policies — allow all / scan-and-allow / scan-and-block / require approval (HITL).                                                              | 3          |

### Sprint 25 Acceptance Criteria
- Memory write interception active for LangChain and AutoGen memory backends in integration tests

- Instruction-like content injected into agent memory write is blocked with audit record created

- Legitimate memory writes (factual information, conversation summaries) pass without false positive in test suite

### Sprint 26 — Agent Memory Store Firewall: Read Controls + Lifecycle \[Weeks 51–52\]
| **Task**                         | **Description**                                                                                                                                                                                             | **Points** |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Memory read anomaly detection    | Monitor agent memory read patterns. Flag: reads of content written by a different agent (cross-agent memory access), reads of high-age memory chunks that have not been accessed in anomaly-threshold days. | 8          |
| Memory lifecycle cap enforcement | Configurable hard token limit on agent long-term memory (e.g., 20,000 tokens). Enforce eviction of oldest content when cap is reached. Prevents unbounded data accumulation.                                | 5          |
| Memory integrity verification    | Periodic hash-chain verification on stored memory records. Detect post-write tampering. Alert on integrity failure.                                                                                         | 5          |
| Memory store dashboard           | Admin UI: per-agent memory size, write velocity, blocked writes count, anomaly flags, integrity status.                                                                                                     | 3          |
| Cross-agent memory isolation     | Policy enforcement: agent A cannot read memory written by agent B unless explicitly permitted. Isolate agent memory namespaces.                                                                             | 5          |

### Sprint 26 Acceptance Criteria
- Cross-agent memory read blocked when not in permitted scope; legitimate same-agent reads pass

- Memory lifecycle cap enforced; eviction fires when token limit is reached

- Memory integrity verification detects simulated post-write tampering and fires alert

### Sprint 27 — Inter-Agent A2A Protocol Firewall \[Weeks 53–54\]
| **Task**                               | **Description**                                                                                                                                        | **Points** |
|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| A2A message interception layer         | Intercept agent-to-agent messages using the Agent2Agent (A2A) protocol. Support LangGraph, AutoGen multi-agent, and CrewAI orchestration frameworks.   | 13         |
| Agent identity token issuance          | Issue signed JWT tokens to each registered agent service account. Tokens carry: agent ID, allowed downstream agents, permission scope, expiry.         | 8          |
| Message signature verification         | Verify A2A message signature on receipt. Reject messages from unregistered agents or with invalid signatures. Block replay attacks via nonce tracking. | 8          |
| Mutual TLS for agent-to-agent channels | Enforce mTLS between agents in the same multi-agent workflow. Certificate issuance via Sphinx-managed CA or SPIFFE/SPIRE integration.                  | 5          |
| A2A audit log                          | Per-message audit: sender agent, receiver agent, message content hash, signature verified, action taken.                                               | 3          |

### Sprint 27 Acceptance Criteria
- A2A message from unregistered agent rejected with audit record in all test scenarios

- Replay attack (reused nonce) blocked correctly

- mTLS enforced between agents in LangGraph multi-agent integration test

## 9. Phase 8 — Enterprise & Strategic Enhancements P1/P2 (Sprints 28–30)
Delivers the remaining high and medium priority enhancements: Human-in-the-Loop enforcement checkpoints (E5), cascading failure detection (E6), ML model supply chain scanning (E7), multi-turn conversation security (E9), AI-SPM integration (E10), and secure semantic caching (E11). These sprints also set up the P3 strategic enhancements for Q1–Q2 2027.

### Sprint 28 — HITL Enforcement Checkpoints + Cascading Failure Detection \[Weeks 55–56\]
| **Task**                           | **Description**                                                                                                                                                             | **Points** |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| HITL action type in policy engine  | Add 'Require Human Approval' as a first-class policy action. When triggered: pause agent workflow, create approval request, return 202 Pending to agent.                    | 8          |
| Approval workflow API              | REST API: GET /approvals (list pending), POST /approvals/{id}/approve, POST /approvals/{id}/reject. Configurable timeout with fallback action (auto-approve or auto-block). | 5          |
| Approval channel integrations      | Slack bot and email integration for approval notifications. Approver receives: agent ID, action description, risk context, approve/reject buttons.                          | 5          |
| Agent behavioral baseline engine   | Track per-agent: tool call sequence patterns, output volume, API call frequency. Establish baseline over first 7 days of operation.                                         | 5          |
| Cascading failure anomaly detector | Detect deviation from agent behavioral baseline. Threshold-based circuit breaker: open on N consecutive anomalous actions within time window.                               | 8          |

### Sprint 28 Acceptance Criteria
- HITL approval request sent via Slack within 30 seconds of policy trigger; approved action resumes within 5 seconds of approval

- Auto-block fires correctly when approval timeout expires with no response

- Agent behavioral baseline established after 7-day observation period; anomaly detected in simulated attack scenario

### Sprint 29 — ML Model Scanning + Multi-Turn Security + AI-SPM Integration \[Weeks 57–58\]
| **Task**                                      | **Description**                                                                                                                                                        | **Points** |
|-----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Model artifact scanner                        | Scan model files (GGUF, safetensors, PyTorch .pt/.bin) for deserialization attacks, malicious pickle payloads, and embedded backdoor triggers before deployment.       | 13         |
| Model provenance registry                     | Hash-based model integrity registry: store SHA-256 of approved model artifacts. Block deployment of unregistered or hash-mismatch models.                              | 5          |
| Session context store for multi-turn security | Maintain session context (last N turns, cumulative risk score) per conversation. Expire sessions on inactivity.                                                        | 5          |
| Cross-turn risk accumulation                  | Accumulate risk score across turns in a session. Trigger escalated action (block or HITL) when session-level cumulative score exceeds threshold.                       | 5          |
| AI-SPM integration (shadow AI discovery)      | Connect Sphinx gateway to AISPM asset inventory. Discovered AI assets not routing through gateway flagged as ungoverned in dashboard. Enrollment flow to onboard them. | 5          |

### Sprint 29 Acceptance Criteria
- Model scanner detects known-malicious pickle payload in test model file; clean models pass with no false positive

- Cross-turn escalation triggers correctly when risk accumulates across a multi-turn jailbreak simulation

- Ungoverned AI assets discovered by AI-SPM appear in Sphinx dashboard with enrollment prompt

### Sprint 30 — Secure Semantic Caching + Phase 8 Hardening & v2.0 Release \[Weeks 59–60\]
| **Task**                             | **Description**                                                                                                                                                                        | **Points** |
|--------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Semantic cache layer                 | Tenant-scoped semantic cache using embedding similarity. Cache hit threshold configurable (default cosine similarity \> 0.95). Cache responses per policy-version + model combination. | 8          |
| Cache security controls              | Per-tenant cache namespace isolation, cache poisoning detection (flag cached responses containing injection patterns), automatic full-cache invalidation on policy change.             | 5          |
| Cache-hit audit logging              | Log cache hits: original query hash, matched cache key, similarity score, policy version at cache time. Distinguish cache-served vs. model-served responses in audit trail.            | 3          |
| Cascading failure circuit breaker UI | Admin UI: per-agent circuit breaker status (closed/open/half-open), anomaly timeline, manual reset, downstream halt event log.                                                         | 3          |
| Phase 8 integration test suite       | End-to-end tests covering: HITL flow, A2A firewall, memory poisoning block, model scan gate, multi-turn escalation, semantic cache with security controls.                             | 8          |
| v2.0 release checklist               | Security review of all Phase 7–8 features, performance regression test (all new checks \< 50 ms p99 overhead), documentation update, v2.0 release notes.                               | 5          |

### Sprint 30 Acceptance Criteria
- Semantic cache achieves 30%+ cache hit rate on repetitive query workload test; cache namespace isolation confirmed (tenant A cannot retrieve tenant B's cached responses)

- All Phase 7–8 integration tests pass in staging environment

- All Phase 7–8 new checks add \< 50 ms p99 overhead in isolation (measured independently)

- v2.0 release checklist signed off by Engineering Lead, Security Lead, and Product Owner

## 10. Sprint Summary & Milestone Map — All 30 Sprints
| **Sprint** | **Title**                                        | **Phase** | **Weeks** | **Key Output**                                                              |
|------------|--------------------------------------------------|-----------|-----------|-----------------------------------------------------------------------------|
| 1          | Gateway Skeleton & API Key Auth                  | P1        | 1–2       | Working proxy + API key validation                                          |
| 2          | Rate Limiting, Token Budgets & Kill-Switch       | P1        | 3–4       | TPM enforcement + kill-switch skeleton                                      |
| 3          | Multi-Provider Routing & Audit Skeleton          | P1        | 5–6       | OpenAI/Claude/Gemini adapters + async audit                                 |
| 4          | Tier 1 Threat Detection Engine                   | P2        | 7–8       | Injection/jailbreak detection + policy actions                              |
| 5          | PII/PHI Detection & Redaction                    | P2        | 9–10      | Data Shield — input PII/PHI/credential redaction                            |
| 6          | RAG Pipeline Classification & Query Firewall     | P2        | 11–12     | RAG stage classification + query-stage controls                             |
| 7          | Tier 2 ML Scanner & Policy Versioning            | P2        | 13–14     | ML semantic analysis + policy snapshot/rollback                             |
| 8          | Vector DB Proxy & Namespace Isolation            | P3        | 15–16     | Pre-retrieval interception + tenant namespace injection                     |
| 9          | Chunk Scanning & Indirect Injection Prevention   | P3        | 17–18     | Retrieved content scanning + anomaly detection                              |
| 10         | Vector DB Hardening & Observability              | P3        | 19–20     | Full Milvus support + pentest (zero escapes)                                |
| 11         | Sensitivity-Based Routing & Budget Downgrade     | P4        | 21–22     | Compliance-tag routing + Llama adapter                                      |
| 12         | Kill-Switch Production Hardening                 | P4        | 23–24     | Bedrock/Azure adapters + production kill-switch                             |
| 13         | Provider Health Monitoring & Failover            | P4        | 25–26     | Circuit breaker + cost dashboard                                            |
| 14         | Streaming Output Scanner                         | P5        | 27–28     | Output PII/credential redaction in stream                                   |
| 15         | MCP Server Discovery & Risk Scoring              | P5        | 29–30     | Tool inventory + automated risk scoring                                     |
| 16         | Per-Agent Scope Enforcement                      | P5        | 31–32     | Service accounts + tool/context access control                              |
| 17         | MCP Guardrails Dashboard                         | P5        | 33–34     | Live agent governance dashboard + compliance tagging                        |
| 18         | Audit Trail Hardening & Compliance Reports       | P6        | 35–36     | Tamper-evident log + GDPR/HIPAA/SOC2 reports                                |
| 19         | Enterprise Dashboard & Alerting                  | P6        | 37–38     | Unified dashboard + real-time alert engine                                  |
| 20         | Performance Hardening & GA v1.0                  | P6        | 39–40     | 1000 RPS load test + pentest + GA release                                   |
| 21         | Multilingual Detection + EU AI Act Controls      | P7        | 41–42     | 100+ language detection + EU AI Act risk classification                     |
| 22         | Language Pack Expansion + EU AI Act Docs         | P7        | 43–44     | 50+ language coverage + Article 11 technical docs export                    |
| 23         | Red Teaming Engine: Attack Probe Library         | P7        | 45–46     | 200+ injection/jailbreak probes + campaign dashboard                        |
| 24         | Red Teaming: Agentic Probes + Policy Feedback    | P7        | 47–48     | Agentic probe suite + policy recommendation engine + CI/CD API              |
| 25         | Agent Memory Firewall: Write Interception        | P7        | 49–50     | Memory write scanner + instruction-pattern block + audit                    |
| 26         | Agent Memory Firewall: Read Controls + Lifecycle | P7        | 51–52     | Memory read anomaly + lifecycle cap + integrity verification                |
| 27         | Inter-Agent A2A Protocol Firewall                | P7        | 53–54     | A2A message signing + mTLS enforcement + replay protection                  |
| 28         | HITL Checkpoints + Cascading Failure Detection   | P8        | 55–56     | Approval workflow + agent behavioral baseline + circuit breaker             |
| 29         | ML Model Scanning + Multi-Turn Security + AI-SPM | P8        | 57–58     | Model artifact scanner + cross-turn risk accumulation + shadow AI discovery |
| 30         | Secure Semantic Caching + v2.0 Release           | P8        | 59–60     | Tenant-isolated cache + cache security controls + v2.0 GA                   |

Sphinx \| sphinx.ai \| support@sphinx.ai

All rights reserved. Confidential and proprietary.
