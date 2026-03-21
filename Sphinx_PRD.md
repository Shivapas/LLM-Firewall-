# Sphinx — AI Mesh Firewall

## Product Requirements Document v2.0

| **Field**      | **Detail**                                                            |
|----------------|-----------------------------------------------------------------------|
| Product        | Sphinx AI Mesh Firewall                                               |
| Version        | 2.0                                                                   |
| Document Type  | Product Requirements Document (PRD)                                   |
| Status         | Updated — Includes Competitive Enhancement Analysis (14 Enhancements) |
| Date           | March 2026                                                            |
| Owner          | Product Management                                                    |
| Classification | Confidential                                                          |

## 1. Executive Summary
Sphinx's AI Mesh Firewall is a server-side security and governance platform that intercepts, inspects, and enforces policy on every AI interaction before it reaches a language model or vector database. It is deployed as a transparent proxy — AI workloads point to the Sphinx gateway instead of calling providers directly, requiring zero code changes to existing applications.

The platform addresses a critical gap in enterprise AI security: the absence of a unified enforcement layer that governs the entire AI request lifecycle — from prompt ingestion through retrieval, model routing, generation, and output delivery. Unlike point solutions focused on prompts or outputs in isolation, the AI Mesh Firewall applies security controls at every stage of the pipeline.

| **Dimension**       | **Value**                                                                   |
|---------------------|-----------------------------------------------------------------------------|
| Primary Value Prop  | Firewall the full AI pipeline — not just the prompt or the output           |
| Deployment Model    | Transparent proxy / reverse gateway — base URL swap only, zero code changes |
| Target Market       | Enterprise — financial services, healthcare, legal, SaaS, technology        |
| Core Differentiator | Vector DB Firewall + inline kill-switch + full-pipeline RAG controls        |
| Compliance Coverage | GDPR, HIPAA, SOC 2 Type II, PCI-DSS, OWASP LLM Top 10                       |
| Latency Overhead    | ~0.01–0.05 s typical (well below LLM first-token latency of 0.5–2 s)        |

## 2. Problem Statement
Enterprise AI adoption has outpaced the security controls designed to govern it. Organizations deploy LLM-powered chatbots, autonomous agents, and RAG applications into production without the visibility or enforcement mechanisms available in traditional network security. The following threat categories represent the core problems Sphinx solves:

| **Threat Category**           | **Description**                                                                                             | **Business Impact**                                       |
|-------------------------------|-------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| Prompt Injection & Jailbreaks | Malicious prompts bypass model alignment, exposing sensitive data or triggering unintended actions          | Data breach, regulatory violation, reputational damage    |
| RAG Data Leakage              | Cross-tenant retrieval in multi-tenant RAG deployments exposes confidential documents to unauthorized users | Privilege escalation, data exposure, compliance failure   |
| PII/PHI in AI Pipelines       | Sensitive personal and health data enters LLM prompts or appears in model output without masking            | GDPR, HIPAA, PCI-DSS violations; regulatory fines         |
| Uncontrolled Model Access     | No unified policy layer; each service calls LLMs directly, creating ungoverned shadow AI                    | No audit trail, no kill-switch, no cost control           |
| Compromised Model Provider    | No mechanism to instantly disable a degraded or compromised AI provider without service restart             | Extended exposure window, operational disruption          |
| MCP Tool Sprawl               | AI agents connect to arbitrary tool servers with write/outbound access, unknown to security teams           | Lateral movement, data exfiltration, privilege escalation |
| Output Data Leakage           | Model responses contain PII, credentials, or regulated data delivered to end users in plain text            | Compliance violation, liability exposure                  |

## 3. Goals & Objectives
### 3.1 Product Goals
- Provide a single, unified enforcement gateway for all enterprise AI traffic across all LLM providers and RAG pipelines

- Deliver pipeline-aware security controls at every stage: ingress authentication, input firewall, RAG query, vector retrieval, context assembly, model routing, output scanning, and audit

- Enable zero-code-change deployment — any AI workload redirected to the Sphinx gateway is governed without modification

- Achieve compliance-grade auditability for GDPR, HIPAA, SOC 2 Type II, and PCI-DSS requirements

- Maintain sub-100 ms total gateway overhead, imperceptible to end users in chatbot and agent workloads

### 3.2 Business Objectives
- Capture enterprise security budget as AI governance becomes a board-level requirement

- Differentiate on the Vector DB Firewall and inline kill-switch capabilities not offered by any competitor

- Drive adoption through frictionless deployment (base URL swap) that lowers barriers compared to SDK-required alternatives

- Generate expansion revenue through per-model, per-tenant, and per-volume pricing tied to AI usage growth

### 3.3 Success Metrics
| **Metric**                   | **Target**                                                       | **Measurement Method**         |
|------------------------------|------------------------------------------------------------------|--------------------------------|
| Time-to-first-governance     | \< 30 minutes from account creation to active policy enforcement | Onboarding telemetry           |
| Gateway latency (p95)        | \< 80 ms additional overhead (keyword + PII path)                | Gateway performance metrics    |
| Policy propagation time      | \< 5 seconds from control plane update to active enforcement     | Policy sync telemetry          |
| Audit log completeness       | 100% of requests produce an audit record with required fields    | Audit pipeline monitoring      |
| Kill-switch activation time  | Next request after activation — no restart required              | Functional test                |
| Vector namespace isolation   | Zero cross-tenant retrieval in test suite (0 escapes)            | Integration test suite         |
| False positive rate (Tier 1) | \< 2% of legitimate requests blocked at Tier 1 detection         | Weekly policy review dashboard |

## 4. Target Users & Personas
| **Persona**                | **Role**                            | **Primary Concern**                                           | **Key Sphinx Value**                                                      |
|----------------------------|-------------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------------|
| CISO / Security Team       | Enterprise security leadership      | Visibility and control over all AI traffic; prevent shadow AI | Centralized gateway; full audit trail; kill-switch                        |
| Platform / DevOps Engineer | AI infrastructure ownership         | Reliable, policy-driven AI infra with failover                | Zero code change deployment; multi-provider abstraction; fallback routing |
| Compliance Officer         | Regulatory and audit responsibility | Auditable AI usage with PII handling evidence                 | Policy versioning; audit log; GDPR/HIPAA/SOC2 controls                    |
| AI / ML Engineer           | Model development and deployment    | Security guardrails that do not block velocity                | Monitor mode before enforce; non-blocking PII redaction                   |
| Enterprise Architect       | Multi-provider AI strategy          | Cost and risk controls across LLM ecosystem                   | Token budgets; model downgrade routing; provider abstraction              |

## 5. Core Feature Modules
**Module 1.1 — AI Gateway & Traffic Ingress**

The gateway is the single entry point for all AI traffic. Every AI client — chatbot, agent framework, backend service — authenticates using a Gateway API Key before any request is forwarded to a model or vector store.

| **API Key Field** | **Function**                                              |
|-------------------|-----------------------------------------------------------|
| Allowed Models    | Restricts which LLM providers this key may call           |
| Rate Limit (TPM)  | Maximum tokens per minute — traffic shaping at ingress    |
| Risk Score        | Baseline risk level used in routing and policy decisions  |
| Expiry            | Automatic invalidation after configured date/time         |
| Project / Tenant  | Isolation boundary for request policies and audit records |

Enforced at every ingress: credential validation, tenant context injection, token budget enforcement, rate limiting, kill-switch status check.

**Module 1.2 — Pipeline-Aware RAG Firewall**

Classifies each request as standard chat or RAG query and applies differentiated enforcement rules at each pipeline stage: Query, Retriever (Ranker), and Generator.

| **RAG Stage** | **Controls Applied**                                   |
|---------------|--------------------------------------------------------|
| Query         | Injection detection, PII scan, intent classification   |
| Retriever     | Namespace isolation, poison scan, context minimization |
| Generator     | Output guardrails, PII redaction on streaming response |

| **Threat**            | **Detection Method**                           | **Action**    |
|-----------------------|------------------------------------------------|---------------|
| Prompt injection      | Sphinx Threat Engine + OWASP-aligned detectors | Block         |
| Jailbreak attempt     | Heuristic and pattern analysis                 | Block         |
| PII / PHI in prompt   | Sphinx Data Shield                             | Mask / Redact |
| Credentials in prompt | Pattern matching                               | Block         |

**Module 1.3 — Vector DB Firewall**

Intercepts retrieval queries before they reach the vector database. Every governed collection requires an explicit access policy — unlisted collections are inaccessible by default. Supported databases: ChromaDB, Pinecone, Milvus.

| **Control**                | **Function**                                                      |
|----------------------------|-------------------------------------------------------------------|
| Default Action             | Deny / Allow / Monitor for unmatched queries                      |
| Allowed Operations         | Configurable: Query, Insert, Update, Delete                       |
| Namespace Isolation        | Tenant identifier injected into every retrieval query (mandatory) |
| Max Results per Query      | Cap on documents returned (1–100 configurable)                    |
| Anomaly Distance Threshold | Statistical monitoring on query embedding vectors                 |
| Sensitive Fields           | Named fields flagged for extra scrutiny                           |
| Context Scan Required      | Retrieved chunks scanned before reaching the model                |
| Block Sensitive Documents  | Auto-block documents matching sensitive field patterns            |

**Module 1.4 — Context Assembly & MCP Guardrails**

Governs the context assembly phase for both RAG pipelines and MCP-connected AI agents. Applies user/agent-scoped context filtering, field-level redaction of PII and IP-tagged content, and compliance tagging to trigger downstream routing policy.

| **Control**                | **Function**                                                     |
|----------------------------|------------------------------------------------------------------|
| Per-user context scope     | Context filtered based on authenticated user permissions         |
| Per-agent context scope    | Agents access context only via scoped service accounts           |
| Field-level redaction      | PII, IP-tagged, and regulated fields stripped before assembly    |
| Compliance tagging         | Chunks tagged as PII / IP / regulated for routing policy trigger |
| MCP tool inventory         | Automated discovery of all tool servers with risk scoring        |
| Guardrail status dashboard | Live view of agent connectivity, violations, kill-switch events  |

**Module 1.5 — Multi-Model Governance & Routing**

Abstracts all LLM providers behind a unified endpoint. Routing decisions are based on data sensitivity, compliance tags, token budget status, and kill-switch state. Supported: OpenAI GPT-4o/4-Turbo, Anthropic Claude, Google Gemini, Azure OpenAI, Llama (self-hosted), AWS Bedrock.

| **Routing Signal**                  | **Result**                              |
|-------------------------------------|-----------------------------------------|
| Sensitive data / compliance tag     | Route to private or on-premise model    |
| No sensitive data detected          | Route to public cloud model             |
| Token budget exceeded               | Downgrade to lower-cost model tier      |
| Kill-switch active for target model | 503 error or silent reroute to fallback |

**Module 1.6 — Inline Model Isolation & Kill-Switch**

Each model provider operates with independent credentials, rate limits, and risk scores. A kill-switch can be activated per model at any time via the control plane. The state is checked at the earliest point in the enforcement chain and propagates to the gateway on the next request — no service restart required.

| **Kill-Switch Field** | **Function**                                                    |
|-----------------------|-----------------------------------------------------------------|
| Model Name            | Target provider (e.g., gpt-4o, claude-3-opus)                   |
| Action                | Block (controlled 503) or Reroute (silent redirect to fallback) |
| Fallback Model        | Target model when action is Reroute                             |
| Reason                | Permanent audit record with username and timestamp              |

**Module 1.7 — Generator-Level Output Guardrails**

Inspects the model's streaming response in chunks before delivery to the client. Streaming performance is maintained — output begins flowing to the client without waiting for the full response.

| **Content Type**                     | **Detection**           | **Action**       |
|--------------------------------------|-------------------------|------------------|
| PII / PHI (names, IDs, card numbers) | Sphinx Data Shield      | Redact in stream |
| Credentials / API keys               | Sphinx Threat Engine    | Block / Redact   |
| Policy violations                    | Policy rule evaluation  | Block / Rewrite  |
| Regulated data leakage               | Compliance tag matching | Redact + Log     |

## 6. Non-Functional Requirements
### 6.1 Performance
| **Check Type**                           | **Target Latency** | **Notes**                                    |
|------------------------------------------|--------------------|----------------------------------------------|
| API key validation + kill-switch         | \< 1 ms            | In-memory cache only; no database round-trip |
| Keyword policy rules                     | \< 1 ms            | Compiled rule evaluation                     |
| PII detection                            | 5–20 ms            | Runs parallel to routing                     |
| Threat Engine injection scoring (Tier 1) | 20–80 ms           | Pattern + heuristic; no GPU                  |
| ML semantic analysis (Tier 2)            | 50–200 ms          | Triggered only when Tier 1 inconclusive      |
| Audit event write                        | 0 ms (async)       | Message queue; zero impact on response path  |
| Total (typical production path)          | ~10–50 ms          | Keyword + PII detection active               |
| Total (with ML scoring)                  | ~100–300 ms        | Tier 2 active                                |

### 6.2 Scalability
- Gateway must scale horizontally — stateless request path with all policy state in shared cache

- Policy cache must support hot reload within 5 seconds of control plane update without gateway restart

- Audit pipeline must be fully asynchronous with no back-pressure on the live request path

- Scanning engines must run in parallel where possible (PII + injection concurrently)

### 6.3 Reliability
- Gateway must not become a single point of failure — active/active or active/passive deployment options

- Kill-switch propagation must be deterministic — next request after activation must respect new state

- Fallback routing must activate without client-visible error when action is Reroute

### 6.4 Security
- All API keys encrypted at rest and in transit; keys never logged in plaintext

- Audit log must be append-only and tamper-evident

- Control plane must enforce RBAC for policy changes, kill-switch activation, and key management

- Gateway must support mTLS for client authentication in high-security deployments

## 7. Governance & Compliance
| **Regulation**                     | **Coverage**                                                                                                                                                                  |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GDPR                               | PII detection and redaction in input and output; audit records support data lineage and right-to-erasure evidence                                                             |
| HIPAA                              | PHI detection and masking for prompt input and generated output; full audit trail per encounter                                                                               |
| SOC 2 Type II                      | Audit trail, access controls, multi-tenant isolation, policy versioning                                                                                                       |
| PCI-DSS                            | Credential and card number detection in prompts and responses; automatic redaction                                                                                            |
| EU AI Act (enforcement Aug 2026)   | Human oversight documentation for high-risk AI; transparency logging for AI-generated content; risk classification records; technical documentation for conformity assessment |
| OWASP LLM Top 10                   | LLM01 Prompt Injection, LLM02 Insecure Output Handling, LLM06 Sensitive Information Disclosure                                                                                |
| OWASP Agentic AI Top 10 (Dec 2025) | AA1 Memory Poisoning, AA3 Insufficient Human Oversight, AA6 Multi-Agent Orchestration, AA9 Cascading Failures — covered by Enhancement Modules                                |

## 8. Competitive Differentiation
The matrix below shows Sphinx's current state and its post-enhancement state (after P0/P1 roadmap delivery, Q2–Q4 2026) against the competitive set. Key acquisition and market events: Check Point acquired Lakera (Sept 2025); Palo Alto Networks acquired Protect AI/Guardian (July 2025); Radware launched Agentic AI Protection (Feb 2026).

| **Capability**                     | **Sphinx v1**                  | **Sphinx v2 (+Enhancements)**         | **Lakera (Check Point)** | **Palo Alto Prisma AIRS** | **Radware Agentic** | **Nexos / GuardionAI** |
|------------------------------------|--------------------------------|---------------------------------------|--------------------------|---------------------------|---------------------|------------------------|
| Multi-Model Gateway                | Yes                            | Yes                                   | No                       | Yes                       | Yes                 | Yes / Yes              |
| Prompt Injection Defence           | Yes — heuristic + ML           | Yes + multilingual (100+ lang)        | Yes — 98%+, 100+ lang    | Yes                       | Yes                 | Yes / Yes              |
| PII / PHI Redaction                | Yes — input + stream output    | Yes                                   | Yes                      | Yes                       | Yes                 | Yes / Yes              |
| RAG Pipeline Controls              | Yes — per stage                | Yes — per stage                       | Prompt only              | Partial                   | No                  | Context only / No      |
| Vector DB Firewall (pre-retrieval) | Yes — unique                   | Yes                                   | No                       | No                        | No                  | No / No                |
| MCP / Agent Tool Governance        | Yes — inventory + risk scoring | Yes + A2A protocol firewall           | No                       | Yes (Guardian)            | Yes                 | No / Yes               |
| Inline Kill-Switch (no restart)    | Yes — unique                   | Yes                                   | No                       | No                        | No                  | No / No                |
| Zero Code Change Deploy            | Yes — base URL swap            | Yes                                   | No (API calls)           | Partial                   | Partial             | SDK req / Yes          |
| Agent Memory Store Security        | No                             | Yes — memory poisoning detection      | No                       | No                        | Partial             | No / No                |
| Inter-Agent (A2A) Security         | No                             | Yes — A2A message firewall            | No                       | No                        | Partial             | No / No                |
| Human-in-the-Loop Enforcement      | No                             | Yes — HITL approval checkpoints       | No                       | No                        | No                  | No / No                |
| Cascading Failure Detection        | No                             | Yes — agent circuit breakers          | No                       | No                        | Partial             | No / No                |
| AI Red Teaming                     | No                             | Yes — automated pre-deploy simulation | Yes (Lakera Red)         | Yes (Prisma)              | No                  | No / No                |
| ML Model Artifact Scanning         | No                             | Yes (Q1 2027)                         | No                       | Yes (Guardian)            | No                  | No / No                |
| EU AI Act Compliance Reports       | No                             | Yes                                   | Partial                  | Partial                   | No                  | No / No                |
| AI-SPM (Asset Discovery)           | Separate product               | Integrated                            | No                       | Yes                       | No                  | No / Partial           |
| Full Audit Trail                   | Yes — every request            | Yes                                   | Yes                      | Yes                       | Yes                 | Yes / Yes              |

**Sphinx v2 unique capabilities — no competitor offers in combination:**

- Vector DB Firewall with pre-retrieval namespace isolation — the only platform to intercept retrieval before it reaches the database

- Agent Memory Store Security & Memory Poisoning Detection — OWASP Agentic Top 10 \#1 risk, no competitor has shipped this

- Inter-Agent A2A Protocol Firewall — first platform to govern agent-to-agent message authentication and replay protection

- HITL Enforcement Checkpoints — pause-and-approve action type for regulated high-impact agent operations

- Inline kill-switch with deterministic propagation + full pipeline coverage + zero code change deployment

## 9. Deployment Model & Adoption Lifecycle
### 9.1 Deployment
AI workloads redirect to the Sphinx gateway by changing the base URL from the LLM provider endpoint to the Sphinx gateway URL. No SDK installation, library import, or code modification is required.

### 9.2 Adoption Phases
| **Phase** | **Mode**                    | **What Happens**                                                                          |
|-----------|-----------------------------|-------------------------------------------------------------------------------------------|
| Deploy    | Configuration               | Register models and vector stores, issue API keys per project, define initial policies    |
| Monitor   | Observe (log without block) | Collect enforcement events, review dashboards, baseline risk patterns, understand traffic |
| Enforce   | Active enforcement          | Tighten policies incrementally — Redact, then Block, then model downgrade routing         |

Policy updates compile and propagate to the gateway in near real-time — no service restart required at any phase transition.

## 10. Constraints & Assumptions
### 10.1 Constraints
- The gateway operates as a synchronous proxy on the critical request path — scanning latency directly impacts user experience

- Streaming support must be maintained for all models that support it (OpenAI, Anthropic, Gemini)

- Policy changes must not require gateway restart — hot reload is mandatory

- On-premise self-hosted deployment option required for customers with data residency requirements

### 10.2 Assumptions
- Enterprise customers will accept a 10–80 ms overhead increase on AI requests in exchange for security and compliance controls

- The majority of threat detection can be handled by Tier 1 (heuristic/pattern) with Tier 2 ML reserved for ambiguous cases

- Customers will route all AI traffic through the gateway — direct-to-provider calls should be blocked at the network level

- Vector database providers (Chroma, Pinecone, Milvus) support metadata filtering that can enforce namespace isolation

### 10.3 Out of Scope (v1.0 GA — addressed in Enhancement Roadmap)
- Kubernetes eBPF runtime enforcement / CNAPP integration (Q2 2027 roadmap)

- Live adversarial threat intelligence feed / community corpus (Q2 2027 roadmap)

- MSSP white-label multi-tenant management portal (Q1 2027 roadmap)

- Model fine-tuning governance and training data provenance

## 11. Open Questions & Decisions Required
| **\#** | **Question**                                                                                                                             | **Owner**             | **Priority** |
|--------|------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|--------------|
| 1      | What is the SLA for audit log availability? Should audit records be queryable in near real-time or is end-of-day acceptable?             | Eng / Product         | High         |
| 2      | What is the data retention policy for audit logs? Configurable per tenant or platform-wide?                                              | Legal / Product       | High         |
| 3      | Should reversible PII redaction (tokenization with vault) be offered in v1.0 or deferred?                                                | Product               | Medium       |
| 4      | What is the target for MCP server risk scoring — heuristic rules or ML-based? What training data is available?                           | Engineering           | Medium       |
| 5      | Is Tier 2 ML scanning run locally (on-premise gateway) or via a Sphinx cloud scanning API?                                               | Architecture          | High         |
| 6      | What is the pricing model — per request, per token, per tenant seat, or a combination?                                                   | Product / Finance     | High         |
| 7      | For HITL enforcement: what is the approval channel — Slack integration, email, native UI? What is the SLA for approval timeout?          | Product               | High         |
| 8      | For A2A security: does Sphinx issue agent identity tokens or integrate with external agent identity providers (SPIFFE/SPIRE)?            | Architecture          | High         |
| 9      | For the red teaming module: is this a SaaS cloud service or an on-premise runner for air-gapped enterprise environments?                 | Product / Engineering | Medium       |
| 10     | For EU AI Act compliance: what risk classification tier does Sphinx itself fall into? Does Sphinx need to file conformity documentation? | Legal / Product       | High         |

## 12. Enhancement Modules — Competitive Roadmap (v2.0)
This section defines the 14 enhancement modules identified through the competitive analysis against Lakera Guard (Check Point), Palo Alto Prisma AIRS, Radware Agentic AI Protection, HiddenLayer, NeMo Guardrails, CalypsoAI, Securiti, and AccuKnox. Enhancements are grouped by priority tier and mapped to the OWASP Agentic AI Top 10 (December 2025) where applicable.

### 12.1 Priority 0 — Critical (Q2 2026)
#### E1: Multilingual Prompt Attack Detection
Extends the Tier 1 and Tier 2 detection engines to support 100+ languages and scripts. Lakera Guard's most-cited benchmark is 98%+ detection across 100+ languages — Sphinx's current detection is effectively English-first. Language-based evasion (Unicode obfuscation, multi-language prompt splitting, character substitution) is an active attack vector in global enterprise deployments.

| **Field**       | **Detail**                                                                                                                |
|-----------------|---------------------------------------------------------------------------------------------------------------------------|
| Threat Coverage | Language-based injection evasion across non-English scripts and Unicode obfuscation                                       |
| Competitive Gap | Lakera Guard (Check Point): 98%+ detection, 100+ languages, trained on 80M+ adversarial prompts                           |
| Key Deliverable | Multilingual detection model integrated into Tier 1; language-specific pattern packs; Unicode normalization pre-processor |
| Effort          | 2 sprints (Sprints 21–22)                                                                                                 |

#### E2: AI Red Teaming — Automated Pre-Deployment Attack Simulation
A pre-deployment red teaming module that runs automated attack simulations against customer AI applications before they go live. Red teaming results feed back into the runtime detection engine. This adds a second product motion (pre-deployment validation) to Sphinx's existing runtime enforcement, creating a land-and-expand opportunity with existing customers.

| **Field**       | **Detail**                                                                                                           |
|-----------------|----------------------------------------------------------------------------------------------------------------------|
| Threat Coverage | Pre-production vulnerability discovery: injection, jailbreak, data extraction, privilege escalation                  |
| Competitive Gap | Lakera Red (Check Point), HiddenLayer AISec, Mindgard — all ship pre-deployment simulation; Sphinx is runtime-only   |
| Key Deliverable | Attack simulation runner; 200+ probe scenarios; results dashboard; findings feed into runtime policy recommendations |
| Effort          | 2 sprints (Sprints 23–24)                                                                                            |

#### E3: Agent Memory Store Security & Memory Poisoning Detection
Governs agent persistent memory reads and writes (Redis, PostgreSQL, vector stores used as memory). Memory poisoning — where an adversary implants malicious instructions into an agent's long-term memory that recall in future sessions — is OWASP Agentic AI Top 10 risk AA1 and the most novel enterprise attack vector in 2026. Unlike prompt injection that ends when a session closes, poisoned memory persists across sessions, users, and agent instances.

| **Field**       | **Detail**                                                                                                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OWASP Coverage  | AA1: Prompt Objective Hijacking via Persistent Memory                                                                                                                                      |
| Competitive Gap | No competitor has shipped a production memory store firewall — first-mover window                                                                                                          |
| Key Deliverable | Memory write scanner (detect instruction-like content before storage), memory read filter (flag anomalous recall patterns), memory integrity audit log, configurable memory lifecycle caps |
| Effort          | 3 sprints (Sprints 25–27)                                                                                                                                                                  |

### 12.2 Priority 1 — High (Q3–Q4 2026)
#### E4: Inter-Agent Communication Security (A2A Protocol Firewall)
Governs agent-to-agent message passing using the Agent2Agent (A2A) protocol. A compromised agent can impersonate a trusted peer and issue instructions across a multi-agent orchestration — a lateral movement path that traditional network monitoring cannot detect. This is OWASP Agentic Top 10 AA6 and the architectural evolution of Sphinx's existing MCP governance module.

| **Field**       | **Detail**                                                                                                                                |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| OWASP Coverage  | AA6: Uncontrolled Multi-Agent Orchestration; AA2: Agent Impersonation                                                                     |
| Competitive Gap | No competitor has shipped A2A message authentication — genuine first-mover opportunity                                                    |
| Key Deliverable | A2A message signing verification, mutual TLS between agents, replay attack prevention, inter-agent audit log with full message provenance |
| Effort          | 3 sprints (Sprints 28–30)                                                                                                                 |

#### E5: Human-in-the-Loop (HITL) Enforcement Checkpoints
Adds a 'Require Human Approval' action type to the policy engine. For configured high-risk agent actions (payments, code deployment, data deletion, credential sharing), the gateway pauses execution and routes the action to an asynchronous approval workflow. OWASP Agentic AA3: Insufficient Human Oversight. Required for financial services AI and clinical AI applications under multiple regulatory frameworks.

| **Field**       | **Detail**                                                                                                                                                             |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OWASP Coverage  | AA3: Insufficient Human Oversight                                                                                                                                      |
| Competitive Gap | AccuKnox runtime governance includes HITL gates; NeMo Guardrails models multi-turn flows; Sphinx has no pause-and-approve action                                       |
| Key Deliverable | HITL action type in policy engine; approval workflow API; Slack/email approval channel integrations; timeout fallback (auto-block or auto-allow); approval audit trail |
| Effort          | 2 sprints (Sprints 31–32)                                                                                                                                              |

#### E6: Cascading Failure Detection & Agent Circuit Breakers
Agent-level circuit breakers that detect when an agent is behaving anomalously across a multi-step workflow and automatically halt propagation to downstream agents. Distinct from the existing provider-level circuit breakers (which protect against LLM provider outages). OWASP Agentic AA9. A single poisoned agent was found to degrade 87% of downstream decisions within 4 hours in a 2025 study.

| **Field**       | **Detail**                                                                                                                                                    |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OWASP Coverage  | AA9: Workflow Manipulation & Cascading Failures                                                                                                               |
| Competitive Gap | Radware Agentic AI includes error propagation monitoring; no competitor has a full agent circuit breaker with automatic propagation halt                      |
| Key Deliverable | Per-agent behavioral baseline, anomaly score, circuit breaker (open/half-open/closed), downstream agent halt signal, incident record with full workflow trace |
| Effort          | 3 sprints (Sprints 33–35)                                                                                                                                     |

#### E7: ML Model Supply Chain Security (Model Artifact Scanning)
Scans AI model artifacts before deployment to self-hosted infrastructure. Detects deserialization attacks, backdoors, and supply chain tampering in model files. Palo Alto Networks acquired Protect AI (Guardian) in July 2025 and integrated it into Prisma AIRS. HiddenLayer has disclosed 48+ CVEs related to model artifact vulnerabilities. Relevant for customers using self-hosted Llama or custom fine-tuned models behind the Sphinx gateway.

| **Field**       | **Detail**                                                                                                                                                            |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Threat Coverage | Model deserialization attacks, backdoored fine-tunes, supply chain model tampering                                                                                    |
| Competitive Gap | Palo Alto Prisma AIRS (Protect AI Guardian), HiddenLayer AISec — both cover 35+ model formats                                                                         |
| Key Deliverable | Model artifact scanner for common formats (GGUF, safetensors, PyTorch), hash-based integrity verification, provenance metadata, pre-deployment gate in model registry |
| Effort          | 3 sprints (Sprints 36–38)                                                                                                                                             |

### 12.3 Priority 2 — Medium (Q3 2026)
#### E8: EU AI Act Compliance Controls & Reporting
EU AI Act enforcement begins August 2026 for high-risk AI systems. Adds EU AI Act-specific controls: human oversight documentation, transparency logging for AI-generated content, risk classification records, and technical documentation packages for conformity assessment. European enterprise buyers will require vendor-supplied AI Act compliance evidence.

| **Field**         | **Detail**                                                                                                                                                                                |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Regulatory Driver | EU AI Act — enforcement for high-risk AI systems begins August 2026                                                                                                                       |
| Key Deliverable   | AI Act risk classification dashboard, human oversight logging, transparency event records, technical documentation export (Article 11 package), AI-generated content transparency markers |
| Effort            | 2 sprints (Sprints 21–22, parallel with E1)                                                                                                                                               |

#### E9: Multi-Turn Conversation Security & Dialog Flow Controls
Session-level context tracking across multi-turn conversations. Multi-turn escalation attacks gradually erode guardrails across a session — Sphinx currently evaluates each request in isolation. NeMo Guardrails is the only competitor with native dialog flow control (via Colang). Adds a new session context model and dialog rail type to the policy engine.

| **Field**       | **Detail**                                                                                                                       |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------|
| Threat Coverage | Multi-turn escalation attacks, session-level jailbreak accumulation, context drift                                               |
| Competitive Gap | NeMo Guardrails (Apache 2.0): five rail types including dialog rails for multi-turn control — unique in the market               |
| Key Deliverable | Session context store, cross-turn risk accumulation score, dialog policy rules, session-level block action, multi-turn audit log |
| Effort          | 2 sprints                                                                                                                        |

#### E10: AI-SPM Integration (Shadow AI Discovery)
Integrates Sphinx's existing AISPM platform as the asset discovery layer for the gateway. Organizations cannot govern AI traffic that bypasses the gateway. AI-SPM discovers all AI assets across the environment (shadow LLM calls, unmanaged agent deployments) and flags them for governance enrollment. Noma Security and Aim Security both ship unified AI-SPM + runtime protection.

| **Field**            | **Detail**                                                                                                           |
|----------------------|----------------------------------------------------------------------------------------------------------------------|
| Strategic Value      | Asset discovery is the enrollment hook that drives gateway adoption — you cannot govern what you have not discovered |
| Integration Approach | Cross-portfolio integration with AISPM platform; shared policy engine; unified dashboard view                        |
| Effort               | 1 sprint (integration work only)                                                                                     |

#### E11: Secure Semantic Caching
Tenant-isolated semantic caching of model responses. Semantically similar queries return cached responses without a full LLM inference round-trip, reducing cost and latency. Cache includes Sphinx-specific security controls: per-tenant namespace isolation, cache poisoning prevention, and automatic invalidation on policy change. Bifrost, LiteLLM, Kong AI Gateway, and Cloudflare AI Gateway all offer semantic caching — none combine it with security controls.

| **Field**         | **Detail**                                                                                                    |
|-------------------|---------------------------------------------------------------------------------------------------------------|
| Value Prop        | Cost reduction (30–60% on repetitive query workloads) + latency reduction without sacrificing security        |
| Security Controls | Per-tenant cache namespace, cache poisoning detection, policy-triggered invalidation, cache-hit audit logging |
| Effort            | 2 sprints                                                                                                     |

### 12.4 Priority 3 — Strategic (Q1–Q2 2027)
#### E12: MSSP / White-Label Multi-Tenant Offering
MSSP-specific management layer enabling channel partners to offer Sphinx AI security as a managed service. Radware launched an MSSP-positioned Agentic AI Protection product in February 2026. Sphinx's architecture is technically MSSP-ready; this enhancement adds the management portal, white-label branding, client hierarchy, and billing export.

#### E13: Kubernetes Runtime Policy Enforcement (eBPF / CNAPP Integration)
Extends Sphinx enforcement to the Kubernetes runtime layer using eBPF. Governs agent process behavior, file access, and network egress at the OS kernel level — not just at the application/API layer. AccuKnox and Palo Alto Prisma AIRS are the primary competitors here. This positions Sphinx as a Zero Trust CNAPP for AI rather than an application-layer gateway.

#### E14: Live Threat Intelligence Feed (Adversarial Corpus)
Continuous adversarial intelligence pipeline that feeds new attack samples into the detection models daily. Lakera's Gandalf corpus (80M+ adversarial prompts, 100K+ new samples per day) is the structural advantage that compounds over time. Sphinx's equivalent requires building a community-contributed data flywheel — likely via a public-facing AI security challenge or red team program. This is the most important long-term moat investment.

Sphinx \| sphinx.ai \| support@sphinx.ai

All rights reserved. Confidential and proprietary.
