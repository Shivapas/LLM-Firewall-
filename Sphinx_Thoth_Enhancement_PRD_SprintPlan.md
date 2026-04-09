# Sphinx AI Mesh Firewall — Enhancement PRD & Sprint Plan
## Thoth Semantic Classification Integration Layer

**Document Type:** Enhancement PRD + Sprint Plan  
**Product:** Sphinx AI Mesh Firewall (TrustFabric Portfolio)  
**Enhancement Scope:** Thoth Semantic Classification Integration  
**Version:** 1.0  
**Author:** TrustFabric Architecture  
**Date:** April 2026  
**Status:** Draft — Pre-Engineering Review

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Integration Thesis](#3-integration-thesis)
4. [Enhancement Scope](#4-enhancement-scope)
5. [Functional Requirements](#5-functional-requirements)
6. [Non-Functional Requirements](#6-non-functional-requirements)
7. [Architecture Design](#7-architecture-design)
8. [Out of Scope](#8-out-of-scope)
9. [Risks & Mitigations](#9-risks--mitigations)
10. [Sprint Plan](#10-sprint-plan)
11. [Acceptance Criteria](#11-acceptance-criteria)
12. [Open Questions](#12-open-questions)

---

## 1. Executive Summary

Sphinx currently operates as a deterministic enforcement layer — blocking, allowing, transforming, or routing AI traffic based on policy rules applied at the AI Mesh Firewall boundary. While Sphinx enforces well, its policy engine today is fed primarily by structural signals (token counts, endpoint identity, rate thresholds, regex-based pattern matching) rather than **semantic intent**.

This enhancement integrates **Thoth** as an upstream semantic classification service that feeds enriched intent, context, and risk-state signals into Sphinx's policy evaluation engine. The result is a materially more precise enforcement posture: Sphinx retains full decision authority and enforcement determinism, while Thoth provides the semantic intelligence layer that Sphinx's policy engine currently lacks.

This is a **complementary integration, not a replacement** of any Sphinx subsystem. Sphinx enforces. Thoth classifies. The enforcement gap being closed is the delta between syntactic pattern matching and true semantic policy enforcement.

---

## 2. Problem Statement

### 2.1 Current Sphinx Enforcement Limitations

| Limitation | Description | Impact |
|---|---|---|
| Pattern-bound detection | Prompt injection and data exfiltration detection relies on regex/heuristic matching | High false negative rate on semantically obfuscated attacks |
| Context-blind routing | Traffic routing decisions lack semantic intent signals | Suboptimal routing; no intent-aware load shedding |
| Static policy evaluation | Policy engine evaluates rules without understanding prompt purpose or risk trajectory | Blunt allow/block decisions; no nuance by role, data sensitivity, or regulatory context |
| No cross-vendor semantic parity | Semantic controls differ per model vendor; Sphinx normalizes traffic but not meaning | Inconsistent enforcement across OpenAI, Anthropic, Azure OAI, and OSS model endpoints |
| Post-inference gap | Response classification is structural, not semantic | Data leakage in outputs is underdetected |

### 2.2 The Enforcement-Classification Gap

Sphinx's current architecture correctly separates the enforcement plane from the model plane. What it does not yet have is a **classification plane** — a layer that produces policy-actionable semantic signals upstream of enforcement decisions. Thoth fills this exact gap.

---

## 3. Integration Thesis

### 3.1 Architectural Positioning

```
┌─────────────────────────────────────────────────────────────┐
│                    Enterprise AI Traffic                    │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              Sphinx AI Mesh Firewall                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Thoth Classification Plane (NEW)          │   │
│  │   Intent Signal │ Context Signal │ Risk State Label  │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                             │                               │
│  ┌─────────────────────────▼───────────────────────────┐   │
│  │         Sphinx Policy Engine (Enhanced)             │   │
│  │   Block │ Allow │ Transform │ Route │ Quarantine    │   │
│  └─────────────────────────┬───────────────────────────┘   │
│                             │                               │
│  ┌─────────────────────────▼───────────────────────────┐   │
│  │         Sphinx Enforcement & Audit Layer            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              LLM / Model Layer                              │
│   Azure OAI │ Anthropic │ Bedrock │ On-prem Models         │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Division of Responsibility

| Responsibility | Owner |
|---|---|
| Semantic Intent Classification | Thoth |
| Risk State Labeling (prompt + response) | Thoth |
| Confidence Scoring | Thoth |
| Policy Evaluation | Sphinx |
| Enforcement Decision (Block/Allow/Route) | Sphinx |
| Audit Trail & Forensic Capture | Sphinx / AFRE |
| Agent Plan & Tool-Call Classification | AgentPEP (roadmap) |
| Behavioral Drift Detection | AASM |

### 3.3 Why This Works

Thoth explicitly positions itself as not a firewall or guardrail — it provides semantic understanding as **input to decision-making, not the decision itself**. This is precisely what Sphinx needs: a richer signal set for its policy engine without ceding enforcement authority to a third party. Sphinx remains the single enforcement point. Thoth becomes the classification oracle.

---

## 4. Enhancement Scope

### 4.1 In Scope

- **Thoth API integration** into Sphinx's pre-inference intercept pipeline
- **Semantic signal ingestion** from Thoth into Sphinx's policy evaluation context
- **Policy rule language extension** in Sphinx to consume Thoth classification metadata (intent category, risk label, confidence score, PII flags)
- **Post-inference response classification** via Thoth's async mode fed into Sphinx's output filter
- **Thoth-enriched audit records** in Sphinx's event log schema
- **Fallback enforcement mode** when Thoth is unavailable (Sphinx enforces on structural signals alone — FAIL_CLOSED default preserved)
- **Latency budget enforcement** — Thoth classification must complete within Sphinx's configurable SLA window; timeout triggers structural-only enforcement
- **Configuration interface** — Sphinx admin UI/API extensions to manage Thoth endpoint, credentials, timeout, and per-policy classification enablement

### 4.2 Integration Modes Adopted from Thoth Architecture

| Thoth Mode | Sphinx Adoption | Priority |
|---|---|---|
| Inline Pre-Inference (Synchronous) | Primary integration — Thoth called before LLM forwarding | P0 |
| Post-Inference & Observability | Async classification of responses; output to Sphinx audit stream | P0 |
| Gateway / Proxy Integration | Thoth plugin within Sphinx's reverse proxy layer | P1 |
| Application-Embedded (SDK) | Reference pattern for downstream app teams; not Sphinx-native | P2 |
| Client-Side / Extension-Based | Shadow AI visibility fed into Sphinx policy context | P2 |
| Agent Runtime Integration | Deferred — awaiting Thoth GA; will integrate with AgentPEP | Roadmap |

---

## 5. Functional Requirements

### 5.1 Pre-Inference Classification (FR-PRE)

| ID | Requirement |
|---|---|
| FR-PRE-01 | Sphinx SHALL invoke Thoth classification API synchronously for all intercepted prompts before forwarding to the LLM endpoint |
| FR-PRE-02 | The Thoth classification call SHALL include: raw prompt text, system prompt (if available), user identity context, application ID, and model endpoint target |
| FR-PRE-03 | Sphinx SHALL receive and parse Thoth's response containing: intent category, risk state label, confidence score, detected PII type flags, and recommended action hint |
| FR-PRE-04 | Sphinx's policy engine SHALL use Thoth classification metadata as first-class policy evaluation attributes alongside existing structural signals |
| FR-PRE-05 | Sphinx SHALL enforce its own policy decision — the Thoth "recommended action hint" is advisory only; Sphinx policy rules take precedence |
| FR-PRE-06 | If Thoth classification latency exceeds configured timeout (default: 150ms), Sphinx SHALL proceed with structural-only enforcement and log a classification timeout event |
| FR-PRE-07 | If Thoth returns an error or is unavailable, Sphinx SHALL FAIL_CLOSED on high-sensitivity policy rules and log a classification unavailability event |

### 5.2 Post-Inference Classification (FR-POST)

| ID | Requirement |
|---|---|
| FR-POST-01 | Sphinx SHALL submit LLM responses to Thoth asynchronously after delivery to the requesting application |
| FR-POST-02 | Thoth SHALL classify response content for risk state, sensitive data exposure, and output intent alignment |
| FR-POST-03 | Post-inference classifications SHALL be written to Sphinx's audit event stream with full prompt-response correlation |
| FR-POST-04 | Policy rules SHALL be configurable to quarantine or alert based on post-inference classification outcomes in near-real-time (sub-5-second loop) |
| FR-POST-05 | Post-inference classifications SHALL be exportable to SIEM, data lake, and GRC tool integrations via Sphinx's existing export connectors |

### 5.3 Policy Engine Extension (FR-POL)

| ID | Requirement |
|---|---|
| FR-POL-01 | Sphinx policy rule language SHALL be extended with a `classification.*` attribute namespace consuming Thoth signals |
| FR-POL-02 | Supported classification attributes SHALL include: `classification.intent`, `classification.risk_level`, `classification.confidence`, `classification.pii_detected`, `classification.pii_types[]` |
| FR-POL-03 | Policy rules SHALL support logical composition of classification attributes with existing Sphinx rule attributes (user role, endpoint, token count, time-of-day, etc.) |
| FR-POL-04 | Example rule pattern: `IF classification.intent == "data_exfiltration" AND classification.confidence > 0.85 THEN block` |
| FR-POL-05 | Policy rules referencing classification attributes SHALL degrade gracefully when classification is unavailable (configurable: skip rule, use fallback action, or FAIL_CLOSED) |

### 5.4 Audit & Observability (FR-AUD)

| ID | Requirement |
|---|---|
| FR-AUD-01 | All Thoth classification payloads (request + response) SHALL be captured in Sphinx audit records |
| FR-AUD-02 | Audit records SHALL include: classification timestamp, latency, classification version/model, intent label, risk label, confidence score, and enforcement decision |
| FR-AUD-03 | Classification timeout and unavailability events SHALL generate dedicated audit entries with severity tagging |
| FR-AUD-04 | Sphinx dashboard SHALL surface classification signal distributions: intent category breakdown, risk level heatmap, confidence score histogram, PII detection frequency |

### 5.5 Configuration & Administration (FR-CFG)

| ID | Requirement |
|---|---|
| FR-CFG-01 | Sphinx admin interface SHALL expose Thoth endpoint configuration: API URL, authentication credentials (API key / mTLS), and timeout settings |
| FR-CFG-02 | Classification enablement SHALL be configurable per policy group, allowing selective activation (e.g., enable for finance application traffic only) |
| FR-CFG-03 | A circuit breaker SHALL be configurable: sustained Thoth error rate above threshold disables classification calls and activates structural-only enforcement mode |
| FR-CFG-04 | Thoth on-prem / VPC deployment configurations SHALL be supported via endpoint URL override |

---

## 6. Non-Functional Requirements

| Category | Requirement |
|---|---|
| Latency | Thoth classification P99 must not increase end-to-end Sphinx intercept latency beyond 200ms; circuit breaker activates if P99 sustained > 300ms |
| Availability | Sphinx enforcement availability SHALL NOT depend on Thoth availability; structural-only fallback must activate within 1 retry cycle |
| Data Residency | Thoth deployment model (SaaS / VPC / on-prem) must be selectable to satisfy Indian data residency requirements (DPDPA, RBI, CERT-In) |
| Security | Classification API calls SHALL be authenticated (API key minimum; mTLS preferred); TLS 1.3 minimum on all Thoth connections |
| Auditability | Classification metadata must be immutably appended to Sphinx audit records; no post-write modification permitted |
| Scalability | Thoth integration SHALL not become a bottleneck at Sphinx's rated throughput capacity; async post-inference calls must use non-blocking I/O |
| Model Agnosticism | Thoth classification SHALL be invoked identically regardless of target LLM vendor (OpenAI, Anthropic, Azure, OSS) |

---

## 7. Architecture Design

### 7.1 Pre-Inference Data Flow

```
[User / App Request]
        │
        ▼
[Sphinx Intercept Layer]
        │
        ├──► [Thoth Classification API Call] ──► [Intent / Risk / PII Labels]
        │            (sync, timeout-guarded)              │
        │                                                 ▼
        └──────────────────────────────────► [Policy Engine]
                                                 │
                               ┌─────────────────┼─────────────────┐
                               ▼                 ▼                 ▼
                           [Block]           [Allow]          [Transform]
                                                 │
                                                 ▼
                                        [LLM Endpoint]
```

### 7.2 Post-Inference Data Flow

```
[LLM Response]
        │
        ├──► [Deliver to Application]
        │
        └──► [Thoth Async Classification] ──► [Response Risk Labels]
                                                      │
                                                      ▼
                                           [Sphinx Audit Stream]
                                                      │
                                         ┌────────────┴────────────┐
                                         ▼                         ▼
                                  [SIEM Export]          [Near-RT Alert Rule]
```

### 7.3 Thoth Classification API Integration Contract

**Request Payload (Sphinx → Thoth):**
```json
{
  "request_id": "<sphinx_trace_id>",
  "content_type": "prompt",
  "content": "<user_prompt_text>",
  "system_prompt": "<system_prompt_if_available>",
  "context": {
    "user_id": "<hashed_user_id>",
    "application_id": "<app_id>",
    "model_endpoint": "<target_llm_endpoint>",
    "session_id": "<session_id>"
  }
}
```

**Response Payload (Thoth → Sphinx):**
```json
{
  "request_id": "<sphinx_trace_id>",
  "classification": {
    "intent": "<intent_category>",
    "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
    "confidence": 0.00-1.00,
    "pii_detected": true | false,
    "pii_types": ["AADHAAR", "BANK_ACCOUNT", "EMAIL", "CREDIT_CARD"],
    "recommended_action": "ALLOW | BLOCK | REVIEW",
    "classification_model_version": "<version>"
  },
  "latency_ms": 42
}
```

### 7.4 Policy Rule Extension Examples

```
# Block high-confidence exfiltration attempts
RULE sphinx.policy.classification.block_exfiltration:
  IF classification.intent == "data_exfiltration"
  AND classification.confidence >= 0.85
  THEN action = BLOCK, audit_severity = CRITICAL

# Route sensitive PII prompts to isolated model endpoint
RULE sphinx.policy.classification.pii_routing:
  IF classification.pii_detected == true
  AND classification.pii_types CONTAINS "AADHAAR"
  THEN action = ROUTE(endpoint="onprem_llm"), audit_tag = "DPDPA_SENSITIVE"

# Require HITL review for medium-risk ambiguous prompts
RULE sphinx.policy.classification.hitl_review:
  IF classification.risk_level == "MEDIUM"
  AND classification.confidence < 0.70
  THEN action = QUEUE_FOR_REVIEW, notify = "security_ops_team"
```

---

## 8. Out of Scope

| Item | Rationale |
|---|---|
| Agent runtime classification (Thoth roadmap item) | Not GA; will be addressed in AgentPEP integration when available |
| Replacing Sphinx's existing prompt injection detection | Thoth supplements, does not replace structural detection |
| Thoth policy authoring within Sphinx | Sphinx manages its own policy language; Thoth signals are inputs only |
| Client-side browser extension integration | Separate workstream; not part of Sphinx core enforcement path |
| Behavioral profiling or drift detection | Owned by AASM; Thoth signals can be forwarded to AASM separately |
| Forensic replay of classification events | Owned by AFRE; Sphinx audit records serve as input |

---

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Thoth API latency degrades Sphinx SLA | High | Configurable timeout with FAIL_OPEN or FAIL_CLOSED fallback per policy group; circuit breaker |
| Thoth classification errors increase false positives | Medium | Confidence threshold gating on classification-dependent rules; human review queue for borderline cases |
| Data residency non-compliance (DPDPA/RBI) | High | Mandatory on-prem or VPC Thoth deployment for regulated workloads; prompt content hashing option |
| Vendor lock-in on semantic classification | Medium | Abstract Thoth behind a Sphinx-internal Classification Provider interface; enables future swap |
| Agentic classification gap (Thoth roadmap) | Medium | AgentPEP handles tool-call enforcement deterministically; Thoth gap is semantic depth only |
| API key / credential exposure | High | Secrets stored in Sphinx secrets vault; mTLS enforcement on Thoth connections |

---

## 10. Sprint Plan

**Assumptions:**
- 2-week sprints
- 1 senior backend engineer + 1 integration engineer
- Thoth sandbox API access available from Sprint 1
- Sphinx codebase familiarity: existing intercept pipeline and policy engine are the integration surfaces

---

### Sprint 1 — Foundation & API Integration Scaffold
**Goal:** Establish Thoth API connectivity and basic classification call from Sphinx intercept pipeline.

| Task | Description | Effort |
|---|---|---|
| S1-T1 | Thoth API client module — REST client with auth, timeout, retry | 3 days |
| S1-T2 | Sphinx intercept hook — inject Thoth call in pre-inference path | 2 days |
| S1-T3 | Classification response parser — map Thoth response to internal Sphinx ClassificationContext object | 2 days |
| S1-T4 | Configuration schema extension — Thoth endpoint, credentials, timeout, enabled flag | 1 day |
| S1-T5 | Basic integration test — end-to-end classification call with mock Thoth response | 2 days |

**Exit Criteria:** Sphinx successfully calls Thoth API and receives classification payload for intercepted prompts in dev environment.

---

### Sprint 2 — Fallback, Circuit Breaker & FAIL_CLOSED Logic
**Goal:** Ensure Sphinx enforcement is never dependent on Thoth availability.

| Task | Description | Effort |
|---|---|---|
| S2-T1 | Timeout enforcement — configurable per-request timeout with structural-only fallback | 2 days |
| S2-T2 | Circuit breaker implementation — sustained error rate threshold disables Thoth calls | 2 days |
| S2-T3 | FAIL_CLOSED mode — high-sensitivity policy rules block when classification unavailable | 2 days |
| S2-T4 | Classification unavailability audit event — structured log entry with error type and fallback mode | 1 day |
| S2-T5 | Unit tests — timeout, circuit breaker trip, recovery, FAIL_CLOSED behavior | 3 days |

**Exit Criteria:** Sphinx enforces correctly under Thoth timeout, error, and unavailability conditions. Zero enforcement gaps validated by test suite.

---

### Sprint 3 — Policy Engine Extension: classification.* Attribute Namespace
**Goal:** Make Thoth classification signals usable in Sphinx policy rules.

| Task | Description | Effort |
|---|---|---|
| S3-T1 | Policy rule DSL extension — add `classification.*` attribute namespace | 3 days |
| S3-T2 | Attribute binding — bind ClassificationContext fields to policy evaluation context | 2 days |
| S3-T3 | Rule composition support — classification attributes composable with existing Sphinx rule predicates | 2 days |
| S3-T4 | Graceful degradation — policy rules with classification attributes behave correctly when classification is unavailable | 1 day |
| S3-T5 | Policy authoring tests — validate rule parsing and evaluation for 10+ classification-dependent rule patterns | 2 days |

**Exit Criteria:** Policy rules can reference classification.intent, classification.risk_level, classification.confidence, classification.pii_detected, and classification.pii_types[]. Rules evaluate correctly in presence and absence of classification data.

---

### Sprint 4 — Post-Inference Async Classification
**Goal:** Extend Thoth integration to response classification for output risk detection.

| Task | Description | Effort |
|---|---|---|
| S4-T1 | Async classification worker — non-blocking post-inference Thoth submission | 2 days |
| S4-T2 | Response classification payload builder — assemble response content + correlation context | 1 day |
| S4-T3 | Audit record enrichment — append post-inference classification to correlated audit event | 2 days |
| S4-T4 | Near-RT alert rule support — policy rules triggered on post-inference classification outcomes | 2 days |
| S4-T5 | SIEM/data lake export extension — include classification metadata in existing export connectors | 2 days |
| S4-T6 | Integration tests — end-to-end post-inference flow with classification correlation | 1 day |

**Exit Criteria:** Response classification is captured asynchronously, correlated with prompt audit records, and exportable via Sphinx's existing SIEM connectors.

---

### Sprint 5 — Audit Schema Extension & Observability Dashboard
**Goal:** Surface classification signals in Sphinx audit records and dashboard.

| Task | Description | Effort |
|---|---|---|
| S5-T1 | Audit record schema v2 — add classification metadata fields to Sphinx audit event schema | 2 days |
| S5-T2 | Schema migration — backward-compatible migration for existing audit records | 1 day |
| S5-T3 | Dashboard: intent category breakdown — pie/bar chart of classification.intent distribution | 2 days |
| S5-T4 | Dashboard: risk level heatmap — risk_level × time heatmap for trend detection | 2 days |
| S5-T5 | Dashboard: classification confidence histogram — distribution of confidence scores | 1 day |
| S5-T6 | Dashboard: PII detection frequency — PII type breakdown and trend over time | 1 day |
| S5-T7 | Dashboard: classification latency — P50/P95/P99 Thoth API latency tracking | 1 day |

**Exit Criteria:** Sphinx audit records include full classification metadata. Dashboard renders classification analytics for the past 30 days.

---

### Sprint 6 — Gateway / Proxy Integration Mode
**Goal:** Implement Thoth as a plugin in Sphinx's reverse proxy layer for centralized multi-application enforcement.

| Task | Description | Effort |
|---|---|---|
| S6-T1 | Proxy plugin architecture — Thoth classification callable from Sphinx reverse proxy intercept | 3 days |
| S6-T2 | Per-application classification enablement — route-level configuration for classification on/off | 2 days |
| S6-T3 | Cross-vendor semantic parity validation — test classification consistency across OpenAI, Anthropic, and OSS model endpoints | 2 days |
| S6-T4 | Proxy plugin integration tests — multi-application traffic with mixed classification policies | 3 days |

**Exit Criteria:** Thoth classification operates identically across all LLM vendor endpoints routed through Sphinx. Per-application classification policy is configurable at the route level.

---

### Sprint 7 — Indian Regulatory Compliance Mode (DPDPA / CERT-In)
**Goal:** Ensure Thoth integration meets Indian data residency and regulatory requirements.

| Task | Description | Effort |
|---|---|---|
| S7-T1 | On-prem / VPC Thoth endpoint support — endpoint URL override with residency tagging | 1 day |
| S7-T2 | DPDPA-sensitive routing rule templates — pre-built policy rules for Aadhaar, PAN, bank account PII types | 2 days |
| S7-T3 | Prompt content hashing option — hash PII fields before transmission to Thoth (configurable) | 2 days |
| S7-T4 | CERT-In audit trail requirements — validate Sphinx + Thoth audit records satisfy CERT-In 6-hour reporting requirements | 2 days |
| S7-T5 | Compliance documentation — data flow diagrams for DPDPA ROPA covering Thoth integration | 1 day |
| S7-T6 | Regulatory QA — end-to-end compliance validation with simulated DPDPA / CERT-In audit scenario | 2 days |

**Exit Criteria:** Sphinx + Thoth integration passes internal DPDPA and CERT-In compliance review. Data residency configurations are validated for on-prem and VPC Thoth deployments.

---

### Sprint 8 — Performance, Load Testing & Production Hardening
**Goal:** Validate performance at production scale and harden for GA readiness.

| Task | Description | Effort |
|---|---|---|
| S8-T1 | Latency benchmarking — P50/P95/P99 measurement of Thoth integration overhead | 2 days |
| S8-T2 | Load testing — Sphinx + Thoth at rated throughput; validate circuit breaker under load | 3 days |
| S8-T3 | Connection pool tuning — optimize Thoth API client for high-concurrency workloads | 1 day |
| S8-T4 | mTLS enforcement — Thoth connections upgraded from API key to mutual TLS | 2 days |
| S8-T5 | Secrets vault integration — Thoth credentials migrated from config file to Sphinx secrets vault | 1 day |
| S8-T6 | Regression test suite — full Sphinx behavioral regression with Thoth integration active | 1 day |

**Exit Criteria:** Thoth integration adds ≤150ms P99 latency at rated throughput. Circuit breaker, FAIL_CLOSED, and mTLS validated under load.

---

### Sprint Summary

| Sprint | Focus | Duration |
|---|---|---|
| Sprint 1 | Foundation & API Integration Scaffold | 2 weeks |
| Sprint 2 | Fallback, Circuit Breaker & FAIL_CLOSED | 2 weeks |
| Sprint 3 | Policy Engine classification.* Extension | 2 weeks |
| Sprint 4 | Post-Inference Async Classification | 2 weeks |
| Sprint 5 | Audit Schema & Observability Dashboard | 2 weeks |
| Sprint 6 | Gateway / Proxy Integration Mode | 2 weeks |
| Sprint 7 | Indian Regulatory Compliance Mode | 2 weeks |
| Sprint 8 | Performance, Load Testing & Hardening | 2 weeks |
| **Total** | | **16 weeks** |

---

## 11. Acceptance Criteria

| # | Criterion |
|---|---|
| AC-01 | Sphinx classifies 100% of intercepted prompts via Thoth when classification is enabled |
| AC-02 | Sphinx enforcement continuity is maintained under Thoth timeout, error, and unavailability conditions |
| AC-03 | Policy rules referencing classification attributes evaluate correctly in all classification availability states |
| AC-04 | Post-inference response classification is captured asynchronously with prompt correlation |
| AC-05 | Thoth classification metadata appears in all Sphinx audit records |
| AC-06 | Thoth integration adds ≤150ms P99 latency at production throughput |
| AC-07 | DPDPA-sensitive routing rules correctly route Aadhaar/PAN/bank account-containing prompts |
| AC-08 | mTLS is enforced on all Thoth API connections in production configuration |
| AC-09 | Circuit breaker activates within 3 consecutive Thoth failures and deactivates after configurable recovery period |
| AC-10 | Sphinx dashboard renders classification analytics (intent distribution, risk heatmap, PII frequency) |

---

## 12. Open Questions

| # | Question | Owner | Target Resolution |
|---|---|---|---|
| OQ-01 | What is Thoth's committed P99 latency SLA for the classification API? | Anter Virk / Thoth | Sprint 1 |
| OQ-02 | Does Thoth support prompt content hashing / pseudonymization before classification to satisfy DPDPA? | Thoth | Sprint 1 |
| OQ-03 | What is Thoth's on-prem / VPC deployment timeline for Indian data residency? | Thoth | Sprint 2 |
| OQ-04 | Will Thoth's classification model be versioned in API responses to enable policy-version locking? | Thoth | Sprint 3 |
| OQ-05 | When is Thoth's agentic runtime classification expected GA? (Agent plan / tool-call inspection) | Thoth Roadmap | TBD — feeds AgentPEP integration |
| OQ-06 | Should Sphinx pass full system prompts to Thoth or only user turns? Privacy vs. classification fidelity tradeoff. | TrustFabric Architecture | Sprint 1 |
| OQ-07 | Is Thoth's classification taxonomy extensible to include India-specific regulatory categories (DPDPA personal data classes)? | Thoth | Sprint 7 |

---

*Document prepared by TrustFabric Architecture. For integration partnership queries, contact Thoth: anter@thoth.ai*
