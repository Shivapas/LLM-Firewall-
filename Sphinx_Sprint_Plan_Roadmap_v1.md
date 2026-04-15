# Sphinx AI Mesh Firewall
## Sprint Plan — Roadmap v1 Extension
### Phase 9: Intelligence Hardening | Sprints 31–36 | Weeks 61–72

> **Document Version:** Roadmap v1 Sprint Extension  
> **Extends:** Sphinx Sprint Plan v2.0 (Sprints 1–30, Weeks 1–60)  
> **Phase:** Phase 9 — Intelligence Hardening  
> **Sprint Range:** Sprints 31–36 | Weeks 61–72

---

Phase 9: Intelligence Hardening \| Sprints 31–36 \| Weeks 61–72

| **Field**               | **Detail**                                                      |
|-------------------------|-----------------------------------------------------------------|
| **Document Version**    | Roadmap v1 Sprint Extension                                     |
| **Extends**             | Sphinx Sprint Plan v2.0 (Sprints 1–30, Weeks 1–60)              |
| **Phase**               | Phase 9 — Intelligence Hardening                                |
| **Sprint Range**        | Sprints 31–36                                                   |
| **Week Range**          | Weeks 61–72                                                     |
| **Sprint Duration**     | 2 weeks per sprint                                              |
| **Enhancement Modules** | E15 (IPIA), E16 (Canary), E17 (Fingerprint), E18 (OWASP Matrix) |
| **Prerequisites**       | Sprint 30 GA release complete; Sphinx v2.0 in production        |

Phase 9 extends the Sphinx platform with four capability modules derived from Agent-Shield v9.0 competitive intelligence analysis. The phase is structured in three logical sub-phases: semantic detection hardening (Sprints 31–33), supply chain integrity (Sprints 34–35), and compliance packaging (Sprint 36).

| **Sprint** | **Theme**                                     | **Module** | **Weeks** | **Key Output**                                                     |
|------------|-----------------------------------------------|------------|-----------|--------------------------------------------------------------------|
| 31         | IPIA Foundation — Embedding Engine            | E15        | 61–62     | SentenceTransformers embedding service, joint-context scorer       |
| 32         | IPIA Production Integration + Batch RAG Scan  | E15        | 63–64     | Batch RAG scan API, IPIA threat events, dashboard widget           |
| 33         | Canary Token Module                           | E16        | 65–66     | Session canary generation, output leakage scanner, CRITICAL alerts |
| 34         | Model Fingerprinting — Baseline Engine        | E17        | 67–68     | 16-feature extractor, baseline profiler, z-score deviation scorer  |
| 35         | Supply Chain Integrity + Endpoint Monitoring  | E17        | 69–70     | SupplyChainMonitor, consecutive-response alerting, drift dashboard |
| 36         | OWASP LLM Top 10 v2025 Matrix + Roadmap v1 GA | E18        | 71–72     | Coverage matrix, gap analysis, PDF/JSON export, Roadmap v1 release |

|                                                                                  |
|----------------------------------------------------------------------------------|
| **Sprint 31 — IPIA Foundation — Joint-Context Embedding Engine** \[Weeks 61–62\] |

**Goal: Build the core embedding service that powers semantic indirect prompt injection detection, with a local SentenceTransformers backend and joint-context scoring API.**

**Stories**

| **ID** | **Story**                                                                                                       | **Pts** | **Layer**      | **Module**  | **Acceptance Criteria**                                                              |
|--------|-----------------------------------------------------------------------------------------------------------------|---------|----------------|-------------|--------------------------------------------------------------------------------------|
| SP-310 | Deploy SentenceTransformers (all-MiniLM-L6-v2) as a FastAPI microservice within the Sphinx gateway pod          | 5       | Infrastructure | IPIA Engine | Service starts, responds to /embed with 384-dim vector in \< 5ms on CPU              |
| SP-311 | Implement JointContextEncoder: encode (retrieved_chunk, user_query) pair as concatenated embedding              | 5       | Detection      | IPIA Engine | Encoder returns joint embedding; unit tests confirm dimensionality and normalisation |
| SP-312 | Implement cosine similarity scorer with configurable threshold (default 0.5) and injection classification logic | 3       | Detection      | IPIA Engine | Scorer correctly classifies 10/10 synthetic injection samples at default threshold   |
| SP-313 | Build PluggableEmbeddingBackend interface (accept any embed(text) → vector function) for future model swap      | 2       | Platform       | IPIA Engine | Interface accepts mock backend; integration test passes with both MiniLM and mock    |
| SP-314 | Unit test suite: 20 benign chunks + 20 known injection chunks; confirm F1 ≥ 0.85 at default threshold           | 3       | QA             | IPIA Engine | Test report: F1 ≥ 0.85, FPR \< 10%, all tests pass in CI                             |

**Definition of Done**

- Embedding microservice deployed and health-checked in staging

- JointContextEncoder tested end-to-end with synthetic corpus

- PluggableEmbeddingBackend interface documented

- All Sprint 31 unit tests green in CI

- p99 embedding latency \< 10ms on staging hardware

**Dependencies**

Requires Sphinx v2.0 production GA (Sprint 30). No dependency on other Phase 9 sprints.

**Risk**

|            |                                                                                                                                                                                                                                               |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **MEDIUM** | Embedding model download and local service startup adds ~300ms to gateway cold start. Mitigated by eager loading at gateway startup. No production traffic risk — IPIA service is additive, not on critical path until Sprint 32 integration. |

**Acceptance Criteria (Sprint-Level)**

- SentenceTransformers service returns 384-dim embedding in \< 5ms on CPU for a 512-token input

- JointContextEncoder correctly encodes (chunk, query) pair; cosine similarity returns expected values for 3 reference pairs

- PluggableEmbeddingBackend swaps in a mock backend without code changes

- F1 ≥ 0.85 on 40-sample synthetic test corpus (20 benign, 20 injection)

|                                                                                 |
|---------------------------------------------------------------------------------|
| **Sprint 32 — IPIA Batch RAG Scanner + Production Integration** \[Weeks 63–64\] |

**Goal: Integrate the IPIA embedding engine into the Sphinx pre-context-injection intercept layer; build the batch RAG scan API and emit IPIA threat events to TrustDetect.**

**Stories**

| **ID** | **Story**                                                                                                                              | **Pts** | **Layer**  | **Module**       | **Acceptance Criteria**                                                                                                 |
|--------|----------------------------------------------------------------------------------------------------------------------------------------|---------|------------|------------------|-------------------------------------------------------------------------------------------------------------------------|
| SP-320 | Wire IPIADetector into Sphinx pre-context-injection intercept layer: scan all RAG chunks before context assembly                       | 5       | Detection  | IPIA Integration | IPIA scan runs on every RAG retrieval event; clean chunks pass through; injection chunks blocked with 400+threat event  |
| SP-321 | Build batch RAG scan API: POST /v1/ipia/scan accepts array of chunks + user_query; returns per-chunk {isInjection, confidence, reason} | 5       | API        | IPIA Integration | API returns correct classification for all 40-sample corpus entries; p99 latency \< 50ms for batch of 10 chunks         |
| SP-322 | Emit IPIA threat event (severity: HIGH, category: IPIA, chunk_hash, confidence, reason) to TrustDetect Kafka topic                     | 3       | Telemetry  | IPIA Integration | Threat event appears in TrustDetect stream within 200ms of detection; schema validates against UCDM threat event spec   |
| SP-323 | Add IPIA detection rate widget to Sphinx admin dashboard: rolling 24h detection count, top blocked chunk categories                    | 3       | UI         | IPIA Dashboard   | Widget renders in admin dashboard; detection count updates within 30s of new detections; category breakdown shows top 5 |
| SP-324 | Configurable IPIA threshold per policy: allow threshold override in Sphinx policy YAML (ipia_threshold: 0.0–1.0)                       | 2       | Policy     | IPIA Integration | Policy override applies correctly; threshold 0.0 blocks all chunks; threshold 1.0 passes all chunks                     |
| SP-325 | CERT-In compliance annotation: IPIA detection events tagged with CERT-In AI security advisory reference in audit log                   | 1       | Compliance | IPIA Integration | Audit log entry for IPIA detection contains cert_in_ref field                                                           |

**Definition of Done**

- IPIA detector live in Sphinx staging intercepting real RAG traffic

- Batch scan API documented and tested end-to-end

- TrustDetect receiving IPIA threat events with correct schema

- Dashboard widget showing live IPIA metrics

- E2E test: send 5 injected RAG chunks through staging gateway; confirm 5/5 blocked + 5/5 threat events emitted

- No regression on existing Sphinx Sprint 30 E2E test suite

**Dependencies**

Sprint 31 (IPIA Engine) must be complete and staged. TrustDetect Kafka topic must be provisioned.

**Risk**

|            |                                                                                                                                                                                                                                              |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **MEDIUM** | Integration with Sphinx intercept layer carries regression risk for existing gateway flows. Mitigated by feature flag (ipia_enabled: false default in Sprint 32; opt-in per policy). Full E2E regression suite run before staging promotion. |

**Acceptance Criteria (Sprint-Level)**

- IPIA scan runs on RAG retrieval path in staging; 5 synthetic injections all blocked

- Batch API returns per-chunk result in \< 50ms p99 for batch of 10 chunks on staging

- TrustDetect Kafka consumer confirms receipt of IPIA threat events with correct fields

- Admin dashboard widget visible in staging with 24h detection count

- Feature flag ipia_enabled works: false passes all chunks, true applies detection

|                                                                                       |
|---------------------------------------------------------------------------------------|
| **Sprint 33 — Canary Token Module — System Prompt Leakage Detection** \[Weeks 65–66\] |

**Goal: Build end-to-end canary token infrastructure: session-scoped HMAC-signed token generation, system prompt injection, output scanner, and CRITICAL threat event emission on leakage detection.**

**Stories**

| **ID** | **Story**                                                                                                                                                   | **Pts** | **Layer** | **Module**   | **Acceptance Criteria**                                                                                                        |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|-----------|--------------|--------------------------------------------------------------------------------------------------------------------------------|
| SP-330 | Build CanaryTokenGenerator: HMAC-SHA256 signed, UUID v4 + session_id input, 12-char base62 output, TTL-managed in-memory store (TTL = session duration)     | 3       | Detection | Canary Token | Generator produces unique token per session; token not logged in audit trail; TTL expiry confirmed in unit test                |
| SP-331 | Inject canary into system prompt preamble at Sphinx session initialisation: prepend invisible canary comment (\<!-- SPHINX-{token} --\>) to system prompt   | 3       | Detection | Canary Token | System prompt delivered to LLM contains canary comment; LLM response to benign queries does not reproduce canary               |
| SP-332 | Build CanaryOutputScanner: regex match per response turn against active session canary; O(1) lookup from session store                                      | 3       | Detection | Canary Token | Scanner detects canary reproduction in agent response in \< 5ms; benign responses produce no false positives in 50-sample test |
| SP-333 | Emit CRITICAL threat event on canary detection: {session_id, turn_index, detection_timestamp, extraction_confidence=1.0, owasp=LLM07-2025} → TrustDetect    | 3       | Telemetry | Canary Token | CRITICAL event visible in TrustDetect within 100ms of detection; OWASP tag LLM07-2025 present                                  |
| SP-334 | Red team validation: 20 extraction attack variants (direct repeat, roleplay extraction, completion attack, indirect ask) — confirm 20/20 blocked or flagged | 5       | QA        | Canary Token | Red team report: 20/20 extraction attacks trigger canary alert; 0 false positives on 50 benign sessions                        |
| SP-335 | Admin toggle: canary_token_enabled per policy; admin dashboard badge showing canary leakage events (30-day count)                                           | 2       | UI        | Canary Token | Toggle applies per policy; dashboard badge updates within 30s                                                                  |

**Definition of Done**

- Canary tokens generated per session with HMAC signing confirmed

- System prompt canary injection confirmed in LLM API call payload (staging)

- Output scanner detects canary in 20/20 red team extraction scenarios

- CRITICAL threat event received in TrustDetect with correct schema

- 0 false positives in 50 benign session red team run

- Admin toggle and dashboard badge functional in staging

**Dependencies**

Sprint 32 complete (IPIA live in staging). TrustDetect CRITICAL event category must be supported (confirmed in TrustDetect PRD S5).

**Risk**

|         |                                                                                                                                                                                                                                                            |
|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **LOW** | LLM may reproduce canary comment if model is very instruction-following and the attacker explicitly asks for comments. Mitigated by making the canary format non-obvious (base62, no readable label). Documented as a known edge case in the threat model. |

**Acceptance Criteria (Sprint-Level)**

- Canary generated per session; TTL expiry confirmed; not present in audit log

- System prompt delivered to LLM contains canary in staging environment

- Output scanner detects canary reproduction within 5ms (unit test timing confirmed)

- TrustDetect receives CRITICAL event with owasp=LLM07-2025 within 100ms

- 20/20 extraction attacks flagged; 0/50 benign false positives in red team run

|                                                                                    |
|------------------------------------------------------------------------------------|
| **Sprint 34 — Model Fingerprinting — Stylometric Baseline Engine** \[Weeks 67–68\] |

**Goal: Build the 16-feature stylometric extractor and baseline profiler that establishes a cryptographically anchored response fingerprint for the deployed inference model.**

**Stories**

| **ID** | **Story**                                                                                                                                                                                                                                                                                                                                                                                                  | **Pts** | **Layer** | **Module**        | **Acceptance Criteria**                                                                                                                                                  |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|-----------|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SP-340 | Implement StylemetricFeatureExtractor: 16 features — token entropy, punctuation density, avg sentence length, paragraph count, refusal phrasing freq, hedging language freq, bullet list rate, code block freq, numbered list freq, citation pattern presence, question-ending freq, response length distribution, capitalisation patterns, conjunctive adverb usage, passive voice freq, negation density | 8       | Detection | Model Fingerprint | All 16 features extracted from a test response; unit tests confirm each feature with 3 reference cases each                                                              |
| SP-341 | Build BaselineProfiler: collect 50 warm-up responses at deployment; compute per-feature mean and standard deviation; export as JSON profile                                                                                                                                                                                                                                                                | 5       | Detection | Model Fingerprint | Profiler completes 50-response warm-up in \< 200ms (async, background); JSON profile exported and re-importable; profile stable (\< 5% variance across two warm-up runs) |
| SP-342 | Build DeviationScorer: z-score per feature vs. baseline; aggregate deviation index; configurable alert threshold (default 2.5σ)                                                                                                                                                                                                                                                                            | 3       | Detection | Model Fingerprint | Scorer returns correct z-score for synthetic feature vectors; threshold alert triggers correctly at 2.5σ default                                                         |
| SP-343 | Admin API: GET /v1/fingerprint/profile (export baseline), POST /v1/fingerprint/profile (import baseline), POST /v1/fingerprint/reset (re-warm-up)                                                                                                                                                                                                                                                          | 3       | API       | Model Fingerprint | All 3 endpoints respond correctly; import/export round-trip produces identical profile                                                                                   |

**Definition of Done**

- All 16 feature extractors implemented and individually tested

- Baseline profiler completes warm-up on staging inference endpoint

- JSON baseline profile exported and validated against spec

- DeviationScorer returns correct z-score for 5 synthetic test vectors

- Admin API endpoints tested with REST client

**Dependencies**

Sprint 33 complete. Staging inference endpoint must be accessible for warm-up profiling.

**Risk**

|            |                                                                                                                                                                                                                                                                                                       |
|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **MEDIUM** | Baseline stability depends on model temperature and sampling settings. If temperature is high, natural feature variance may exceed threshold, causing false positives. Mitigated by running warm-up at the deployment temperature setting; recommending temperature ≤ 0.7 in Sphinx deployment guide. |

**Acceptance Criteria (Sprint-Level)**

- StylemetricFeatureExtractor extracts all 16 features from a 200-word test response; values match hand-computed reference

- BaselineProfiler warm-up completes in \< 200ms on staging; JSON profile contains mean + std for each feature

- DeviationScorer returns z-score \> 2.5 for a synthetic model-swap feature vector; z-score \< 1.0 for baseline-consistent vector

- Admin API import/export round-trip: exported profile re-imported and produces identical scorer output

|                                                                                        |
|----------------------------------------------------------------------------------------|
| **Sprint 35 — Supply Chain Integrity + Inference Endpoint Monitoring** \[Weeks 69–70\] |

**Goal: Build the SupplyChainMonitor for consecutive-response alerting, wire fingerprinting into the Sphinx output scanning layer, and deliver the inference endpoint health dashboard.**

**Stories**

| **ID** | **Story**                                                                                                                                                            | **Pts** | **Layer**  | **Module**   | **Acceptance Criteria**                                                                                                    |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|------------|--------------|----------------------------------------------------------------------------------------------------------------------------|
| SP-350 | Build SupplyChainMonitor: track consecutive per-response deviation scores; alert HIGH if N consecutive responses exceed threshold (default N=5, configurable)        | 5       | Detection  | Supply Chain | Monitor alerts correctly when 5 consecutive synthetic high-deviation responses sent; single outlier does not trigger alert |
| SP-351 | Wire ModelFingerprintScorer into Sphinx output scanning layer: score every LLM response; write deviation score to response metadata                                  | 5       | Detection  | Supply Chain | Deviation score present in Sphinx response metadata for 100% of responses in staging; p99 scoring latency \< 10ms          |
| SP-352 | Emit HIGH severity threat event on supply chain swap detection: {model_id, baseline_version, deviation_scores\[\], feature_delta, consecutive_count} → TrustDetect   | 3       | Telemetry  | Supply Chain | TrustDetect receives HIGH event with feature_delta within 200ms of 5th consecutive breach; all required fields present     |
| SP-353 | Inference endpoint health dashboard: rolling 24h deviation score chart, per-feature drift chart, current model alignment status badge (ALIGNED / DRIFTING / SWAPPED) | 5       | UI         | Supply Chain | Dashboard visible in admin UI; status badge transitions correctly in staging (simulate by importing a different baseline)  |
| SP-354 | Controlled model swap red team: replace staging inference backend with alternate model; confirm alert within 5 responses                                             | 3       | QA         | Supply Chain | Alert triggers within 5 responses; no false positive on original model in 50-response soak test                            |
| SP-355 | DPDPA annotation: confirm feature vectors contain no PII (aggregate statistics only); document in TrustDLP integration note                                          | 1       | Compliance | Supply Chain | TrustDLP review confirms feature vectors contain no personal data; note added to compliance documentation                  |

**Definition of Done**

- SupplyChainMonitor correctly alerts on 5 consecutive high-deviation responses in red team

- Fingerprint scorer live in Sphinx output scanning layer on staging

- TrustDetect receiving supply chain HIGH events with correct schema

- Inference endpoint health dashboard deployed in staging admin UI

- DPDPA compliance note documented

- Full E2E regression suite green after wiring fingerprint scanner into output path

**Dependencies**

Sprint 34 complete (baseline engine). TrustDetect HIGH event category must support feature_delta field.

**Risk**

|            |                                                                                                                                                                                                                                                                              |
|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **MEDIUM** | Wiring fingerprinting into the output scanning layer (critical path) carries performance regression risk. Mitigated by running DeviationScorer async against a copy of response metadata; main response path is not blocked. Scorer result logged; alert emitted separately. |

**Acceptance Criteria (Sprint-Level)**

- SupplyChainMonitor: 5 consecutive synthetic high-deviation responses trigger HIGH alert; 4 consecutive do not

- Deviation score in response metadata for 100% of staging responses; p99 \< 10ms confirmed in load test

- TrustDetect receives HIGH event with all required fields within 200ms

- Dashboard status badge shows SWAPPED when alternate model imported as baseline mismatch

- Alternate model red team: alert within 5 responses; no false positive in 50-response baseline-consistent soak

|                                                                                          |
|------------------------------------------------------------------------------------------|
| **Sprint 36 — OWASP LLM Top 10 v2025 Compliance Matrix + Roadmap v1 GA** \[Weeks 71–72\] |

**Goal: Deliver the OWASP LLM Top 10 v2025 coverage matrix as a native Sphinx compliance module, run the full Roadmap v1 integration test suite, and cut the Roadmap v1 GA release.**

**Stories**

| **ID** | **Story**                                                                                                                                                | **Pts** | **Layer**  | **Module**         | **Acceptance Criteria**                                                                                                    |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------|---------|------------|--------------------|----------------------------------------------------------------------------------------------------------------------------|
| SP-360 | Apply OWASP LLM Top 10 v2025 capability tags to all Sphinx modules (existing v2.0 + new E15–E17); build tag registry YAML                                | 3       | Platform   | OWASP Matrix       | Tag registry covers all 30 v2.0 modules + 3 new modules; each module tagged with 1–N OWASP categories; reviewed by product |
| SP-361 | Build OWASPCoverageEngine: compute per-category coverage score (0–100%) from active Sphinx configuration; re-score on config change (\< 500ms)           | 5       | Detection  | OWASP Matrix       | Coverage scores computed correctly for LLM01–LLM10; disabling IPIA reduces LLM08 score; re-score completes in \< 500ms     |
| SP-362 | Build gap analysis: per uncovered requirement, list: requirement description, Sphinx modules that partially address it, recommended configuration change | 3       | Compliance | OWASP Matrix       | Gap analysis generates correctly for a staging config with 2 modules disabled; recommendations are actionable              |
| SP-363 | Compliance dashboard widget: radar chart (LLM01–LLM10 scores), overall Shield Score (weighted average), top 3 gaps                                       | 3       | UI         | OWASP Matrix       | Radar chart renders in admin dashboard; Shield Score ≥ 85 for default Sphinx Roadmap v1 configuration                      |
| SP-364 | PDF compliance report export: branded TrustFabric report, per-category score table, gap analysis, remediation guidance, Sphinx version + config snapshot | 5       | Compliance | OWASP Matrix       | PDF renders correctly; all 10 categories present; config snapshot matches staging environment                              |
| SP-365 | JSON compliance export: machine-readable {category, score, modules\[\], gaps\[\], recommendations\[\]} for each LLM01–LLM10                              | 2       | API        | OWASP Matrix       | JSON export validates against schema spec; importable into SIEM test environment                                           |
| SP-366 | Phase 9 integration test suite: E2E tests covering IPIA detection, canary leakage alert, model swap alert, OWASP re-score on config change; all pass     | 5       | QA         | Roadmap v1 QA      | All 4 E2E scenarios pass; no regression on Sprint 30 E2E suite; Roadmap v1 release checklist signed off                    |
| SP-367 | Roadmap v1 GA: documentation update (4 new modules), release notes, version tag (v2.1), CHANGELOG entry                                                  | 2       | Release    | Roadmap v1 Release | v2.1 tagged in git; CHANGELOG published; documentation updated                                                             |

**Definition of Done**

- OWASP tag registry covers all Sphinx modules (v2.0 + Roadmap v1)

- Coverage engine computes correct scores for all 10 categories in staging

- Gap analysis generates actionable recommendations for 2-module-disabled test config

- Radar chart and Shield Score ≥ 85 in default Roadmap v1 config

- PDF and JSON compliance exports validated

- Phase 9 integration test suite: all E2E scenarios passing

- Sprint 30 E2E regression suite: no failures

- v2.1 release tag cut; CHANGELOG published

**Dependencies**

Sprints 31–35 all complete. All E15–E17 modules live in staging. Sprint 30 regression baseline available.

**Risk**

|         |                                                                                                                                                                                                                                                                                                     |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **LOW** | OWASP matrix Shield Score depends on configuration coverage. If default Sphinx Roadmap v1 config scores \< 85, the gap analysis itself flags the remediation path — this is a feature, not a failure. Target is ≥ 85 with all E15–E17 modules enabled. Confirm score in staging before GA sign-off. |

**Acceptance Criteria (Sprint-Level)**

- OWASPCoverageEngine returns correct scores: LLM08 score drops when IPIA disabled, recovers when re-enabled

- LLM07 score ≥ 90 with canary token enabled; ≤ 50 with canary disabled (gap analysis flags the gap)

- LLM03 score ≥ 85 with model fingerprinting enabled

- Overall Shield Score ≥ 85 for default Roadmap v1 configuration

- PDF export renders all 10 categories with scores and gap analysis on 3-module-disabled test config

- Phase 9 E2E: IPIA blocks 5/5 injected chunks; canary alerts on extraction; model swap detected within 5 responses; OWASP re-score completes \< 500ms

| **Sprint** | **Theme**                            | **Weeks** | **Module** | **Story Pts** | **Key Milestone**                                      |
|------------|--------------------------------------|-----------|------------|---------------|--------------------------------------------------------|
| 31         | IPIA Foundation — Embedding Engine   | 61–62     | E15        | 18            | Embedding service + joint-context scorer staged        |
| 32         | IPIA Batch RAG Scanner + Integration | 63–64     | E15        | 22            | IPIA live in gateway; threat events to TrustDetect     |
| 33         | Canary Token Module                  | 65–66     | E16        | 19            | Canary end-to-end; 20/20 extraction attacks flagged    |
| 34         | Model Fingerprinting Baseline Engine | 67–68     | E17        | 19            | All 16 features extracted; baseline profiler staged    |
| 35         | Supply Chain Integrity + Monitoring  | 69–70     | E17        | 22            | Model swap detected in red team; health dashboard live |
| 36         | OWASP Matrix + Roadmap v1 GA         | 71–72     | E18        | 28            | Shield Score ≥ 85; PDF export; v2.1 GA release         |
|            | TOTAL                                | 61–72     | E15–E18    | 128           | 12 weeks · 6 sprints · 4 new modules                   |

**Roadmap v1 Release Checklist**

All items must be signed off before the v2.1 GA release tag is cut at the end of Sprint 36.

| **Area**    | **Checklist Item**                                              | **Owner**   | **Status** |
|-------------|-----------------------------------------------------------------|-------------|------------|
| IPIA        | Batch RAG scan API tested at p99 \< 50ms for batch of 10 chunks | Engineering | □          |
| IPIA        | IPIA threat events confirmed in TrustDetect UCDM schema         | Engineering | □          |
| IPIA        | Feature flag ipia_enabled tested (on/off/per-policy)            | Engineering | □          |
| IPIA        | CERT-In audit tag present in IPIA detection events              | Compliance  | □          |
| Canary      | 20/20 extraction attack red team scenarios confirmed            | Security    | □          |
| Canary      | 0 false positives in 50-session benign soak                     | Security    | □          |
| Canary      | Canary string absent from audit log (privacy check)             | Compliance  | □          |
| Canary      | Admin toggle tested per policy                                  | Engineering | □          |
| Fingerprint | 16-feature extractor unit tested individually                   | Engineering | □          |
| Fingerprint | Baseline profile warm-up \< 200ms on staging                    | Engineering | □          |
| Fingerprint | Model swap red team: alert within 5 responses                   | Security    | □          |
| Fingerprint | DPDPA: feature vectors confirmed PII-free                       | Compliance  | □          |
| Fingerprint | p99 scoring latency \< 10ms in load test                        | Engineering | □          |
| OWASP       | Tag registry reviewed by product and security                   | Product     | □          |
| OWASP       | Shield Score ≥ 85 for default Roadmap v1 config                 | Product     | □          |
| OWASP       | PDF compliance report reviewed by product (branded correctly)   | Product     | □          |
| OWASP       | JSON export validates against schema spec                       | Engineering | □          |
| OWASP       | Re-score latency \< 500ms confirmed                             | Engineering | □          |
| QA          | Phase 9 E2E integration test suite: all scenarios pass          | Engineering | □          |
| QA          | Sprint 30 regression suite: no new failures                     | Engineering | □          |
| Security    | Penetration test of canary token (canary bypass attempts)       | Security    | □          |
| Release     | v2.1 CHANGELOG drafted and reviewed                             | Product     | □          |
| Release     | Documentation updated for all 4 new modules                     | Product     | □          |
| Release     | v2.1 release tag cut on main branch                             | Engineering | □          |

This sprint plan extension is the operational companion to the Sphinx PRD Addendum — Roadmap v1 (Enhancement Modules E15–E18). Questions and design decisions arising during Sprint 31–36 should be tracked against the open questions in PRD Section 7. Sprint retrospectives should feed directly into the Roadmap v2 backlog.
