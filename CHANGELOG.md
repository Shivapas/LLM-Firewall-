# Changelog

## v2.1.0 — Roadmap v1 GA Release (2026-04-16)

### Phase 9: Intelligence Hardening (Sprints 31-36)

Four new capability modules derived from Agent-Shield v9.0 competitive
intelligence analysis. Structured across semantic detection hardening,
supply chain integrity, and compliance packaging.

### New Modules

#### E15 — IPIA Indirect Prompt Injection Attack Detection (Sprints 31-32)
- SentenceTransformers embedding service (all-MiniLM-L6-v2) with pluggable backend
- JointContextEncoder for (chunk, query) pair embedding
- Cosine similarity scorer with configurable threshold (default 0.5)
- Pre-context-injection intercept layer scanning all RAG chunks
- Batch RAG scan API: `POST /v1/ipia/scan`
- IPIA threat events emitted to TrustDetect Kafka topic (severity: HIGH, OWASP: LLM08-2025)
- Per-policy configurable threshold (`ipia_threshold: 0.0-1.0`)
- CERT-In compliance annotation on detection events
- IPIA detection rate dashboard widget (rolling 24h)
- Feature flag: `ipia_enabled` (default: false)

#### E16 — Canary Token Module (Sprint 33)
- HMAC-SHA256 signed session-scoped canary token generation
- System prompt canary injection at session initialisation
- CanaryOutputScanner: regex match per response turn (< 5ms)
- CRITICAL threat event on canary detection (OWASP: LLM07-2025)
- Red team validated: 20/20 extraction attacks flagged, 0/50 benign false positives
- Admin toggle: `canary_token_enabled` per policy
- Dashboard badge showing 30-day canary leakage events

#### E17 — Model Fingerprinting & Supply Chain Integrity (Sprints 34-35)
- 16-feature StylemetricFeatureExtractor (token entropy, punctuation density,
  sentence length, paragraph count, refusal/hedging frequency, list rates,
  code blocks, citations, questions, capitalisation, passive voice, negation)
- BaselineProfiler: 50-response warm-up, JSON profile export/import
- DeviationScorer: per-feature z-score with configurable alert threshold (default 2.5 sigma)
- SupplyChainMonitor: consecutive-response alerting (default N=5)
- Fingerprint scoring in output scanning layer (p99 < 10ms)
- HIGH severity threat event on supply chain swap detection (OWASP: LLM03-2025)
- Inference endpoint health dashboard (24h deviation, per-feature drift, alignment badge)
- Admin API: GET/POST /v1/fingerprint/profile, POST /v1/fingerprint/reset
- DPDPA compliance: feature vectors confirmed PII-free
- Feature flags: `fingerprint_enabled`, `supply_chain_scoring_enabled`

#### E18 — OWASP LLM Top 10 v2025 Compliance Matrix (Sprint 36)
- OWASP tag registry YAML covering 30 v2.0 modules + 3 Roadmap v1 modules
- OWASPCoverageEngine: per-category coverage scoring (0-100%), re-score < 500ms
- Gap analysis engine with actionable remediation recommendations
- Compliance dashboard widget: radar chart (LLM01-LLM10), Shield Score, top 3 gaps
- PDF compliance report export (branded TrustFabric, per-category scores, gap analysis)
- JSON compliance export (machine-readable, SIEM-importable)
- Phase 9 E2E integration test suite
- API endpoints: `/v1/owasp/registry`, `/v1/owasp/coverage`, `/v1/owasp/gaps`,
  `/v1/owasp/dashboard`, `/v1/owasp/export/json`, `/v1/owasp/export/pdf`

### Configuration Changes

| Setting | Default | Module |
|---------|---------|--------|
| `IPIA_ENABLED` | `false` | E15 |
| `IPIA_DEFAULT_THRESHOLD` | `0.50` | E15 |
| `CANARY_TOKEN_ENABLED` | `true` | E16 |
| `CANARY_TOKEN_SECRET_KEY` | (set in prod) | E16 |
| `CANARY_TOKEN_DEFAULT_TTL_SECONDS` | `3600` | E16 |
| `FINGERPRINT_ENABLED` | `false` | E17 |
| `FINGERPRINT_WARM_UP_COUNT` | `50` | E17 |
| `FINGERPRINT_ALERT_THRESHOLD` | `2.5` | E17 |
| `FINGERPRINT_MODEL_ID` | `""` | E17 |
| `SUPPLY_CHAIN_CONSECUTIVE_THRESHOLD` | `5` | E17 |
| `SUPPLY_CHAIN_SCORING_ENABLED` | `false` | E17 |

### Breaking Changes

None. All new modules are additive and gated behind feature flags.

### Dependencies

- PyYAML (for OWASP tag registry YAML parsing)
- All other dependencies unchanged from v2.0.0

---

## v2.0.0 — GA Release (Sprints 1-30)

Initial production release of Sphinx AI Mesh Firewall with 30 sprint
iterations covering: threat detection, PII/PHI protection, RAG security,
multi-provider routing, policy engine, MCP guardrails, memory firewall,
A2A firewall, HITL workflows, model scanning, semantic cache, red team
automation, and enterprise dashboard.
