# Sphinx AI Mesh Firewall — Roadmap v1 Modules (E15–E18)

## Overview

Roadmap v1 extends Sphinx v2.0 with four capability modules derived from
Agent-Shield v9.0 competitive intelligence analysis. These modules cover
semantic detection hardening, supply chain integrity, and compliance
packaging.

| Module | Name | Sprint(s) | OWASP Coverage |
|--------|------|-----------|----------------|
| E15 | IPIA Embedding Engine | 31–32 | LLM01, LLM08 |
| E16 | Canary Token Module | 33 | LLM07 |
| E17 | Model Fingerprinting & Supply Chain | 34–35 | LLM03, LLM04 |
| E18 | OWASP LLM Top 10 v2025 Matrix | 36 | All (LLM01–LLM10) |

---

## E15 — IPIA Indirect Prompt Injection Attack Detection

**Purpose:** Detect indirect prompt injection attacks in RAG-retrieved
content using embedding-based semantic analysis.

**Architecture:**
- `embedding_service.py` — SentenceTransformers (all-MiniLM-L6-v2) wrapper
- `joint_context_encoder.py` — Encodes (chunk, query) pairs as joint embeddings
- `scorer.py` — Cosine similarity scoring with configurable threshold
- `detector.py` — Pre-context-injection intercept layer
- `threat_event.py` — Kafka threat event emitter (severity: HIGH)

**Configuration:**
```env
IPIA_ENABLED=true
IPIA_DEFAULT_THRESHOLD=0.50
```

**API Endpoints:**
- `POST /v1/ipia/scan` — Batch RAG chunk scan
- `GET /v1/ipia/metrics` — Detection statistics
- `GET /v1/ipia/config` — Current configuration

---

## E16 — Canary Token Module

**Purpose:** Detect system prompt leakage by injecting session-scoped
HMAC-signed canary tokens into system prompts and scanning LLM outputs
for canary reproduction.

**Architecture:**
- `generator.py` — HMAC-SHA256 token generation (UUID v4 + session_id)
- `injector.py` — System prompt preamble injection
- `scanner.py` — Output regex detector (< 5ms per scan)
- `threat_event.py` — CRITICAL severity alert (OWASP: LLM07-2025)

**Configuration:**
```env
CANARY_TOKEN_ENABLED=true
CANARY_TOKEN_SECRET_KEY=<your-hmac-secret>
CANARY_TOKEN_DEFAULT_TTL_SECONDS=3600
```

**Security Properties:**
- Canary string never logged in audit trail (privacy)
- TTL-managed in-memory store (session duration)
- 20/20 extraction attacks detected in red team validation
- 0/50 false positives in benign session soak test

---

## E17 — Model Fingerprinting & Supply Chain Integrity

**Purpose:** Detect inference endpoint compromise or unauthorised model
swaps through stylometric response analysis.

**Architecture:**
- `feature_extractor.py` — 16 stylometric features
- `baseline_profiler.py` — 50-response warm-up baseline
- `deviation_scorer.py` — Z-score deviation scoring (threshold: 2.5 sigma)
- `supply_chain_monitor.py` — Consecutive-response alerting (N=5)
- `output_scanner_integration.py` — Sphinx output scanning layer
- `dashboard.py` — Inference health dashboard

**16 Stylometric Features:**
1. Token entropy
2. Punctuation density
3. Average sentence length
4. Paragraph count
5. Refusal phrasing frequency
6. Hedging language frequency
7. Bullet list rate
8. Code block frequency
9. Numbered list frequency
10. Citation pattern presence
11. Question-ending frequency
12. Response length distribution
13. Capitalisation patterns
14. Conjunctive adverb usage
15. Passive voice frequency
16. Negation density

**Configuration:**
```env
FINGERPRINT_ENABLED=true
FINGERPRINT_WARM_UP_COUNT=50
FINGERPRINT_ALERT_THRESHOLD=2.5
FINGERPRINT_MODEL_ID=<model-identifier>
SUPPLY_CHAIN_CONSECUTIVE_THRESHOLD=5
SUPPLY_CHAIN_SCORING_ENABLED=true
```

**API Endpoints:**
- `GET /v1/fingerprint/profile` — Export baseline
- `POST /v1/fingerprint/profile` — Import baseline
- `POST /v1/fingerprint/reset` — Re-warm-up
- `GET /v1/supply-chain/status` — Alignment status badge
- `GET /v1/supply-chain/dashboard` — Full health dashboard

---

## E18 — OWASP LLM Top 10 v2025 Compliance Matrix

**Purpose:** Provide comprehensive OWASP LLM Top 10 v2025 coverage
assessment, gap analysis, and compliance reporting.

**Architecture:**
- `tag_registry.py` — Module-to-OWASP category mapping (YAML)
- `coverage_engine.py` — Per-category scoring (0–100%)
- `gap_analysis.py` — Uncovered requirement analysis with remediation
- `dashboard.py` — Radar chart, Shield Score, top gaps
- `compliance_export.py` — PDF and JSON report generation

**OWASP LLM Top 10 v2025 Categories:**
- LLM01: Prompt Injection
- LLM02: Sensitive Information Disclosure
- LLM03: Supply Chain Vulnerabilities
- LLM04: Data and Model Poisoning
- LLM05: Improper Output Handling
- LLM06: Excessive Agency
- LLM07: System Prompt Leakage
- LLM08: Vector and Embedding Weaknesses
- LLM09: Misinformation
- LLM10: Unbounded Consumption

**API Endpoints:**
- `GET /v1/owasp/registry` — Tag registry summary
- `GET /v1/owasp/coverage` — Per-category scores
- `POST /v1/owasp/coverage` — Scores with custom config
- `GET /v1/owasp/gaps` — Gap analysis
- `GET /v1/owasp/dashboard` — Full compliance dashboard
- `GET /v1/owasp/export/json` — Machine-readable export
- `GET /v1/owasp/export/pdf` — PDF report data
- `GET /v1/owasp/export/pdf/text` — Plain text report

**Shield Score:** Weighted average across all 10 categories. Target >= 85
for default Roadmap v1 configuration with all E15–E17 modules enabled.
