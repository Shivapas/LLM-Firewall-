# Sphinx — AI Mesh Firewall

A server-side security and governance platform that intercepts, inspects, and enforces policy on every AI interaction before it reaches a language model or vector database. Deployed as a transparent proxy — AI workloads point to the Sphinx gateway instead of calling providers directly, requiring **zero code changes** to existing applications.

| Dimension | Value |
|---|---|
| Deployment Model | Transparent proxy — base URL swap only |
| Supported Providers | OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Llama, Google Gemini |
| Compliance Coverage | GDPR, HIPAA, SOC 2 Type II, PCI-DSS, OWASP LLM Top 10, EU AI Act, DPDPA |
| Gateway Latency (p95) | < 80 ms overhead |

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Admin UI](#admin-ui)
- [Running Tests](#running-tests)
- [CI/CD Red Team Security Gate](#cicd-red-team-security-gate)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [License](#license)

---

## Key Features

### Full-Pipeline Security
- **Input Firewall** — Tier 1 (regex/pattern) and Tier 2 (ML semantic) threat detection for prompt injection, jailbreaks, and data extraction attempts
- **Output Scanner** — Response content leakage detection before delivery to end users
- **PII/PHI Redaction** — Automatic detection and masking of sensitive data in prompts and responses

### Vector DB Firewall
- **Namespace Isolation** — Multi-tenant RAG safety with zero cross-tenant retrieval
- **Chunk Scanning** — Security controls on retrieved context before assembly
- **RAG Query Firewall** — Intent classification and policy enforcement on retrieval queries

### Operational Controls
- **Inline Kill-Switch** — Instantly disable compromised providers without restart (next-request enforcement via Redis pub/sub)
- **Circuit Breakers** — Automatic provider disabling on failure rate thresholds
- **Failover Routing** — Health-aware fallback routing across providers
- **Token Budgeting & Cost Tracking** — Per-key budgets with automatic model downgrade on exhaustion

### Governance & Compliance
- **Tamper-Proof Audit Trail** — Kafka-based audit events with hash chain integrity
- **Policy Versioning** — Full lifecycle management with < 5 second propagation
- **Compliance Reporting** — GDPR, HIPAA, SOC 2, DPDPA report generation
- **SIEM Export** — Webhook export in Splunk and Datadog formats

### Agentic AI Security
- **MCP Tool Scanner** — Model Context Protocol discovery, risk scoring, and scope enforcement
- **Agent-to-Agent Firewall** — mTLS, signature verification, and token issuance for inter-agent communication
- **Memory Firewall** — Memory store isolation, read anomaly detection, and integrity verification
- **Session Security** — Cross-turn risk accumulation and context isolation

### Enterprise Features
- **Human-in-the-Loop** — Approval workflows with anomaly detection baselines
- **Red Team Automation** — Continuous adversarial probing with CI/CD integration
- **Thoth Semantic Classification** — ML-powered request classification with circuit breaker and fail-closed modes
- **Multilingual Support** — Unicode normalization, language detection, EU AI Act compliance

---

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────┐     ┌─────────────┐
│  AI App /   │     │              Sphinx Gateway                  │     │   LLM       │
│  Agent      │────>│  Auth ─> Input Scan ─> Policy ─> Route ─>   │────>│  Provider   │
│             │<────│  <─ Audit <─ Output Scan <─ PII Redact <─   │<────│  (OpenAI,   │
└─────────────┘     │                                              │     │  Anthropic, │
                    │  Kill-Switch │ Circuit Breaker │ Rate Limit  │     │  Azure ...) │
                    └──────────────────────────────────────────────┘     └─────────────┘
                         │              │              │
                    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐
                    │Postgres│    │ Redis  │    │ Kafka  │
                    │  (data)│    │(cache) │    │(audit) │
                    └────────┘    └────────┘    └────────┘
```

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Git

### 1. Clone and configure

```bash
git clone https://github.com/shivapas/LLM-Firewall-.git
cd LLM-Firewall-/sphinx
cp .env.example .env
```

Generate an encryption key and add it to `.env`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Start services

```bash
docker compose up -d --build
```

This starts:

| Service | Port | Description |
|---|---|---|
| Gateway | `8000` | Sphinx API gateway |
| Admin UI | `3000` | React management dashboard |
| PostgreSQL | `5432` | Primary data store |
| Redis | `6379` | Cache and pub/sub |
| Kafka | `9092` | Audit event bus |
| Mock LLM | `9000` | Test LLM endpoint |

### 3. Run database migrations

```bash
docker compose exec gateway alembic upgrade head
```

### 4. Verify

```bash
curl http://localhost:8000/health
```

### 5. Point your AI application to Sphinx

Replace your LLM provider base URL with the Sphinx gateway:

```python
# Before
client = OpenAI(base_url="https://api.openai.com/v1")

# After — zero code changes beyond the URL
client = OpenAI(base_url="http://localhost:8000")
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL async connection string | `postgresql+asyncpg://sphinx:sphinx_secret@localhost:5432/sphinx` |
| `REDIS_URL` | Redis URL for cache and pub/sub | `redis://localhost:6379/0` |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key for encrypting provider credentials | (required) |
| `DEFAULT_PROVIDER_URL` | Fallback LLM endpoint | `http://localhost:9000` |
| `GATEWAY_HOST` | Server bind address | `0.0.0.0` |
| `GATEWAY_PORT` | Server bind port | `8000` |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka brokers for audit events | `kafka:9092` |
| `THOTH_ENABLED` | Enable Thoth semantic classification | `false` |
| `THOTH_API_URL` | Thoth service endpoint | — |
| `SIEM_EXPORT_ENABLED` | Enable SIEM/data lake webhook export | `false` |

### Threat Patterns

Threat detection rules are defined in `sphinx/config/threat_patterns.yaml` — 200+ regex patterns organized by category (prompt injection, jailbreak, data extraction, privilege escalation, model manipulation, and more). Each pattern includes severity level and OWASP LLM Top 10 tags. Patterns can also be managed at runtime through the Admin API.

---

## Admin UI

The React-based Admin UI (`http://localhost:3000`) provides dashboards for:

- **API Key Management** — Create, rotate, and revoke API keys
- **Policy Builder** — Create and version security policies
- **Security Dashboard** — Real-time threat detection metrics
- **RAG Policy** — Vector DB namespace and retrieval controls
- **Kill Switch** — One-click provider disablement
- **Red Team Campaigns** — Launch and review adversarial probes
- **Circuit Breaker Dashboard** — Provider health and failover status
- **MCP Scanner** — Discover and audit agent tool connections
- **Memory Store Dashboard** — Memory firewall isolation controls
- **Incident Management** — Alert triage and response
- **Compliance Reports** — Generate regulatory reports
- **Onboarding Wizard** — Guided first-time setup

---

## Running Tests

```bash
cd sphinx
pytest tests/ -v
```

The test suite covers authentication, kill-switch, audit, policy cache, providers, health, proxy, admin endpoints, vector DB, agent scope, red team, HITL, memory firewall, multilingual, and more.

---

## CI/CD Red Team Security Gate

A GitHub Actions workflow (`.github/workflows/red-team-security-gate.yml`) integrates automated red team probing into your deployment pipeline:

1. Triggers a red team campaign against a staging endpoint on every push to `main`/`develop`
2. Probes across categories: injection, jailbreak, PII extraction, tool call injection, memory poisoning, privilege escalation, multi-step attacks
3. Fails the build if Critical findings are detected

### Setup

Set the following repository secrets:
- `SPHINX_GATEWAY_URL` — Sphinx gateway base URL
- `SPHINX_API_KEY` — API key with red-team permissions
- `TARGET_ENDPOINT` — AI application endpoint under test

---

## Kubernetes Deployment

Kubernetes manifests are provided in `sphinx/k8s/`:

```bash
kubectl apply -f sphinx/k8s/namespace.yaml
kubectl apply -f sphinx/k8s/secrets.yaml
kubectl apply -f sphinx/k8s/gateway-deployment.yaml
kubectl apply -f sphinx/k8s/hpa.yaml
kubectl apply -f sphinx/k8s/ingress.yaml
```

Includes Horizontal Pod Autoscaler and network policies. See `sphinx/docs/on-premise-deployment.md` for detailed deployment guidance including air-gapped environments.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Gateway | FastAPI 0.115.6, Uvicorn 0.34.0, Python 3.12 |
| Database | PostgreSQL 16, SQLAlchemy 2.0.36, Alembic 1.14.1 |
| Cache | Redis 7 |
| Audit Bus | Apache Kafka 3.7 |
| Frontend | React 19, React Router 7 |
| HTTP Client | httpx 0.28.1 |
| Encryption | cryptography 44.0.0 (Fernet) |
| Validation | Pydantic 2.10.4 |
| Infrastructure | Docker, Kubernetes |

---

## Project Structure

```
LLM-Firewall-/
├── .github/workflows/         # CI/CD pipelines
├── sphinx/
│   ├── app/
│   │   ├── main.py            # FastAPI application entry point
│   │   ├── routers/           # API routers (proxy, admin, health, HITL, memory, model, A2A)
│   │   ├── services/          # Core service modules
│   │   │   ├── threat_detection/  # Tier 1 & Tier 2 threat scanning
│   │   │   ├── data_shield/       # PII/PHI redaction engine
│   │   │   ├── providers/         # LLM provider adapters
│   │   │   ├── rag/               # RAG query firewall & pipeline controls
│   │   │   ├── vectordb/          # Vector DB proxy & namespace isolation
│   │   │   ├── mcp/               # MCP tool discovery & audit
│   │   │   ├── a2a/               # Agent-to-agent security
│   │   │   ├── thoth/             # Semantic classification engine
│   │   │   ├── dashboard/         # Security ops dashboards
│   │   │   ├── hitl/              # Human-in-the-loop workflows
│   │   │   ├── memory_firewall/   # Memory store isolation
│   │   │   ├── red_team/          # Automated adversarial probing
│   │   │   ├── multilingual/      # Unicode normalization & EU AI Act
│   │   │   └── ...               # Rate limiting, audit, cost tracking, etc.
│   │   └── models/            # SQLAlchemy ORM models
│   ├── admin-ui/              # React admin dashboard
│   ├── alembic/               # Database migrations
│   ├── config/                # Threat patterns & configuration
│   ├── docs/                  # Deployment & compliance documentation
│   ├── k8s/                   # Kubernetes manifests
│   ├── tests/                 # Test suite
│   ├── docker-compose.yml     # Local development environment
│   ├── Dockerfile             # Production container image
│   └── requirements.txt       # Python dependencies
├── Sphinx_PRD.md              # Product Requirements Document v2.0
└── Sphinx_Sprint_Plan.md      # Sprint roadmap
```

---

## License

See repository for license details.