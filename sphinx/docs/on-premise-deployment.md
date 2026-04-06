# Sphinx Gateway — On-Premise Deployment Guide

Self-hosted deployment of the Sphinx AI Mesh Firewall for air-gapped and
on-premise environments.

## Prerequisites

| Component       | Minimum Version | Purpose                      |
|-----------------|-----------------|------------------------------|
| Docker          | 24.0+           | Container runtime            |
| Docker Compose  | 2.20+           | Multi-container orchestration|
| Kubernetes      | 1.28+           | Production orchestration     |
| Helm (optional) | 3.14+           | K8s package management       |
| PostgreSQL      | 16+             | Primary data store           |
| Redis           | 7+              | Cache and pub/sub            |
| Kafka           | 3.7+            | Async audit event bus        |

## Architecture Overview

```
                  ┌─────────────────────────┐
                  │     Load Balancer /      │
                  │     Ingress Controller   │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │   Sphinx Gateway (×N)   │
                  │   - Auth & Rate Limit   │
                  │   - Threat Detection    │
                  │   - PII/PHI Redaction   │
                  │   - Policy Engine       │
                  └──┬──────┬──────┬───────┘
                     │      │      │
              ┌──────▼─┐ ┌─▼────┐ ┌▼──────┐
              │Postgres│ │Redis │ │ Kafka  │
              │ (data) │ │(cache)│ │(audit) │
              └────────┘ └──────┘ └───────┘
```

---

## Option A: Docker Compose Deployment

Best for: small teams, evaluation, development environments.

### 1. Clone and Configure

```bash
git clone <repository-url> sphinx-gateway
cd sphinx-gateway/sphinx
cp .env.example .env
```

Edit `.env`:

```env
# Database
DATABASE_URL=postgresql+asyncpg://sphinx:YOUR_STRONG_PASSWORD@postgres:5432/sphinx

# Redis
REDIS_URL=redis://redis:6379/0

# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:9092

# Encryption key for stored provider credentials (generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
CREDENTIAL_ENCRYPTION_KEY=your-generated-fernet-key

# For air-gapped environments using local Llama
DEFAULT_PROVIDER_URL=http://llama-server:8080
```

### 2. Build and Start

```bash
docker compose up -d --build
```

### 3. Run Database Migrations

```bash
docker compose exec gateway alembic upgrade head
```

### 4. Verify

```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy", ...}
```

### 5. Air-Gapped LLM (Llama)

For environments without internet access, add a local Llama server:

```yaml
# Add to docker-compose.yml
  llama:
    image: ghcr.io/ggerganov/llama.cpp:server
    volumes:
      - ./models:/models
    command: ["-m", "/models/your-model.gguf", "--host", "0.0.0.0", "--port", "8080"]
    ports:
      - "8080:8080"
```

Pre-download the model file and place it in `./models/` before deployment.

---

## Option B: Kubernetes Deployment

Best for: production, multi-tenant, high-availability requirements.

### 1. Create Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 2. Configure Secrets

**Option B1: Direct secrets (simple)**

Edit `k8s/secrets.yaml` with your actual values, then:

```bash
kubectl apply -f k8s/secrets.yaml
```

**Option B2: HashiCorp Vault (recommended for production)**

1. Install the Vault Agent Injector in your cluster
2. Create Vault secrets:

```bash
vault kv put secret/sphinx/database url="postgresql+asyncpg://sphinx:PASS@postgres:5432/sphinx"
vault kv put secret/sphinx/redis url="redis://redis:6379/0"
vault kv put secret/sphinx/encryption key="your-fernet-key"
```

3. Create a Vault policy and role for the `sphinx-gateway` service account
4. Uncomment the Vault annotations in `k8s/gateway-deployment.yaml`

### 3. Deploy Infrastructure

Deploy PostgreSQL, Redis, and Kafka to your cluster using your preferred
operators (e.g., CloudNativePG, Redis Operator, Strimzi).

### 4. Deploy Gateway

```bash
kubectl apply -f k8s/gateway-deployment.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/pdb.yaml
kubectl apply -f k8s/network-policy.yaml
kubectl apply -f k8s/ingress.yaml
```

### 5. Run Migrations

```bash
kubectl -n sphinx exec deploy/sphinx-gateway -- alembic upgrade head
```

### 6. Verify

```bash
kubectl -n sphinx get pods
kubectl -n sphinx logs deploy/sphinx-gateway --tail=50
```

---

## Security Hardening Checklist

- [ ] TLS termination at ingress / load balancer
- [ ] Network policies restrict pod-to-pod traffic
- [ ] Secrets managed via Vault or sealed-secrets (not plain K8s secrets)
- [ ] Gateway runs as non-root (UID 1000)
- [ ] Resource limits set on all containers
- [ ] PodDisruptionBudget ensures minimum availability
- [ ] Audit logs shipped to immutable storage (S3, GCS)
- [ ] Database connections use TLS (`?sslmode=require`)
- [ ] Redis requires authentication (`requirepass`)
- [ ] Kafka configured with SASL/TLS in production

## Monitoring

- Gateway exposes `/health` for liveness/readiness probes
- Prometheus metrics available via admin API
- Recommended: deploy Prometheus + Grafana for dashboards
- Alert on: p99 latency > 80ms, error rate > 1%, pod restarts

## Backup & Recovery

- PostgreSQL: use `pg_dump` or continuous archiving (WAL-G)
- Redis: enable RDB snapshots or AOF persistence
- Kafka: configure topic replication factor ≥ 3

## Scaling Guidelines

| Load (RPS) | Gateway Replicas | CPU (per pod) | Memory (per pod) |
|------------|------------------|---------------|------------------|
| < 100      | 2                | 500m          | 512Mi            |
| 100–500    | 3–5              | 1             | 1Gi              |
| 500–1000   | 5–10             | 2             | 2Gi              |
| > 1000     | 10+              | 2–4           | 2–4Gi            |

HPA will auto-scale based on CPU utilization (target: 70%).
