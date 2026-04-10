# DPDPA ROPA — Thoth Integration Data Flow Documentation

**Document Type:** Compliance Documentation — Record of Processing Activities (ROPA)  
**Regulatory Framework:** Digital Personal Data Protection Act (DPDPA), 2023  
**System:** Sphinx AI Mesh Firewall + Thoth Semantic Classification  
**Version:** 1.0  
**Sprint:** Sprint 7 — Indian Regulatory Compliance Mode  
**Date:** April 2026

---

## 1. Purpose

This document provides the data flow diagrams and processing activity records
required under DPDPA Section 6 (Lawful Processing) and Section 8 (Duties of
Data Fiduciary) for the Thoth semantic classification integration within the
Sphinx AI Mesh Firewall. It covers all personal data processing that occurs
during prompt classification, response classification, and audit record creation.

---

## 2. Data Categories Processed

| Data Category | DPDPA Classification | Examples | Processing Purpose |
|---|---|---|---|
| Aadhaar Number | Sensitive Personal Data | 12-digit UID | PII detection, routing to on-prem |
| PAN Card Number | Personal Data | ABCDE1234F | PII detection, routing to on-prem |
| Bank Account Number | Financial Personal Data | 9–18 digit account number | PII detection, routing to on-prem |
| IFSC Code | Financial Personal Data | SBIN0001234 | PII context detection |
| UPI ID | Financial Personal Data | user@bankname | PII context detection |
| User Identity (hashed) | Pseudonymised Personal Data | SHA-256 hash of user ID | Request correlation, audit |
| Prompt Content | Potentially contains Personal Data | Free-text LLM prompts | Semantic classification |
| LLM Response Content | Potentially contains Personal Data | AI-generated text | Post-inference risk analysis |

---

## 3. Data Flow Diagram — Pre-Inference Classification

```
┌───────────────────────────────────────────────────────────────────────┐
│                     Enterprise Application                            │
│                  (Data Principal's request)                            │
└─────────────────────────┬─────────────────────────────────────────────┘
                          │ Prompt containing personal data
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Sphinx AI Mesh Firewall                               │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Step 1: PII Content Hashing (S7-T3)                           │   │
│  │  • Detect India-specific PII (Aadhaar, PAN, Bank Account)      │   │
│  │  • Hash PII values with HMAC-SHA256 (salted)                   │   │
│  │  • Original PII NEVER leaves Sphinx boundary                   │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                               │ Hashed prompt text                     │
│                               ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Step 2: Residency Resolution (S7-T1)                          │   │
│  │  • Check ResidencyConfigRegistry for application                │   │
│  │  • Route to on-prem/VPC Thoth if INDIA zone configured         │   │
│  │  • Block if require_on_prem=True and no local endpoint         │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                               │                                        │
│              ┌────────────────┼──────────────────┐                    │
│              ▼ (INDIA zone)   ▼ (GLOBAL zone)    ▼ (Blocked)         │
│  ┌──────────────────┐ ┌──────────────┐  ┌────────────────────┐       │
│  │ On-prem/VPC Thoth│ │ SaaS Thoth   │  │ FAIL_CLOSED block  │       │
│  │ (India DC)       │ │ (Global)     │  │ Audit + reject     │       │
│  └────────┬─────────┘ └──────┬───────┘  └────────────────────┘       │
│           │                   │                                        │
│           └───────┬───────────┘                                        │
│                   ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Step 3: Classification Context (Thoth Response)               │   │
│  │  • intent, risk_level, confidence, pii_detected, pii_types     │   │
│  │  • No raw personal data in Thoth response                      │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                               ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Step 4: DPDPA Policy Evaluation (S7-T2)                       │   │
│  │  • Aadhaar routing → on-prem LLM endpoint                     │   │
│  │  • PAN routing → on-prem LLM endpoint                         │   │
│  │  • Bank account routing → on-prem LLM endpoint                │   │
│  │  • Exfiltration block rules (Aadhaar, PAN)                    │   │
│  │  • Multi-PII block rule (elevated risk)                        │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                               │                                        │
│              ┌────────────────┼──────────────────┐                    │
│              ▼                ▼                   ▼                    │
│         [BLOCK]          [ROUTE to          [ALLOW]                   │
│         Audit event      on-prem LLM]       (no PII)                  │
│                              │                   │                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Step 5: CERT-In Audit Trail (S7-T4)                           │   │
│  │  • Complete audit record with all required fields               │   │
│  │  • DPDPA regulatory tags appended                               │   │
│  │  • CERT-In incident tracking (6-hour window)                    │   │
│  │  • Tamper-evident hash chain                                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Flow Diagram — Post-Inference Classification

```
┌───────────────────────────────────────────────────────────────┐
│                      LLM Endpoint                             │
│            (On-prem for DPDPA-sensitive traffic)              │
└───────────────────────────┬───────────────────────────────────┘
                            │ LLM Response
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                   Sphinx Post-Inference Pipeline                  │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Step 1: Deliver response to application (non-blocking)     │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Step 2: Async response classification via Thoth            │ │
│  │  • Response text extraction                                  │ │
│  │  • PII hashing applied (if enabled)                         │ │
│  │  • Classification via on-prem Thoth (INDIA zone)            │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Step 3: Audit enrichment + CERT-In tracking                │ │
│  │  • Correlated audit record (prompt + response)              │ │
│  │  • PII detection in response flagged                        │ │
│  │  • CERT-In incident recorded if HIGH/CRITICAL risk          │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Step 4: SIEM Export                                        │ │
│  │  • Classification metadata exported to SIEM                 │ │
│  │  • DPDPA regulatory tags included in export payload         │ │
│  │  • 180-day retention requirement tracked                    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

---

## 5. Processing Activity Record (ROPA Entry)

| Field | Value |
|---|---|
| **Processing Activity** | AI Traffic Semantic Classification for Security Enforcement |
| **Data Fiduciary** | Organisation operating Sphinx AI Mesh Firewall |
| **Data Processor** | Thoth Semantic Classification Service (on-prem/VPC deployment) |
| **Lawful Basis** | DPDPA Section 4 — Legitimate uses (security of AI systems, prevention of data breaches) |
| **Categories of Data Principals** | Employees, customers, and partners whose prompts are processed through AI systems |
| **Categories of Personal Data** | Aadhaar, PAN, bank account numbers, financial data, contact information |
| **Purpose of Processing** | Detect and prevent data exfiltration, ensure compliance with data localisation requirements, enforce security policies |
| **Data Retention** | Audit records: 180 days (CERT-In requirement). Classification metadata: 180 days. Raw prompt content: NOT retained by Thoth. |
| **Data Transfers** | No cross-border transfer when on-prem/VPC Thoth deployed in India. PII content hashed before any transmission. |
| **Security Measures** | TLS 1.3, mTLS (Sprint 8), PII hashing, tamper-evident audit chain, role-based access control |
| **DPIA Required** | Yes — high-risk processing involving sensitive personal data at scale |

---

## 6. Data Minimisation Controls

| Control | Implementation | Sprint |
|---|---|---|
| PII Content Hashing | HMAC-SHA256 hashing of Aadhaar/PAN/bank account before Thoth transmission | S7-T3 |
| On-prem Thoth Deployment | Classification API deployed within Indian data centre | S7-T1 |
| Endpoint URL Override | Per-application routing to local Thoth instances | S7-T1 |
| require_on_prem Flag | Blocks classification if local endpoint unavailable | S7-T1 |
| No Raw PII in Classification Response | Thoth returns labels, not raw values | By design |
| Hashed User Identity | User IDs are SHA-256 hashed before inclusion in classification requests | S1-T3 |

---

## 7. CERT-In Compliance Controls

| Requirement | Implementation | Validation |
|---|---|---|
| 6-hour incident reporting | CERTInAuditTracker with time-windowed tracking | S7-T4 |
| 180-day log retention | Configurable audit retention policy | S7-T4 |
| Incident categorisation | Automated severity classification (CRITICAL/HIGH/MEDIUM/LOW) | S7-T4 |
| Audit trail completeness | Mandatory field validation (CERTIN_REQUIRED_AUDIT_FIELDS) | S7-T4 |
| Tamper-evident logs | SHA-256 hash chain on all audit records | Sprint 18 |
| SIEM integration | Classification metadata exported to SIEM within 5s | Sprint 4 |

---

## 8. Cross-Reference: Acceptance Criteria

| AC | Description | ROPA Coverage |
|---|---|---|
| AC-07 | DPDPA-sensitive routing rules correctly route Aadhaar/PAN/bank account-containing prompts | §3, §4, §5 |
| AC-02 | Enforcement continuity under Thoth unavailability | §3 (FAIL_CLOSED block path) |
| AC-05 | Thoth classification metadata in audit records | §5, §7 |
| AC-09 | Circuit breaker activates within 3 consecutive failures | §3 (Residency + circuit breaker) |

---

*Document prepared for DPDPA ROPA compliance review. For questions, contact TrustFabric Architecture.*
