"""Sprint 27 — Inter-Agent A2A Protocol Firewall.

Intercepts and secures agent-to-agent (A2A) communication across
multi-agent orchestration frameworks (LangGraph, AutoGen, CrewAI).

Components:
- interceptor: A2A message interception layer
- token_issuer: Agent identity JWT token issuance
- signature: Message signature verification + nonce replay protection
- mtls: Mutual TLS enforcement for agent channels
- audit: Per-message A2A audit log
"""
