"""Credential Pattern Scanner — detects API keys, credit cards, private keys, and connection strings.

Zero false negatives on standard formats is the design target.
"""

import re
from dataclasses import dataclass
from enum import Enum

from app.services.data_shield.pii_recognizer import PIIEntity, PIIType


class CredentialType(str, Enum):
    OPENAI_API_KEY = "OPENAI_API_KEY"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    GITHUB_PAT = "GITHUB_PAT"
    SLACK_TOKEN = "SLACK_TOKEN"
    STRIPE_KEY = "STRIPE_KEY"
    GOOGLE_API_KEY = "GOOGLE_API_KEY"
    ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"
    AZURE_KEY = "AZURE_KEY"
    GENERIC_API_KEY = "GENERIC_API_KEY"
    CREDIT_CARD = "CREDIT_CARD"
    PRIVATE_KEY = "PRIVATE_KEY"
    CONNECTION_STRING = "CONNECTION_STRING"
    JWT_TOKEN = "JWT_TOKEN"
    BEARER_TOKEN = "BEARER_TOKEN"


@dataclass
class _CredentialPattern:
    credential_type: CredentialType
    pattern: re.Pattern
    confidence: float = 0.95


# ── Credential patterns ─────────────────────────────────────────────────

_CREDENTIAL_PATTERNS: list[_CredentialPattern] = [
    # OpenAI API keys: sk-... (48+ chars)
    _CredentialPattern(
        CredentialType.OPENAI_API_KEY,
        re.compile(r'\bsk-[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?\b'),
        0.99,
    ),
    # Anthropic API keys: sk-ant-...
    _CredentialPattern(
        CredentialType.ANTHROPIC_API_KEY,
        re.compile(r'\bsk-ant-[A-Za-z0-9\-]{20,}\b'),
        0.99,
    ),
    # AWS Access Key ID: AKIA...
    _CredentialPattern(
        CredentialType.AWS_ACCESS_KEY,
        re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b'),
        0.98,
    ),
    # AWS Secret Access Key: 40-char base64
    _CredentialPattern(
        CredentialType.AWS_SECRET_KEY,
        re.compile(
            r'(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*'
            r'([A-Za-z0-9/+=]{40})',
            re.IGNORECASE,
        ),
        0.97,
    ),
    # GitHub classic tokens: ghp_, gho_, ghu_, ghs_, ghr_
    _CredentialPattern(
        CredentialType.GITHUB_TOKEN,
        re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
        0.99,
    ),
    # GitHub fine-grained PAT: github_pat_
    _CredentialPattern(
        CredentialType.GITHUB_PAT,
        re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,}\b'),
        0.99,
    ),
    # Slack tokens: xoxb-, xoxp-, xoxo-, xoxa-
    _CredentialPattern(
        CredentialType.SLACK_TOKEN,
        re.compile(r'\bxox[bpoa]-[A-Za-z0-9\-]{10,}\b'),
        0.98,
    ),
    # Stripe keys: sk_live_, pk_live_, sk_test_, pk_test_
    _CredentialPattern(
        CredentialType.STRIPE_KEY,
        re.compile(r'\b[sp]k_(?:live|test)_[A-Za-z0-9]{20,}\b'),
        0.99,
    ),
    # Google API key: AIza...
    _CredentialPattern(
        CredentialType.GOOGLE_API_KEY,
        re.compile(r'\bAIza[A-Za-z0-9\-_]{30,}\b'),
        0.97,
    ),
    # Azure subscription/API key: 32 hex chars
    _CredentialPattern(
        CredentialType.AZURE_KEY,
        re.compile(
            r'(?:azure|subscription)[_\-\s]*(?:key|secret)\s*[=:]\s*'
            r'([A-Fa-f0-9]{32})',
            re.IGNORECASE,
        ),
        0.90,
    ),
    # Generic API key pattern: api_key=..., apikey=..., api-key: ...
    _CredentialPattern(
        CredentialType.GENERIC_API_KEY,
        re.compile(
            r'(?:api[_\-\s]*key|apikey|api[_\-\s]*secret|api[_\-\s]*token)\s*[=:]\s*'
            r'["\']?([A-Za-z0-9\-_]{16,})["\']?',
            re.IGNORECASE,
        ),
        0.85,
    ),
    # JWT token
    _CredentialPattern(
        CredentialType.JWT_TOKEN,
        re.compile(r'\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'),
        0.95,
    ),
    # Bearer token
    _CredentialPattern(
        CredentialType.BEARER_TOKEN,
        re.compile(
            r'(?:Bearer|Authorization[:\s]+Bearer)\s+([A-Za-z0-9\-_\.]{20,})',
            re.IGNORECASE,
        ),
        0.90,
    ),
    # Private key blocks (PEM format)
    _CredentialPattern(
        CredentialType.PRIVATE_KEY,
        re.compile(
            r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----'
            r'[\s\S]{10,}'
            r'-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
        ),
        0.99,
    ),
    # Connection strings: postgres://, mysql://, mongodb://, redis://
    _CredentialPattern(
        CredentialType.CONNECTION_STRING,
        re.compile(
            r'(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)'
            r'://[^\s"\'<>]{10,}',
            re.IGNORECASE,
        ),
        0.95,
    ),
]

# Credit card: Luhn-validated number patterns
_CC_RE = re.compile(
    r'\b(?:'
    r'4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'          # Visa
    r'|5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'    # Mastercard
    r'|3[47]\d{1}[\s\-]?\d{6}[\s\-]?\d{5}'                   # Amex
    r'|6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}' # Discover
    r')\b'
)


def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in re.sub(r'\D', '', number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class CredentialScanner:
    """Scans text for credential patterns including API keys, credit cards, and secrets."""

    def scan(self, text: str) -> list[PIIEntity]:
        """Scan text and return all detected credential entities."""
        entities: list[PIIEntity] = []

        # Named credential patterns
        for cp in _CREDENTIAL_PATTERNS:
            for m in cp.pattern.finditer(text):
                # Use first group if present, otherwise full match
                value = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group()
                start = m.start(1) if m.lastindex and m.lastindex >= 1 else m.start()
                end = m.end(1) if m.lastindex and m.lastindex >= 1 else m.end()
                entities.append(
                    PIIEntity(
                        entity_type=PIIType(cp.credential_type.value),
                        value=value,
                        start=start,
                        end=end,
                        confidence=cp.confidence,
                    )
                )

        # Credit card numbers with Luhn validation
        for m in _CC_RE.finditer(text):
            if _luhn_check(m.group()):
                entities.append(
                    PIIEntity(
                        entity_type=PIIType(CredentialType.CREDIT_CARD.value),
                        value=m.group(),
                        start=m.start(),
                        end=m.end(),
                        confidence=0.97,
                    )
                )

        return entities
