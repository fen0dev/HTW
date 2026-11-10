"""Best-effort redaction of secret-looking text.

The primary control is structural: scanner fields that carry secret values or source
snippets are never read into a finding. This module is the second line of defence for
free text such as scanner messages, which can interpolate matched code.
"""

from __future__ import annotations

import math
import re
from collections import Counter

REDACTED = "[REDACTED]"

_PATTERNS = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    ),
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s:@]+(?=@)"),
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([\w.-]*(?:passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|credential)[\w.-]*"
    r"""\s*[:=]\s*)(['"]?)([^\s'",;]{6,})(['"]?)"""
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def _looks_secret(token: str) -> bool:
    if _HEX_RE.match(token):
        # Long hex strings in scanner messages are far more often digests than keys.
        return False
    has_classes = (
        any(c.isdigit() for c in token)
        and any(c.islower() for c in token)
        and any(c.isupper() for c in token)
    )
    return has_classes and "/" not in token.strip("/") and _entropy(token) >= 4.5


def _mask_assignment(match: re.Match[str]) -> str:
    value = match.group(3)
    # Scanner messages are prose ("password: consider using a vault"); only mask values
    # that do not read like an ordinary word.
    wordlike = value.isalpha() and (value.islower() or value.istitle() or len(value) < 12)
    if wordlike or value == REDACTED:
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(4)}"


def redact_text(text: str) -> str:
    """Mask credentials and credential-like tokens in free text."""
    if not text:
        return text
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _ASSIGNMENT_RE.sub(_mask_assignment, text)
    return _TOKEN_RE.sub(lambda m: REDACTED if _looks_secret(m.group(0)) else m.group(0), text)


def clean_text(text: object, limit: int = 600) -> str:
    """Normalize scanner-supplied text: single line, redacted, bounded length."""
    cleaned = " ".join(str(text or "").split())
    cleaned = redact_text(cleaned)
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned
