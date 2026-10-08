"""Minimização LGPD: remove credenciais e identificadores pessoais dos dados sintéticos."""

from __future__ import annotations

import hashlib
import re
from typing import Any

EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_TEXT_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*\S+"
)
SENSITIVE_KEY_RE = re.compile(
    r"(?i)pass|secret|token|api[_-]?key|auth|cookie|session|credential|private"
)


def alias(kind: str, value: str) -> str:
    text = (value or "").strip()
    if not text or text.lower() in {"nan", "none", "-"}:
        return ""
    digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:6]
    return f"{kind}-{digest}"


def redact_text(value: Any) -> str:
    text = str(value or "")
    text = SECRET_TEXT_RE.sub("[credencial-omitida]", text)
    text = EMAIL_RE.sub("[e-mail-omitido]", text)
    text = IPV4_RE.sub("[endereço-interno]", text)
    return text[:240]


def drop_sensitive_fields(row: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in row.items():
        if SENSITIVE_KEY_RE.search(str(key)):
            continue
        clean[str(key)] = redact_text(value)
    return clean
