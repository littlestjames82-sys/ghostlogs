"""Secret-shape redaction for emitted log excerpts.

Shape names follow GhostSlice's secret guard naming so a redaction
reads the same way across the suite. A matched value is replaced with
a typed placeholder, for example [REDACTED:aws-access-key]. The value
itself is never returned, printed, or stored by this module: callers
get the redacted text plus the list of shape names that hit.

Deliberately conservative, same posture as the Slice guard: known
provider shapes match on sight; generic assignments only when the
name looks sensitive AND the value is long, varied, and not an
obvious placeholder.
"""
from __future__ import annotations

import re

_KNOWN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai-or-anthropic-key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]

_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._\-]{10,}")
_URL_PASSWORD_RE = re.compile(r"(://[^/\s:@'\"]+:)([^/\s:@'\"]{3,})@")
_SENSITIVE_NAME_RE = re.compile(
    r"(key|token|secret|password|passwd|pwd|credential|auth|private)",
    re.IGNORECASE)
# NAME = value / NAME: value, quoted or bare. Groups: 1=head incl name
# and separator, 2=opening quote, 3=value.
_ASSIGN_RE = re.compile(
    r"""((?:export\s+)?["']?[A-Za-z_][A-Za-z0-9_.\-]*["']?\s*[:=]\s*)(["']?)([^\s"',;#]{8,})""")

PLACEHOLDER_MARKERS = (
    "example", "xxx", "your-", "your_", "yourkey", "placeholder",
    "changeme", "change-me", "change_me", "dummy", "sample", "fixture",
    "redacted", "insert-", "insert_", "todo", "fake", "test-key",
    "test_key", "not-a-real", "not_real", "mock", "none", "null",
)


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    if any(marker in low for marker in PLACEHOLDER_MARKERS):
        return True
    if value.startswith("<") or value.startswith("${") or value.startswith("$"):
        return True
    if set(value) <= set("*.xX-"):
        return True
    return False


def redact_line(text: str) -> tuple[str, list[str]]:
    """Return (redacted_text, shape_names_hit). Value never returned."""
    hits: list[str] = []
    out = text
    for shape, pattern in _KNOWN_PATTERNS:
        out, n = pattern.subn(f"[REDACTED:{shape}]", out)
        if n:
            hits.extend([shape] * n)
    out, n = _BEARER_RE.subn(r"\1[REDACTED:bearer-token]", out)
    if n:
        hits.extend(["bearer-token"] * n)
    out, n = _URL_PASSWORD_RE.subn(r"\1[REDACTED:url-password]@", out)
    if n:
        hits.extend(["url-password"] * n)

    def _assign_sub(m: re.Match) -> str:
        head, quote, value = m.group(1), m.group(2), m.group(3)
        if not _SENSITIVE_NAME_RE.search(head):
            return m.group(0)
        if _looks_placeholder(value):
            return m.group(0)
        if len(set(value)) < 4:
            return m.group(0)
        hits.append("generic-assignment")
        return f"{head}{quote}[REDACTED:generic-assignment]"

    out = _ASSIGN_RE.sub(_assign_sub, out)
    return out, hits
