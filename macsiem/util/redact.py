"""Secret scrubbing for probe output.

A 360-degree sweep reads configuration, keychain metadata, logs and browser
databases.  Some of that will contain credentials.  Redaction runs on probe
output before it is written to a bundle, and what was redacted is recorded in
the manifest so an analyst knows something was removed rather than missing.

This is defence in depth, not a guarantee: a bundle is still sensitive and is
written 0700 regardless.
"""

from __future__ import annotations

import re

_PATTERNS = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.S)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AIDA|AGPA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abpsr]-[A-Za-z0-9-]{10,}\b")),
    ("bearer", re.compile(
        r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._\-+/=]{12,})")),
    ("password_kv", re.compile(
        r"(?i)\b(passwo?r?d|passwd|secret|api[_-]?key|token)\b(\s*[:=]\s*)"
        r"(\"[^\"]{3,}\"|'[^']{3,}'|[^\s,;}\]]{3,})")),
    ("keychain_data", re.compile(r'(?m)^(password:\s*)(".*")$')),
]


def redact(text, enabled=True):
    """Return ``(text, findings)`` where findings maps pattern name -> count."""
    if not enabled or not text:
        return text, {}
    findings = {}
    for name, pattern in _PATTERNS:
        if name in ("bearer", "password_kv", "keychain_data"):
            def _keep_key(match, _name=name):
                groups = match.groups()
                head = "".join(g for g in groups[:-1] if g)
                return head + "[REDACTED:%s]" % _name
            text, count = pattern.subn(_keep_key, text)
        else:
            text, count = pattern.subn("[REDACTED:%s]" % name, text)
        if count:
            findings[name] = findings.get(name, 0) + count
    return text, findings
