"""SecretValue: a wrapper that refuses to reveal itself by accident.

SECURITY: str()/repr()/format() all return a masked form, so a stray print,
f-string, log call, or exception message can never leak the raw value.
The only way to get the plaintext is the explicit `.reveal()` call, which
should be used solely at the exact point of handing the value to an HTTP
client or a destination writer.
"""

from __future__ import annotations

import hashlib
import re


class SecretValue:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not value:
            raise ValueError("SecretValue cannot be empty")
        self._value = value

    def reveal(self) -> str:
        """Return plaintext. Call only when sending to a provider/destination."""
        return self._value

    @property
    def masked(self) -> str:
        v = self._value
        prefix = v[:4] if len(v) > 12 else ""
        return f"{prefix}…{v[-4:]}" if len(v) > 8 else "****"

    @property
    def fingerprint(self) -> str:
        """Short non-reversible id, safe to show agents/logs for correlation."""
        return hashlib.sha256(self._value.encode()).hexdigest()[:12]

    def __str__(self) -> str:
        return self.masked

    __repr__ = lambda self: f"SecretValue({self.masked})"  # noqa: E731

    def __format__(self, spec: str) -> str:
        return self.masked

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SecretValue) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    def __reduce__(self):  # block pickling to disk/caches
        raise TypeError("SecretValue cannot be pickled")


# Patterns of well-known key formats; used to scrub any untrusted text
# (subprocess output, provider error bodies) before it is displayed.
_SECRET_PATTERNS = [
    re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}\b"),  # Stripe
    re.compile(r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}\b"),  # OpenAI
    re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}\b"),  # GitHub
    re.compile(r"(?i)(api[_-]?key|token|secret)(\"?\s*[:=]\s*\"?)[^\s\"']{8,}"),
]


def redact(text: str) -> str:
    """Replace anything that looks like a credential with [REDACTED]."""
    for pat in _SECRET_PATTERNS:
        if pat.groups >= 2 and pat.pattern.startswith("(?i)"):
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        else:
            text = pat.sub("[REDACTED]", text)
    return text
