"""Provider adapter interface.

Every adapter implements exactly three operations: create_key, verify_key,
revoke_key. The `source` attribute declares HOW create/revoke happen
(API, CLI, or ASSISTED); the orchestrator treats all modes identically.

Adapters must never log or return raw secrets: new keys are always wrapped
in SecretValue, and any provider error text is passed through `redact()`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from rekey.models import KeySource, NewKey, RevokeResult, RotationContext, VerifyResult
from rekey.secrets import SecretValue


class AdapterError(RuntimeError):
    """Raised for provider failures. Messages must already be redacted."""


class ProviderAdapter(ABC):
    name: str
    source: KeySource

    @abstractmethod
    def create_key(self, ctx: RotationContext) -> NewKey:
        """Create a NEW key. The old key must remain valid (overlap window)."""

    @abstractmethod
    def verify_key(self, secret: SecretValue) -> VerifyResult:
        """Make a cheap, read-only call proving the key works."""

    @abstractmethod
    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        """Revoke the OLD key. Only called after destinations + verify succeed."""
