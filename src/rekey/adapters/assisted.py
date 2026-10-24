"""Assisted mode placeholder: the human creates the key, Rekey does the rest.

Lightweight by design. The key is read with getpass (no echo) directly into
a SecretValue. Never usable from MCP: it requires an interactive terminal.
"""

from __future__ import annotations

import getpass
import sys

from rekey.adapters.base import AdapterError, ProviderAdapter
from rekey.models import (
    KeySource, NewKey, RevokeOutcome, RevokeResult, RotationContext, VerifyResult,
)
from rekey.secrets import SecretValue


class AssistedAdapter(ProviderAdapter):
    """Wraps another adapter's verify_key; replaces create/revoke with prompts."""

    source = KeySource.ASSISTED

    def __init__(self, inner: ProviderAdapter, instructions: str = ""):
        self._inner = inner
        self.name = inner.name
        self._instructions = instructions

    def create_key(self, ctx: RotationContext) -> NewKey:
        if not sys.stdin.isatty():
            raise AdapterError("assisted mode needs an interactive terminal")
        print(self._instructions or f"Create a new {self.name} key in its dashboard (keep the old one active).")
        secret = SecretValue(getpass.getpass("Paste new key (hidden): ").strip())
        return NewKey(key_id=f"{self.name}-assisted:{secret.fingerprint}", secret=secret)

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        return self._inner.verify_key(secret)

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        return RevokeResult(RevokeOutcome.MANUAL, f"revoke old {self.name} key {key_id} in the dashboard")
