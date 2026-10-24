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


# Provider-specific guidance and format prefixes
_PROVIDER_HINTS = {
    "openai": {
        "label": "OpenAI Application API Key",
        "format": "sk-proj-... or sk-...",
        "prefix": ("sk-proj-", "sk-svcacct-", "sk-"),
        "where": "platform.openai.com -> Project Settings -> API Keys",
        "warning": "Do not paste an Admin key ('sk-admin-...'). Use a project key that applications use.",
    },
    "stripe": {
        "label": "Stripe Secret / Restricted Key",
        "format": "sk_live_..., rk_live_... (or test equivalent)",
        "prefix": ("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
        "where": "dashboard.stripe.com -> Developers -> API keys",
        "warning": "Ensure the key has necessary permissions for your destinations.",
    },
    "github": {
        "label": "GitHub Personal Access Token (PAT)",
        "format": "ghp_..., github_pat_...",
        "prefix": ("ghp_", "gho_", "github_pat_"),
        "where": "github.com/settings/tokens",
        "warning": "Ensure the token has repo/workflow scopes as needed.",
    },
}


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

        info = _PROVIDER_HINTS.get(self.name, {})
        label = info.get("label", f"{self.name} API Key")
        expected_fmt = info.get("format", "")
        where = info.get("where", f"{self.name} dashboard")
        warning = info.get("warning", "")

        print(f"\n\033[1;36m=== Assisted Mode: Rotate {self.name.upper()} Key ===\033[0m")
        print(f"Target requires: \033[1m{label}\033[0m")
        if expected_fmt:
            print(f"Expected format: \033[33m{expected_fmt}\033[0m")
        print(f"Where to get it: {where}")
        if warning:
            print(f"\033[33mNotice: {warning}\033[0m")
        print(f"--------------------------------------------------")

        while True:
            prompt = f"Paste new {label} (hidden): "
            try:
                raw = getpass.getpass(prompt).strip()
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                sys.exit(1)

            if not raw:
                print("\033[31mError: Key cannot be empty. Please try again.\033[0m")
                continue

            # Format check
            prefixes = info.get("prefix")
            if prefixes and not any(raw.startswith(p) for p in prefixes):
                if raw.startswith("sk-admin-"):
                    print(
                        f"\033[31mError: You pasted an Admin Key ('{raw[:8]}...'). This destination requires an application key ('{expected_fmt}').\033[0m"
                    )
                else:
                    print(
                        f"\033[31mWarning: Key '{raw[:6]}...' does not match typical format '{expected_fmt}'.\033[0m"
                    )
                retry = input("Proceed anyway? [y/N]: ").strip().lower()
                if retry not in ("y", "yes"):
                    continue

            secret = SecretValue(raw)
            print("✓ Key captured successfully\n")
            return NewKey(key_id=f"{self.name}-assisted:{secret.fingerprint}", secret=secret)

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        return self._inner.verify_key(secret)

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        return RevokeResult(
            RevokeOutcome.MANUAL,
            f"Assisted mode: please revoke old {self.name} key ({key_id}) in the {self.name} dashboard",
        )
