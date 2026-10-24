"""Adapter registry: builds an adapter from (provider, mode) config."""

from __future__ import annotations

from typing import Any

from rekey.adapters.assisted import AssistedAdapter
from rekey.adapters.base import AdapterError, ProviderAdapter
from rekey.adapters.github import GitHubAppAdapter
from rekey.adapters.github_oauth import GitHubOAuthAdapter
from rekey.adapters.openai import OpenAIAdapter
from rekey.adapters.stripe import StripeCLIAdapter

# provider -> {mode -> factory}. Modes listed in priority order.
_REGISTRY: dict[str, dict[str, Any]] = {
    "openai": {"api": lambda o: OpenAIAdapter(o.get("admin_key_env", "OPENAI_ADMIN_KEY"))},
    "github": {
        "api": lambda o: GitHubAppAdapter(o.get("private_key_path_env", "GITHUB_APP_PRIVATE_KEY_PATH")),
        "oauth": lambda o: GitHubOAuthAdapter(
            client_id=o.get("client_id"),
            scopes=o.get("scopes", ["repo"]),
        ),
    },
    "stripe": {"cli": lambda o: StripeCLIAdapter(o.get("binary", "stripe"))},
}


def build_adapter(provider: str, mode: str | None, options: dict[str, Any]) -> ProviderAdapter:
    modes = _REGISTRY.get(provider)
    if not modes:
        raise AdapterError(f"unknown provider '{provider}'")
    if mode == "assisted":
        base = next(iter(modes.values()))(options)  # reuse its verify_key
        return AssistedAdapter(base, options.get("instructions", ""))
    mode = mode or next(iter(modes))  # default = highest-priority mode
    if mode not in modes:
        raise AdapterError(f"provider '{provider}' does not support mode '{mode}' (has: {list(modes)} + assisted)")
    return modes[mode](options)
