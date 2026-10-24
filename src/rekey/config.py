"""Config loading.

The YAML config holds ONLY non-secret settings: which provider, which mode,
which destinations. Credentials are referenced by env var NAME
(e.g. admin_key_env: OPENAI_ADMIN_KEY), never inlined.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rekey.secrets import redact

DEFAULT_CONFIG = "rekey.yaml"


@dataclass
class TargetConfig:
    name: str
    provider: str
    mode: str | None
    provider_options: dict[str, Any]
    destinations: list[dict[str, Any]]


@dataclass
class Config:
    targets: dict[str, TargetConfig]
    state_file: Path = field(default=Path(".rekey/state.json"))


def find_config_file(path: str | Path | None = None) -> Path:
    """Find config file, checking current dir, parent dirs, and common alternatives."""
    if path and path != DEFAULT_CONFIG:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Config file not found at '{p}'.")
        return p

    # Default search: walk up from current working directory
    candidates = ["rekey.yaml", "rekey.yml"]
    current = Path.cwd().resolve()
    for directory in [current, *current.parents]:
        for candidate in candidates:
            cfg = directory / candidate
            if cfg.is_file():
                return cfg

    # Fallback to current directory default
    return Path(DEFAULT_CONFIG).resolve()


def load_config(path: str | Path = DEFAULT_CONFIG) -> Config:
    p = find_config_file(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config file '{path}' not found.\n"
            "👉 To create one: run 'cp rekey.example.yaml rekey.yaml'\n"
            "👉 Or specify a path: 'rekey -c <path>' or set REKEY_CONFIG=<path>"
        )

    content = p.read_text()
    if not content.strip():
        raise ValueError(f"Config file '{p}' is empty. Define targets under 'targets:'.")

    raw = yaml.safe_load(content) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Config file '{p}' must be a YAML mapping.")

    _reject_inline_secrets(json.dumps(raw))
    targets_dict = raw.get("targets")
    if not targets_dict or not isinstance(targets_dict, dict):
        raise ValueError(f"No targets found in '{p}'. Define at least one target under 'targets:'.")

    targets = {}
    for name, t in targets_dict.items():
        if not isinstance(t, dict):
            raise ValueError(f"Target '{name}' must be a mapping in '{p}'")
        prov = dict(t.get("provider") or {})
        ptype = prov.pop("type", None)
        if not ptype:
            raise ValueError(f"Target '{name}': provider.type is required")
        targets[name] = TargetConfig(
            name=name, provider=ptype, mode=prov.pop("mode", None),
            provider_options=prov, destinations=list(t.get("destinations") or []),
        )

    state = Path(raw.get("state_file", ".rekey/state.json"))
    if not state.is_absolute():
        state = p.parent / state
    return Config(targets=targets, state_file=state)


def _reject_inline_secrets(text: str) -> None:
    # SECURITY: refuse configs that appear to contain real credentials.
    if redact(text) != text:
        raise ValueError("config appears to contain a secret value; reference env var names instead")
