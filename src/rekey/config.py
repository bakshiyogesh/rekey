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


def load_config(path: str | Path = DEFAULT_CONFIG) -> Config:
    p = Path(path)
    raw = yaml.safe_load(p.read_text()) or {}
    _reject_inline_secrets(json.dumps(raw))
    targets = {}
    for name, t in (raw.get("targets") or {}).items():
        prov = dict(t.get("provider") or {})
        ptype = prov.pop("type", None)
        if not ptype:
            raise ValueError(f"target '{name}': provider.type is required")
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
