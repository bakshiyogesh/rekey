"""Typed data passed between orchestrator, adapters, and destinations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rekey.secrets import SecretValue


class KeySource(str, Enum):
    """How a key is created/revoked. Priority: API > CLI > OAUTH > ASSISTED."""

    API = "api"
    CLI = "cli"
    OAUTH = "oauth"
    ASSISTED = "assisted"


class RevokeOutcome(str, Enum):
    REVOKED = "revoked"
    WILL_EXPIRE = "will_expire"   # provider expires it on its own (e.g. 1h tokens)
    MANUAL = "manual"             # user must revoke in a dashboard
    NOTHING_TO_REVOKE = "nothing_to_revoke"


@dataclass
class NewKey:
    key_id: str                    # non-secret provider identifier
    secret: SecretValue
    metadata: dict[str, Any] = field(default_factory=dict)  # non-secret only


@dataclass
class VerifyResult:
    ok: bool
    detail: str = ""


@dataclass
class RevokeResult:
    outcome: RevokeOutcome
    detail: str = ""


@dataclass
class UpdateResult:
    destination: str
    ok: bool
    dry_run: bool
    detail: str = ""


@dataclass
class RotationContext:
    target: str                    # name of the rotation target in config
    provider_options: dict[str, Any]
    dry_run: bool
