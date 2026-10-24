"""Stripe adapter — CLI mode (proof of concept).

Stripe exposes no API for creating secret/restricted keys, so API mode is not
possible. Instead we drive the official Stripe CLI:
  create  -> `stripe login` (one browser approval) mints new restricted keys
             and stores them in the CLI config file; we read the key from that
             file straight into a SecretValue.
  verify  -> GET https://api.stripe.com/v1/balance (with the new key)
  revoke  -> Stripe CLI keys expire on their own (~90 days); an older pairing
             can be removed in Dashboard > Developers > API keys.

SECURITY:
  * Subprocess output is streamed line-by-line through `redact()` before it is
    shown, so the user still sees the pairing URL/code but never a key.
  * We never call `stripe config --list` (it prints keys).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import httpx

from rekey.adapters.base import AdapterError, ProviderAdapter
from rekey.models import (
    KeySource, NewKey, RevokeOutcome, RevokeResult, RotationContext, VerifyResult,
)
from rekey.platform_paths import get_stripe_config_path
from rekey.secrets import SecretValue, redact


def _default_config_path() -> Path:
    return get_stripe_config_path()


class StripeCLIAdapter(ProviderAdapter):
    name = "stripe"
    source = KeySource.CLI

    def __init__(self, binary: str = "stripe", config_path: Path | None = None,
                 client: httpx.Client | None = None, echo=None):
        self._binary = binary
        self._config_path = config_path or _default_config_path()
        self._client = client or httpx.Client(timeout=20)
        # Receives ONLY redacted lines. stderr keeps MCP's stdio transport clean.
        self._echo = echo or (lambda m: print(m, file=sys.stderr))

    def _run_login(self, profile: str) -> None:
        if not shutil.which(self._binary):
            raise AdapterError(f"stripe CLI '{self._binary}' not found on PATH")
        proc = subprocess.Popen(
            [self._binary, "login", "--project-name", profile],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            # SECURITY: never echo raw subprocess output.
            self._echo(f"  [stripe] {redact(line.rstrip())}")
        if proc.wait() != 0:
            raise AdapterError(f"`stripe login` exited with code {proc.returncode}")

    def _read_key(self, profile: str, live: bool) -> SecretValue:
        try:
            data = tomllib.loads(self._config_path.read_text())
        except FileNotFoundError as e:
            raise AdapterError(f"stripe config not found at {self._config_path}") from e
        section = data.get(profile) or {}
        field = "live_mode_api_key" if live else "test_mode_api_key"
        raw = section.get(field)
        if not raw:
            raise AdapterError(
                f"stripe: '{field}' not in profile '{profile}' "
                "(newer CLI versions may store keys in the OS keyring; use assisted mode)"
            )
        return SecretValue(raw)

    def create_key(self, ctx: RotationContext) -> NewKey:
        profile = ctx.provider_options.get("profile", "default")
        live = bool(ctx.provider_options.get("live_mode", False))
        self._run_login(profile)
        secret = self._read_key(profile, live)
        # Stripe CLI keys have no public id; use a fingerprint as a stable non-secret id.
        return NewKey(key_id=f"stripe-cli:{secret.fingerprint}", secret=secret,
                      metadata={"profile": profile, "live_mode": live})

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        r = self._client.get("https://api.stripe.com/v1/balance", auth=(secret.reveal(), ""))
        return VerifyResult(ok=r.status_code == 200, detail=f"GET /v1/balance -> {r.status_code}")

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        return RevokeResult(
            RevokeOutcome.MANUAL,
            f"old CLI key {key_id} expires automatically; to revoke now use "
            "Dashboard > Developers > API keys",
        )
