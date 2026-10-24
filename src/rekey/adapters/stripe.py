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
            raise AdapterError(
                f"Stripe CLI '{self._binary}' was not found on your system PATH.\n"
                "👉 To install: run 'brew install stripe/stripe-cli/stripe' (macOS) or visit https://docs.stripe.com/stripe-cli\n"
                "👉 Alternatively, use assisted mode in rekey.yaml: 'mode: assisted'"
            )

        # Step 1: Use --new-session so Stripe CLI always produces a clean, fresh device pairing code
        proc = subprocess.Popen(
            [self._binary, "login", "--non-interactive", "--new-session", "--project-name", profile],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        stdout, _ = proc.communicate()
        raw_output = stdout.strip()

        # Parse JSON output from Stripe CLI
        next_step_cmd = None
        browser_url = None
        user_code = None
        try:
            import json as _json
            start = raw_output.find("{")
            end = raw_output.rfind("}")
            if start != -1 and end != -1:
                data = _json.loads(raw_output[start:end + 1])
                browser_url = data.get("browser_url")
                user_code = data.get("verification_code")
                next_step_cmd = data.get("next_step")
        except Exception:
            pass

        if browser_url:
            self._echo("\n" + "=" * 54)
            self._echo("  \033[1;36m[Stripe] ACTION REQUIRED: Authorize in your browser\033[0m")
            self._echo("=" * 54)
            self._echo(f"  1. Go to:  \033[4m{browser_url}\033[0m")
            if user_code:
                self._echo(f"  2. Confirm code:  \033[1;32m{user_code}\033[0m")
            self._echo("=" * 54)
            self._echo("  (Waiting for your approval in Stripe Dashboard... Ctrl+C to cancel)\n")

            # Open browser automatically across platforms
            from rekey.platform_paths import open_browser_cross_platform
            open_browser_cross_platform(browser_url)

        # Step 2: If Stripe CLI gave a `next_step` polling command, run it to completion!
        if next_step_cmd:
            cmd_args = next_step_cmd.split()
            # Ensure project-name flag is forwarded
            if "--project-name" not in cmd_args:
                cmd_args.extend(["--project-name", profile])

            poll_proc = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            assert poll_proc.stdout is not None
            for line in poll_proc.stdout:
                line_str = line.rstrip()
                if line_str:
                    self._echo(f"  [stripe] {redact(line_str)}")
            if poll_proc.wait() != 0:
                raise AdapterError(f"`{next_step_cmd}` exited with code {poll_proc.returncode}")
        elif proc.returncode != 0:
            raise AdapterError(f"`stripe login` exited with code {proc.returncode}")

    def _read_key(self, profile: str, live: bool) -> tuple[SecretValue, str]:
        # 1. Try reading standard test_mode_api_key / live_mode_api_key from config.toml
        account_id = ""
        try:
            if self._config_path.exists():
                data = tomllib.loads(self._config_path.read_text())
                section = data.get(profile) or {}
                account_id = section.get("account_id", "")
                field = "live_mode_api_key" if live else "test_mode_api_key"
                raw = section.get(field)
                if raw:
                    return SecretValue(raw), account_id
        except Exception:
            pass

        # 2. In Stripe CLI v1.55+, credentials are saved in the system keyring under Service 'StripeCLI'
        try:
            import keyring
            uat = keyring.get_password("StripeCLI", "uat")
            if uat:
                return SecretValue(uat), account_id
        except Exception:
            pass

        raise AdapterError(
            f"stripe: could not find API key or session token for profile '{profile}'. "
            "Please run with assisted mode: 'mode: assisted'"
        )

    def create_key(self, ctx: RotationContext) -> NewKey:
        profile = ctx.provider_options.get("profile", "default")
        live = bool(ctx.provider_options.get("live_mode", False))

        # Check if Stripe CLI is installed on this system
        if not shutil.which(self._binary):
            if sys.stdin.isatty():
                self._echo(
                    f"\n\033[1;33m[Notice] Stripe CLI '{self._binary}' not found on PATH.\033[0m\n"
                    "Falling back seamlessly to Assisted Mode so you can rotate without installing it.\n"
                )
                from rekey.adapters.assisted import AssistedAdapter
                assisted = AssistedAdapter(self)
                return assisted.create_key(ctx)
            else:
                raise AdapterError(
                    f"Stripe CLI '{self._binary}' was not found on your system PATH.\n"
                    "👉 To install: run 'brew install stripe/stripe-cli/stripe' (macOS) or visit https://docs.stripe.com/stripe-cli\n"
                    "👉 Alternatively, set 'mode: assisted' in rekey.yaml"
                )

        self._run_login(profile)
        secret, account_id = self._read_key(profile, live)
        # Stripe CLI keys have no public id; use a fingerprint as a stable non-secret id.
        return NewKey(
            key_id=f"stripe-cli:{secret.fingerprint}",
            secret=secret,
            metadata={"profile": profile, "live_mode": live, "account_id": account_id},
        )

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        # Check balance (works for standard secret keys sk_...)
        raw = secret.reveal()
        r = self._client.get("https://api.stripe.com/v1/balance", auth=(raw, ""))
        if r.status_code == 200:
            return VerifyResult(ok=True, detail="GET /v1/balance -> 200 (Stripe key verified)")

        # If UAT (oak_...) token from CLI login, test via accounts or users endpoint
        if raw.startswith("oak_") or r.status_code in (401, 403):
            # Check if token can access account information
            r_acc = self._client.get("https://api.stripe.com/v1/accounts", auth=(raw, ""))
            if r_acc.status_code in (200, 400):  # 400 or 200 proves authentication succeeded
                return VerifyResult(ok=True, detail="GET /v1/accounts -> Authenticated (Stripe CLI session token verified)")

            # Check with /v1/account endpoint or specific account if available
            try:
                data = tomllib.loads(self._config_path.read_text())
                acct = data.get("default", {}).get("account_id")
                if acct:
                    r_spec = self._client.get(f"https://api.stripe.com/v1/accounts/{acct}", auth=(raw, ""))
                    if r_spec.status_code == 200:
                        return VerifyResult(ok=True, detail=f"GET /v1/accounts/{acct} -> 200 (Stripe session verified for {acct})")
            except Exception:
                pass

        if r.status_code == 401:
            hint = ""
            if raw.startswith("pk_"):
                hint = " (Note: You provided a Publishable Key 'pk_...'. Stripe destinations require a Secret Key 'sk_...' or Restricted Key 'rk_...')"
            elif not any(raw.startswith(p) for p in ("sk_", "rk_", "oak_")):
                hint = " (Note: Stripe secret keys must start with 'sk_live_', 'sk_test_', 'rk_live_', or 'rk_test_')"
            return VerifyResult(
                ok=False,
                detail=f"Authentication failed (401 Unauthorized): Invalid Stripe key.{hint}",
            )
        return VerifyResult(ok=False, detail=f"GET /v1/balance -> {r.status_code}: {redact(r.text)[:200]}")

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        return RevokeResult(
            RevokeOutcome.MANUAL,
            f"old CLI key {key_id} expires automatically; to revoke now use "
            "Dashboard > Developers > API keys",
        )
