"""GitHub adapter — OAuth mode (RFC 8628 Device Authorization Grant).

Supports:
- Initial device authentication flow (opens browser / prompts user_code)
- Storing access & refresh tokens securely (mode 0600)
- Minting / refreshing tokens for rotation
- Verifying the token via GET /user
- Revoking old OAuth tokens on completion
"""

from __future__ import annotations

import os
import sys
import time
import webbrowser
from typing import Any, Callable

import httpx

from rekey.adapters.base import AdapterError, ProviderAdapter
from rekey.models import (
    KeySource,
    NewKey,
    RevokeOutcome,
    RevokeResult,
    RotationContext,
    VerifyResult,
)
from rekey.oauth_store import OAuthTokenStore
from rekey.secrets import SecretValue, redact

GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"
_HDRS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class GitHubOAuthAdapter(ProviderAdapter):
    name = "github"
    source = KeySource.OAUTH

    def __init__(
        self,
        client_id: str | None = None,
        scopes: list[str] | None = None,
        store: OAuthTokenStore | None = None,
        client: httpx.Client | None = None,
        echo: Callable[[str], None] | None = None,
    ) -> None:
        self._client_id = client_id
        self._scopes = scopes or ["repo"]
        self._store = store or OAuthTokenStore()
        self._client = client or httpx.Client(timeout=20)
        self._echo = echo or (lambda m: print(m, file=sys.stderr))

    def _get_client_id(self, ctx: RotationContext) -> str:
        cid = self._client_id or ctx.provider_options.get("client_id") or os.environ.get("GITHUB_OAUTH_CLIENT_ID")
        if not cid or "XXXX" in str(cid):
            from rekey.credentials import resolve_credential
            cid = resolve_credential(
                "GITHUB_OAUTH_CLIENT_ID",
                prompt_label="GitHub OAuth App Client ID (e.g. Ov23li...)",
                hidden=False,
                hint="github.com/settings/developers -> OAuth Apps -> Client ID",
            )
        if not cid:
            raise AdapterError(
                "github oauth: provider.client_id or GITHUB_OAUTH_CLIENT_ID is required"
            )
        return str(cid)

    def _authenticate_device_flow(self, client_id: str, scopes: list[str]) -> SecretValue:
        """Run RFC 8628 Device Authorization Grant."""
        scope_str = " ".join(scopes)
        resp = self._client.post(
            GITHUB_DEVICE_CODE_URL,
            headers={"Accept": "application/json"},
            data={"client_id": client_id, "scope": scope_str},
        )
        if resp.status_code >= 300:
            raise AdapterError(f"device code request failed ({resp.status_code}): {redact(resp.text)}")

        data = resp.json()
        device_code = data.get("device_code")
        user_code = data.get("user_code")
        verification_uri = data.get("verification_uri") or "https://github.com/login/device"
        expires_in = int(data.get("expires_in", 900))
        interval = int(data.get("interval", 5))

        self._echo("\n[OAuth] Complete authentication in your browser:")
        self._echo(f"  URL:  {verification_uri}")
        self._echo(f"  Code: {user_code}\n")

        # Attempt to open the verification URL in browser if interactive
        try:
            webbrowser.open(verification_uri)
        except Exception:
            pass

        # Poll for user approval
        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(interval)
            poll_resp = self._client.post(
                GITHUB_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": client_id,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )
            if poll_resp.status_code >= 300:
                continue

            res_json = poll_resp.json()
            err = res_json.get("error")
            if not err and "access_token" in res_json:
                secret = SecretValue(res_json["access_token"])
                refresh = SecretValue(res_json["refresh_token"]) if "refresh_token" in res_json else None
                expires_at = int(time.time()) + int(res_json.get("expires_in", 28800))
                self._store.save_token(
                    provider="github",
                    client_id=client_id,
                    access_token=secret,
                    refresh_token=refresh,
                    expires_at=expires_at,
                    scope=scope_str,
                )
                self._echo("[OAuth] Authentication successful!")
                return secret

            if err == "authorization_pending":
                continue
            elif err == "slow_down":
                interval += 5
            else:
                desc = res_json.get("error_description", err)
                raise AdapterError(f"OAuth error: {desc}")

        raise AdapterError("OAuth device flow authorization timed out")

    def _refresh_or_reauth(self, client_id: str, ctx: RotationContext) -> SecretValue:
        """Fetch existing token from store or trigger device flow."""
        token_entry = self._store.get_token("github", client_id)
        if token_entry and token_entry.get("access_token"):
            now = int(time.time())
            expires_at = token_entry.get("expires_at")
            # If not expired or no expiration, verify it
            if not expires_at or expires_at > (now + 60):
                cached = SecretValue(token_entry["access_token"])
                v = self.verify_key(cached)
                if v.ok:
                    # Token is still valid; to rotate, re-authenticate or refresh
                    if not ctx.dry_run and ctx.provider_options.get("force_reauth", True):
                        return self._authenticate_device_flow(client_id, self._scopes)
                    return cached

            # If refresh token exists, attempt refresh
            if token_entry.get("refresh_token"):
                r_resp = self._client.post(
                    GITHUB_TOKEN_URL,
                    headers={"Accept": "application/json"},
                    data={
                        "client_id": client_id,
                        "grant_type": "refresh_token",
                        "refresh_token": token_entry["refresh_token"],
                    },
                )
                if r_resp.status_code == 200:
                    r_data = r_resp.json()
                    if "access_token" in r_data:
                        sec = SecretValue(r_data["access_token"])
                        ref = SecretValue(r_data["refresh_token"]) if "refresh_token" in r_data else None
                        exp = int(time.time()) + int(r_data.get("expires_in", 28800))
                        self._store.save_token("github", client_id, sec, ref, exp, self._scopes[0])
                        return sec

        # If no valid token or refresh failed, prompt device authentication
        return self._authenticate_device_flow(client_id, self._scopes)

    def create_key(self, ctx: RotationContext) -> NewKey:
        client_id = self._get_client_id(ctx)
        secret = self._refresh_or_reauth(client_id, ctx)
        return NewKey(
            key_id=f"gh-oauth:{secret.fingerprint}",
            secret=secret,
            metadata={"client_id": client_id, "source": "oauth"},
        )

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        r = self._client.get(
            f"{GITHUB_API_URL}/user",
            headers={**_HDRS, "Authorization": f"Bearer {secret.reveal()}"},
        )
        return VerifyResult(
            ok=r.status_code == 200,
            detail=f"GET /user -> {r.status_code} ({r.json().get('login', 'unknown') if r.status_code == 200 else 'unauthorized'})",
        )

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        """Revoke OAuth token grant or let old token expire."""
        client_id = self._get_client_id(ctx)
        token_entry = self._store.get_token("github", client_id)
        if token_entry and token_entry.get("access_token"):
            # Attempt to revoke token if client credentials available
            client_secret = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET")
            if client_secret:
                r = self._client.request(
                    "DELETE",
                    f"{GITHUB_API_URL}/applications/{client_id}/grant",
                    auth=(client_id, client_secret),
                    json={"access_token": token_entry["access_token"]},
                )
                if r.status_code in (204, 404):
                    self._store.clear_token("github", client_id)
                    return RevokeResult(RevokeOutcome.REVOKED, f"revoked OAuth grant for {key_id}")

        return RevokeResult(
            RevokeOutcome.WILL_EXPIRE,
            f"token {key_id} rotated; previous session will expire or can be revoked at github.com/settings/applications",
        )
