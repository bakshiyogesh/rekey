"""GitHub adapter — API mode via a GitHub App.

GitHub has no API to create PATs. A GitHub App can, however, mint short-lived
installation tokens fully automatically:
  create  -> sign JWT with App private key, POST /app/installations/{id}/access_tokens
  verify  -> GET /installation/repositories (with the new token)
  revoke  -> no-op: installation tokens expire after 1 hour by design.

The App private key is read from a file path given via env var
(default GITHUB_APP_PRIVATE_KEY_PATH); it is never placed in config.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
import jwt

from rekey.adapters.base import AdapterError, ProviderAdapter
from rekey.models import (
    KeySource, NewKey, RevokeOutcome, RevokeResult, RotationContext, VerifyResult,
)
from rekey.secrets import SecretValue, redact

API = "https://api.github.com"
_HDRS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class GitHubAppAdapter(ProviderAdapter):
    name = "github"
    source = KeySource.API

    def __init__(self, key_path_env: str = "GITHUB_APP_PRIVATE_KEY_PATH", client: httpx.Client | None = None):
        self._key_path_env = key_path_env
        self._client = client or httpx.Client(timeout=20)

    def _app_jwt(self, app_id: str) -> str:
        path = os.environ.get(self._key_path_env)
        if not path:
            raise AdapterError(f"env var {self._key_path_env} is not set")
        now = int(time.time())
        # SECURITY: JWT valid for <10 min, backdated 60s for clock skew.
        payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
        return jwt.encode(payload, Path(path).read_text(), algorithm="RS256")

    def create_key(self, ctx: RotationContext) -> NewKey:
        opts = ctx.provider_options
        app_id, inst = str(opts.get("app_id", "")), str(opts.get("installation_id", ""))
        if not app_id or not inst:
            raise AdapterError("github: provider.app_id and provider.installation_id are required")
        body: dict = {}
        if opts.get("repositories"):
            body["repositories"] = opts["repositories"]   # scope down when possible
        if opts.get("permissions"):
            body["permissions"] = opts["permissions"]
        r = self._client.post(
            f"{API}/app/installations/{inst}/access_tokens",
            headers={**_HDRS, "Authorization": f"Bearer {self._app_jwt(app_id)}"}, json=body,
        )
        if r.status_code >= 300:
            raise AdapterError(f"github create failed ({r.status_code}): {redact(r.text)[:300]}")
        data = r.json()
        secret = SecretValue(data.pop("token"))
        expires = data.get("expires_at", "")
        return NewKey(key_id=f"installation-token@{expires}", secret=secret, metadata={"expires_at": expires})

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        r = self._client.get(
            f"{API}/installation/repositories",
            headers={**_HDRS, "Authorization": f"Bearer {secret.reveal()}"}, params={"per_page": 1},
        )
        return VerifyResult(ok=r.status_code == 200, detail=f"GET /installation/repositories -> {r.status_code}")

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        return RevokeResult(RevokeOutcome.WILL_EXPIRE, "installation tokens expire within 1 hour")
