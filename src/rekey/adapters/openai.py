"""OpenAI adapter — API mode.

OpenAI's Admin API cannot mint plain project API keys, but creating a
*project service account* returns a fresh API key. So:
  create  -> POST   /v1/organization/projects/{project}/service_accounts
  verify  -> GET    /v1/models  (with the new key)
  revoke  -> DELETE /v1/organization/projects/{project}/service_accounts/{id}

key_id == service account id. Requires an Admin key, read from the env var
named in config (default OPENAI_ADMIN_KEY) — never from the config file itself.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx

from rekey.adapters.base import AdapterError, ProviderAdapter
from rekey.models import (
    KeySource, NewKey, RevokeOutcome, RevokeResult, RotationContext, VerifyResult,
)
from rekey.secrets import SecretValue, redact

API = "https://api.openai.com/v1"


class OpenAIAdapter(ProviderAdapter):
    name = "openai"
    source = KeySource.API

    def __init__(self, admin_key_env: str = "OPENAI_ADMIN_KEY", client: httpx.Client | None = None):
        self._admin_key_env = admin_key_env
        self._client = client or httpx.Client(timeout=20)

    def _admin_headers(self) -> dict[str, str]:
        from rekey.credentials import resolve_credential
        key = resolve_credential(self._admin_key_env, prompt_label="OpenAI Admin Key (sk-admin-...)")
        return {"Authorization": f"Bearer {key}"}

    @staticmethod
    def _project(ctx: RotationContext) -> str:
        project = ctx.provider_options.get("project_id")
        if not project:
            raise AdapterError("openai: provider.project_id is required")
        return project

    def create_key(self, ctx: RotationContext) -> NewKey:
        project = self._project(ctx)
        prefix = ctx.provider_options.get("name_prefix", "rekey")
        name = f"{prefix}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
        r = self._client.post(
            f"{API}/organization/projects/{project}/service_accounts",
            headers=self._admin_headers(), json={"name": name},
        )
        if r.status_code >= 300:
            raise AdapterError(f"openai create failed ({r.status_code}): {redact(r.text)[:300]}")
        body = r.json()
        try:
            secret = SecretValue(body["api_key"]["value"])  # wrap immediately
        except (KeyError, TypeError, ValueError) as e:
            raise AdapterError("openai create: response missing api_key.value") from e
        finally:
            body.pop("api_key", None)  # drop plaintext reference from the dict
        return NewKey(key_id=body["id"], secret=secret, metadata={"name": name})

    def verify_key(self, secret: SecretValue) -> VerifyResult:
        r = self._client.get(f"{API}/models", headers={"Authorization": f"Bearer {secret.reveal()}"})
        return VerifyResult(ok=r.status_code == 200, detail=f"GET /models -> {r.status_code}")

    def revoke_key(self, key_id: str, ctx: RotationContext) -> RevokeResult:
        project = self._project(ctx)
        r = self._client.delete(
            f"{API}/organization/projects/{project}/service_accounts/{key_id}",
            headers=self._admin_headers(),
        )
        if r.status_code == 404:
            return RevokeResult(RevokeOutcome.NOTHING_TO_REVOKE, "service account already gone")
        if r.status_code >= 300:
            raise AdapterError(f"openai revoke failed ({r.status_code}): {redact(r.text)[:300]}")
        return RevokeResult(RevokeOutcome.REVOKED, f"deleted service account {key_id}")
