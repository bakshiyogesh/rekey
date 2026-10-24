"""GitHub Actions repository secret destination.

Flow (GitHub REST API):
  1. GET  /repos/{repo}/actions/secrets/public-key
  2. Encrypt value with libsodium sealed box (client-side; GitHub never sees
     plaintext in transit beyond TLS, and we never log it).
  3. PUT  /repos/{repo}/actions/secrets/{name}

Auth token comes from the env var named in config (default GITHUB_TOKEN).
"""

from __future__ import annotations

import base64
import os

import httpx
from nacl import encoding, public

from rekey.destinations.base import DestinationUpdater
from rekey.models import UpdateResult
from rekey.secrets import SecretValue, redact

API = "https://api.github.com"


class GitHubActionsDestination(DestinationUpdater):
    kind = "github_actions"

    def __init__(self, repo: str, secret_name: str, environment: str | None = None,
                 token_env: str = "GITHUB_TOKEN", client: httpx.Client | None = None):
        self.repo = repo.strip("/")
        self.secret_name = secret_name
        self.environment = environment
        self.token_env = token_env
        self._client = client or httpx.Client(timeout=20)

    def describe(self) -> str:
        env_suffix = f"@{self.environment}" if self.environment else ""
        return f"github:{self.repo}{env_suffix}/{self.secret_name}"

    def _headers(self) -> dict[str, str]:
        from rekey.credentials import resolve_credential
        token = resolve_credential(self.token_env, prompt_label=f"GitHub Token for repo {self.repo} (repo scope)")
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    def _get_public_key_url(self) -> str:
        if self.environment:
            # Environment secret public key endpoint
            return f"{API}/repositories/{self._get_repo_id()}/environments/{self.environment}/secrets/public-key"
        return f"{API}/repos/{self.repo}/actions/secrets/public-key"

    def _get_secret_url(self) -> str:
        if self.environment:
            # Environment secret endpoint
            return f"{API}/repositories/{self._get_repo_id()}/environments/{self.environment}/secrets/{self.secret_name}"
        return f"{API}/repos/{self.repo}/actions/secrets/{self.secret_name}"

    def _get_repo_id(self) -> int:
        r = self._client.get(f"{API}/repos/{self.repo}", headers=self._headers())
        if r.status_code != 200:
            raise RuntimeError(f"failed to fetch repo id for {self.repo} ({r.status_code}): {redact(r.text)[:200]}")
        return r.json()["id"]

    def write(self, value: SecretValue, dry_run: bool) -> UpdateResult:
        name = self.describe()
        try:
            headers = self._headers()
            pk_url = self._get_public_key_url()
        except Exception as e:
            return UpdateResult(name, False, dry_run, str(e))

        r = self._client.get(pk_url, headers=headers)
        if r.status_code != 200:
            return UpdateResult(name, False, dry_run, f"public-key fetch {r.status_code}: {redact(r.text)[:200]}")
        if dry_run:
            target_desc = f"{self.secret_name} (env: {self.environment})" if self.environment else self.secret_name
            return UpdateResult(name, True, True, f"would set {target_desc}")

        pk = r.json()
        box = public.SealedBox(public.PublicKey(pk["key"].encode(), encoding.Base64Encoder()))
        encrypted = base64.b64encode(box.encrypt(value.reveal().encode())).decode()
        put_url = self._get_secret_url()
        r = self._client.put(
            put_url,
            headers=headers, json={"encrypted_value": encrypted, "key_id": pk["key_id"]},
        )
        ok = r.status_code in (201, 204)
        return UpdateResult(name, ok, False, f"PUT -> {r.status_code}" if ok else redact(r.text)[:200])
