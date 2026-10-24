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

    def __init__(self, repo: str, secret_name: str, token_env: str = "GITHUB_TOKEN",
                 client: httpx.Client | None = None):
        self.repo, self.secret_name, self.token_env = repo, secret_name, token_env
        self._client = client or httpx.Client(timeout=20)

    def describe(self) -> str:
        return f"github:{self.repo}/{self.secret_name}"

    def _headers(self) -> dict[str, str]:
        token = os.environ.get(self.token_env)
        if not token:
            raise RuntimeError(f"env var {self.token_env} is not set")
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    def write(self, value: SecretValue, dry_run: bool) -> UpdateResult:
        name = self.describe()
        try:
            headers = self._headers()
        except RuntimeError as e:
            return UpdateResult(name, False, dry_run, str(e))
        r = self._client.get(f"{API}/repos/{self.repo}/actions/secrets/public-key", headers=headers)
        if r.status_code != 200:
            return UpdateResult(name, False, dry_run, f"public-key fetch {r.status_code}: {redact(r.text)[:200]}")
        if dry_run:
            return UpdateResult(name, True, True, f"would set {self.secret_name}")

        pk = r.json()
        box = public.SealedBox(public.PublicKey(pk["key"].encode(), encoding.Base64Encoder()))
        encrypted = base64.b64encode(box.encrypt(value.reveal().encode())).decode()
        r = self._client.put(
            f"{API}/repos/{self.repo}/actions/secrets/{self.secret_name}",
            headers=headers, json={"encrypted_value": encrypted, "key_id": pk["key_id"]},
        )
        ok = r.status_code in (201, 204)
        return UpdateResult(name, ok, False, f"PUT -> {r.status_code}" if ok else redact(r.text)[:200])
