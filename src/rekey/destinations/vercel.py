"""Vercel environment variables destination.

Flow (Vercel REST API):
  1. Check if env var already exists on the project (GET /v9/projects/{project}/env)
  2. If exists: PATCH /v9/projects/{project}/env/{id} or update targets
  3. If not: POST /v9/projects/{project}/env with targets=[production, preview, development]

Auth token comes from env var named in config (default VERCEL_TOKEN).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from rekey.destinations.base import DestinationUpdater
from rekey.models import UpdateResult
from rekey.secrets import SecretValue, redact

API = "https://api.vercel.com"


class VercelDestination(DestinationUpdater):
    kind = "vercel"

    def __init__(
        self,
        project: str,
        env_name: str,
        targets: list[str] | str | None = None,
        team_id: str | None = None,
        token_env: str = "VERCEL_TOKEN",
        client: httpx.Client | None = None,
    ):
        self.project = project
        self.env_name = env_name
        # Accept string or list for targets, default to ['production'] if omitted
        if isinstance(targets, str):
            self.targets = [targets]
        elif targets:
            self.targets = list(targets)
        else:
            self.targets = ["production"]

        self.team_id = team_id
        self.token_env = token_env
        self._client = client or httpx.Client(timeout=20)

    def describe(self) -> str:
        targets_str = ",".join(self.targets)
        return f"vercel:{self.project}[{targets_str}]/{self.env_name}"

    def _headers(self) -> dict[str, str]:
        from rekey.credentials import resolve_credential
        token = resolve_credential(self.token_env, prompt_label=f"Vercel Token for project {self.project}")
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _params(self) -> dict[str, str]:
        return {"teamId": self.team_id} if self.team_id else {}

    def write(self, value: SecretValue, dry_run: bool) -> UpdateResult:
        name = self.describe()
        try:
            headers = self._headers()
            params = self._params()
        except Exception as e:
            return UpdateResult(name, False, dry_run, str(e))

        # Check existing environment variables on Vercel project
        r = self._client.get(
            f"{API}/v9/projects/{self.project}/env",
            headers=headers,
            params=params,
        )
        if r.status_code != 200:
            return UpdateResult(name, False, dry_run, f"GET project env {r.status_code}: {redact(r.text)[:200]}")

        if dry_run:
            return UpdateResult(name, True, True, f"would set {self.env_name} on {self.targets}")

        envs = r.json().get("envs", [])
        existing = next((e for e in envs if e.get("key") == self.env_name), None)

        payload: dict[str, Any] = {
            "key": self.env_name,
            "value": value.reveal(),
            "type": "encrypted",
            "target": self.targets,
        }

        if existing:
            # Edit existing variable
            env_id = existing["id"]
            patch_resp = self._client.patch(
                f"{API}/v9/projects/{self.project}/env/{env_id}",
                headers=headers,
                params=params,
                json={"value": value.reveal(), "target": self.targets},
            )
            ok = patch_resp.status_code in (200, 201)
            return UpdateResult(
                name, ok, False, f"PATCH -> {patch_resp.status_code}" if ok else redact(patch_resp.text)[:200]
            )
        else:
            # Create new variable
            post_resp = self._client.post(
                f"{API}/v9/projects/{self.project}/env",
                headers=headers,
                params=params,
                json=payload,
            )
            ok = post_resp.status_code in (200, 201)
            return UpdateResult(
                name, ok, False, f"POST -> {post_resp.status_code}" if ok else redact(post_resp.text)[:200]
            )
