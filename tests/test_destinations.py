"""Tests for destination environment targeting (Vercel, GitHub Actions environments, .env paths)."""

from __future__ import annotations

import httpx
import pytest

from rekey.destinations import build_destination
from rekey.destinations.github_actions import GitHubActionsDestination
from rekey.destinations.vercel import VercelDestination
from rekey.secrets import SecretValue


def test_github_actions_with_and_without_environment():
    # Without environment (repo-level secret)
    d_repo = build_destination({
        "type": "github_actions",
        "repo": "owner/repo",
        "secret_name": "API_KEY",
    })
    assert isinstance(d_repo, GitHubActionsDestination)
    assert d_repo.describe() == "github:owner/repo/API_KEY"
    assert d_repo.environment is None

    # With environment (e.g. production)
    d_env = build_destination({
        "type": "github_actions",
        "owner": "owner",
        "repo_name": "repo",
        "env_name": "API_KEY",
        "environment": "production",
    })
    assert isinstance(d_env, GitHubActionsDestination)
    assert d_env.describe() == "github:owner/repo@production/API_KEY"
    assert d_env.environment == "production"


def test_vercel_destination_targets():
    # Default targets to production if omitted
    d_def = build_destination({
        "type": "vercel",
        "project": "my-app",
        "env_name": "STRIPE_KEY",
    })
    assert isinstance(d_def, VercelDestination)
    assert d_def.targets == ["production"]
    assert d_def.describe() == "vercel:my-app[production]/STRIPE_KEY"

    # Multi-environment targets [production, preview]
    d_multi = build_destination({
        "type": "vercel",
        "project": "my-app",
        "env_name": "OPENAI_API_KEY",
        "targets": ["production", "preview"],
    })
    assert isinstance(d_multi, VercelDestination)
    assert d_multi.targets == ["production", "preview"]
    assert d_multi.describe() == "vercel:my-app[production,preview]/OPENAI_API_KEY"


def test_vercel_destination_dry_run_and_write():
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append((request.method, str(request.url)))
        if request.method == "GET":
            return httpx.Response(200, json={"envs": [{"id": "env_123", "key": "OPENAI_API_KEY"}]})
        elif request.method == "PATCH":
            return httpx.Response(200, json={"id": "env_123"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    d = VercelDestination(
        project="my-app",
        env_name="OPENAI_API_KEY",
        targets=["production", "preview"],
        token_env="TEST_VERCEL_TOKEN",
        client=client,
    )
    import os
    os.environ["TEST_VERCEL_TOKEN"] = "fake_vercel_token"

    # Dry run
    res_dry = d.write(SecretValue("sk-new-key"), dry_run=True)
    assert res_dry.ok
    assert "would set" in res_dry.detail

    # Real write
    res_real = d.write(SecretValue("sk-new-key"), dry_run=False)
    assert res_real.ok
    assert "PATCH -> 200" in res_real.detail
