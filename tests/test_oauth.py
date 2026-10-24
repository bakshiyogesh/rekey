"""Unit tests for OAuth store and GitHub OAuth adapter."""

from __future__ import annotations

import httpx
import pytest

from rekey.adapters import build_adapter
from rekey.adapters.github_oauth import GitHubOAuthAdapter
from rekey.models import KeySource, RevokeOutcome, RotationContext
from rekey.oauth_store import OAuthTokenStore
from rekey.secrets import SecretValue


def test_oauth_store_save_and_retrieve(tmp_path):
    store_file = tmp_path / "oauth.json"
    store = OAuthTokenStore(store_file)

    sec = SecretValue("gho_secret_access_token_1234")
    ref = SecretValue("ghr_secret_refresh_token_5678")
    store.save_token("github", "client_1", sec, ref, expires_at=9999999999, scope="repo")

    token = store.get_token("github", "client_1")
    assert token is not None
    assert token["access_token"] == "gho_secret_access_token_1234"
    assert token["refresh_token"] == "ghr_secret_refresh_token_5678"
    assert token["scope"] == "repo"
    assert oct(store_file.stat().st_mode)[-3:] == "600"


def test_build_adapter_selects_oauth():
    adapter = build_adapter("github", "oauth", {"client_id": "test_client_id"})
    assert adapter.source == KeySource.OAUTH
    assert isinstance(adapter, GitHubOAuthAdapter)


def test_github_oauth_device_flow_and_rotation(tmp_path):
    store = OAuthTokenStore(tmp_path / "oauth.json")

    # Mock responses for device code and token polling
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "device/code" in url:
            return httpx.Response(
                200,
                json={
                    "device_code": "dev123",
                    "user_code": "ABCD-1234",
                    "verification_uri": "https://github.com/login/device",
                    "expires_in": 60,
                    "interval": 1,
                },
            )
        elif "oauth/access_token" in url:
            return httpx.Response(
                200,
                json={"access_token": "gho_mock_access_token_9999", "expires_in": 3600},
            )
        elif "api.github.com/user" in url:
            return httpx.Response(200, json={"login": "octocat"})
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = GitHubOAuthAdapter(
        client_id="test_client",
        scopes=["repo"],
        store=store,
        client=mock_client,
        echo=lambda m: None,
    )

    ctx = RotationContext("github-oauth-target", {"client_id": "test_client"}, dry_run=False)
    new_key = adapter.create_key(ctx)

    assert new_key.key_id.startswith("gh-oauth:")
    assert new_key.secret.reveal() == "gho_mock_access_token_9999"
    assert "gho_mock_access_token" not in str(new_key.secret)

    # Verify
    v = adapter.verify_key(new_key.secret)
    assert v.ok
    assert "octocat" in v.detail

    # Revoke old
    r = adapter.revoke_key("gh-oauth:old_key", ctx)
    assert r.outcome in (RevokeOutcome.WILL_EXPIRE, RevokeOutcome.REVOKED)
