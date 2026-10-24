import asyncio
import os
import pytest
from pathlib import Path

from rekey.mcp.server import mcp, list_targets, rotate_key


@pytest.fixture
def mock_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg_file = tmp_path / "rekey-mcp.yaml"
    cfg_file.write_text(f"""
state_file: {tmp_path / "state.json"}
targets:
  stripe-mcp:
    provider:
      type: stripe
      mode: cli
    destinations:
      - type: env_file
        path: {tmp_path / ".env"}
        variable: STRIPE_KEY
""")
    monkeypatch.setenv("REKEY_CONFIG", str(cfg_file))
    return cfg_file


def test_mcp_list_targets(mock_config):
    targets = list_targets()
    assert len(targets) == 1
    assert targets[0]["target"] == "stripe-mcp"
    assert targets[0]["provider"] == "stripe"
    assert targets[0]["mode"] == "cli"
    assert targets[0]["destinations"] == 1


def test_mcp_rotate_key_dry_run(mock_config):
    result = rotate_key("stripe-mcp", dry_run=True)
    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["target"] == "stripe-mcp"
    # Ensure no raw secret leaks in result
    assert "sk_" not in str(result)


def test_mcp_rotate_unknown_target(mock_config):
    result = rotate_key("unknown-svc", dry_run=True)
    assert result["success"] is False
    assert "error" in result
