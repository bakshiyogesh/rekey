"""Destination registry."""

from __future__ import annotations

from typing import Any

from rekey.destinations.base import DestinationUpdater
from rekey.destinations.env_file import EnvFileDestination
from rekey.destinations.github_actions import GitHubActionsDestination


def build_destination(spec: dict[str, Any]) -> DestinationUpdater:
    kind = spec.get("type")
    if kind == "env_file":
        return EnvFileDestination(spec["path"], spec["variable"])
    if kind == "github_actions":
        return GitHubActionsDestination(spec["repo"], spec["secret_name"], spec.get("token_env", "GITHUB_TOKEN"))
    raise ValueError(f"unknown destination type '{kind}'")
