"""Destination registry."""

from __future__ import annotations

from rekey.destinations.base import DestinationUpdater
from rekey.destinations.env_file import EnvFileDestination
from rekey.destinations.github_actions import GitHubActionsDestination
from rekey.destinations.vercel import VercelDestination


def build_destination(spec: dict[str, Any]) -> DestinationUpdater:
    kind = spec.get("type")
    if kind == "env_file":
        # Supports variable or env_name
        var_name = spec.get("variable") or spec.get("env_name")
        if not var_name:
            raise ValueError("env_file destination requires 'variable' (or 'env_name')")
        return EnvFileDestination(spec["path"], var_name)

    if kind == "github_actions":
        # Supports repo (or owner/repo), secret_name (or env_name), and optional environment
        repo = spec.get("repo")
        if not repo and spec.get("owner") and spec.get("repo_name"):
            repo = f"{spec['owner']}/{spec['repo_name']}"
        elif not repo and spec.get("owner"):
            repo = spec["owner"]

        secret_name = spec.get("secret_name") or spec.get("env_name")
        if not repo or not secret_name:
            raise ValueError("github_actions destination requires 'repo' and 'secret_name'")

        environment = spec.get("environment")
        return GitHubActionsDestination(
            repo=repo,
            secret_name=secret_name,
            environment=environment,
            token_env=spec.get("token_env", "GITHUB_TOKEN"),
        )

    if kind == "vercel":
        project = spec.get("project")
        env_name = spec.get("env_name") or spec.get("secret_name") or spec.get("variable")
        if not project or not env_name:
            raise ValueError("vercel destination requires 'project' and 'env_name'")

        # Support targets: [production, preview] or target: production or environment: production
        targets = spec.get("targets") or spec.get("target") or spec.get("environment")
        return VercelDestination(
            project=project,
            env_name=env_name,
            targets=targets,
            team_id=spec.get("team_id"),
            token_env=spec.get("token_env", "VERCEL_TOKEN"),
        )

    raise ValueError(f"unknown destination type '{kind}'")
