"""Shared wiring: config target -> Rotator. Used by both CLI and MCP."""

from __future__ import annotations

from typing import Callable

from rekey.adapters import build_adapter
from rekey.config import Config
from rekey.destinations import build_destination
from rekey.orchestrator import RotationReport, Rotator, StepLog
from rekey.state import StateStore


def run_rotation(cfg: Config, target: str, dry_run: bool,
                 on_step: Callable[[StepLog], None] | None = None,
                 allow_interactive: bool = True) -> RotationReport:
    t = cfg.targets.get(target)
    if not t:
        raise KeyError(f"unknown target '{target}' (have: {sorted(cfg.targets)})")
    adapter = build_adapter(t.provider, t.mode, t.provider_options)
    if not allow_interactive and adapter.source.value == "assisted":
        raise PermissionError("assisted mode requires a human at a terminal; run `rekey rotate` instead")
    dests = [build_destination(d) for d in t.destinations]
    return Rotator(adapter, dests, StateStore(cfg.state_file), on_step).rotate(
        target, t.provider_options, dry_run=dry_run)
