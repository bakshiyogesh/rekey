"""Rotation orchestrator — the dual-key flow.

    1. CREATE  new key            (old key stays valid → overlap window)
    1b. VERIFY new key            (pre-flight: never push a broken key)
    2. UPDATE  all destinations
    3. VERIFY  new key again      (post-update confirmation)
    4. REVOKE  old key            (only if every step above succeeded)

Failure policy (zero downtime first):
  * Fail before any destination was written → revoke the NEW key, old key untouched.
  * Fail after some destination was written → DO NOT revoke anything; report
    which destinations hold the new key so the user can finish or roll back.
  * The old key is never revoked unless steps 1–3 all succeeded.

The orchestrator is mode-agnostic: API / CLI / ASSISTED adapters look identical here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from rekey.adapters.base import ProviderAdapter
from rekey.destinations.base import DestinationUpdater
from rekey.models import RevokeOutcome, RotationContext, UpdateResult
from rekey.secrets import SecretValue, redact
from rekey.state import StateStore


@dataclass
class StepLog:
    step: str
    ok: bool
    detail: str


@dataclass
class RotationReport:
    target: str
    provider: str
    mode: str
    dry_run: bool
    success: bool = False
    new_key_fingerprint: str | None = None   # safe: non-reversible
    new_key_masked: str | None = None
    steps: list[StepLog] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {**{k: v for k, v in self.__dict__.items() if k != "steps"},
                "steps": [s.__dict__ for s in self.steps]}


class Rotator:
    def __init__(self, adapter: ProviderAdapter, destinations: list[DestinationUpdater],
                 state: StateStore, on_step: Callable[[StepLog], None] | None = None):
        self.adapter, self.destinations, self.state = adapter, destinations, state
        self.on_step = on_step or (lambda s: None)

    def _log(self, report: RotationReport, step: str, ok: bool, detail: str) -> None:
        entry = StepLog(step, ok, redact(detail))  # belt-and-braces redaction
        report.steps.append(entry)
        self.on_step(entry)

    def rotate(self, target: str, provider_options: dict, dry_run: bool = True) -> RotationReport:
        a = self.adapter
        report = RotationReport(target, a.name, a.source.value, dry_run)
        ctx = RotationContext(target, provider_options, dry_run)
        old_id = self.state.current_key_id(target)

        if dry_run:
            return self._plan(report, old_id)

        # 1. CREATE
        try:
            new = a.create_key(ctx)
        except Exception as e:
            self._log(report, "create", False, str(e))
            return report
        report.new_key_fingerprint, report.new_key_masked = new.secret.fingerprint, new.secret.masked
        self._log(report, "create", True, f"created {new.key_id} ({new.secret.masked})")

        # 1b. PRE-FLIGHT VERIFY
        if not self._verify(report, new.secret, "verify:preflight"):
            self._abort_revoke_new(report, new.key_id, ctx)
            return report

        # 2. UPDATE DESTINATIONS
        written: list[str] = []
        for d in self.destinations:
            try:
                res = d.write(new.secret, dry_run=False)
            except Exception as e:
                res = UpdateResult(d.describe(), False, False, str(e))
            self._log(report, f"update:{res.destination}", res.ok, res.detail)
            if not res.ok:
                if written:
                    self._log(report, "abort", False,
                              f"partial update; NEW key is in {written}. Old key NOT revoked. "
                              "Fix the failing destination and re-run, or restore backups.")
                else:
                    self._abort_revoke_new(report, new.key_id, ctx)
                return report
            written.append(res.destination)

        # 3. POST-UPDATE VERIFY
        if not self._verify(report, new.secret, "verify:post-update"):
            self._log(report, "abort", False, "new key failed after update; old key NOT revoked")
            return report

        # Record the new key BEFORE revoking, so a crash during revoke
        # never loses track of which key is live.
        self.state.set_current(target, new.key_id, a.name)

        # 4. REVOKE OLD
        if not old_id:
            self._log(report, "revoke", True, "no previous key recorded; nothing to revoke")
        elif old_id == new.key_id:
            self._log(report, "revoke", True, "old and new key ids match; skipping revoke")
        else:
            try:
                r = a.revoke_key(old_id, ctx)
                self._log(report, "revoke", True, f"{r.outcome.value}: {r.detail}")
            except Exception as e:
                # Rotation still succeeded; the old key just remains valid.
                self._log(report, "revoke", False, f"revoke of {old_id} failed: {e}. Revoke manually.")
        report.success = True
        return report

    # -- helpers ---------------------------------------------------------
    def _verify(self, report: RotationReport, secret, label: str) -> bool:
        try:
            v = self.adapter.verify_key(secret)
        except Exception as e:
            self._log(report, label, False, str(e))
            return False
        self._log(report, label, v.ok, v.detail)
        return v.ok

    def _abort_revoke_new(self, report: RotationReport, new_id: str, ctx: RotationContext) -> None:
        try:
            r = self.adapter.revoke_key(new_id, ctx)
            self._log(report, "rollback", r.outcome != RevokeOutcome.MANUAL, f"new key {r.outcome.value}: {r.detail}")
        except Exception as e:
            self._log(report, "rollback", False, f"could not revoke new key {new_id}: {e}")

    def _plan(self, report: RotationReport, old_id: str | None) -> RotationReport:
        a = self.adapter
        self._log(report, "create", True, f"would create new {a.name} key via {a.source.value} mode")
        self._log(report, "verify:preflight", True, "would verify new key")
        for d in self.destinations:
            try:
                res = d.write(_DRY_PLACEHOLDER, dry_run=True)
            except Exception as e:
                res = UpdateResult(d.describe(), False, True, str(e))
            self._log(report, f"update:{res.destination}", res.ok, res.detail)
        self._log(report, "verify:post-update", True, "would verify new key again")
        self._log(report, "revoke", True, f"would revoke old key {old_id}" if old_id else "no previous key recorded")
        report.success = all(s.ok for s in report.steps)
        return report


# Never written anywhere: dry-run destinations must not touch the value.
_DRY_PLACEHOLDER = SecretValue("dry-run-placeholder-not-a-key")
