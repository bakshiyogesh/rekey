"""Dual-key flow tests using fake adapter/destinations (no network)."""

from __future__ import annotations

import pytest

from rekey.adapters.base import ProviderAdapter
from rekey.destinations.base import DestinationUpdater
from rekey.destinations.env_file import EnvFileDestination
from rekey.models import (
    KeySource, NewKey, RevokeOutcome, RevokeResult, UpdateResult, VerifyResult,
)
from rekey.orchestrator import Rotator
from rekey.secrets import SecretValue, redact
from rekey.state import StateStore


class FakeAdapter(ProviderAdapter):
    name, source = "fake", KeySource.API

    def __init__(self, verify_ok=True):
        self.verify_ok, self.revoked, self.n = verify_ok, [], 0

    def create_key(self, ctx):
        self.n += 1
        return NewKey(f"key-{self.n}", SecretValue(f"sk-test-secret-value-{self.n:04d}"))

    def verify_key(self, secret):
        return VerifyResult(self.verify_ok, "fake")

    def revoke_key(self, key_id, ctx):
        self.revoked.append(key_id)
        return RevokeResult(RevokeOutcome.REVOKED)


class FakeDest(DestinationUpdater):
    kind = "fake"

    def __init__(self, ok=True):
        self.ok, self.values = ok, []

    def describe(self):
        return "fake-dest"

    def write(self, value, dry_run):
        if not dry_run and self.ok:
            self.values.append(value)
        return UpdateResult("fake-dest", self.ok, dry_run)


@pytest.fixture
def state(tmp_path):
    return StateStore(tmp_path / "state.json")


def test_happy_path_revokes_old_only_after_success(state):
    a, d = FakeAdapter(), FakeDest()
    state.set_current("t", "key-old", "fake")
    rep = Rotator(a, [d], state).rotate("t", {}, dry_run=False)
    assert rep.success and a.revoked == ["key-old"]
    assert state.current_key_id("t") == "key-1"


def test_dry_run_changes_nothing(state):
    a, d = FakeAdapter(), FakeDest()
    state.set_current("t", "key-old", "fake")
    rep = Rotator(a, [d], state).rotate("t", {}, dry_run=True)
    assert rep.success and a.n == 0 and a.revoked == [] and d.values == []
    assert state.current_key_id("t") == "key-old"


def test_verify_failure_revokes_new_keeps_old(state):
    a = FakeAdapter(verify_ok=False)
    state.set_current("t", "key-old", "fake")
    rep = Rotator(a, [FakeDest()], state).rotate("t", {}, dry_run=False)
    assert not rep.success and a.revoked == ["key-1"]
    assert state.current_key_id("t") == "key-old"


def test_partial_destination_failure_revokes_nothing(state):
    a = FakeAdapter()
    state.set_current("t", "key-old", "fake")
    rep = Rotator(a, [FakeDest(), FakeDest(ok=False)], state).rotate("t", {}, dry_run=False)
    assert not rep.success and a.revoked == []


def test_report_never_contains_secret(state):
    rep = Rotator(FakeAdapter(), [FakeDest()], state).rotate("t", {}, dry_run=False)
    assert "sk-test-secret-value-0001" not in str(rep.to_dict())


def test_secret_value_masks():
    s = SecretValue("sk-proj-abcdefghijklmnop1234")
    assert "abcdefghijklmnop" not in f"{s} {s!r} {str(s)}"
    assert s.reveal().endswith("1234")


def test_redact():
    assert "[REDACTED]" in redact("key: sk_live_ABCDEFGH12345678")
    assert "ghs_" not in redact("token ghs_abcdefghijklmnopqrstuvwxyz")


def test_env_file_atomic_replace(tmp_path):
    f = tmp_path / ".env"
    f.write_text("A=1\nOPENAI_API_KEY=old\n")
    res = EnvFileDestination(str(f), "OPENAI_API_KEY").write(SecretValue("sk-new-value-xyz1"), dry_run=False)
    assert res.ok and 'OPENAI_API_KEY="sk-new-value-xyz1"' in f.read_text()
    assert (tmp_path / ".env.rekey.bak").read_text().endswith("old\n")
    assert oct(f.stat().st_mode)[-3:] == "600"
