"""Destination updater interface.

A destination does ONE job: write a secret to its target. It knows nothing
about providers or rotation order — that is the orchestrator's job.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from rekey.models import UpdateResult
from rekey.secrets import SecretValue


class DestinationUpdater(ABC):
    kind: str

    @abstractmethod
    def describe(self) -> str:
        """Human-readable, non-secret description (e.g. '.env:OPENAI_API_KEY')."""

    @abstractmethod
    def write(self, value: SecretValue, dry_run: bool) -> UpdateResult:
        """Write the new value. In dry_run, validate access but change nothing."""
