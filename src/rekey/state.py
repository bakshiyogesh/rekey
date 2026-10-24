"""Tiny JSON state store: remembers the CURRENT key id per target.

Contains only non-secret identifiers (service-account ids, fingerprints),
so the orchestrator knows which old key to revoke on the next rotation.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class StateStore:
    def __init__(self, path: Path):
        self.path = path

    def _load(self) -> dict:
        return json.loads(self.path.read_text()) if self.path.exists() else {}

    def current_key_id(self, target: str) -> str | None:
        return self._load().get(target, {}).get("key_id")

    def set_current(self, target: str, key_id: str, provider: str) -> None:
        data = self._load()
        data[target] = {"key_id": key_id, "provider": provider,
                        "rotated_at": datetime.now(timezone.utc).isoformat()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, self.path)
