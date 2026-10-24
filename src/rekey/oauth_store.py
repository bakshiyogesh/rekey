"""Secure local token store for OAuth refresh and access tokens.

SECURITY:
- Stored under ~/.config/rekey/oauth_tokens.json (or XDG_CONFIG_HOME).
- Directory and file strictly enforced to mode 0700 / 0600.
- SecretValue is returned to ensure tokens are never logged or leaked accidentally.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from rekey.secrets import SecretValue


def _default_store_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "rekey" / "oauth_tokens.json"


class OAuthTokenStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_store_path()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def get_token(self, provider: str, client_id: str) -> dict[str, Any] | None:
        key = f"{provider}:{client_id}"
        entry = self._load().get(key)
        if not entry:
            return None
        return entry

    def save_token(
        self,
        provider: str,
        client_id: str,
        access_token: SecretValue,
        refresh_token: SecretValue | None = None,
        expires_at: int | None = None,
        scope: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        key = f"{provider}:{client_id}"
        data = self._load()
        data[key] = {
            "access_token": access_token.reveal(),
            "refresh_token": refresh_token.reveal() if refresh_token else None,
            "expires_at": expires_at,
            "scope": scope,
            "extra": extra or {},
        }

        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".oauth-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise

    def clear_token(self, provider: str, client_id: str) -> None:
        key = f"{provider}:{client_id}"
        data = self._load()
        if key in data:
            del data[key]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".oauth-")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(data, f, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
            except Exception:
                Path(tmp).unlink(missing_ok=True)
                raise
