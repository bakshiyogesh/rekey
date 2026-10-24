"""Local .env file destination.

SECURITY:
  * Writes atomically (temp file + os.replace) so a crash never leaves a
    half-written file.
  * Preserves/enforces 0600 permissions.
  * Keeps a one-generation backup (<file>.rekey.bak, 0600) so a failed
    rotation can be rolled back by hand.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from rekey.destinations.base import DestinationUpdater
from rekey.models import UpdateResult
from rekey.secrets import SecretValue


class EnvFileDestination(DestinationUpdater):
    kind = "env_file"

    def __init__(self, path: str, variable: str):
        self.path = Path(path).expanduser()
        self.variable = variable
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
            raise ValueError(f"invalid env variable name: {variable!r}")

    def describe(self) -> str:
        return f"{self.path}:{self.variable}"

    def write(self, value: SecretValue, dry_run: bool) -> UpdateResult:
        name = self.describe()
        exists = self.path.exists()
        lines = self.path.read_text().splitlines(keepends=True) if exists else []
        pattern = re.compile(rf"^\s*(export\s+)?{re.escape(self.variable)}\s*=")
        idx = next((i for i, ln in enumerate(lines) if pattern.match(ln)), None)
        action = "replace" if idx is not None else "append"

        if dry_run:
            if exists and not os.access(self.path, os.W_OK):
                return UpdateResult(name, False, True, "file not writable")
            return UpdateResult(name, True, True, f"would {action} {self.variable}")

        raw = value.reveal()
        if "\n" in raw:
            return UpdateResult(name, False, False, "secret contains newline; refusing")
        new_line = f'{self.variable}="{raw}"\n'
        if idx is not None:
            prefix = "export " if lines[idx].lstrip().startswith("export") else ""
            lines[idx] = prefix + new_line
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(new_line)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        if exists:
            bak = self.path.with_name(self.path.name + ".rekey.bak")
            shutil.copy2(self.path, bak)
            os.chmod(bak, 0o600)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".rekey-")
        try:
            with os.fdopen(fd, "w") as f:
                f.writelines(lines)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise
        past = "replaced" if action == "replace" else "appended"
        return UpdateResult(name, True, False, f"{past} {self.variable} ({value.masked})")
