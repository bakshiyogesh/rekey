"""Interactive prompt helper for missing credentials.

If an environment variable is missing in a terminal session:
1. Prompts the user interactively (with hidden input via getpass).
2. Sets it in os.environ for the duration of the process.
3. Automatically offers to remember it securely in ~/.config/rekey/credentials.env
   (with mode 0600) so the user doesn't have to keep retyping it!
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from rekey.secrets import SecretValue


def _credentials_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "rekey" / "credentials.env"


def _load_stored_credentials() -> dict[str, str]:
    path = _credentials_file()
    if not path.exists():
        return {}
    creds = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        creds[k.strip()] = v.strip().strip("'\"")
    return creds


def _save_credential(var_name: str, value: str) -> None:
    path = _credentials_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass

    creds = _load_stored_credentials()
    creds[var_name] = value

    lines = [f'{k}="{v}"\n' for k, v in creds.items()]
    path.write_text("".join(lines))
    os.chmod(path, 0o600)


def resolve_credential(var_name: str, prompt_label: str = "Credential", required: bool = True) -> str:
    """Get credential from environment, cached local store, or prompt the user."""
    # 1. Check current process environment
    val = os.environ.get(var_name)
    if val:
        return val

    # 2. Check local secure credentials store (~/.config/rekey/credentials.env)
    stored = _load_stored_credentials()
    if stored.get(var_name):
        val = stored[var_name]
        os.environ[var_name] = val
        return val

    # 3. If running interactively, prompt the user instead of crashing!
    if sys.stdin.isatty():
        print(f"\n\033[1;33m[Rekey] Missing {var_name}\033[0m")
        print(f"Please provide your {prompt_label} to continue rotation.")
        try:
            entered = getpass.getpass(f"Enter {var_name} (hidden): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

        if entered:
            os.environ[var_name] = entered
            # Ask if they want it saved locally for future convenience
            try:
                save_choice = input("Remember this credential locally for future rotations? [Y/n]: ").strip().lower()
                if save_choice in ("", "y", "yes"):
                    _save_credential(var_name, entered)
                    print(f"✓ Saved securely to {_credentials_file()} (mode 0600)\n")
            except Exception:
                pass
            return entered

    if required:
        from rekey.adapters.base import AdapterError
        raise AdapterError(f"env var {var_name} is not set and no interactive terminal is available")

    return ""
