"""Cross-platform path resolution for config, credentials, and token storage.

Supports:
- Linux: ~/.config/rekey (respects XDG_CONFIG_HOME)
- macOS: ~/Library/Application Support/rekey
- Windows: %APPDATA%/rekey (or %USERPROFILE%/.config/rekey)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def get_user_config_dir() -> Path:
    """Return platform-standard user configuration directory for Rekey."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "rekey"
        return Path.home() / "AppData" / "Roaming" / "rekey"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "rekey"
    else:
        # Linux and other UNIX systems (XDG Base Directory specification)
        base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
        return Path(base) / "rekey"


def get_credentials_path() -> Path:
    return get_user_config_dir() / "credentials.env"


def get_oauth_tokens_path() -> Path:
    return get_user_config_dir() / "oauth_tokens.json"


def get_stripe_config_path() -> Path:
    """Return platform-standard location where the official Stripe CLI stores its config."""
    if sys.platform == "win32":
        appdata = os.environ.get("USERPROFILE") or os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / ".config" / "stripe" / "config.toml"
        return Path.home() / ".config" / "stripe" / "config.toml"
    elif sys.platform == "darwin":
        # On macOS, Stripe CLI uses ~/.config/stripe/config.toml
        return Path.home() / ".config" / "stripe" / "config.toml"
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
        return Path(base) / "stripe" / "config.toml"


def open_browser_cross_platform(url: str) -> None:
    """Open URL in the default browser cleanly across Linux, macOS, and Windows without terminal clutter."""
    import subprocess
    import webbrowser

    try:
        if sys.platform == "win32":
            os.startfile(url)  # type: ignore[attr-defined]
            return
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        elif sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
    except Exception:
        pass

    # Fallback to standard library webbrowser
    try:
        webbrowser.open(url)
    except Exception:
        pass
