"""MCP server: lets agents trigger rotations without ever seeing a secret.

Tools:
  list_targets()                       -> names/providers/modes
  rotate_key(target, dry_run=True)     -> masked report (fingerprints only)

SECURITY:
  * Secrets live only inside the server process; responses contain masked
    values + fingerprints and step details that were passed through redact().
  * Assisted mode is refused (it needs a human at a terminal).
  * CLI-mode subprocess output goes to stderr (redacted), never to the agent.
  * dry_run defaults to True; agents must explicitly opt into execution.
"""

from __future__ import annotations

import os
import sys

from rekey.config import load_config
from rekey.runner import run_rotation
from rekey.secrets import redact

try:  # mcp SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:
    try:  # mcp SDK 1.x
        from mcp.server.fastmcp import FastMCP as _Server
    except ImportError:  # pragma: no cover
        sys.exit("install the MCP extra: pip install 'rekey[mcp]'")

mcp = _Server("rekey")
CONFIG = os.environ.get("REKEY_CONFIG", "rekey.yaml")


@mcp.tool()
def list_targets() -> list[dict]:
    """List configured rotation targets (no secrets)."""
    cfg = load_config(CONFIG)
    return [{"target": n, "provider": t.provider, "mode": t.mode or "default",
             "destinations": len(t.destinations)} for n, t in cfg.targets.items()]


@mcp.tool()
def rotate_key(target: str, dry_run: bool = True) -> dict:
    """Rotate a key using the dual-key flow. Returns a masked report only."""
    cfg = load_config(CONFIG)
    try:
        return run_rotation(cfg, target, dry_run, allow_interactive=False).to_dict()
    except Exception as e:
        return {"target": target, "success": False, "error": redact(str(e))}


def main() -> None:
    # stdout is the MCP transport; adapters write progress to stderr only.
    mcp.run()


if __name__ == "__main__":
    main()
