# Rekey

Zero-downtime API key rotation for developers and agents, using a **dual-key (overlap) flow**.

```
CLI / MCP ──► Orchestrator ──► Provider Adapter  (create / verify / revoke)
                         └───► Destination Updaters (write only)
```

## Dual-key flow

1. **Create** a new key — the old key stays valid
2. **Verify** it (pre-flight)
3. **Update** every destination
4. **Verify** again
5. **Revoke** the old key (or let it expire)

The old key is **never** revoked unless steps 1–4 succeed. If something fails before any
destination is written, the *new* key is revoked. If it fails mid-update, nothing is revoked and
the report lists which destinations already hold the new key.

## Bootstrap Modes (How keys are acquired)

Rekey supports three bootstrap mechanisms to mint or rotate keys, all adhering to the exact same dual-key interface:

| Mode | How keys are minted | Best Used When | Supported Providers |
|---|---|---|---|
| `api` | Direct REST API calls with admin credential | Fully automated pipelines, server environments, or CI/CD | OpenAI (Admin key), GitHub (App private key) |
| `cli` | Official vendor CLI subprocess (redacted output) | Tooling already has a logged-in CLI on dev machines | Stripe (`stripe login`) |
| `oauth` | RFC 8628 Device Flow (browser delegation + token store) | Developer machines where human authentication is preferred over long-lived root keys | GitHub (OAuth Apps) |
| `assisted` | User pastes rotated key into hidden prompt | Fallback when automated endpoints do not exist | Any |

Choose the mode in `rekey.yaml` via `provider.mode: api | cli | oauth`.

### OAuth Flow Example (GitHub)
When using `mode: oauth`:
1. Rekey initiates RFC 8628 Device Flow and presents a short user code:
   ```
   [OAuth] Complete authentication in your browser:
     URL:  https://github.com/login/device
     Code: WDWN-ABCD
   ```
2. Your browser opens automatically; confirm the device.
3. Rekey securely stores the refresh & access token in `~/.config/rekey/oauth_tokens.json` (`0600` permissions).
4. Rekey completes the dual-key flow: verifies `/user`, syncs destinations, and lets old tokens expire.

## Install & run

```bash
pip install -e ".[mcp,dev]"
cp rekey.example.yaml rekey.yaml        # edit ids; no secrets in this file
export OPENAI_ADMIN_KEY=...             # credentials come from env vars only

rekey list
rekey rotate openai-prod                # dry run (default)
rekey rotate openai-prod --execute
```

## MCP server

```bash
REKEY_CONFIG=./rekey.yaml rekey-mcp
```

Add to your MCP client config (e.g. `mcp_config.json`):

```json
{
  "mcpServers": {
    "rekey": {
      "command": "/abs/path/to/rekey/.venv/bin/rekey-mcp",
      "env": { "REKEY_CONFIG": "/abs/path/to/rekey/rekey.yaml" }
    }
  }
}
```

Provider credentials (e.g. `OPENAI_ADMIN_KEY`) must be in the server's environment — never
pass them through the agent. Works with MCP SDK 1.x (`FastMCP`) and 2.x (`MCPServer`).

Tools: `list_targets`, `rotate_key(target, dry_run=True)`. Responses contain only masked values
and fingerprints — agents never see a secret. Assisted mode is refused over MCP.

## Security

- `SecretValue` masks itself in `str`/`repr`/f-strings; plaintext only via `.reveal()`.
- All provider errors and subprocess output pass through `redact()`.
- Config loader rejects files that look like they contain keys.
- `.env` writes are atomic, `0600`, with a `.rekey.bak` backup.

## Layout

```
src/rekey/
  adapters/      base.py openai.py github.py stripe.py assisted.py
  destinations/  base.py env_file.py github_actions.py
  orchestrator/  rotator.py
  mcp/           server.py
  cli.py config.py state.py secrets.py runner.py
tests/
```

## Tests

```bash
pytest
```
