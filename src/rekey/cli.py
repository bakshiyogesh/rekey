"""Rekey CLI.

    rekey rotate <target> --dry-run      # default: preview only
    rekey rotate <target> --execute      # perform the dual-key rotation
    rekey list
"""

from __future__ import annotations

import argparse
import json
import sys

from rekey.config import DEFAULT_CONFIG, load_config
from rekey.orchestrator import StepLog
from rekey.runner import run_rotation


def _print_step(s: StepLog) -> None:
    mark = "✓" if s.ok else "✗"
    print(f"  {mark} {s.step:<28} {s.detail}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rekey", description="Zero-downtime dual-key API key rotation")
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("rotate", help="rotate a configured target")
    r.add_argument("target")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="preview only (default)")
    g.add_argument("--execute", action="store_true", help="actually rotate")
    r.add_argument("--json", action="store_true", help="emit report as JSON (masked)")

    sub.add_parser("list", help="list configured targets")
    args = p.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "list":
        for name, t in cfg.targets.items():
            print(f"{name}: {t.provider} [{t.mode or 'default'}] -> {len(t.destinations)} destination(s)")
        return 0

    dry = not args.execute  # SECURITY: dry-run unless explicitly told otherwise
    if not args.json:
        print(f"{'DRY RUN' if dry else 'EXECUTE'}: rotating '{args.target}'")
    try:
        report = run_rotation(cfg, args.target, dry, on_step=None if args.json else _print_step)
    except KeyboardInterrupt:
        print("\n\033[33mRotation cancelled by user.\033[0m")
        return 130
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        if report.success:
            print("\n\033[32m✔ Result: ROTATION SUCCESSFUL\033[0m")
        else:
            print("\n\033[1;31m✖ Result: ROTATION FAILED\033[0m")
            failed_steps = [s for s in report.steps if not s.ok]
            if failed_steps:
                print("\n\033[1;33m--- Troubleshooting & Fix Guide ---\033[0m")
                for s in failed_steps:
                    print(f"  • Step '\033[1m{s.step}\033[0m' failed: {s.detail}")
                    # Provide actionable hints based on the failed step
                    if "401" in s.detail or "unauthorized" in s.detail.lower():
                        print("    👉 Check that your API key / token has not expired and has valid permissions.")
                    elif "permission" in s.detail.lower() or "errno 13" in s.detail.lower():
                        print("    👉 File permission issue: check write permissions on your .env destination (chmod 600 .env).")
                    elif "github" in s.step and ("404" in s.detail or "403" in s.detail):
                        print("    👉 GitHub Actions error: ensure GITHUB_TOKEN has 'Secrets: Read & Write' on the repository.")
                    elif "device" in s.detail.lower() or "oauth" in s.detail.lower():
                        print("    👉 OAuth issue: make sure 'Enable Device Flow' is checked in your GitHub OAuth App settings.")
                print("\n  \033[2mNotice: Because Rekey uses dual-key zero-downtime safety, your working key was NOT revoked.\033[0m")
                print("  \033[2mTo preview fixes before executing, run with default dry-run mode (without --execute).\033[0m\n")
    return 0 if report.success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\033[33mRotation cancelled by user.\033[0m")
        sys.exit(130)
