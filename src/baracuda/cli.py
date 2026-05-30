"""CLI interface for BARACUDA."""

import argparse
import sys
from pathlib import Path

from baracuda.policy import load_policy

STARTER_POLICY = """\
# BARACUDA Policy File
# Defines which tool calls are allowed, denied, or require human review.

version: 1

# Mode controls enforcement behavior:
#   enforce - block denied calls (default)
#   shadow  - log decisions but never block
#   review  - queue all calls for human approval
mode: enforce

# Path to the SQLite audit log (relative to working directory)
audit_path: .baracuda/audit.db

# Tool policies: map tool names to their rules.
# Each tool can set:
#   allow: true | false | "review"
#   rate_limit: "N/minute" or "N/hour" (planned, not enforced in v0.1)
#   parameter_rules:
#     <param_name>:
#       deny_patterns:
#         - "<python regex>"
tools:
  # Example: allow read_file but block paths containing /etc or ..
  read_file:
    allow: true
    parameter_rules:
      path:
        deny_patterns:
          - "/etc/"
          - "\\\\.\\\\."

  # Example: block execute_command entirely
  execute_command:
    allow: false

  # Example: queue database writes for human review
  db_write:
    allow: "review"
"""


def cmd_init(args: argparse.Namespace) -> None:
    """Write a starter baracuda.yaml to the current directory."""
    target = Path("baracuda.yaml")
    if target.exists():
        print(f"{target} already exists. Not overwriting.")
        return

    target.write_text(STARTER_POLICY)
    print(f"Created {target} with starter policy. Edit it to match your tools.")


def cmd_check(args: argparse.Namespace) -> None:
    """Validate a policy file and print a summary."""
    try:
        policy = load_policy(args.policy_file)
    except ValueError as e:
        print(f"Validation failed: {e}")
        sys.exit(1)

    tool_count = len(policy.tools)
    print(f"Policy valid. Mode: {policy.mode}, Tools configured: {tool_count}")


def main() -> None:
    """Entry point for the baracuda CLI."""
    parser = argparse.ArgumentParser(
        prog="baracuda",
        description="BARACUDA - Runtime policy enforcement for AI tool calls.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Create a starter baracuda.yaml in the current directory")

    check_parser = subparsers.add_parser("check", help="Validate a policy file")
    check_parser.add_argument("policy_file", help="Path to the policy YAML file")

    args = parser.parse_args()

    if args.command is None:
        parser.print_usage()
        sys.exit(0)

    commands = {
        "init": cmd_init,
        "check": cmd_check,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
