"""CLI interface for HYDRACUDA.

`validate` and `plan` are read-only introspection: they load a policy, analyse
it, and print. No tool runs, no audit record is written, and the dashboard does
not need to be running.
"""

import argparse
import sys
from pathlib import Path

from hydracuda.introspect import analyze, plan
from hydracuda.policy import load_policy

DEFAULT_POLICY_FILE = "hydracuda.yaml"

STARTER_POLICY = """\
version: 1
mode: enforce
audit_path: .hydracuda/audit.db

tools:
  read_file:
    allow: true
    parameter_rules:
      path:
        deny_patterns:
          - "/etc/"
          - "\\\\.\\\\."
          - "/root/"

  delete_record:
    allow: false
    reason: "Destructive operation. Blocked by default."

  execute_shell:
    allow: "review"
"""

#: Column width for the action in `plan` output. "REVIEW" is the longest.
_ACTION_WIDTH = 6


def cmd_init(args: argparse.Namespace) -> int:
    """Write a starter hydracuda.yaml to the current directory."""
    target = Path(DEFAULT_POLICY_FILE)
    if target.exists():
        print(f"{target} already exists. Not overwriting.")
        return 0

    target.write_text(STARTER_POLICY)
    print(f"Created {target} with starter policy. Edit it to match your tools.")
    return 0


def _load(path: str):
    """Load a policy, or print the schema error and return None."""
    print(f"Policy: {path}")
    try:
        return load_policy(path)
    except ValueError as e:
        # PolicyError and ConditionError are both ValueError. A schema problem
        # is fatal: there is nothing well-formed enough to analyse.
        print(f"error: schema\n  {e}")
        return None


def _describe(policy) -> str:
    parts = [
        f"Version {policy.version}",
        f"mode {policy.mode}",
        f"default {policy.default_action}",
        f"{len(policy.rules)} rule(s)",
    ]
    if policy.adapters:
        parts.append(f"{len(policy.adapters)} adapter(s)")
    return ", ".join(parts)


def cmd_validate(args: argparse.Namespace) -> int:
    """Check a policy for schema errors and for rules that do not mean what
    they appear to."""
    policy = _load(args.policy_file)
    if policy is None:
        print("Policy is invalid.")
        return 1

    print(_describe(policy))

    report = analyze(policy)
    for diagnostic in report.diagnostics:
        print()
        print(diagnostic.format())

    errors = len(report.errors)
    warnings = len(report.warnings)
    print()
    print(f"{errors} error(s), {warnings} warning(s)")

    if errors:
        print("Policy is invalid.")
        return 1
    if warnings and args.strict:
        print("Policy is valid, but --strict treats warnings as failures.")
        return 1

    print("Policy is valid.")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    """Print the decision for every resource on the declared surface."""
    policy = _load(args.policy_file)
    if policy is None:
        print("Cannot plan: the policy did not load.")
        return 1

    print(_describe(policy))
    entries = plan(policy)

    print()
    if not entries:
        print(
            "Declared surface: 0 resources. Add an `adapters` block naming the "
            "resources this policy governs — `plan` walks that list."
        )
        return 0

    print(
        f"Declared surface: {len(entries)} resource(s). Evaluated with no "
        f"parameters and no context."
    )
    print()

    width = max(len(entry.resource) for entry in entries)
    for entry in entries:
        rule = entry.rule or "(default)"
        line = (
            f"  {entry.action.upper():<{_ACTION_WIDTH}}  "
            f"{entry.resource:<{width}}  {rule}"
        )
        if entry.conditional:
            line += f"  [conditional: {', '.join(entry.conditional_rules)}]"
        print(line)
        if args.reasons:
            print(f"  {'':<{_ACTION_WIDTH}}  {'':<{width}}  {entry.reason}")

    print()
    counts = {action: 0 for action in ("allow", "deny", "review")}
    for entry in entries:
        counts[entry.action] = counts.get(entry.action, 0) + 1
    print(", ".join(f"{count} {action}" for action, count in counts.items()))

    conditional = [entry for entry in entries if entry.conditional]
    if conditional:
        print(
            f"{len(conditional)} resource(s) have a conditional outcome: the "
            f"action above holds for a call with no parameters and no context, "
            f"and the listed rules can change it for a real call."
        )

    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Deprecated alias for `validate`."""
    print("note: `check` is a deprecated alias for `validate`.")
    return cmd_validate(args)


def main() -> None:
    """Entry point for the hydracuda CLI."""
    parser = argparse.ArgumentParser(
        prog="hydracuda",
        description="HYDRACUDA - Runtime policy enforcement for AI tool calls.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "init", help="Create a starter hydracuda.yaml in the current directory"
    )

    def add_policy_argument(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument(
            "policy_file",
            nargs="?",
            default=DEFAULT_POLICY_FILE,
            help=f"Path to the policy YAML file (default: {DEFAULT_POLICY_FILE})",
        )

    validate_parser = subparsers.add_parser(
        "validate",
        help="Check a policy for schema errors, conflicting and unreachable "
        "rules, and unpinned trust assumptions",
    )
    add_policy_argument(validate_parser)
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on warnings as well as errors",
    )

    plan_parser = subparsers.add_parser(
        "plan",
        help="Print the decision for every declared resource, without "
        "executing anything",
    )
    add_policy_argument(plan_parser)
    plan_parser.add_argument(
        "--reasons",
        action="store_true",
        help="Print the reason attached to each decision",
    )

    check_parser = subparsers.add_parser(
        "check", help="Deprecated alias for `validate`"
    )
    add_policy_argument(check_parser)
    check_parser.set_defaults(strict=False)

    args = parser.parse_args()

    if args.command is None:
        parser.print_usage()
        sys.exit(0)

    commands = {
        "init": cmd_init,
        "validate": cmd_validate,
        "plan": cmd_plan,
        "check": cmd_check,
    }
    sys.exit(commands[args.command](args))


if __name__ == "__main__":
    main()
