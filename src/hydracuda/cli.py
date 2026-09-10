"""CLI interface for HYDRACUDA.

`validate`, `plan` and `test` are read-only introspection: they load a policy,
analyse it, and print. No tool runs, no audit record is written, and the
dashboard does not need to be running.

Every one of them states which engine decided, and runs exactly one — the
`--engine` flag, else `HYDRACUDA_ENGINE`, else whichever is available. Running
both by default would make the output depend on the build, and a consumer that
pinned `HYDRACUDA_ENGINE=python` for reproducibility would silently get the other
one. `--compare-engines` opts into both, and reports a disagreement with an exit
status of its own, because two engines diverging is a bug in HYDRACUDA rather
than a finding about the policy.
"""

import argparse
import contextlib
import difflib
import io
import sys
from collections.abc import Callable
from pathlib import Path

from hydracuda._backend import (
    BackendUnavailable,
    engine_backend,
    rust_available,
    use_backend,
)
from hydracuda.introspect import FAIL, UNSUPPORTED, analyze, plan, run_tests
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

#: Column width for a test case's status. "UNSUPPORTED" is the longest.
_STATUS_WIDTH = 11

#: Exit status for `--compare-engines` when the two engines disagree.
#:
#: Deliberately not 1. Exit 1 means the *policy* has a problem, and a divergence
#: between the engines is a HYDRACUDA bug that says nothing about the policy — a
#: CI job has to be able to tell "your policy is wrong" from "the tool is
#: broken", and the same exit code for both would hide the second behind the
#: first.
ENGINE_DIVERGENCE_EXIT = 3


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
    # Stated, not inferred, and stated separately from the engine: the loader is
    # always the Python one here even when the compiled engine decides, because
    # the extension is handed the evaluable part of an already-parsed policy. The
    # standalone `hcuda` binary prints the same two fields with `rust` in both,
    # which is the difference worth being able to see.
    print(f"Engine: {engine_backend()}    Loader: python")
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


def cmd_test(args: argparse.Namespace) -> int:
    """Run the policy's `tests:` block: what the author believed it allowed."""
    policy = _load(args.policy_file)
    if policy is None:
        print("Cannot run tests: the policy did not load.")
        return 1

    print(_describe(policy))

    # Diagnostics before any case runs. An error-level finding stops the run
    # rather than being printed alongside results: a duplicate case name makes
    # the per-case report unreadable, and a wildcard `resource` means the case
    # does not stand for one request, so there is nothing to report on yet.
    report = analyze(policy)
    if report.errors:
        for diagnostic in report.errors:
            print()
            print(diagnostic.format())
        print()
        print(f"{len(report.errors)} error(s). No cases were run.")
        return 1

    for diagnostic in report.warnings:
        print()
        print(diagnostic.format())

    print()
    if not policy.tests:
        print(
            "No test cases. Add a `tests:` block naming the requests this policy "
            "is supposed to allow and refuse — validation catches a misspelled "
            "key, not a correctly spelled rule in the wrong order."
        )
        return 0

    results = run_tests(policy)
    width = max(len(result.name) for result in results)
    for result in results:
        print(
            f"  {result.status.upper():<{_STATUS_WIDTH}}  "
            f"{result.name:<{width}}  {result.resource}"
        )
        if result.detail:
            print(f"  {'':<{_STATUS_WIDTH}}  {result.detail}")

    passed = sum(1 for result in results if result.passed)
    failed = sum(1 for result in results if result.status == FAIL)
    unsupported = sum(1 for result in results if result.status == UNSUPPORTED)

    print()
    counts = f"{passed} passed, {failed} failed"
    if unsupported:
        counts += f", {unsupported} unsupported"
    print(f"{counts} of {len(results)} case(s)")

    if unsupported:
        print(
            "An unsupported case was not run, which is not a pass: its adapter "
            "could not be built, so nothing is known about the decision."
        )

    return 0 if passed == len(results) else 1


def cmd_check(args: argparse.Namespace) -> int:
    """Deprecated alias for `validate`."""
    print("note: `check` is a deprecated alias for `validate`.")
    return cmd_validate(args)


Command = Callable[[argparse.Namespace], int]


def _dispatch(command: Command, args: argparse.Namespace) -> int:
    """Run `command` under exactly one engine, or under both to compare them."""
    if getattr(args, "compare_engines", False):
        return _compare_engines(command, args)

    try:
        # The flag beats the environment variable, so a `HYDRACUDA_ENGINE` pinned
        # in a shell profile does not quietly override an explicit `--engine`.
        backend = getattr(args, "engine", None) or engine_backend()
    except BackendUnavailable as error:
        print(f"error: engine\n  {error}")
        return 1

    with use_backend(backend):
        return command(args)


def _compare_engines(command: Command, args: argparse.Namespace) -> int:
    """Run `command` under both engines and report any disagreement."""
    if not rust_available():
        print(
            "error: engine\n  --compare-engines runs both engines, and "
            "hydracuda._core is not importable, so there is only one to run. "
            "Build it with `maturin develop -m bindings/python/Cargo.toml`, or "
            "drop the flag."
        )
        return 1

    runs: dict[str, tuple[int, str]] = {}
    for backend in ("python", "rust"):
        captured = io.StringIO()
        with use_backend(backend), contextlib.redirect_stdout(captured):
            status = command(args)
        runs[backend] = (status, captured.getvalue())

    python_status, python_output = runs["python"]
    rust_status, rust_output = runs["rust"]

    # The Python run is the one printed, because it is the reference
    # implementation and its output is what the recorded golden file holds.
    print(python_output, end="")

    if python_status == rust_status and _comparable(python_output) == _comparable(
        rust_output
    ):
        print(f"Both engines agree (exit {python_status}).")
        return python_status

    print()
    print(
        "The engines disagree. This is a HYDRACUDA bug, not a finding about the "
        "policy — please report it with the policy file and the diff below."
    )
    if python_status != rust_status:
        print(f"exit status: python {python_status}, rust {rust_status}")
    for line in difflib.unified_diff(
        _comparable(python_output),
        _comparable(rust_output),
        fromfile="python",
        tofile="rust",
        lineterm="",
    ):
        print(line)
    return ENGINE_DIVERGENCE_EXIT


def _comparable(output: str) -> list[str]:
    """Output lines with the engine header dropped.

    That header names the engine that produced the run, so it differs between the
    two by construction. Comparing it would report every single run as a
    divergence and make the flag useless.
    """
    return [line for line in output.splitlines() if not line.startswith("Engine: ")]


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
        subparser.add_argument(
            "--engine",
            choices=("python", "rust"),
            default=None,
            help="Which engine decides (default: $HYDRACUDA_ENGINE, else "
            "whichever is available). This flag overrides the variable.",
        )
        subparser.add_argument(
            "--compare-engines",
            action="store_true",
            help="Run both engines and report any disagreement, exiting "
            f"{ENGINE_DIVERGENCE_EXIT} if they differ. Requires the compiled "
            "engine.",
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

    test_parser = subparsers.add_parser(
        "test",
        help="Run the policy's `tests:` block: the requests the author says it "
        "should allow and refuse",
    )
    add_policy_argument(test_parser)

    check_parser = subparsers.add_parser(
        "check", help="Deprecated alias for `validate`"
    )
    add_policy_argument(check_parser)
    check_parser.set_defaults(strict=False)

    args = parser.parse_args()

    if args.command is None:
        parser.print_usage()
        sys.exit(0)

    # `init` writes a file and evaluates nothing, so it is not dispatched through
    # engine selection: failing it because `HYDRACUDA_ENGINE=rust` is set on a
    # machine with no extension would refuse to create a starter policy over a
    # setting that starter policy never consults.
    if args.command == "init":
        sys.exit(cmd_init(args))

    commands: dict[str, Command] = {
        "validate": cmd_validate,
        "plan": cmd_plan,
        "test": cmd_test,
        "check": cmd_check,
    }
    sys.exit(_dispatch(commands[args.command], args))


if __name__ == "__main__":
    main()
