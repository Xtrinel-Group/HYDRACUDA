#!/usr/bin/env python3
"""Record what the Python engine decides, for the Rust engine to be checked against.

Reads ``core/tests/differential/cases.yaml``, runs every case through the Python
implementation, and writes ``core/tests/differential/expected.json``.

The recording is committed so that ``cargo test`` needs no Python interpreter,
and ``tests/test_differential.py`` re-runs this script in memory and fails if the
committed file no longer matches — so the golden file cannot drift away from the
engine that produced it.

Run it after changing either engine's behaviour::

    python scripts/record_differential.py

and commit the result alongside the change.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "core" / "tests" / "differential" / "cases.yaml"
EXPECTED = ROOT / "core" / "tests" / "differential" / "expected.json"

sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from hydracuda._backend import use_backend  # noqa: E402
from hydracuda.engine import PolicyEngine  # noqa: E402
from hydracuda.introspect import analyze, plan, run_tests  # noqa: E402
from hydracuda.policy import PolicyError, parse_policy  # noqa: E402

#: The one diagnostic the Rust crate cannot produce, because it has no adapter
#: registry to try `build_adapter` against — see `core/src/introspect.rs`. Dropped
#: from the recording rather than special-cased on the Rust side, so the gap is
#: written down once and everything else is compared strictly.
UNPORTABLE_DIAGNOSTICS = {"adapter-unbuildable"}


def normalize_error(message: str) -> str:
    """Drop the parts of a message only one regex engine can produce.

    An invalid pattern is a load error in both engines, and the *prefix* — which
    field of which rule — is the part that has to agree. The tail is `re`'s or
    `fancy-regex`'s own wording and will never match. `core/tests/differential.rs`
    applies the identical truncation.
    """
    marker = "invalid regex"
    index = message.find(marker)
    if index == -1:
        return message
    return message[: index + len(marker)] + " <engine-specific detail elided>"


def record_scalar(source: str) -> dict[str, str]:
    """How ``yaml.safe_load`` resolves one plain scalar.

    Wrapped in a mapping so the scalar goes through the same implicit-resolution
    path a policy file's values do.
    """
    try:
        value = yaml.safe_load(f"a: {source}")["a"]
    except Exception as exc:  # noqa: BLE001 - any failure is the recorded outcome
        return {"error": type(exc).__name__}
    return {"repr": repr(value), "type": type(value).__name__}


def record_regex(case: dict[str, Any]) -> dict[str, Any]:
    """``re.search`` for one pattern against each of its subjects."""
    pattern = case["pattern"]
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return {"pattern": pattern, "error": str(exc)}
    return {
        "pattern": pattern,
        "matches": [bool(compiled.search(subject)) for subject in case["subjects"]],
    }


def record_example(case: dict[str, Any]) -> dict[str, Any]:
    """One of the shipped example policies, loaded from its own file."""
    path = case["path"]
    recorded = record_policy({"name": path, "policy": (ROOT / path).read_text(), **case})
    recorded["path"] = recorded.pop("name")
    return recorded


def record_policy(case: dict[str, Any]) -> dict[str, Any]:
    """One policy: either the load error it raises, or its decisions."""
    name = case["name"]
    try:
        raw = yaml.safe_load(case["policy"])
    except yaml.YAMLError as exc:
        return {"name": name, "yaml_error": str(exc)}

    try:
        policy = parse_policy(raw)
    except PolicyError as exc:
        return {"name": name, "load_error": normalize_error(str(exc))}

    # Explicitly the Python engine, for the whole recording rather than just the
    # engine on the next line. This file is the record of what Python decides, and
    # `PolicyEngine` uses the compiled engine by default wherever it is built —
    # including inside `plan` and `run_tests`, which construct their own. Without
    # the pin the golden file becomes a recording of Rust and
    # `core/tests/differential.rs` becomes a comparison of Rust against itself.
    with use_backend("python"):
        return record_loaded(name, case, policy)


def record_loaded(name: str, case: dict[str, Any], policy: Any) -> dict[str, Any]:
    """Everything a policy that loaded produces. Call inside ``use_backend``."""
    engine = PolicyEngine(policy)
    decisions = []
    for request in case.get("requests") or []:
        decision = engine.evaluate(
            request["resource"],
            request.get("params") or {},
            request.get("context") or {},
        )
        decisions.append(
            {
                "resource": decision.resource,
                "action": decision.action,
                "reason": decision.reason,
                "rule": decision.rule,
                "mode": decision.mode,
                "enforced": decision.enforced,
                "blocked": decision.blocked,
            }
        )

    return {
        "name": name,
        "policy": {
            "version": policy.version,
            "mode": policy.mode,
            "audit_path": policy.audit_path,
            "default_action": policy.default_action,
            "default_reason": policy.default_reason,
            "rules": [rule.label for rule in policy.rules],
            "when_fields": sorted(policy.when_fields()),
            "unpinned_when_fields": sorted(policy.unpinned_when_fields()),
            "declared_resources": policy.declared_resources(),
        },
        "decisions": decisions,
        "diagnostics": record_diagnostics(policy),
        # `plan` and `test` are recorded because `hcuda` is a second
        # implementation of both, and a CLI that agrees on every decision while
        # disagreeing about which resources exist or which cases pass is still two
        # tools telling one policy author different things.
        "plan": [
            {
                "resource": entry.resource,
                "action": entry.action,
                "rule": entry.rule,
                "reason": entry.reason,
                "conditional_rules": list(entry.conditional_rules),
            }
            for entry in plan(policy)
        ],
        "tests": [
            {
                "name": result.name,
                "resource": result.resource,
                "expect": result.expect,
                "status": result.status,
                "detail": result.detail,
            }
            for result in run_tests(policy)
        ],
    }


def record_diagnostics(policy: Any) -> list[dict[str, Any]]:
    """`validate`'s findings, minus the one Rust structurally cannot produce."""
    return [
        {
            "level": diagnostic.level,
            "code": diagnostic.code,
            "location": diagnostic.location,
            "message": diagnostic.message,
        }
        for diagnostic in analyze(policy).diagnostics
        if diagnostic.code not in UNPORTABLE_DIAGNOSTICS
    ]


def record() -> dict[str, Any]:
    cases = yaml.safe_load(CASES.read_text())
    return {
        "scalars": {source: record_scalar(source) for source in cases["scalars"]},
        "regexes": [record_regex(case) for case in cases["regexes"]],
        "examples": [record_example(case) for case in cases["examples"]],
        "policies": [record_policy(case) for case in cases["policies"]],
    }


def serialize(recording: dict[str, Any]) -> str:
    return json.dumps(recording, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed recording is stale, without rewriting it",
    )
    args = parser.parse_args()

    recorded = serialize(record())
    if args.check:
        if not EXPECTED.exists():
            print(f"{EXPECTED} does not exist; run this script without --check")
            return 1
        if EXPECTED.read_text() != recorded:
            print(f"{EXPECTED} is stale; run: python scripts/record_differential.py")
            return 1
        print(f"{EXPECTED} is current")
        return 0

    EXPECTED.write_text(recorded)
    print(f"wrote {EXPECTED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
