"""Both engines, in one process, on the same corpus.

`core/tests/differential.rs` compares Rust against a *recording* of Python, so
`cargo test` needs no interpreter. That is the right trade for CI and it leaves
one thing unproven: that the engine a Python caller actually reaches decides the
same way as the one it replaced. The recording cannot show that — it is a file.

So these tests build both engines from the same `Policy` object and compare the
decisions they return, field by field, over the whole differential corpus. They
skip when the extension is not built, which is the normal state of a fresh
checkout; `python scripts/build_extension.py` makes them run.

This is the check behind the promise that the pure-Python path can stay as a
fallback rather than a liability: whichever one loads, the verdict is the same.
"""

from pathlib import Path

import pytest
import yaml

from hydracuda._backend import (
    ENGINE_ENV_VAR,
    BackendUnavailable,
    engine_backend,
    engine_version,
    rust_available,
    use_backend,
)
from hydracuda.engine import PolicyEngine
from hydracuda.policy import Policy, PolicyError, Rule, parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES = REPO_ROOT / "core" / "tests" / "differential" / "cases.yaml"

needs_rust = pytest.mark.skipif(
    not rust_available(),
    reason="hydracuda._core is not built; run python scripts/build_extension.py",
)


# --- backend selection ---------------------------------------------------


def test_the_backend_is_one_of_two_answers():
    assert engine_backend() in ("python", "rust")


def test_python_can_always_be_forced():
    # The fallback is not conditional on anything, which is why it can be the
    # answer for a platform with no wheel.
    with use_backend("python"):
        assert engine_backend() == "python"
        assert PolicyEngine(parse_policy({"version": 2, "rules": []}))._rust is None


def test_an_unknown_backend_is_refused_rather_than_ignored(monkeypatch):
    # Silently falling back would mean a typo in a CI job runs the engine the job
    # was written to prove something about the other of.
    monkeypatch.setenv(ENGINE_ENV_VAR, "rusty")
    with pytest.raises(BackendUnavailable, match="is not a backend"):
        engine_backend()


def test_forcing_rust_without_the_extension_is_an_error_not_a_fallback(monkeypatch):
    monkeypatch.setattr("hydracuda._backend._core", None)
    monkeypatch.setenv(ENGINE_ENV_VAR, "rust")
    with pytest.raises(BackendUnavailable, match="not importable"):
        engine_backend()


def test_the_absent_extension_selects_python(monkeypatch):
    monkeypatch.setattr("hydracuda._backend._core", None)
    monkeypatch.delenv(ENGINE_ENV_VAR, raising=False)
    assert engine_backend() == "python"


@needs_rust
def test_the_extension_reports_the_crate_version():
    # Ties a loaded module to the source it was built from, so a stale build is
    # identifiable rather than merely suspected.
    assert engine_version() is not None


def test_engine_version_is_none_without_the_extension(monkeypatch):
    monkeypatch.setattr("hydracuda._backend._core", None)
    assert engine_version() is None


# --- decision parity over the differential corpus ------------------------


def load_cases() -> list[tuple[str, dict]]:
    """Every corpus policy that loads, paired with its requests.

    Load *errors* are not compared here — they are Python's, since the loader
    stayed in Python, and `core/tests/differential.rs` already checks Rust's
    against the same corpus.
    """
    if not CASES.exists():
        return []

    corpus = yaml.safe_load(CASES.read_text())
    cases: list[tuple[str, dict]] = []

    for case in corpus["policies"]:
        if case["name"].startswith("error-"):
            continue
        cases.append((case["name"], case))

    for case in corpus["examples"]:
        source = (REPO_ROOT / case["path"]).read_text()
        cases.append((case["path"], {**case, "policy": source}))

    return cases


#: Empty outside a checkout, where `core/` is not shipped. pytest skips a
#: parametrized test with no parameters, which is the wanted behaviour — and the
#: backend-selection tests above still run, because they need no corpus.
CORPUS = load_cases()


def decision_fields(decision) -> dict:
    """Everything about a decision that either engine could get wrong.

    `params` and `context` are excluded on purpose: they are the caller's own
    objects, attached by Python in both cases, so comparing them would test the
    test.
    """
    return {
        "resource": decision.resource,
        "action": decision.action,
        "reason": decision.reason,
        "rule": decision.rule,
        "mode": decision.mode,
        "enforced": decision.enforced,
        "blocked": decision.blocked,
    }


@needs_rust
@pytest.mark.parametrize("name,case", CORPUS, ids=[name for name, _ in CORPUS])
def test_both_engines_decide_identically(name, case):
    policy = parse_policy(yaml.safe_load(case["policy"]))

    with use_backend("python"):
        python_engine = PolicyEngine(policy)
    with use_backend("rust"):
        rust_engine = PolicyEngine(policy)

    assert python_engine._rust is None
    assert rust_engine._rust is not None
    assert rust_engine._rust.rule_count == len(policy.rules), (
        "the conversion dropped or invented a rule, which would make every "
        "comparison below meaningless"
    )

    requests = case.get("requests") or []
    assert requests, f"corpus case {name} has no requests to compare"

    for request in requests:
        arguments = (
            request["resource"],
            request.get("params") or {},
            request.get("context") or {},
        )
        expected = decision_fields(python_engine.evaluate(*arguments))
        actual = decision_fields(rust_engine.evaluate(*arguments))
        assert actual == expected, f"{name}: {request['resource']} decided differently"


@needs_rust
def test_the_comparison_would_notice_a_divergence():
    """The corpus check passes; this shows it is capable of failing."""
    policy = parse_policy(
        {"version": 2, "rules": [{"resource": "fs.read", "action": "deny"}]}
    )
    other = parse_policy(
        {"version": 2, "rules": [{"resource": "fs.read", "action": "allow"}]}
    )
    with use_backend("python"):
        python_engine = PolicyEngine(policy)
    with use_backend("rust"):
        rust_engine = PolicyEngine(other)

    assert decision_fields(python_engine.evaluate("fs.read")) != decision_fields(
        rust_engine.evaluate("fs.read")
    )


# --- the decision object is still Python's -------------------------------


@needs_rust
def test_the_decision_carries_the_caller_s_own_params_object():
    # The extension is handed a copy, because it takes a dict and a caller may
    # pass any mapping. What comes back out has to be the original: the audit log
    # records it, and a copy would silently drop a later mutation the proxy made.
    policy = parse_policy({"version": 2, "default_action": "allow", "rules": []})
    with use_backend("rust"):
        engine = PolicyEngine(policy)
    params = {"path": "/tmp/x"}
    context = {"agent": "bot"}
    decision = engine.evaluate("fs.read", params, context)
    assert decision.params is params
    assert decision.context is context
    assert decision.notes == []


# --- rule lists the compiled engine refuses ------------------------------


@needs_rust
def test_a_rule_the_extension_refuses_is_reported_as_a_policy_error():
    # Reachable only by building the dataclasses directly — `parse_policy` would
    # have rejected this action. The point is the exception *type*: a caller
    # catching `PolicyError` must not have to know which engine is loaded.
    policy = Policy(version=2, rules=[Rule(resource="x", action="destroy")])
    with use_backend("rust"):
        with pytest.raises(PolicyError, match="unknown action"):
            PolicyEngine(policy)


@needs_rust
def test_an_unrepresentable_parameter_is_refused_rather_than_mismatched():
    """The one known behavioural gap between the engines.

    The pure-Python engine compares any object with `==` and stringifies it for
    `matches`, so a tuple or a set reaches a rule and is tested against it. The
    compiled engine has no representation for one and refuses the request.

    Refusing is the deliberate choice. Coercing a tuple to a list would make
    `matches` compare against `[1, 2]` where Python compared against `(1, 2)` —
    a rule that quietly stops firing, which is the fail-open shape this project
    exists to prevent. An exception in the enforcement path stops the call.

    No policy format produces such a value: YAML gives lists, maps, scalars and
    dates. Only a Python caller passing one directly gets here.
    """
    policy = parse_policy(
        {
            "version": 2,
            "default_action": "allow",
            "rules": [
                {
                    "resource": "fs.read",
                    "action": "deny",
                    "where": {"path": {"matches": ["x"]}},
                }
            ],
        }
    )
    with use_backend("python"):
        python_engine = PolicyEngine(policy)
    with use_backend("rust"):
        rust_engine = PolicyEngine(policy)

    params = {"path": (1, 2)}
    assert python_engine.evaluate("fs.read", params).action == "allow"
    with pytest.raises(ValueError, match="cannot evaluate a parameter of type tuple"):
        rust_engine.evaluate("fs.read", params)
