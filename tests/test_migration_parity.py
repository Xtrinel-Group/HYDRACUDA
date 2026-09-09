"""Regression tests for the Phase 1 refactor.

Two things are pinned here:

1. The core decision loop still produces the ALLOW/DENY/REVIEW outcomes that
   v0.2.0 produced for the version 1 policy format, with the same reason
   strings. `V0_2_0_DECISIONS` was recorded by running the request matrix
   through the pre-refactor engine at commit db88623.
2. examples/policy.yaml (version 2) and examples/policy-v1-legacy.yaml
   (version 1) decide identically, so the migration preserves behaviour.
"""

import pytest

from hydracuda.engine import PolicyEngine
from hydracuda.policy import load_policy

_DENY_PATTERN = "read_file: parameter 'path' matched deny pattern '{}'"
_ALLOWED = "all policy checks passed"
_DEFAULT_DENY = "{}: not listed in policy — default deny"

# (resource, params, expected action, expected reason) as produced by v0.2.0
# against examples/policy-v1-legacy.yaml.
V0_2_0_DECISIONS = [
    ("read_file", {"path": "/tmp/report.txt"}, "allow", _ALLOWED),
    ("read_file", {"path": "/etc/passwd"}, "deny", _DENY_PATTERN.format("/etc/")),
    # Traversal hits the "/etc/" pattern before "\.\.", which is the order the
    # patterns are declared in; the reason must name the first match.
    ("read_file", {"path": "../../etc/passwd"}, "deny", _DENY_PATTERN.format("/etc/")),
    ("read_file", {"path": "../../secret"}, "deny", _DENY_PATTERN.format("\\.\\.")),
    ("read_file", {"path": "/root/.ssh/id_rsa"}, "deny", _DENY_PATTERN.format("/root/")),
    ("read_file", {"path": "/home/user/notes.txt"}, "allow", _ALLOWED),
    # A parameter the request never supplies must not trip the deny rule.
    ("read_file", {}, "allow", _ALLOWED),
    ("read_file", {"other": "/etc/passwd"}, "allow", _ALLOWED),
    # Non-string values are stringified before matching.
    ("read_file", {"path": 42}, "allow", _ALLOWED),
    ("execute_shell", {"command": "ls -la"}, "review", "tool requires human review"),
    ("execute_shell", {"command": "rm -rf /"}, "review", "tool requires human review"),
    ("send_email", {"to": "admin@corp.com"}, "deny", _DEFAULT_DENY.format("send_email")),
    ("", {}, "deny", _DEFAULT_DENY.format("")),
    # Resource matching is case-sensitive.
    ("READ_FILE", {"path": "/tmp/x"}, "deny", _DEFAULT_DENY.format("READ_FILE")),
]

# delete_record is handled separately: the verdict is unchanged from v0.2.0 but
# the reason now reflects the policy's own `reason` field. See
# test_v1_deny_reason_now_reflects_the_policy.
REQUESTS = [(resource, params) for resource, params, _, _ in V0_2_0_DECISIONS] + [
    ("delete_record", {"id": "usr_123"}),
    ("delete_record", {}),
    ("read_file", {"path": "/etc/hydracuda/policy.yaml"}),
]


@pytest.fixture
def legacy_engine(examples_dir):
    return PolicyEngine(load_policy(str(examples_dir / "policy-v1-legacy.yaml")))


@pytest.fixture
def migrated_engine(examples_dir):
    return PolicyEngine(load_policy(str(examples_dir / "policy.yaml")))


@pytest.mark.parametrize("resource,params,action,reason", V0_2_0_DECISIONS)
def test_v1_decisions_match_v0_2_0(legacy_engine, resource, params, action, reason):
    decision = legacy_engine.evaluate(resource, params)
    assert (decision.action, decision.reason) == (action, reason)


def test_v1_deny_reason_now_reflects_the_policy(legacy_engine):
    # The one intended reason change: v0.2.0 discarded the per-tool `reason`
    # and always reported "tool blocked by policy". The verdict is unchanged.
    decision = legacy_engine.evaluate("delete_record", {"id": "usr_123"})
    assert decision.action == "deny"
    assert decision.reason == "Destructive operation. Blocked by default."


@pytest.mark.parametrize("resource,params", REQUESTS)
def test_migrated_policy_decides_identically(
    legacy_engine, migrated_engine, resource, params
):
    legacy = legacy_engine.evaluate(resource, params)
    migrated = migrated_engine.evaluate(resource, params)
    assert legacy.action == migrated.action, (
        f"{resource}({params}): v1 said {legacy.action} ({legacy.reason}), "
        f"v2 said {migrated.action} ({migrated.reason})"
    )


def test_both_representations_declare_the_same_surface(legacy_engine, migrated_engine):
    assert sorted(legacy_engine.policy.declared_resources()) == sorted(
        migrated_engine.policy.declared_resources()
    )


def test_evaluation_is_deterministic(migrated_engine):
    first = [migrated_engine.evaluate(r, p) for r, p in REQUESTS]
    second = [migrated_engine.evaluate(r, p) for r, p in REQUESTS]
    assert [(d.action, d.reason, d.rule) for d in first] == [
        (d.action, d.reason, d.rule) for d in second
    ]


def test_advanced_example_exercises_namespaced_resources(examples_dir):
    engine = PolicyEngine(load_policy(str(examples_dir / "policy-advanced.yaml")))

    assert engine.evaluate("github.repository.read", {}).action == "allow"
    assert engine.evaluate("github.repository.write", {}).action == "review"
    assert engine.evaluate("filesystem.read_file", {"path": "/etc/x"}).action == "allow"
    assert engine.evaluate("filesystem.delete_file", {}).action == "review"
    assert (
        engine.evaluate("filesystem.write_file", {"path": "/workspace/a"}).action
        == "allow"
    )
    assert (
        engine.evaluate("filesystem.write_file", {"path": "/etc/a"}).action == "deny"
    )
    # `when` narrows the surface for an untrusted caller without changing the
    # rules that apply to a trusted one.
    assert (
        engine.evaluate(
            "filesystem.read_file", {"mode": "write"}, {"trust": "untrusted"}
        ).action
        == "deny"
    )
    assert (
        engine.evaluate(
            "filesystem.read_file", {"mode": "write"}, {"trust": "trusted"}
        ).action
        == "allow"
    )
    # Nothing outside the declared surface is permitted.
    assert engine.evaluate("network.request", {}).action == "deny"
