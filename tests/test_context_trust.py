"""Tests for the `when` context trust boundary.

`where` tests agent-controlled parameters. `when` tests context that the agent
must not be able to influence. These tests pin the mechanisms that enforce
that separation — see the "Trust model" section of docs/policy-spec.md.
"""

import pytest

from hydracuda.engine import PolicyEngine
from hydracuda.policy import Policy, PolicyError, Rule, parse_policy
from hydracuda.proxy import ContextError, ToolCallProxy


def engine_for(rules, audit_path, pinned_context=None, mode="enforce"):
    return PolicyEngine(
        Policy(
            version=2,
            mode=mode,
            rules=list(rules),
            audit_path=audit_path,
            pinned_context=list(pinned_context or []),
        )
    )


TRUST_RULES = [
    Rule(
        resource="read_file",
        action="deny",
        name="untrusted-denied",
        when={"trust": {"equals": "untrusted"}},
    ),
    Rule(resource="read_file", action="allow", name="allow-reads"),
]


async def handler(tool_name: str, params: dict) -> dict:
    return {"executed": tool_name}


# --- separation of params and context ------------------------------------


def test_when_does_not_read_params(tmp_path):
    engine = engine_for(TRUST_RULES, str(tmp_path / "a.db"))

    # A parameter of the same name must not satisfy a `when` condition — that
    # would let the agent assert its own trust level.
    decision = engine.evaluate("read_file", {"trust": "untrusted"}, {})
    assert decision.action == "allow"
    assert decision.rule == "allow-reads"


def test_where_does_not_read_context(tmp_path):
    rules = [
        Rule(
            resource="read_file",
            action="deny",
            name="bad-path",
            where={"path": {"matches": ["/etc/"]}},
        ),
        Rule(resource="read_file", action="allow", name="allow-reads"),
    ]
    engine = engine_for(rules, str(tmp_path / "a.db"))

    decision = engine.evaluate("read_file", {}, {"path": "/etc/passwd"})
    assert decision.action == "allow"


def test_when_matches_only_on_real_context(tmp_path):
    engine = engine_for(TRUST_RULES, str(tmp_path / "a.db"))

    assert engine.evaluate("read_file", {}, {"trust": "untrusted"}).action == "deny"
    assert engine.evaluate("read_file", {}, {"trust": "trusted"}).action == "allow"
    # Absent context field satisfies no value operator, so the deny rule does
    # not fire and evaluation falls through.
    assert engine.evaluate("read_file", {}, {}).action == "allow"


# --- pinned context ------------------------------------------------------


@pytest.mark.asyncio
async def test_pinned_context_is_used_for_evaluation(tmp_path):
    import sqlite3

    db = str(tmp_path / "audit.db")
    proxy = ToolCallProxy(
        engine_for(TRUST_RULES, db, pinned_context=["trust"]),
        pinned_context={"trust": "untrusted"},
    )

    with pytest.raises(PermissionError):
        await proxy.call("read_file", {"path": "/tmp/x"}, handler)

    conn = sqlite3.connect(db)
    assert conn.execute("SELECT rule FROM audit_log").fetchone() == (
        "untrusted-denied",
    )
    conn.close()


@pytest.mark.asyncio
async def test_per_call_context_cannot_override_a_pinned_field(tmp_path):
    proxy = ToolCallProxy(
        engine_for(TRUST_RULES, str(tmp_path / "audit.db"), pinned_context=["trust"]),
        pinned_context={"trust": "untrusted"},
    )

    # The bypass this exists to stop: claiming a better trust level per call.
    with pytest.raises(ContextError, match=r"may not override pinned field\(s\)"):
        await proxy.call("read_file", {}, handler, context={"trust": "trusted"})


@pytest.mark.asyncio
async def test_per_call_context_may_add_unpinned_fields(tmp_path):
    rules = [
        Rule(
            resource="read_file",
            action="deny",
            name="prod-denied",
            when={"env": {"equals": "prod"}},
        ),
        Rule(resource="read_file", action="allow", name="allow-reads"),
    ]
    proxy = ToolCallProxy(
        engine_for(rules, str(tmp_path / "audit.db"), pinned_context=["trust"]),
        pinned_context={"trust": "trusted"},
    )

    with pytest.raises(PermissionError):
        await proxy.call("read_file", {}, handler, context={"env": "prod"})
    assert await proxy.call("read_file", {}, handler, context={"env": "dev"}) == {
        "executed": "read_file"
    }


@pytest.mark.asyncio
async def test_params_and_context_may_not_be_the_same_object(tmp_path):
    proxy = ToolCallProxy(engine_for(TRUST_RULES, str(tmp_path / "audit.db")))
    params = {"trust": "trusted"}

    with pytest.raises(ContextError, match="must not be the same object"):
        await proxy.call("read_file", params, handler, context=params)


@pytest.mark.asyncio
async def test_mutating_the_pinned_dict_after_construction_has_no_effect(tmp_path):
    pinned = {"trust": "untrusted"}
    proxy = ToolCallProxy(
        engine_for(TRUST_RULES, str(tmp_path / "audit.db"), pinned_context=["trust"]),
        pinned_context=pinned,
    )

    pinned["trust"] = "trusted"

    with pytest.raises(PermissionError):
        await proxy.call("read_file", {}, handler)


# --- policy-declared pinning requirement --------------------------------


def test_proxy_refuses_to_construct_without_required_pinned_context(tmp_path):
    engine = engine_for(
        TRUST_RULES, str(tmp_path / "audit.db"), pinned_context=["trust", "agent"]
    )

    with pytest.raises(ContextError, match=r"pinned context field\(s\) \['agent', 'trust'\]"):
        ToolCallProxy(engine)


def test_proxy_refuses_partial_pinned_context(tmp_path):
    engine = engine_for(
        TRUST_RULES, str(tmp_path / "audit.db"), pinned_context=["trust", "agent"]
    )

    with pytest.raises(ContextError, match=r"\['agent'\]"):
        ToolCallProxy(engine, pinned_context={"trust": "trusted"})


def test_proxy_constructs_when_requirement_is_met(tmp_path):
    engine = engine_for(
        TRUST_RULES, str(tmp_path / "audit.db"), pinned_context=["trust"]
    )
    assert ToolCallProxy(engine, pinned_context={"trust": "trusted"}) is not None


def test_no_requirement_means_no_pinning_needed(tmp_path):
    engine = engine_for(TRUST_RULES, str(tmp_path / "audit.db"))
    assert ToolCallProxy(engine) is not None


# --- policy introspection ------------------------------------------------


def test_when_fields_reported():
    policy = parse_policy(
        {
            "version": 2,
            "pinned_context": ["trust"],
            "rules": [
                {
                    "resource": "read_file",
                    "action": "deny",
                    "when": {"trust": {"equals": "untrusted"}, "env": {"equals": "prod"}},
                }
            ],
        }
    )
    assert policy.when_fields() == {"trust", "env"}
    # `env` gates a decision but is not pinned, so the guarantee rests on the
    # integrator. `validate` surfaces this.
    assert policy.unpinned_when_fields() == {"env"}


def test_pinned_context_must_be_a_list_of_strings():
    with pytest.raises(PolicyError, match="'pinned_context' must be a list"):
        parse_policy({"version": 2, "pinned_context": "trust"})


def test_pinned_context_rejected_in_v1():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['pinned_context'\]"):
        parse_policy({"version": 1, "tools": {}, "pinned_context": ["trust"]})


def test_advanced_example_pins_its_when_field(examples_dir):
    from hydracuda.policy import load_policy

    policy = load_policy(str(examples_dir / "policy-advanced.yaml"))
    assert policy.unpinned_when_fields() == set()
