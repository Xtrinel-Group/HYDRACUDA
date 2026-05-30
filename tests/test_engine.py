"""Unit tests for the BARACUDA policy engine."""

import pytest

from baracuda.engine import PolicyEngine
from baracuda.policy import Policy, ToolPolicy


def make_policy(tools: dict[str, ToolPolicy]) -> Policy:
    return Policy(version=1, tools=tools)


def test_unconfigured_tool_defaults_to_deny():
    engine = PolicyEngine(make_policy({}))
    decision = engine.evaluate("unknown_tool", {"arg": "value"})

    assert decision.action == "deny"
    assert "not listed in policy" in decision.reason


def test_tool_explicitly_denied():
    engine = PolicyEngine(make_policy({
        "dangerous_tool": ToolPolicy(allow=False),
    }))
    decision = engine.evaluate("dangerous_tool", {})

    assert decision.action == "deny"
    assert decision.reason == "tool blocked by policy"


def test_tool_set_to_review():
    engine = PolicyEngine(make_policy({
        "sensitive_tool": ToolPolicy(allow="review"),
    }))
    decision = engine.evaluate("sensitive_tool", {"x": 1})

    assert decision.action == "review"


def test_deny_pattern_match():
    engine = PolicyEngine(make_policy({
        "read_file": ToolPolicy(
            allow=True,
            parameter_rules={
                "path": {"deny_patterns": ["/etc/", "\\.\\."]}
            },
        ),
    }))
    decision = engine.evaluate("read_file", {"path": "/etc/passwd"})

    assert decision.action == "deny"
    assert "read_file" in decision.reason
    assert "path" in decision.reason
    assert "/etc/" in decision.reason


def test_no_deny_pattern_match_returns_allow():
    engine = PolicyEngine(make_policy({
        "read_file": ToolPolicy(
            allow=True,
            parameter_rules={
                "path": {"deny_patterns": ["/etc/", "\\.\\."]}
            },
        ),
    }))
    decision = engine.evaluate("read_file", {"path": "/home/user/notes.txt"})

    assert decision.action == "allow"
    assert decision.reason == "all policy checks passed"


def test_unlisted_tool_denied_by_default():
    engine = PolicyEngine(make_policy({
        "read_file": ToolPolicy(allow=True),
    }))
    decision = engine.evaluate("send_email", {"to": "admin@corp.com"})

    assert decision.action == "deny"
    assert "send_email" in decision.reason
    assert "default deny" in decision.reason


def test_delete_record_blocked():
    engine = PolicyEngine(make_policy({
        "delete_record": ToolPolicy(allow=False),
    }))
    decision = engine.evaluate("delete_record", {"id": "usr_123"})

    assert decision.action == "deny"
    assert decision.reason == "tool blocked by policy"
