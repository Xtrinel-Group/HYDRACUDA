"""Tests for policy `mode` handling, including shadow mode.

`mode` was parsed and validated in v0.2.0 but never read, so `shadow` blocked
calls exactly like `enforce`. These tests pin the wired-up behaviour.
"""

import pytest

from hydracuda.engine import PolicyEngine
from hydracuda.policy import Policy, Rule
from hydracuda.proxy import ReviewRequired, ToolCallProxy

RULES = [
    Rule(resource="read_file", action="allow", name="allow-reads"),
    Rule(resource="delete_record", action="deny", name="block-deletes"),
    Rule(resource="execute_shell", action="review", name="review-shell"),
]


def engine_for(mode: str, audit_path: str) -> PolicyEngine:
    return PolicyEngine(
        Policy(version=2, mode=mode, rules=list(RULES), audit_path=audit_path)
    )


async def handler(tool_name: str, params: dict) -> dict:
    return {"executed": tool_name}


# --- engine-level -------------------------------------------------------


@pytest.mark.parametrize("resource", ["read_file", "delete_record", "execute_shell"])
def test_shadow_mode_preserves_the_verdict(resource, tmp_path):
    enforce = engine_for("enforce", str(tmp_path / "a.db")).evaluate(resource, {})
    shadow = engine_for("shadow", str(tmp_path / "b.db")).evaluate(resource, {})

    assert shadow.action == enforce.action
    assert shadow.reason == enforce.reason


def test_shadow_mode_does_not_enforce_deny_or_review(tmp_path):
    engine = engine_for("shadow", str(tmp_path / "a.db"))

    assert engine.evaluate("delete_record", {}).enforced is False
    assert engine.evaluate("delete_record", {}).blocked is False
    assert engine.evaluate("execute_shell", {}).enforced is False
    assert engine.evaluate("unlisted", {}).blocked is False


def test_shadow_mode_leaves_allow_enforced(tmp_path):
    decision = engine_for("shadow", str(tmp_path / "a.db")).evaluate("read_file", {})
    assert decision.enforced is True
    assert decision.blocked is False


def test_enforce_mode_blocks(tmp_path):
    engine = engine_for("enforce", str(tmp_path / "a.db"))

    assert engine.evaluate("delete_record", {}).blocked is True
    assert engine.evaluate("execute_shell", {}).blocked is True
    assert engine.evaluate("read_file", {}).blocked is False


def test_review_mode_behaves_as_enforce(tmp_path):
    # `review` is reserved for the human-approval workflow and must not fail
    # open in the meantime.
    engine = engine_for("review", str(tmp_path / "a.db"))
    assert engine.evaluate("delete_record", {}).blocked is True


def test_decision_records_the_matched_rule(tmp_path):
    decision = engine_for("enforce", str(tmp_path / "a.db")).evaluate(
        "delete_record", {}
    )
    assert decision.rule == "block-deletes"
    assert decision.mode == "enforce"


def test_decision_records_no_rule_on_default_action(tmp_path):
    decision = engine_for("enforce", str(tmp_path / "a.db")).evaluate("unlisted", {})
    assert decision.rule is None


# --- proxy-level --------------------------------------------------------


@pytest.mark.asyncio
async def test_enforce_mode_raises_on_deny(tmp_path):
    db = str(tmp_path / "audit.db")
    proxy = ToolCallProxy(engine_for("enforce", db))

    with pytest.raises(PermissionError):
        await proxy.call("delete_record", {}, handler)


@pytest.mark.asyncio
async def test_enforce_mode_raises_on_review(tmp_path):
    db = str(tmp_path / "audit.db")
    proxy = ToolCallProxy(engine_for("enforce", db))

    with pytest.raises(ReviewRequired):
        await proxy.call("execute_shell", {}, handler)


@pytest.mark.asyncio
async def test_review_still_raises_not_implemented_error(tmp_path):
    # v0.2.0 raised NotImplementedError; integrators may catch that.
    db = str(tmp_path / "audit.db")
    proxy = ToolCallProxy(engine_for("enforce", db))

    with pytest.raises(NotImplementedError):
        await proxy.call("execute_shell", {}, handler)


@pytest.mark.asyncio
async def test_shadow_mode_executes_denied_calls(tmp_path):
    db = str(tmp_path / "audit.db")
    proxy = ToolCallProxy(engine_for("shadow", db))

    assert await proxy.call("delete_record", {}, handler) == {
        "executed": "delete_record"
    }
    assert await proxy.call("execute_shell", {}, handler) == {
        "executed": "execute_shell"
    }


@pytest.mark.asyncio
async def test_shadow_mode_records_the_true_verdict(tmp_path):
    import sqlite3

    db = str(tmp_path / "audit.db")
    proxy = ToolCallProxy(engine_for("shadow", db))
    await proxy.call("delete_record", {"id": "x"}, handler)

    conn = sqlite3.connect(db)
    row = conn.execute(
        "SELECT tool, action, rule, mode, enforced FROM audit_log"
    ).fetchone()
    conn.close()

    # A shadow-mode log answers both "what would this have blocked?" and
    # "what did we actually block?"
    assert row == ("delete_record", "deny", "block-deletes", "shadow", 0)


@pytest.mark.asyncio
async def test_audit_log_migrates_a_v0_2_0_database(tmp_path):
    import sqlite3

    db = tmp_path / "audit.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            tool TEXT,
            action TEXT,
            reason TEXT,
            params TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO audit_log (timestamp, tool, action, reason, params) "
        "VALUES ('2026-01-01T00:00:00+00:00', 'read_file', 'allow', 'ok', '{}')"
    )
    conn.commit()
    conn.close()

    proxy = ToolCallProxy(engine_for("enforce", str(db)))
    await proxy.call("read_file", {"path": "/tmp/x"}, handler)

    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT tool, action, mode FROM audit_log ORDER BY id"
    ).fetchall()
    conn.close()

    assert rows == [
        ("read_file", "allow", None),
        ("read_file", "allow", "enforce"),
    ]


@pytest.mark.asyncio
async def test_audit_path_without_a_parent_directory(tmp_path, monkeypatch):
    import sqlite3

    monkeypatch.chdir(tmp_path)
    proxy = ToolCallProxy(engine_for("enforce", "audit.db"))
    await proxy.call("read_file", {}, handler)

    conn = sqlite3.connect("audit.db")
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    conn.close()
