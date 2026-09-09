"""Tests for the dashboard's place in the system, and for the dashboard itself.

Two separate concerns:

1. The dashboard is optional and downstream. The core runtime and the CLI must
   work with it absent, and it must hold no policy state — it reads the audit
   log and nothing else. Those tests do not need Flask.
2. The API is a faithful report of what the audit log says, including whether a
   decision was actually enforced.
"""

import ast
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The dashboard is not part of the installed wheel, so the repository root has
# to be importable for `dashboard.app` to be reachable at all.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DASHBOARD_APP = REPO_ROOT / "dashboard" / "app.py"


@pytest.fixture
def dashboard_app():
    """The dashboard module, skipped when the optional extra is not installed.

    Deliberately not a module-level import: the tests proving that the core and
    the CLI run headless must still run in exactly the environment where Flask
    is missing.
    """
    pytest.importorskip("flask", reason="dashboard extra not installed")

    import dashboard.app

    return dashboard.app


# --- the dashboard is optional and downstream ----------------------------
#
# These are the Step 4 guarantees. They are asserted about the source rather
# than mocked, because the point is that the dependency edge does not exist.


def test_the_core_package_does_not_reference_flask_or_the_dashboard():
    """A one-way edge: nothing under src/ may import the dashboard."""
    offenders = []
    for path in (REPO_ROOT / "src").rglob("*.py"):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            statement = line.strip()
            if not statement.startswith(("import ", "from ")):
                continue
            if "flask" in statement.lower() or "dashboard" in statement.lower():
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number} {statement}")
    assert offenders == []


def test_the_dashboard_does_not_import_hydracuda():
    """It cannot hold policy state if it cannot reach the policy code.

    If the dashboard ever needs to read a policy file, that is a design change
    to raise explicitly — not something to let in through an import.
    """
    imports = [
        line.strip()
        for line in DASHBOARD_APP.read_text().splitlines()
        if line.strip().startswith(("import ", "from "))
    ]
    assert imports
    assert not [line for line in imports if "hydracuda" in line.lower()]


def test_the_dashboard_reads_no_policy_file():
    source = DASHBOARD_APP.read_text()
    assert "load_policy" not in source
    assert "yaml" not in source
    assert ".yaml" not in source


def test_the_dashboard_issues_no_write_statements():
    """Checks the string literals, not the prose — the docstring says "create"."""
    literals = [
        node.value.upper().lstrip()
        for node in ast.walk(ast.parse(DASHBOARD_APP.read_text()))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    writes = ("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "REPLACE")
    assert [text for text in literals if text.startswith(writes)] == []


#: Blocks `import flask` and `import dashboard` in a subprocess, so "runs
#: headless" is demonstrated rather than assumed from the dependency list.
IMPORT_BLOCKER = """
import sys

class _Blocked:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {"flask", "dashboard"}:
            raise ImportError(f"{name} is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())
"""


def run_headless(body: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", IMPORT_BLOCKER + body],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_the_core_imports_with_flask_unavailable():
    result = run_headless(
        "import hydracuda\n"
        "from hydracuda import PolicyEngine, ToolCallProxy, load_policy\n"
        "print('ok')\n"
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_the_cli_runs_with_flask_unavailable():
    """`hydracuda validate` must not need the dashboard installed or running."""
    result = run_headless(
        "import sys\n"
        "sys.argv = ['hydracuda', 'validate', 'examples/policy.yaml']\n"
        "from hydracuda.cli import main\n"
        "try:\n"
        "    main()\n"
        "except SystemExit as e:\n"
        "    sys.exit(e.code)\n"
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "Policy is valid." in result.stdout


def test_a_policy_decision_needs_no_dashboard():
    """The full intercept-to-audit loop, with the dashboard unimportable."""
    result = run_headless(
        "import asyncio, sys\n"
        "from hydracuda import PolicyEngine, ToolCallProxy, load_policy\n"
        "policy = load_policy('examples/policy.yaml')\n"
        "proxy = ToolCallProxy(PolicyEngine(policy), audit_path=None)\n"
        "async def main():\n"
        "    try:\n"
        "        await proxy.call('delete_record', {'id': 1}, None)\n"
        "    except PermissionError:\n"
        "        print('denied')\n"
        "asyncio.run(main())\n"
    )
    assert result.returncode == 0, result.stderr
    assert "denied" in result.stdout


# --- the API -------------------------------------------------------------


@pytest.fixture
def audit_db(tmp_path, monkeypatch):
    """An audit database holding one enforced deny, one allow, one shadow deny.

    The shadow row is the interesting one: action 'deny', enforced 0, meaning
    the call ran regardless.
    """
    path = tmp_path / "audit.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, timestamp TEXT, "
        "tool TEXT, action TEXT, reason TEXT, params TEXT, rule TEXT, "
        "mode TEXT, enforced INTEGER, normalization TEXT)"
    )
    conn.executemany(
        "INSERT INTO audit_log (timestamp, tool, action, reason, params, rule, "
        "mode, enforced, normalization) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                "2026-09-09T10:00:00+00:00", "read_file", "allow", "Allowed.",
                "{}", "allow-file-reads", "enforce", 1, None,
            ),
            (
                "2026-09-09T10:01:00+00:00", "delete_record", "deny",
                "Destructive operation.", "{}", "block-deletes", "enforce", 1, None,
            ),
            (
                "2026-09-09T10:02:00+00:00", "delete_record", "deny",
                "Destructive operation.", "{}", "block-deletes", "shadow", 0, None,
            ),
        ],
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("HYDRACUDA_AUDIT_DB", str(path))
    return path


@pytest.fixture
def client(dashboard_app, audit_db):
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def test_stats_counts_each_action(client):
    data = client.get("/api/stats").get_json()
    assert data["total"] == 3
    assert (data["allow"], data["deny"], data["review"]) == (1, 2, 0)


def test_stats_reports_decisions_that_were_not_enforced(client):
    """Two denies are shown, but only one call was actually stopped.

    Without this number the counters read as calls that were blocked, which is
    wrong for every row written in shadow mode.
    """
    assert client.get("/api/stats").get_json()["unenforced"] == 1


def test_history_says_whether_each_decision_was_enforced(client):
    rows = client.get("/api/history").get_json()
    assert [row["enforced"] for row in rows] == [False, True, True]
    assert rows[0]["mode"] == "shadow"


def test_history_filters_by_action_and_tool(client):
    assert len(client.get("/api/history?action=allow").get_json()) == 1
    assert len(client.get("/api/history?tool=delete").get_json()) == 2


def test_history_survives_an_unparseable_limit(client):
    """`?limit=abc` raised ValueError and returned a 500."""
    response = client.get("/api/history?limit=abc&offset=nope")
    assert response.status_code == 200
    assert len(response.get_json()) == 3


def test_history_caps_the_limit(dashboard_app):
    # An unbounded limit turns one request into a full-table fetch.
    huge = dashboard_app.MAX_LIMIT * 100
    with dashboard_app.app.test_request_context(f"/api/history?limit={huge}"):
        capped = dashboard_app.query_arg("limit", 100, dashboard_app.MAX_LIMIT)
    assert capped == dashboard_app.MAX_LIMIT


def test_timeline_groups_by_minute(client):
    rows = client.get("/api/timeline").get_json()
    assert {row["minute"] for row in rows} == {
        "2026-09-09T10:00", "2026-09-09T10:01", "2026-09-09T10:02"
    }


# --- read-only -----------------------------------------------------------


def test_the_connection_cannot_write(dashboard_app, audit_db):
    """`mode=ro` makes the read-only claim the driver's job, not a convention.

    The audit log has a live writer. A read-write connection here can create
    journal files beside it and take locks that block the proxy.
    """
    with dashboard_app.open_db() as conn:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM audit_log")


def test_serving_requests_creates_no_files_beside_the_audit_log(client, tmp_path):
    before = sorted(p.name for p in tmp_path.iterdir())

    client.get("/api/stats")
    client.get("/api/history")
    client.get("/api/timeline")

    assert sorted(p.name for p in tmp_path.iterdir()) == before == ["audit.db"]


def test_a_missing_database_is_reported_not_created(client, tmp_path, monkeypatch):
    missing = tmp_path / "nowhere" / "audit.db"
    monkeypatch.setenv("HYDRACUDA_AUDIT_DB", str(missing))

    assert "error" in client.get("/api/stats").get_json()
    assert client.get("/api/history").get_json() == []
    assert client.get("/api/timeline").get_json() == []
    assert not missing.exists()


def test_a_database_with_no_decisions_yet_does_not_error(client, tmp_path, monkeypatch):
    """The proxy creates audit_log on its first write, so the gap is reachable."""
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    monkeypatch.setenv("HYDRACUDA_AUDIT_DB", str(empty))

    assert client.get("/api/stats").status_code == 200
    assert "error" in client.get("/api/stats").get_json()
    assert client.get("/api/history").get_json() == []


def test_rows_predating_the_enforced_column_count_as_enforced(client, tmp_path, monkeypatch):
    """A v0.2.0 database migrated in place has NULL there, and back then every
    decision was enforced."""
    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    conn.execute(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, timestamp TEXT, "
        "tool TEXT, action TEXT, reason TEXT, params TEXT, rule TEXT, "
        "mode TEXT, enforced INTEGER, normalization TEXT)"
    )
    conn.execute(
        "INSERT INTO audit_log (timestamp, tool, action, reason, params) "
        "VALUES ('2026-09-09T10:00:00+00:00', 'read_file', 'deny', 'No.', '{}')"
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("HYDRACUDA_AUDIT_DB", str(legacy))

    assert client.get("/api/stats").get_json()["unenforced"] == 0
    assert client.get("/api/history").get_json()[0]["enforced"] is True


# --- against a real audit log --------------------------------------------


async def test_the_api_reads_a_log_the_proxy_actually_wrote(
    dashboard_app, tmp_path, monkeypatch
):
    """End to end, with the schema the proxy writes rather than a copy of it.

    A hand-built fixture can drift from the real table. This runs a shadow-mode
    policy — where a denied call executes anyway — and checks the dashboard
    reports it as logged but not enforced.
    """
    from hydracuda import PolicyEngine, ToolCallProxy
    from hydracuda.policy import parse_policy

    audit = tmp_path / "real.db"
    policy = parse_policy(
        {
            "version": 2,
            "mode": "shadow",
            "default_action": "deny",
            "rules": [{"name": "block-deletes", "resource": "delete_record",
                       "action": "deny", "reason": "Destructive."}],
        }
    )
    proxy = ToolCallProxy(PolicyEngine(policy), audit_path=str(audit))

    async def handler(tool, params):
        return "ran"

    # Shadow mode: the decision is deny, and the call runs regardless.
    assert await proxy.call("delete_record", {"id": 1}, handler) == "ran"

    monkeypatch.setenv("HYDRACUDA_AUDIT_DB", str(audit))
    dashboard_app.app.config.update(TESTING=True)
    client = dashboard_app.app.test_client()

    stats = client.get("/api/stats").get_json()
    assert (stats["total"], stats["deny"], stats["unenforced"]) == (1, 1, 1)

    (row,) = client.get("/api/history").get_json()
    assert row["tool"] == "delete_record"
    assert row["action"] == "deny"
    assert row["enforced"] is False
    assert row["mode"] == "shadow"


# --- output escaping -----------------------------------------------------

TEMPLATE = REPO_ROOT / "dashboard" / "templates" / "index.html"


def test_a_tool_name_is_returned_verbatim_by_the_api(client, audit_db):
    """The API is JSON, so it must not mangle the value; the page escapes it."""
    conn = sqlite3.connect(audit_db)
    conn.execute(
        "INSERT INTO audit_log (timestamp, tool, action, reason, params, enforced) "
        "VALUES ('2026-09-09T10:03:00+00:00', ?, 'deny', 'No.', '{}', 1)",
        ("<img src=x onerror=alert(1)>",),
    )
    conn.commit()
    conn.close()

    rows = client.get("/api/history").get_json()
    assert rows[0]["tool"] == "<img src=x onerror=alert(1)>"


#: Interpolations that are safe for a reason other than `esc()`, each reviewed
#: individually. Anything not here and not `esc(...)` fails the test below.
REVIEWED_INTERPOLATIONS = {
    # Restricted to the three actions the stylesheet knows, so a value from the
    # database cannot become an attribute or a class of its own choosing.
    "actionClass(r.action)",
    # The parameter inside actionClass, reachable only past that allowlist.
    "action",
    # A local built above, already escaped at construction.
    "enforced",
    # Integers from COUNT(*), and the sink is textContent.
    "d.total",
    "d.unenforced",
}

#: Sinks that interpret markup. textContent does not, so it is not listed.
HTML_SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write")


def test_every_interpolation_in_the_page_is_escaped_or_reviewed():
    """The guard has to be structural, not a list of the fields caught so far.

    A tool name is chosen by the agent being policed and a reason string quotes
    it back, so both are untrusted input rendered into this page — unescaped,
    that was script execution. `params` is the raw agent-supplied arguments and
    is deliberately not rendered; this fails if anyone adds it to a row without
    escaping.
    """
    source = TEMPLATE.read_text()
    assert "function esc(" in source

    unescaped = [
        expression
        for expression in re.findall(r"\$\{([^}]*)\}", source)
        if not expression.startswith("esc(")
        and expression.strip() not in REVIEWED_INTERPOLATIONS
    ]
    assert unescaped == [], f"unescaped interpolation(s): {unescaped}"


def test_the_page_uses_no_markup_sink_beyond_the_two_audited_ones():
    """Two innerHTML assignments are audited above. A third, or any other sink,
    is new attack surface that has not been reviewed."""
    source = TEMPLATE.read_text()
    lines = [
        f"{number}: {line.strip()}"
        for number, line in enumerate(source.splitlines(), start=1)
        # Skip the comment explaining the fix, which names the sink.
        if not line.strip().startswith("//")
        and any(sink in line for sink in HTML_SINKS)
    ]
    assert len(lines) == 2, lines
    assert all("innerHTML" in line for line in lines)


def test_the_api_does_not_expose_fields_the_page_would_render_unescaped():
    """`params` and `id` are returned but not rendered.

    Recorded so that the escaping audit above has a stated scope: these are the
    two fields in the payload that no row in the table reads.
    """
    source = TEMPLATE.read_text()
    assert "r.params" not in source
    assert "${r.id}" not in source
