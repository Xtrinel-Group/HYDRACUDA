"""HYDRACUDA Dashboard — read-only audit log visualization.

Run: python -m dashboard.app
Opens at http://localhost:8321

The dashboard is a consumer of the audit log and nothing else. It holds no
policy state, never imports `hydracuda`, and cannot influence a decision. The
core runtime and the CLI work identically whether it is running or not, and
Flask is an optional extra rather than a dependency.

"Read-only" is enforced by the driver, not promised in prose: connections are
opened `mode=ro`. That matters beyond hygiene — the audit log is written by a
live proxy, and a read-write connection can create journal files beside it and
take locks that block the writer.
"""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from flask import Flask, jsonify, render_template, request

app = Flask(__name__, template_folder="templates", static_folder="static")

DEFAULT_DB = ".hydracuda/audit.db"

#: Cap on `?limit=`. A dashboard page cannot usefully render more, and an
#: unbounded limit turns one request into an out-of-memory fetch.
MAX_LIMIT = 1000

DEFAULT_LIMIT = 100


def get_db_path() -> str:
    return os.environ.get("HYDRACUDA_AUDIT_DB", DEFAULT_DB)


@contextmanager
def open_db():
    """Yield a read-only connection, or None when there is no audit log yet.

    Always closes. The previous version closed only on the success path, so any
    query error leaked a connection for the lifetime of the process.
    """
    path = Path(get_db_path())
    if not path.exists():
        yield None
        return

    conn = sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True)
    try:
        yield conn
    finally:
        conn.close()


def query(conn, sql: str, params=()) -> list | None:
    """Run a read query, returning None if the audit table does not exist.

    A database file can exist before any decision has been recorded — the proxy
    creates the table on its first write. That used to surface as a 500.
    """
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return None


def query_arg(name: str, default: int, maximum: int | None = None) -> int:
    """Read an integer query argument, ignoring anything unparseable.

    `?limit=abc` raised ValueError and returned a 500.
    """
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    if value < 0:
        return default
    return min(value, maximum) if maximum is not None else value


def no_audit_log(reason: str):
    return jsonify({"error": reason, "path": get_db_path()})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    with open_db() as conn:
        if conn is None:
            return no_audit_log("Audit database not found")

        # COALESCE, because rows written before the `enforced` column existed
        # have NULL there, and every decision back then was enforced.
        rows = query(
            conn,
            "SELECT action, COALESCE(enforced, 1), COUNT(*) FROM audit_log "
            "GROUP BY action, COALESCE(enforced, 1)",
        )
        if rows is None:
            return no_audit_log("Audit database has no decisions yet")

        top_tools = query(
            conn,
            "SELECT tool, COUNT(*) AS n FROM audit_log "
            "GROUP BY tool ORDER BY n DESC LIMIT 10",
        )

    counts = {"allow": 0, "deny": 0, "review": 0}
    unenforced = 0
    for action, enforced, count in rows:
        counts[action] = counts.get(action, 0) + count
        if not enforced:
            unenforced += count

    return jsonify(
        {
            "total": sum(counts.values()),
            "allow": counts["allow"],
            "deny": counts["deny"],
            "review": counts["review"],
            # Decisions that were computed and logged but not acted on, because
            # the policy was in shadow mode. Without this the counters above
            # read as calls that were stopped.
            "unenforced": unenforced,
            "top_tools": [{"tool": tool, "count": n} for tool, n in top_tools or []],
        }
    )


@app.route("/api/history")
def history():
    limit = query_arg("limit", DEFAULT_LIMIT, MAX_LIMIT)
    offset = query_arg("offset", 0)
    action_filter = request.args.get("action")
    tool_filter = request.args.get("tool")

    sql = (
        "SELECT id, timestamp, tool, action, reason, params, mode, "
        "COALESCE(enforced, 1) FROM audit_log"
    )
    conditions = []
    values: list = []
    if action_filter:
        conditions.append("action = ?")
        values.append(action_filter)
    if tool_filter:
        conditions.append("tool LIKE ?")
        values.append(f"%{tool_filter}%")
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    values.extend([limit, offset])

    with open_db() as conn:
        rows = query(conn, sql, values) if conn is not None else None

    return jsonify(
        [
            {
                "id": row[0],
                "timestamp": row[1],
                "tool": row[2],
                "action": row[3],
                "reason": row[4],
                "params": row[5],
                "mode": row[6],
                "enforced": bool(row[7]),
            }
            for row in rows or []
        ]
    )


@app.route("/api/timeline")
def timeline():
    with open_db() as conn:
        rows = (
            query(
                conn,
                "SELECT substr(timestamp, 1, 16) AS minute, action, COUNT(*) "
                "FROM audit_log GROUP BY minute, action ORDER BY minute",
            )
            if conn is not None
            else None
        )

    return jsonify(
        [
            {"minute": row[0], "action": row[1], "count": row[2]}
            for row in rows or []
        ]
    )


if __name__ == "__main__":
    print("HYDRACUDA Dashboard: http://localhost:8321")
    app.run(host="127.0.0.1", port=8321, debug=False)
