"""HYDRACUDA Dashboard — read-only audit log visualization.

Run: python -m dashboard.app
Opens at http://localhost:8321
"""

import json
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__, template_folder="templates", static_folder="static")

DEFAULT_DB = ".hydracuda/audit.db"


def get_db_path() -> str:
    import os
    return os.environ.get("HYDRACUDA_AUDIT_DB", DEFAULT_DB)


def get_connection():
    db_path = get_db_path()
    if not Path(db_path).exists():
        return None
    return sqlite3.connect(db_path)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    conn = get_connection()
    if not conn:
        return jsonify({"error": "Audit database not found", "path": get_db_path()})

    cur = conn.cursor()
    cur.execute("SELECT action, COUNT(*) FROM audit_log GROUP BY action")
    action_counts = dict(cur.fetchall())

    cur.execute("SELECT COUNT(*) FROM audit_log")
    total = cur.fetchone()[0]

    cur.execute("SELECT tool, COUNT(*) FROM audit_log GROUP BY tool ORDER BY COUNT(*) DESC LIMIT 10")
    top_tools = [{"tool": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({
        "total": total,
        "allow": action_counts.get("allow", 0),
        "deny": action_counts.get("deny", 0),
        "review": action_counts.get("review", 0),
        "top_tools": top_tools,
    })


@app.route("/api/history")
def history():
    conn = get_connection()
    if not conn:
        return jsonify([])

    cur = conn.cursor()
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    action_filter = request.args.get("action")
    tool_filter = request.args.get("tool")

    query = "SELECT id, timestamp, tool, action, reason, params FROM audit_log"
    conditions = []
    params = []
    if action_filter:
        conditions.append("action = ?")
        params.append(action_filter)
    if tool_filter:
        conditions.append("tool LIKE ?")
        params.append(f"%{tool_filter}%")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cur.execute(query, params)
    rows = [
        {"id": r[0], "timestamp": r[1], "tool": r[2], "action": r[3], "reason": r[4], "params": r[5]}
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify(rows)


@app.route("/api/timeline")
def timeline():
    conn = get_connection()
    if not conn:
        return jsonify([])

    cur = conn.cursor()
    cur.execute("""
        SELECT substr(timestamp, 1, 16) as minute, action, COUNT(*)
        FROM audit_log GROUP BY minute, action ORDER BY minute
    """)
    rows = [{"minute": r[0], "action": r[1], "count": r[2]} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


if __name__ == "__main__":
    print("HYDRACUDA Dashboard: http://localhost:8321")
    app.run(host="127.0.0.1", port=8321, debug=False)
