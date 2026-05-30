"""Tool call interception layer for BARACUDA."""

import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from baracuda.engine import PolicyEngine


class ToolCallProxy:
    """Intercepts tool calls, enforces policy, and writes an audit log."""

    def __init__(self, engine: PolicyEngine, audit_path: str | None = None):
        self.engine = engine
        self.audit_path = audit_path or engine.policy.audit_path

    async def call(self, tool_name: str, params: dict, handler) -> dict:
        """Evaluate, log, and optionally execute a tool call."""
        decision = self.engine.evaluate(tool_name, params)
        await self._write_audit(decision)

        if decision.action == "deny":
            raise PermissionError(decision.reason)

        if decision.action == "review":
            raise NotImplementedError(f"tool call queued for human review: {tool_name}")

        return await handler(tool_name, params)

    async def _write_audit(self, decision) -> None:
        """Append a decision to the SQLite audit log."""
        db_path = Path(self.audit_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(
                """CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    tool TEXT,
                    action TEXT,
                    reason TEXT,
                    params TEXT
                )"""
            )
            await db.execute(
                "INSERT INTO audit_log (timestamp, tool, action, reason, params) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    decision.tool,
                    decision.action,
                    decision.reason,
                    json.dumps(decision.params),
                ),
            )
            await db.commit()
