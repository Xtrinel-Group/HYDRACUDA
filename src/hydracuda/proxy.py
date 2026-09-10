"""Tool call interception layer for HYDRACUDA.

This module is where the trust boundary lives. `PolicyEngine` is a pure
decision function and will evaluate whatever it is handed; the proxy is what
guarantees that the untrusted side of a tool call (the parameters the model
chose) cannot reach the trusted side (the context a `when` condition tests).

See the "Trust model" section of docs/policy-spec.md.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from hydracuda.adapters import Adapter, UndeclaredResource
from hydracuda.canonical import CanonicalizationError
from hydracuda.engine import Decision, PolicyEngine

_SCHEMA = """CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    tool TEXT,
    action TEXT,
    reason TEXT,
    params TEXT,
    rule TEXT,
    mode TEXT,
    enforced INTEGER,
    normalization TEXT
)"""

#: Columns added after v0.2.0. Existing audit databases are migrated in place
#: because CREATE TABLE IF NOT EXISTS will not add them.
_ADDED_COLUMNS = {
    "rule": "TEXT",
    "mode": "TEXT",
    "enforced": "INTEGER",
    "normalization": "TEXT",
}


class ReviewRequired(NotImplementedError):
    """Raised when a call needs human approval.

    Subclasses NotImplementedError, which is what v0.2.0 raised, so existing
    handlers keep catching it.
    """

    def __init__(self, decision: Decision):
        super().__init__(f"tool call queued for human review: {decision.tool}")
        self.decision = decision


class ContextError(ValueError):
    """Raised when evaluation context is assembled unsafely.

    Every case this covers is an integrator mistake that would let the caller
    of a tool influence the context its own request is judged against. It is
    raised rather than worked around, so the mistake fails closed.
    """


class ToolCallProxy:
    """Intercepts tool calls, enforces policy, and writes an audit log.

    `pinned_context` is evaluation context established once, at construction,
    from a source the agent cannot reach — a server-side session record, a
    verified credential, a deployment environment variable. Keys pinned here
    cannot be added to, overridden, or removed by any later `call()`, which is
    what makes a `when` condition on agent identity or trust level meaningful.

    If the loaded policy declares `pinned_context`, every field it names must
    be supplied here or construction fails.
    """

    def __init__(
        self,
        engine: PolicyEngine,
        audit_path: str | None = None,
        pinned_context: dict | None = None,
        adapter: Adapter | None = None,
    ):
        self.engine = engine
        self.audit_path = audit_path or engine.policy.audit_path
        self.pinned_context = dict(pinned_context or {})
        self.adapter = adapter

        required = set(engine.policy.pinned_context)
        missing = sorted(required - set(self.pinned_context))
        if missing:
            raise ContextError(
                f"policy requires pinned context field(s) {missing}, which were "
                f"not supplied to ToolCallProxy(pinned_context=...). These "
                f"fields gate policy decisions, so they must come from a source "
                f"the agent cannot influence."
            )

    def _resolve_context(self, params: dict, context: dict | None) -> dict:
        """Merge per-call context under the pinned context.

        Pinned keys win. A per-call attempt to set one is an error rather than
        a silent no-op, because that attempt is indistinguishable from the
        bypass it would be if pinning were absent.
        """
        context = context or {}

        if context is params:
            raise ContextError(
                "params and context must not be the same object — context would "
                "then be model-controlled, defeating every `when` condition."
            )

        overridden = sorted(set(context) & set(self.pinned_context))
        if overridden:
            raise ContextError(
                f"per-call context may not override pinned field(s) {overridden}"
            )

        return {**context, **self.pinned_context}

    def _refusal(
        self, tool_name: str, params: dict, context: dict, reason: str, rule: str
    ) -> Decision:
        """A denial decided at the boundary rather than by a policy rule.

        Recorded like any other decision so the audit log shows refusals, and
        enforced regardless of `mode` — shadow mode trials a policy, it does
        not disable the adapter's own preconditions.
        """
        return Decision(
            action="deny",
            reason=reason,
            tool=tool_name,
            params=params,
            rule=rule,
            mode=self.engine.policy.mode,
            enforced=True,
            context=context,
        )

    async def call(
        self,
        tool_name: str,
        params: dict,
        handler=None,
        context: dict | None = None,
    ) -> dict:
        """Evaluate, log, and optionally execute a tool call.

        `params` is untrusted: it is whatever the model asked for, and is what
        `where` conditions test. `context` is trusted: it must be supplied by
        the integrator, never forwarded from model output, and is what `when`
        conditions test.

        When an adapter is configured, the request is canonicalized before
        evaluation and the canonical parameters are the ones handed to the
        handler. Evaluating one value and executing another would not be a
        check at all.

        Under `mode: shadow` the decision is still computed and logged, but the
        call executes regardless — that is what makes shadow mode useful for
        trialling a policy against live traffic.
        """
        resolved_context = self._resolve_context(params, context)
        notes: list[str] = []
        effective_params = params

        if self.adapter is not None:
            # An undeclared resource is refused before any rule is consulted,
            # so a broad `resource: "**"` allow rule cannot reach something no
            # adapter exposes.
            try:
                normalized = self.adapter.normalize(tool_name, params)
            except UndeclaredResource as e:
                decision = self._refusal(
                    tool_name, params, resolved_context, str(e), "adapter:undeclared"
                )
                await self._write_audit(decision)
                raise PermissionError(decision.reason) from e
            except CanonicalizationError as e:
                decision = self._refusal(
                    tool_name,
                    params,
                    resolved_context,
                    f"{tool_name}: {e}",
                    "adapter:canonicalization",
                )
                await self._write_audit(decision)
                raise PermissionError(decision.reason) from e

            tool_name = normalized.resource
            effective_params = normalized.params
            notes = normalized.notes

        decision = self.engine.evaluate(tool_name, effective_params, resolved_context)
        decision.notes = notes
        await self._write_audit(decision)

        if decision.blocked:
            if decision.action == "deny":
                raise PermissionError(decision.reason)
            raise ReviewRequired(decision)

        if handler is not None:
            return await handler(tool_name, effective_params)
        if self.adapter is not None:
            return await self.adapter.execute(tool_name, effective_params)
        raise TypeError(
            "ToolCallProxy.call() needs a handler, or a ToolCallProxy built "
            "with adapter=..."
        )

    async def _write_audit(self, decision: Decision) -> None:
        """Append a decision to the SQLite audit log."""
        db_path = Path(self.audit_path)
        if db_path.parent != Path(""):
            db_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(_SCHEMA)
            await self._migrate(db)
            await db.execute(
                "INSERT INTO audit_log (timestamp, tool, action, reason, params, "
                "rule, mode, enforced, normalization) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    decision.tool,
                    decision.action,
                    decision.reason,
                    json.dumps(decision.params, default=str),
                    decision.rule,
                    decision.mode,
                    int(decision.enforced),
                    json.dumps(decision.notes) if decision.notes else None,
                ),
            )
            await db.commit()

    @staticmethod
    async def _migrate(db) -> None:
        """Add columns introduced after v0.2.0 to a pre-existing audit log."""
        async with db.execute("PRAGMA table_info(audit_log)") as cursor:
            existing = {row[1] for row in await cursor.fetchall()}

        for column, sql_type in _ADDED_COLUMNS.items():
            if column not in existing:
                await db.execute(
                    f"ALTER TABLE audit_log ADD COLUMN {column} {sql_type}"
                )
