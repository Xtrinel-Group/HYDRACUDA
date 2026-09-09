"""Policy evaluation core for HYDRACUDA.

Rules are evaluated in file order and the first match wins. If nothing
matches, the policy's `default_action` applies. Evaluation is pure: no I/O, no
clock reads, no model calls, so the same request always yields the same
decision.
"""

from dataclasses import dataclass, field
from typing import Any

from hydracuda.conditions import matches_conditions, resource_matches
from hydracuda.policy import Policy

#: Verdicts that `mode: shadow` records without acting on.
_BLOCKING_ACTIONS = frozenset({"deny", "review"})


@dataclass
class Decision:
    """Result of evaluating a tool call against a policy."""

    action: str
    reason: str
    tool: str
    params: dict
    rule: str | None = None
    mode: str = "enforce"
    enforced: bool = True
    context: dict = field(default_factory=dict)

    @property
    def resource(self) -> str:
        """Alias for `tool`, using the version 2 vocabulary."""
        return self.tool

    @property
    def blocked(self) -> bool:
        """True when this decision actually stops the call from executing."""
        return self.enforced and self.action in _BLOCKING_ACTIONS


def _safe_format(template: str, **values: Any) -> str:
    """Format a reason template, falling back to the raw string on error.

    Reason text can legitimately contain braces (regex quantifiers, JSON
    fragments), and a bad template must not turn into a runtime exception in
    the enforcement path.
    """
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


class PolicyEngine:
    """Evaluates tool calls against a loaded policy."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(
        self,
        tool_name: str,
        params: dict | None = None,
        context: dict | None = None,
    ) -> Decision:
        """Evaluate a proposed action and return an allow/deny/review decision.

        `params` are the request arguments, tested by each rule's `where`
        block. `context` is caller-supplied evaluation state (agent name,
        environment, session), tested by each rule's `when` block.
        """
        params = params or {}
        context = context or {}

        for rule in self.policy.rules:
            if not resource_matches(rule.resource, tool_name):
                continue
            if not matches_conditions(rule.where, params):
                continue
            if not matches_conditions(rule.when, context):
                continue
            return self._decide(
                action=rule.action,
                reason=rule.reason or rule.action,
                tool_name=tool_name,
                params=params,
                context=context,
                rule=rule.label,
            )

        return self._decide(
            action=self.policy.default_action,
            reason=_safe_format(
                self.policy.default_reason,
                resource=tool_name,
                action=self.policy.default_action,
            ),
            tool_name=tool_name,
            params=params,
            context=context,
            rule=None,
        )

    def _decide(
        self,
        action: str,
        reason: str,
        tool_name: str,
        params: dict,
        context: dict,
        rule: str | None,
    ) -> Decision:
        # `shadow` computes the real verdict but does not act on it, so a
        # policy can be trialled against live traffic. `review` mode is
        # reserved for the human-approval workflow and behaves as `enforce`.
        enforced = not (
            self.policy.mode == "shadow" and action in _BLOCKING_ACTIONS
        )
        return Decision(
            action=action,
            reason=reason,
            tool=tool_name,
            params=params,
            rule=rule,
            mode=self.policy.mode,
            enforced=enforced,
            context=context,
        )
