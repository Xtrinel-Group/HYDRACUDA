"""Policy evaluation core for HYDRACUDA."""

import re
from dataclasses import dataclass

from hydracuda.policy import Policy


@dataclass
class Decision:
    """Result of evaluating a tool call against a policy."""

    action: str
    reason: str
    tool: str
    params: dict


class PolicyEngine:
    """Evaluates tool calls against a loaded policy."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(self, tool_name: str, params: dict) -> Decision:
        """Evaluate a tool call and return an allow/deny/review decision."""
        if tool_name not in self.policy.tools:
            return Decision(
                action="deny",
                reason=f"{tool_name}: not listed in policy — default deny",
                tool=tool_name,
                params=params,
            )

        tool_policy = self.policy.tools[tool_name]

        if tool_policy.allow is False:
            return Decision(
                action="deny",
                reason="tool blocked by policy",
                tool=tool_name,
                params=params,
            )

        if tool_policy.allow == "review":
            return Decision(
                action="review",
                reason="tool requires human review",
                tool=tool_name,
                params=params,
            )

        if tool_policy.parameter_rules:
            for param_name, rules in tool_policy.parameter_rules.items():
                if param_name not in params:
                    continue
                deny_patterns = rules.get("deny_patterns", [])
                param_value = str(params[param_name])
                for pattern in deny_patterns:
                    if re.search(pattern, param_value):
                        return Decision(
                            action="deny",
                            reason=f"{tool_name}: parameter '{param_name}' matched deny pattern '{pattern}'",
                            tool=tool_name,
                            params=params,
                        )

        return Decision(
            action="allow",
            reason="all policy checks passed",
            tool=tool_name,
            params=params,
        )
