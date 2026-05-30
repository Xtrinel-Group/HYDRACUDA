"""YAML policy parser and validator for HYDRACUDA."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import yaml


@dataclass
class ToolPolicy:
    """Policy configuration for a single tool."""

    allow: Union[bool, str] = True
    rate_limit: str | None = None
    parameter_rules: dict[str, dict] | None = None


@dataclass
class Policy:
    """Top-level policy configuration parsed from hydracuda.yaml."""

    version: int
    tools: dict[str, ToolPolicy]
    mode: str = "enforce"
    audit_path: str = ".hydracuda/audit.db"


VALID_MODES = {"enforce", "shadow", "review"}


def load_policy(path: str) -> Policy:
    """Load and validate a hydracuda.yaml policy file.

    Raises ValueError with a descriptive message on invalid input.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise ValueError(f"Policy file not found: {path}")

    with open(policy_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Policy file must be a YAML mapping, got {type(raw).__name__}")

    if "version" not in raw:
        raise ValueError("Policy file missing required key: 'version'")

    version = raw["version"]
    if not isinstance(version, int):
        raise ValueError(f"'version' must be an integer, got {type(version).__name__}")

    mode = raw.get("mode", "enforce")
    if mode not in VALID_MODES:
        raise ValueError(f"'mode' must be one of {sorted(VALID_MODES)}, got '{mode}'")

    if "tools" not in raw:
        raise ValueError("Policy file missing required key: 'tools'")

    raw_tools = raw["tools"]
    if not isinstance(raw_tools, dict):
        raise ValueError("'tools' must be a mapping of tool names to configurations")

    tools: dict[str, ToolPolicy] = {}
    for tool_name, tool_conf in raw_tools.items():
        if not isinstance(tool_conf, dict):
            raise ValueError(f"Tool '{tool_name}' configuration must be a mapping")

        allow = tool_conf.get("allow", True)
        if allow not in (True, False, "review"):
            raise ValueError(
                f"Tool '{tool_name}': 'allow' must be true, false, or 'review', got '{allow}'"
            )

        tools[tool_name] = ToolPolicy(
            allow=allow,
            rate_limit=tool_conf.get("rate_limit"),
            parameter_rules=tool_conf.get("parameter_rules"),
        )

    audit_path = raw.get("audit_path", ".hydracuda/audit.db")

    return Policy(version=version, mode=mode, tools=tools, audit_path=audit_path)
