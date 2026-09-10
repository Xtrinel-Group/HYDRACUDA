"""YAML policy parser and validator for HYDRACUDA.

Two policy versions are supported. Version 2 is the ordered-rule format
described in `docs/policy-spec.md`. Version 1 is the flat `tools:` map from
v0.1.0–v0.2.0; it is translated into version 2 rules at load time so there is
a single evaluation path, and its decisions are unchanged.

Validation is strict: an unrecognized key anywhere in a policy file is an
error. Silently ignoring a misspelled key means the author believes a rule is
active when it is not, which fails open.
"""

import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import yaml

from hydracuda.conditions import ConditionError, validate_conditions

DEFAULT_AUDIT_PATH = ".hydracuda/audit.db"

VALID_MODES = {"enforce", "shadow", "review"}
VALID_ACTIONS = {"allow", "deny", "review"}
SUPPORTED_VERSIONS = {1, 2}

DEFAULT_REASON = "{resource}: no matching rule — default {action}"
DEFAULT_REASON_V1 = "{resource}: not listed in policy — default deny"

DEFAULT_RULE_REASONS = {
    "allow": "all policy checks passed",
    "deny": "tool blocked by policy",
    "review": "tool requires human review",
}

_TOP_LEVEL_KEYS_V1 = {"version", "mode", "audit_path", "audit", "tools"}
_TOP_LEVEL_KEYS_V2 = {
    "version",
    "mode",
    "audit_path",
    "audit",
    "default_action",
    "default_reason",
    "adapters",
    "rules",
    "pinned_context",
}
_TOOL_KEYS = {"allow", "parameter_rules", "reason"}
_PARAMETER_RULE_KEYS = {"deny_patterns"}
_RULE_KEYS = {"name", "resource", "action", "reason", "where", "when"}
_ADAPTER_KEYS = {"name", "type", "resources", "config"}
_AUDIT_KEYS = {"path"}

#: Keys that are rejected outright with a specific explanation, wherever they
#: appear. A key that reads as an active control but has no effect is the
#: failure this loader exists to prevent, so it must not be merely ignored.
_REJECTED_KEYS = {
    "rate_limit": (
        "'rate_limit' is not enforced by HYDRACUDA and never has been — it was "
        "parsed and discarded in v0.1.0-v0.2.0. Remove it. Rate limiting is "
        "stateful and belongs in the calling layer; leaving the key in a policy "
        "file asserts a control that does not exist."
    ),
}


class PolicyError(ValueError):
    """Raised when a policy file is invalid.

    Subclasses ValueError so callers written against v0.2.0 keep working.
    """


@dataclass
class ToolPolicy:
    """Policy configuration for a single tool (version 1 format)."""

    allow: Union[bool, str] = True
    parameter_rules: dict[str, dict] | None = None
    reason: str | None = None


@dataclass
class Rule:
    """A single ordered policy rule."""

    resource: str
    action: str
    name: str | None = None
    reason: str | None = None
    where: dict[str, dict[str, Any]] = field(default_factory=dict)
    when: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """Stable identifier for logs and `plan` output."""
        return self.name or f"{self.action}:{self.resource}"


@dataclass
class AdapterSpec:
    """Declaration of one adapter instance and the resources it exposes."""

    name: str
    type: str
    resources: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """Top-level policy configuration.

    Constructing this with `tools=` (the version 1 representation) translates
    those tools into `rules` automatically, so callers written against v0.2.0
    keep working.
    """

    version: int
    tools: dict[str, ToolPolicy] | None = None
    mode: str = "enforce"
    audit_path: str = DEFAULT_AUDIT_PATH
    default_action: str = "deny"
    default_reason: str = DEFAULT_REASON
    rules: list[Rule] = field(default_factory=list)
    adapters: list[AdapterSpec] = field(default_factory=list)
    pinned_context: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.tools is not None and not self.rules:
            self.rules = rules_from_tools(self.tools)
            self.default_reason = DEFAULT_REASON_V1
            self.default_action = "deny"

    def when_fields(self) -> set[str]:
        """Every context field any rule's `when` block tests."""
        fields: set[str] = set()
        for rule in self.rules:
            fields.update(rule.when)
        return fields

    def unpinned_when_fields(self) -> set[str]:
        """Context fields that gate decisions but are not pinned.

        A `when` field that is not listed in `pinned_context` is supplied per
        call, so the guarantee that the agent cannot influence it rests on the
        integrator rather than on HYDRACUDA. `hydracuda validate` reports these.
        """
        return self.when_fields() - set(self.pinned_context)

    def declared_resources(self) -> list[str]:
        """Every concrete resource named by an adapter, then by a rule.

        Rule resources containing wildcards are skipped — they describe a set,
        not a resource that can be planned against.
        """
        seen: dict[str, None] = {}
        for adapter in self.adapters:
            for resource in adapter.resources:
                seen.setdefault(resource, None)
        for rule in self.rules:
            if "*" not in rule.resource:
                seen.setdefault(rule.resource, None)
        return list(seen)


def rules_from_tools(tools: dict[str, ToolPolicy]) -> list[Rule]:
    """Translate the version 1 `tools:` map into ordered version 2 rules.

    Rule order reproduces the v0.2.0 evaluation order exactly: blocked and
    review tools short-circuit, then parameter deny patterns are tried in
    declaration order, then the call is allowed.
    """
    rules: list[Rule] = []

    for tool_name, tool_policy in tools.items():
        if tool_policy.allow is False:
            rules.append(
                Rule(
                    resource=tool_name,
                    action="deny",
                    name=f"legacy:{tool_name}:blocked",
                    reason=tool_policy.reason or DEFAULT_RULE_REASONS["deny"],
                )
            )
            continue

        if tool_policy.allow == "review":
            rules.append(
                Rule(
                    resource=tool_name,
                    action="review",
                    name=f"legacy:{tool_name}:review",
                    reason=tool_policy.reason or DEFAULT_RULE_REASONS["review"],
                )
            )
            continue

        for param_name, param_rules in (tool_policy.parameter_rules or {}).items():
            # The index keeps generated names unique. Without it a tool with
            # several deny patterns produced several identically named rules,
            # which made an audit record ambiguous about which pattern fired.
            for position, pattern in enumerate(param_rules.get("deny_patterns", [])):
                rules.append(
                    Rule(
                        resource=tool_name,
                        action="deny",
                        name=f"legacy:{tool_name}:{param_name}:deny_pattern[{position}]",
                        reason=(
                            f"{tool_name}: parameter '{param_name}' "
                            f"matched deny pattern '{pattern}'"
                        ),
                        where={param_name: {"matches": [pattern]}},
                    )
                )

        rules.append(
            Rule(
                resource=tool_name,
                action="allow",
                name=f"legacy:{tool_name}:allow",
                reason=DEFAULT_RULE_REASONS["allow"],
            )
        )

    return rules


def _normalize_key(key: str) -> str:
    return key.replace("_", "").replace("-", "").lower()


def _suggest_key(key: str, allowed: set[str]) -> str | None:
    """Find the key the author probably meant.

    Catches the camelCase drift the v0.2.0 README encouraged (`denyPatterns`
    for `deny_patterns`) as an exact match after normalization, then falls back
    to fuzzy matching for ordinary typos.
    """
    target = _normalize_key(key)
    for candidate in sorted(allowed):
        if _normalize_key(candidate) == target:
            return candidate
    close = difflib.get_close_matches(key, sorted(allowed), n=1, cutoff=0.8)
    return close[0] if close else None


def _reject_unknown_keys(where: str, mapping: dict, allowed: set[str]) -> None:
    rejected = {_normalize_key(k): v for k, v in _REJECTED_KEYS.items()}
    for key in mapping:
        message = rejected.get(_normalize_key(key))
        if message:
            raise PolicyError(f"{where}: {message}")

    unknown = sorted(k for k in mapping if k not in allowed)
    if not unknown:
        return

    hints = []
    for key in unknown:
        suggestion = _suggest_key(key, allowed)
        if suggestion:
            hints.append(f"'{key}' — did you mean '{suggestion}'?")
    hint = f" {' '.join(hints)}" if hints else ""

    raise PolicyError(
        f"{where}: unrecognized key(s) {unknown}.{hint} "
        f"Allowed: {sorted(allowed)}"
    )


def _require_mapping(value: Any, where: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _parse_audit_path(raw: dict) -> str:
    """Resolve the audit log path, honouring the deprecated nested form.

    `audit: {path: ...}` was documented in the v0.2.0 README but never read,
    so policies using it silently logged to the default location. It is now
    honoured as an alias; `audit_path` wins when both are present.
    """
    if "audit" in raw:
        audit = _require_mapping(raw["audit"], "'audit'")
        _reject_unknown_keys("'audit'", audit, _AUDIT_KEYS)
        nested = audit.get("path", DEFAULT_AUDIT_PATH)
        if not isinstance(nested, str):
            raise PolicyError("'audit.path' must be a string")
    else:
        nested = DEFAULT_AUDIT_PATH

    audit_path = raw.get("audit_path", nested)
    if not isinstance(audit_path, str):
        raise PolicyError("'audit_path' must be a string")
    return audit_path


def _parse_mode(raw: dict) -> str:
    mode = raw.get("mode", "enforce")
    if mode not in VALID_MODES:
        raise PolicyError(f"'mode' must be one of {sorted(VALID_MODES)}, got '{mode}'")
    return mode


def _parse_tools(raw: dict) -> dict[str, ToolPolicy]:
    if "tools" not in raw:
        raise PolicyError("Policy file missing required key: 'tools'")

    raw_tools = raw["tools"]
    if not isinstance(raw_tools, dict):
        raise PolicyError("'tools' must be a mapping of tool names to configurations")

    tools: dict[str, ToolPolicy] = {}
    for tool_name, tool_conf in raw_tools.items():
        where = f"Tool '{tool_name}'"
        tool_conf = _require_mapping(tool_conf, f"{where} configuration")
        _reject_unknown_keys(where, tool_conf, _TOOL_KEYS)

        allow = tool_conf.get("allow", True)
        # `isinstance`, not `allow in (True, False, "review")`. The membership
        # test accepted `0` and `0.0`, because Python compares by value and
        # `0 == False` — but the branch in `rules_from_tools` that denies asks
        # `allow is False`, which no integer satisfies. So `allow: 0` passed
        # validation and then translated to an *allow* rule: a tool the author
        # had written down as blocked was permitted, with the accompanying
        # `reason:` silently dropped and `validate` reporting no problem.
        if not (isinstance(allow, bool) or allow == "review"):
            raise PolicyError(
                f"{where}: 'allow' must be true, false, or 'review', got '{allow}'"
            )

        parameter_rules = tool_conf.get("parameter_rules")
        if parameter_rules is not None:
            parameter_rules = _require_mapping(
                parameter_rules, f"{where}: 'parameter_rules'"
            )
            for param_name, param_rules in parameter_rules.items():
                param_where = f"{where}: parameter_rules.{param_name}"
                param_rules = _require_mapping(param_rules, param_where)
                _reject_unknown_keys(param_where, param_rules, _PARAMETER_RULE_KEYS)
                patterns = param_rules.get("deny_patterns", [])
                if not isinstance(patterns, list) or not all(
                    isinstance(p, str) for p in patterns
                ):
                    raise PolicyError(
                        f"{param_where}: 'deny_patterns' must be a list of strings"
                    )
                # Compile now so a malformed regex is a load error, matching
                # version 2 condition behaviour.
                try:
                    validate_conditions(
                        {param_name: {"matches": patterns}}, param_where
                    )
                except ConditionError as e:
                    raise PolicyError(str(e)) from e

        reason = tool_conf.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise PolicyError(f"{where}: 'reason' must be a string")

        tools[tool_name] = ToolPolicy(
            allow=allow,
            parameter_rules=parameter_rules,
            reason=reason,
        )

    return tools


def _parse_rules(raw: dict) -> list[Rule]:
    raw_rules = raw.get("rules", [])
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list")

    rules: list[Rule] = []
    for index, raw_rule in enumerate(raw_rules):
        where = f"rules[{index}]"
        raw_rule = _require_mapping(raw_rule, where)
        _reject_unknown_keys(where, raw_rule, _RULE_KEYS)

        name = raw_rule.get("name")
        if name is not None and not isinstance(name, str):
            raise PolicyError(f"{where}: 'name' must be a string")
        if name:
            where = f"rules[{index}] ('{name}')"

        resource = raw_rule.get("resource")
        if not isinstance(resource, str) or not resource:
            raise PolicyError(f"{where}: 'resource' is required and must be a string")

        action = raw_rule.get("action")
        if action not in VALID_ACTIONS:
            raise PolicyError(
                f"{where}: 'action' must be one of {sorted(VALID_ACTIONS)}, "
                f"got {action!r}"
            )

        reason = raw_rule.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise PolicyError(f"{where}: 'reason' must be a string")

        try:
            conditions = validate_conditions(raw_rule.get("where"), f"{where}.where")
            context = validate_conditions(raw_rule.get("when"), f"{where}.when")
        except ConditionError as e:
            raise PolicyError(str(e)) from e

        rules.append(
            Rule(
                resource=resource,
                action=action,
                name=name,
                reason=reason or DEFAULT_RULE_REASONS[action],
                where=conditions,
                when=context,
            )
        )

    return rules


def _parse_adapters(raw: dict) -> list[AdapterSpec]:
    raw_adapters = raw.get("adapters", [])
    if raw_adapters is None:
        raw_adapters = []
    if not isinstance(raw_adapters, list):
        raise PolicyError("'adapters' must be a list")

    adapters: list[AdapterSpec] = []
    names: set[str] = set()
    for index, raw_adapter in enumerate(raw_adapters):
        where = f"adapters[{index}]"
        raw_adapter = _require_mapping(raw_adapter, where)
        _reject_unknown_keys(where, raw_adapter, _ADAPTER_KEYS)

        name = raw_adapter.get("name")
        if not isinstance(name, str) or not name:
            raise PolicyError(f"{where}: 'name' is required and must be a string")
        if name in names:
            raise PolicyError(f"{where}: duplicate adapter name '{name}'")
        names.add(name)

        adapter_type = raw_adapter.get("type")
        if not isinstance(adapter_type, str) or not adapter_type:
            raise PolicyError(f"{where}: 'type' is required and must be a string")

        resources = raw_adapter.get("resources", []) or []
        if not isinstance(resources, list) or not all(
            isinstance(r, str) for r in resources
        ):
            raise PolicyError(f"{where}: 'resources' must be a list of strings")

        config = raw_adapter.get("config") or {}
        config = _require_mapping(config, f"{where}: 'config'")

        adapters.append(
            AdapterSpec(
                name=name, type=adapter_type, resources=resources, config=config
            )
        )

    return adapters


def load_policy(path: str) -> Policy:
    """Load and validate a hydracuda.yaml policy file.

    Raises PolicyError (a ValueError) with a descriptive message on invalid
    input.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise PolicyError(f"Policy file not found: {path}")

    with open(policy_path) as f:
        raw = yaml.safe_load(f)

    return parse_policy(raw)


def parse_policy(raw: Any) -> Policy:
    """Validate an already-parsed policy mapping and build a Policy."""
    if not isinstance(raw, dict):
        raise PolicyError(
            f"Policy file must be a YAML mapping, got {type(raw).__name__}"
        )

    if "version" not in raw:
        raise PolicyError("Policy file missing required key: 'version'")

    version = raw["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise PolicyError(
            f"'version' must be an integer, got {type(version).__name__}"
        )
    if version not in SUPPORTED_VERSIONS:
        raise PolicyError(
            f"Unsupported policy version {version} — "
            f"supported: {sorted(SUPPORTED_VERSIONS)}"
        )

    mode = _parse_mode(raw)
    audit_path = _parse_audit_path(raw)

    if version == 1:
        _reject_unknown_keys("Policy file", raw, _TOP_LEVEL_KEYS_V1)
        return Policy(
            version=version,
            mode=mode,
            audit_path=audit_path,
            tools=_parse_tools(raw),
        )

    _reject_unknown_keys("Policy file", raw, _TOP_LEVEL_KEYS_V2)

    default_action = raw.get("default_action", "deny")
    if default_action not in VALID_ACTIONS:
        raise PolicyError(
            f"'default_action' must be one of {sorted(VALID_ACTIONS)}, "
            f"got {default_action!r}"
        )

    default_reason = raw.get("default_reason", DEFAULT_REASON)
    if not isinstance(default_reason, str):
        raise PolicyError("'default_reason' must be a string")

    pinned_context = raw.get("pinned_context", []) or []
    if not isinstance(pinned_context, list) or not all(
        isinstance(f, str) for f in pinned_context
    ):
        raise PolicyError("'pinned_context' must be a list of context field names")

    return Policy(
        version=version,
        mode=mode,
        audit_path=audit_path,
        default_action=default_action,
        default_reason=default_reason,
        rules=_parse_rules(raw),
        adapters=_parse_adapters(raw),
        pinned_context=pinned_context,
    )
