"""Condition and resource-pattern matching for HYDRACUDA policy rules.

Everything here is pure: no I/O, no clock reads, no model calls. The same
inputs always produce the same result, which is what lets `plan` and `test`
report decisions without executing anything.
"""

import re
from fnmatch import fnmatchcase
from typing import Any

REGEX_OPERATORS = frozenset({"matches", "not_matches"})
LIST_OPERATORS = frozenset({"in", "not_in"})
BOOL_OPERATORS = frozenset({"present", "absent"})
SCALAR_OPERATORS = frozenset({"equals", "not_equals"})

OPERATORS = REGEX_OPERATORS | LIST_OPERATORS | BOOL_OPERATORS | SCALAR_OPERATORS

_MISSING = object()


class ConditionError(ValueError):
    """Raised when a condition block is malformed."""


def validate_conditions(conditions: Any, where: str) -> dict[str, dict[str, Any]]:
    """Validate and normalize a `where`/`when` block.

    Returns the normalized block: scalar arguments to list-taking operators
    are wrapped in a list, and regexes are compiled once to surface malformed
    patterns as a policy error rather than a runtime failure.
    """
    if conditions is None:
        return {}
    if not isinstance(conditions, dict):
        raise ConditionError(f"{where} must be a mapping of field names to conditions")

    normalized: dict[str, dict[str, Any]] = {}
    for field, ops in conditions.items():
        if not isinstance(ops, dict):
            raise ConditionError(
                f"{where}.{field} must be a mapping of operators, "
                f"got {type(ops).__name__}"
            )

        normalized_ops: dict[str, Any] = {}
        for op, arg in ops.items():
            if op not in OPERATORS:
                raise ConditionError(
                    f"{where}.{field}: unknown operator '{op}' — "
                    f"allowed: {sorted(OPERATORS)}"
                )

            if op in REGEX_OPERATORS:
                patterns = [arg] if isinstance(arg, str) else arg
                if not isinstance(patterns, list) or not all(
                    isinstance(p, str) for p in patterns
                ):
                    raise ConditionError(
                        f"{where}.{field}.{op} must be a regex string or a list of them"
                    )
                for pattern in patterns:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        raise ConditionError(
                            f"{where}.{field}.{op}: invalid regex {pattern!r}: {e}"
                        ) from e
                normalized_ops[op] = patterns

            elif op in LIST_OPERATORS:
                if not isinstance(arg, list):
                    raise ConditionError(f"{where}.{field}.{op} must be a list")
                normalized_ops[op] = arg

            elif op in BOOL_OPERATORS:
                if not isinstance(arg, bool):
                    raise ConditionError(f"{where}.{field}.{op} must be true or false")
                normalized_ops[op] = arg

            else:
                normalized_ops[op] = arg

        normalized[field] = normalized_ops

    return normalized


def _evaluate_operator(op: str, arg: Any, value: Any) -> bool:
    """Evaluate a single operator against a field value.

    `value` is `_MISSING` when the subject does not supply the field.
    """
    is_present = value is not _MISSING

    if op == "present":
        return is_present is arg
    if op == "absent":
        return (not is_present) is arg

    # Every remaining operator needs a value to compare against. An absent
    # field therefore fails the condition, so a rule keyed on a parameter the
    # request never supplied does not fire.
    if not is_present:
        return False

    if op == "matches":
        return any(re.search(p, str(value)) for p in arg)
    if op == "not_matches":
        return not any(re.search(p, str(value)) for p in arg)
    if op == "equals":
        return value == arg
    if op == "not_equals":
        return value != arg
    if op == "in":
        return value in arg
    if op == "not_in":
        return value not in arg

    raise ConditionError(f"unknown operator '{op}'")


def matches_conditions(
    conditions: dict[str, dict[str, Any]], subject: dict[str, Any]
) -> bool:
    """True when every operator on every field holds. An empty block matches."""
    for field, ops in conditions.items():
        value = subject.get(field, _MISSING)
        for op, arg in ops.items():
            if not _evaluate_operator(op, arg, value):
                return False
    return True


def _match_segments(pattern: list[str], resource: list[str]) -> bool:
    """Match dot-separated resource segments, honouring `*` and `**`."""
    if not pattern:
        return not resource

    if pattern[0] == "**":
        if len(pattern) == 1:
            return True
        # `**` absorbs zero or more segments; try each split point.
        return any(
            _match_segments(pattern[1:], resource[i:])
            for i in range(len(resource) + 1)
        )

    if not resource:
        return False
    if not fnmatchcase(resource[0], pattern[0]):
        return False
    return _match_segments(pattern[1:], resource[1:])


def resource_matches(pattern: str, resource: str) -> bool:
    """True when a rule's resource pattern matches a concrete resource name."""
    if pattern == resource:
        return True
    return _match_segments(pattern.split("."), resource.split("."))


def pattern_subsumes(outer: str, inner: str) -> bool:
    """True when everything `inner` matches, `outer` also matches.

    Deliberately conservative: it returns True only when subsumption is
    provable, and False when it merely cannot be ruled out. `validate` uses
    this to report a rule as unreachable, and a false positive there would
    accuse a working policy of being broken.
    """
    if outer == inner:
        return True
    return _subsumes_segments(outer.split("."), inner.split("."))


def _subsumes_segments(outer: list[str], inner: list[str]) -> bool:
    if not outer:
        return not inner

    if outer[0] == "**":
        if len(outer) == 1:
            return True
        return any(
            _subsumes_segments(outer[1:], inner[i:]) for i in range(len(inner) + 1)
        )

    if not inner:
        return False

    if not _segment_subsumes(outer[0], inner[0]):
        return False
    return _subsumes_segments(outer[1:], inner[1:])


def _segment_subsumes(outer: str, inner: str) -> bool:
    """True when a single pattern segment covers another."""
    if outer == inner:
        return True
    # `**` in the inner pattern spans a variable number of segments, which a
    # single outer segment cannot cover.
    if inner == "**":
        return False
    if outer == "*":
        return True
    # An inner segment carrying its own wildcards describes a set. Proving that
    # one fnmatch pattern covers another is more than this needs to do, so it
    # is treated as not provable.
    if any(c in inner for c in "*?["):
        return False
    return fnmatchcase(inner, outer)
