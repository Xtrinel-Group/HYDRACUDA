"""Unit tests for condition and resource-pattern matching."""

import pytest

from hydracuda.conditions import (
    ConditionError,
    matches_conditions,
    resource_matches,
    validate_conditions,
)


# --- resource patterns ---------------------------------------------------


@pytest.mark.parametrize(
    "pattern,resource,expected",
    [
        ("read_file", "read_file", True),
        ("read_file", "write_file", False),
        ("filesystem.read_file", "filesystem.read_file", True),
        ("filesystem.*", "filesystem.read_file", True),
        ("filesystem.*", "filesystem.file.read", False),
        ("filesystem.*", "filesystem", False),
        ("filesystem.read_*", "filesystem.read_dir", True),
        ("filesystem.read_*", "filesystem.write_dir", False),
        ("filesystem.**", "filesystem.read_file", True),
        ("filesystem.**", "filesystem.file.read.deep", True),
        ("filesystem.**", "filesystem", True),
        ("filesystem.**", "github.repository.read", False),
        ("github.*.read", "github.repository.read", True),
        ("github.*.read", "github.issue.comment", False),
        ("**", "anything.at.all", True),
        ("**", "read_file", True),
    ],
)
def test_resource_matches(pattern, resource, expected):
    assert resource_matches(pattern, resource) is expected


# --- condition evaluation ------------------------------------------------


def check(conditions, subject):
    return matches_conditions(validate_conditions(conditions, "where"), subject)


def test_empty_conditions_match_everything():
    assert check({}, {}) is True
    assert check(None, {"anything": 1}) is True


def test_matches_is_unanchored_substring_search():
    assert check({"path": {"matches": ["/etc/"]}}, {"path": "/var/etc/x"}) is True
    assert check({"path": {"matches": ["^/etc/"]}}, {"path": "/var/etc/x"}) is False


def test_matches_accepts_bare_string():
    assert check({"path": {"matches": "/etc/"}}, {"path": "/etc/passwd"}) is True


def test_matches_stringifies_non_string_values():
    assert check({"port": {"matches": ["^22$"]}}, {"port": 22}) is True


def test_not_matches():
    conditions = {"path": {"not_matches": ["^/workspace/"]}}
    assert check(conditions, {"path": "/etc/passwd"}) is True
    assert check(conditions, {"path": "/workspace/a.txt"}) is False


def test_equals_is_type_sensitive():
    assert check({"recursive": {"equals": True}}, {"recursive": True}) is True
    assert check({"recursive": {"equals": True}}, {"recursive": "true"}) is False


def test_not_equals():
    assert check({"mode": {"not_equals": "read"}}, {"mode": "write"}) is True
    assert check({"mode": {"not_equals": "read"}}, {"mode": "read"}) is False


def test_in_and_not_in():
    assert check({"env": {"in": ["dev", "staging"]}}, {"env": "dev"}) is True
    assert check({"env": {"in": ["dev", "staging"]}}, {"env": "prod"}) is False
    assert check({"env": {"not_in": ["prod"]}}, {"env": "dev"}) is True


def test_present_and_absent():
    assert check({"path": {"present": True}}, {"path": "x"}) is True
    assert check({"path": {"present": True}}, {}) is False
    assert check({"path": {"absent": True}}, {}) is True
    assert check({"path": {"absent": True}}, {"path": "x"}) is False
    assert check({"path": {"present": False}}, {}) is True


def test_missing_field_fails_value_operators():
    # A rule keyed on a parameter the request never supplied must not fire,
    # so evaluation falls through to the next rule.
    assert check({"path": {"matches": ["/etc/"]}}, {"other": "x"}) is False
    assert check({"path": {"not_matches": ["/etc/"]}}, {"other": "x"}) is False
    assert check({"path": {"equals": "x"}}, {}) is False


def test_all_operators_on_a_field_must_hold():
    conditions = {
        "path": {"matches": ["^/etc/"], "not_matches": ["^/etc/hydracuda/"]}
    }
    assert check(conditions, {"path": "/etc/passwd"}) is True
    assert check(conditions, {"path": "/etc/hydracuda/policy.yaml"}) is False


def test_all_fields_must_hold():
    conditions = {"path": {"matches": ["/etc/"]}, "mode": {"equals": "write"}}
    assert check(conditions, {"path": "/etc/x", "mode": "write"}) is True
    assert check(conditions, {"path": "/etc/x", "mode": "read"}) is False


# --- condition validation ------------------------------------------------


def test_unknown_operator_rejected():
    with pytest.raises(ConditionError, match="unknown operator 'startswith'"):
        validate_conditions({"path": {"startswith": "/etc"}}, "where")


def test_invalid_regex_rejected_at_load():
    with pytest.raises(ConditionError, match="invalid regex"):
        validate_conditions({"path": {"matches": ["([unclosed"]}}, "where")


def test_list_operator_requires_list():
    with pytest.raises(ConditionError, match="must be a list"):
        validate_conditions({"env": {"in": "dev"}}, "where")


def test_bool_operator_requires_bool():
    with pytest.raises(ConditionError, match="must be true or false"):
        validate_conditions({"path": {"present": "yes"}}, "where")


def test_conditions_must_be_a_mapping():
    with pytest.raises(ConditionError, match="must be a mapping"):
        validate_conditions(["path"], "where")


def test_field_conditions_must_be_a_mapping():
    with pytest.raises(ConditionError, match="must be a mapping of operators"):
        validate_conditions({"path": "/etc/"}, "where")
