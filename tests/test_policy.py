"""Unit tests for policy parsing, strict validation, and v1 translation."""

import textwrap

import pytest

from hydracuda.policy import (
    DEFAULT_AUDIT_PATH,
    PolicyError,
    load_policy,
    parse_policy,
)


def policy_from_yaml(source: str):
    import yaml

    return parse_policy(yaml.safe_load(textwrap.dedent(source)))


# --- top-level validation ------------------------------------------------


def test_missing_version_rejected():
    with pytest.raises(PolicyError, match="missing required key: 'version'"):
        policy_from_yaml("mode: enforce\n")


def test_non_mapping_rejected():
    with pytest.raises(PolicyError, match="must be a YAML mapping"):
        policy_from_yaml("- one\n- two\n")


def test_unsupported_version_rejected():
    with pytest.raises(PolicyError, match="Unsupported policy version 3"):
        policy_from_yaml("version: 3\nrules: []\n")


def test_boolean_version_rejected():
    # YAML parses `yes` as True, which is not a version.
    with pytest.raises(PolicyError, match="'version' must be an integer"):
        policy_from_yaml("version: yes\n")


def test_invalid_mode_rejected():
    with pytest.raises(PolicyError, match="'mode' must be one of"):
        policy_from_yaml("version: 2\nmode: blocking\n")


def test_invalid_default_action_rejected():
    with pytest.raises(PolicyError, match="'default_action' must be one of"):
        policy_from_yaml("version: 2\ndefault_action: maybe\n")


def test_default_action_is_deny_when_omitted():
    policy = policy_from_yaml("version: 2\nrules: []\n")
    assert policy.default_action == "deny"


def test_audit_path_defaults():
    policy = policy_from_yaml("version: 2\nrules: []\n")
    assert policy.audit_path == DEFAULT_AUDIT_PATH


# --- strict unknown-key rejection ----------------------------------------
# A silently ignored key means the author believes a rule is active when it
# is not, which fails open. Every level rejects unknown keys.


def test_unknown_top_level_key_rejected():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['audit_pat'\]"):
        policy_from_yaml("version: 2\naudit_pat: x.db\n")


def test_v2_rejects_v1_tools_block():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['tools'\]"):
        policy_from_yaml("version: 2\ntools:\n  read_file:\n    allow: true\n")


def test_v1_rejects_v2_rules_block():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['rules'\]"):
        policy_from_yaml("version: 1\ntools: {}\nrules: []\n")


def test_unknown_rule_key_rejected():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['effect'\]"):
        policy_from_yaml(
            """
            version: 2
            rules:
              - resource: read_file
                action: allow
                effect: deny
            """
        )


def test_unknown_tool_key_rejected():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['allowed'\]"):
        policy_from_yaml(
            """
            version: 1
            tools:
              read_file:
                allowed: true
            """
        )


def test_misspelled_parameter_rule_key_rejected():
    # The v0.2.0 failure this replaces: `denyPatterns` parsed fine and did
    # nothing, so the policy looked active but permitted everything.
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['denyPatterns'\]"):
        policy_from_yaml(
            """
            version: 1
            tools:
              read_file:
                allow: true
                parameter_rules:
                  path:
                    denyPatterns: ["/etc/"]
            """
        )


def test_unknown_adapter_key_rejected():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['kind'\]"):
        policy_from_yaml(
            """
            version: 2
            adapters:
              - name: local
                type: local_tools
                kind: other
            """
        )


def test_unknown_audit_key_rejected():
    with pytest.raises(PolicyError, match=r"unrecognized key\(s\) \['pth'\]"):
        policy_from_yaml("version: 2\naudit:\n  pth: x.db\n")


# --- version 2 rules -----------------------------------------------------


def test_rules_are_parsed_in_order():
    policy = policy_from_yaml(
        """
        version: 2
        rules:
          - name: first
            resource: read_file
            action: deny
          - name: second
            resource: read_file
            action: allow
        """
    )
    assert [r.name for r in policy.rules] == ["first", "second"]


def test_rule_requires_resource():
    with pytest.raises(PolicyError, match="'resource' is required"):
        policy_from_yaml("version: 2\nrules:\n  - action: allow\n")


def test_rule_requires_valid_action():
    with pytest.raises(PolicyError, match="'action' must be one of"):
        policy_from_yaml("version: 2\nrules:\n  - resource: x\n    action: block\n")


def test_rule_error_message_names_the_rule():
    with pytest.raises(PolicyError, match=r"rules\[0\] \('my-rule'\)"):
        policy_from_yaml(
            """
            version: 2
            rules:
              - name: my-rule
                resource: x
                action: allow
                where:
                  path:
                    nope: 1
            """
        )


def test_rules_may_be_omitted():
    policy = policy_from_yaml("version: 2\n")
    assert policy.rules == []


def test_default_rule_reason_supplied_per_action():
    policy = policy_from_yaml(
        "version: 2\nrules:\n  - resource: x\n    action: review\n"
    )
    assert policy.rules[0].reason == "tool requires human review"


def test_rule_label_falls_back_to_action_and_resource():
    policy = policy_from_yaml(
        "version: 2\nrules:\n  - resource: read_file\n    action: allow\n"
    )
    assert policy.rules[0].label == "allow:read_file"


# --- adapters ------------------------------------------------------------


def test_adapters_parsed():
    policy = policy_from_yaml(
        """
        version: 2
        adapters:
          - name: local
            type: local_tools
            resources: [read_file, execute_shell]
        """
    )
    assert policy.adapters[0].name == "local"
    assert policy.adapters[0].resources == ["read_file", "execute_shell"]


def test_duplicate_adapter_name_rejected():
    with pytest.raises(PolicyError, match="duplicate adapter name 'local'"):
        policy_from_yaml(
            """
            version: 2
            adapters:
              - name: local
                type: local_tools
              - name: local
                type: local_tools
            """
        )


def test_declared_resources_merges_adapters_and_concrete_rules():
    policy = policy_from_yaml(
        """
        version: 2
        adapters:
          - name: local
            type: local_tools
            resources: [read_file]
        rules:
          - resource: execute_shell
            action: review
          - resource: "filesystem.**"
            action: deny
        """
    )
    # Wildcard rule resources describe a set, not a plannable resource.
    assert policy.declared_resources() == ["read_file", "execute_shell"]


# --- version 1 translation ----------------------------------------------


def test_v1_tools_translated_to_ordered_rules():
    policy = policy_from_yaml(
        """
        version: 1
        tools:
          read_file:
            allow: true
            parameter_rules:
              path:
                deny_patterns: ["/etc/", "/root/"]
          delete_record:
            allow: false
          execute_shell:
            allow: "review"
        """
    )
    assert [(r.resource, r.action) for r in policy.rules] == [
        ("read_file", "deny"),
        ("read_file", "deny"),
        ("read_file", "allow"),
        ("delete_record", "deny"),
        ("execute_shell", "review"),
    ]


def test_v1_per_tool_reason_is_honoured():
    # In v0.2.0 this was parsed and discarded, so denials always read
    # "tool blocked by policy" no matter what the policy said.
    policy = policy_from_yaml(
        """
        version: 1
        tools:
          delete_record:
            allow: false
            reason: "Destructive operation."
        """
    )
    assert policy.rules[0].reason == "Destructive operation."


def test_v1_invalid_allow_rejected():
    with pytest.raises(PolicyError, match="'allow' must be true, false, or 'review'"):
        policy_from_yaml("version: 1\ntools:\n  x:\n    allow: sometimes\n")


def test_v1_bad_deny_pattern_regex_rejected():
    with pytest.raises(PolicyError, match="invalid regex"):
        policy_from_yaml(
            """
            version: 1
            tools:
              read_file:
                allow: true
                parameter_rules:
                  path:
                    deny_patterns: ["([unclosed"]
            """
        )


# --- rejected keys -------------------------------------------------------


def test_rate_limit_is_a_load_error_in_v1():
    # Accepted and discarded in v0.1.0-v0.2.0, so the policy asserted a control
    # that did not exist.
    with pytest.raises(PolicyError, match="'rate_limit' is not enforced"):
        policy_from_yaml(
            """
            version: 1
            tools:
              execute_shell:
                allow: true
                rate_limit: "3/minute"
            """
        )


def test_rate_limit_is_a_load_error_in_v2():
    with pytest.raises(PolicyError, match="'rate_limit' is not enforced"):
        policy_from_yaml(
            """
            version: 2
            rules:
              - resource: execute_shell
                action: allow
                rate_limit: "3/minute"
            """
        )


def test_rate_limit_rejected_at_top_level():
    with pytest.raises(PolicyError, match="'rate_limit' is not enforced"):
        policy_from_yaml("version: 2\nrate_limit: 3/minute\n")


def test_rate_limit_camel_case_spelling_also_rejected():
    with pytest.raises(PolicyError, match="'rate_limit' is not enforced"):
        policy_from_yaml(
            """
            version: 1
            tools:
              execute_shell:
                allow: true
                rateLimit: "3/minute"
            """
        )


def test_tool_policy_no_longer_carries_rate_limit():
    from hydracuda.policy import ToolPolicy

    assert not hasattr(ToolPolicy(), "rate_limit")


# --- misspelling hints ---------------------------------------------------


def test_camel_case_key_suggests_the_snake_case_spelling():
    with pytest.raises(PolicyError, match="did you mean 'deny_patterns'"):
        policy_from_yaml(
            """
            version: 1
            tools:
              read_file:
                allow: true
                parameter_rules:
                  path:
                    denyPatterns: ["/etc/"]
            """
        )


def test_camel_case_top_level_key_suggests_snake_case():
    with pytest.raises(PolicyError, match="did you mean 'default_action'"):
        policy_from_yaml("version: 2\ndefaultAction: allow\n")


def test_ordinary_typo_suggests_the_nearest_key():
    with pytest.raises(PolicyError, match="did you mean 'resource'"):
        policy_from_yaml(
            "version: 2\nrules:\n  - resourse: x\n    action: allow\n"
        )


# --- deprecated audit alias ---------------------------------------------


def test_nested_audit_path_alias_is_honoured():
    # v0.2.0 documented `audit.path` in the README but never read it, so the
    # audit log silently went to the default location.
    policy = policy_from_yaml("version: 2\naudit:\n  path: custom/audit.db\n")
    assert policy.audit_path == "custom/audit.db"


def test_audit_path_wins_over_nested_alias():
    policy = policy_from_yaml(
        """
        version: 2
        audit_path: preferred.db
        audit:
          path: legacy.db
        """
    )
    assert policy.audit_path == "preferred.db"


# --- file loading --------------------------------------------------------


def test_missing_file_rejected():
    with pytest.raises(PolicyError, match="Policy file not found"):
        load_policy("does/not/exist.yaml")


def test_policy_error_is_a_value_error():
    # Callers written against v0.2.0 catch ValueError.
    assert issubclass(PolicyError, ValueError)


def test_example_policies_load(examples_dir):
    for name in ("policy.yaml", "policy-v1-legacy.yaml", "policy-advanced.yaml"):
        assert load_policy(str(examples_dir / name)) is not None
