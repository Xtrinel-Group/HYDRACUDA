"""Tests for policy introspection: `analyze` and `plan`.

The CLI surface is tested in test_cli.py. These cover the analysis itself.
"""

import pytest
import yaml

from hydracuda.conditions import pattern_subsumes
from hydracuda.introspect import ERROR, WARNING, analyze, plan
from hydracuda.policy import parse_policy


def _policy(text):
    return parse_policy(yaml.safe_load(text))


def codes(report):
    return [d.code for d in report.diagnostics]


# --- pattern subsumption -------------------------------------------------


@pytest.mark.parametrize(
    "outer,inner,expected",
    [
        ("**", "anything", True),
        ("**", "a.b.c", True),
        ("**", "**", True),
        ("filesystem.**", "filesystem.read_file", True),
        ("filesystem.**", "filesystem", True),
        ("filesystem.**", "filesystem.a.b", True),
        ("filesystem.*", "filesystem.read_file", True),
        ("filesystem.*", "filesystem.a.b", False),
        ("filesystem.read_*", "filesystem.read_file", True),
        ("filesystem.read_*", "filesystem.write_file", False),
        ("read_file", "read_file", True),
        ("read_file", "read_dir", False),
        ("filesystem.read_file", "filesystem.**", False),
        # A single-segment wildcard cannot cover a multi-segment one.
        ("filesystem.*", "filesystem.**", False),
        # Proving one fnmatch pattern covers another is not attempted, so the
        # conservative answer is no.
        ("filesystem.read_*", "filesystem.read_f*", False),
    ],
)
def test_pattern_subsumes(outer, inner, expected):
    assert pattern_subsumes(outer, inner) is expected


# --- trust ---------------------------------------------------------------


def test_unpinned_when_field_is_reported():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: untrusted-cannot-write
                resource: fs.write
                action: deny
                when:
                  trust:
                    equals: untrusted
            """
        )
    )
    (diagnostic,) = [d for d in report.diagnostics if d.code == "unpinned-when-field"]
    assert diagnostic.level == WARNING
    assert "'trust'" in diagnostic.message or "trust" in diagnostic.message
    assert "untrusted-cannot-write" in diagnostic.location


def test_pinned_when_field_is_not_reported():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            pinned_context: [trust]
            rules:
              - resource: fs.write
                action: deny
                when:
                  trust:
                    equals: untrusted
            """
        )
    )
    assert "unpinned-when-field" not in codes(report)


def test_every_unpinned_field_is_named():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            pinned_context: [trust]
            rules:
              - resource: fs.write
                action: deny
                when:
                  trust: {equals: untrusted}
                  agent: {in: [bot]}
                  environment: {equals: prod}
            """
        )
    )
    (diagnostic,) = [d for d in report.diagnostics if d.code == "unpinned-when-field"]
    # The field list names the unpinned fields and only those. ("trust" also
    # appears in the prose, so the list itself is what is asserted.)
    assert str(["agent", "environment"]) in diagnostic.message


# --- negative conditions -------------------------------------------------

NEGATIVE = """
version: 2
default_action: allow
rules:
  - name: no-writes-outside-workspace
    resource: fs.write
    action: deny
    where:
      path:
        not_matches: ["^/workspace/"]
"""


def test_negative_condition_on_a_deny_rule_is_reported():
    report = analyze(_policy(NEGATIVE))
    (diagnostic,) = [
        d for d in report.diagnostics if d.code == "negative-condition-fails-open"
    ]
    assert "where.path" in diagnostic.message
    assert "not_matches" in diagnostic.message


def test_negative_condition_on_an_allow_rule_is_not_reported():
    # A missing field means the allow rule does not fire, which fails closed.
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - resource: fs.write
                action: allow
                where:
                  path:
                    not_matches: ["^/etc/"]
            """
        )
    )
    assert "negative-condition-fails-open" not in codes(report)


def test_a_companion_absent_rule_silences_the_report():
    report = analyze(
        _policy(
            NEGATIVE
            + """
  - name: writes-must-state-a-path
    resource: fs.write
    action: deny
    where:
      path:
        absent: true
"""
        )
    )
    assert "negative-condition-fails-open" not in codes(report)


def test_present_true_does_not_silence_the_report():
    # `present: true` alongside a negative operator documents the intent but
    # changes nothing: conditions are ANDed, so the rule still needs the field.
    report = analyze(
        _policy(
            """
            version: 2
            default_action: allow
            rules:
              - resource: fs.write
                action: deny
                where:
                  path:
                    not_matches: ["^/workspace/"]
                    present: true
            """
        )
    )
    assert "negative-condition-fails-open" in codes(report)


def test_a_companion_rule_must_actually_cover_the_resources():
    report = analyze(
        _policy(
            NEGATIVE
            + """
  - resource: fs.delete
    action: deny
    where:
      path:
        absent: true
"""
        )
    )
    assert "negative-condition-fails-open" in codes(report)


# --- rule order ----------------------------------------------------------


def test_unreachable_rule_is_reported():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: allow-everything
                resource: "**"
                action: allow
              - name: block-secrets
                resource: fs.read_secret
                action: deny
            """
        )
    )
    (diagnostic,) = [d for d in report.diagnostics if d.code == "unreachable-rule"]
    assert "block-secrets" in diagnostic.location
    assert "allow-everything" in diagnostic.message


def test_a_conditional_earlier_rule_does_not_shadow():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: allow-reads-only
                resource: "**"
                action: allow
                where:
                  mode:
                    equals: read
              - name: block-secrets
                resource: fs.read_secret
                action: deny
            """
        )
    )
    assert "unreachable-rule" not in codes(report)


def test_conflicting_rules_are_reported():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: allow-reads
                resource: fs.read
                action: allow
              - name: block-reads
                resource: fs.read
                action: deny
            """
        )
    )
    (diagnostic,) = [d for d in report.diagnostics if d.code == "conflicting-rules"]
    assert "'allow' is what happens" in diagnostic.message


def test_duplicate_rule_is_reported_separately_from_a_conflict():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - resource: fs.read
                action: allow
              - resource: fs.read
                action: allow
            """
        )
    )
    assert "duplicate-rule" in codes(report)
    assert "conflicting-rules" not in codes(report)


def test_narrow_rule_above_broad_rule_is_clean():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - resource: fs.read_secret
                action: deny
              - resource: fs.**
                action: allow
            """
        )
    )
    assert "unreachable-rule" not in codes(report)
    assert "conflicting-rules" not in codes(report)


def test_one_diagnostic_per_shadowed_rule_not_per_pair():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: allow-all
                resource: "**"
                action: allow
              - name: allow-fs
                resource: fs.**
                action: allow
              - name: block-read
                resource: fs.read
                action: deny
            """
        )
    )
    # rules[1] and rules[2] are both shadowed by rules[0]. Each is reported
    # once, against the first rule that shadows it.
    unreachable = [d for d in report.diagnostics if d.code == "unreachable-rule"]
    assert [d.location for d in unreachable] == [
        "rules[1] allow-fs",
        "rules[2] block-read",
    ]
    assert all("rules[0] allow-all" in d.message for d in unreachable)


def test_a_broad_rule_above_a_narrow_one_is_unreachable_not_a_conflict():
    # The two rules do not describe the same resource set, so calling it a
    # conflict would misdescribe it.
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - resource: "**"
                action: allow
              - resource: fs.read_secret
                action: deny
            """
        )
    )
    assert codes(report) == ["default-allow"] or "unreachable-rule" in codes(report)
    assert "conflicting-rules" not in codes(report)


def test_same_conditions_under_a_broader_pattern_is_unreachable():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: broad
                resource: fs.**
                action: allow
                where:
                  mode: {equals: read}
              - name: narrow
                resource: fs.read
                action: deny
                where:
                  mode: {equals: read}
            """
        )
    )
    (diagnostic,) = [d for d in report.diagnostics if d.code == "unreachable-rule"]
    assert "under the same conditions" in diagnostic.message


def test_duplicate_rule_names_are_reported():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - name: block
                resource: fs.read
                action: deny
                where:
                  path: {matches: ["a"]}
              - name: block
                resource: fs.read
                action: deny
                where:
                  path: {matches: ["b"]}
            """
        )
    )
    assert "duplicate-rule-name" in codes(report)


def test_v1_translation_produces_unique_rule_names(examples_dir):
    """The generated deny-pattern rules are indexed.

    They were not, so a tool with several deny patterns produced several
    identically named rules and an audit record could not say which fired.
    """
    policy = _policy((examples_dir / "policy-v1-legacy.yaml").read_text())
    names = [rule.name for rule in policy.rules]
    assert len(names) == len(set(names))
    assert "duplicate-rule-name" not in codes(analyze(policy))


# --- posture -------------------------------------------------------------


def test_shadow_mode_is_reported():
    report = analyze(_policy("version: 2\nmode: shadow\ndefault_action: deny\n"))
    assert "shadow-mode" in codes(report)


def test_default_allow_is_reported():
    report = analyze(_policy("version: 2\ndefault_action: allow\n"))
    assert "default-allow" in codes(report)


def test_a_policy_with_no_rules_is_reported():
    report = analyze(_policy("version: 2\ndefault_action: deny\n"))
    assert "no-rules" in codes(report)


# --- adapters ------------------------------------------------------------


def test_unbuildable_adapter_is_an_error():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            adapters:
              - name: fs
                type: mystery
            """
        )
    )
    (diagnostic,) = report.errors
    assert diagnostic.code == "adapter-unbuildable"
    assert not report.ok


def test_bad_adapter_config_is_an_error():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            adapters:
              - name: fs
                type: local_tools
                config:
                  rooot: /tmp
            """
        )
    )
    assert [d.code for d in report.errors] == ["adapter-unbuildable"]


def test_rule_matching_no_declared_resource_is_reported():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            adapters:
              - name: fs
                type: local_tools
                resources: [fs.read]
            rules:
              - resource: fs.raed
                action: allow
            """
        )
    )
    assert "unmatched-rule-resource" in codes(report)


def test_wildcard_rules_are_checked_against_the_surface_too():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            adapters:
              - name: fs
                type: local_tools
                resources: [fs.read]
            rules:
              - resource: github.**
                action: allow
              - resource: fs.**
                action: allow
            """
        )
    )
    unmatched = [
        d for d in report.diagnostics if d.code == "unmatched-rule-resource"
    ]
    assert len(unmatched) == 1
    assert "github.**" in unmatched[0].message


def test_no_surface_check_without_adapters():
    report = analyze(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - resource: anything.at.all
                action: allow
            """
        )
    )
    assert "unmatched-rule-resource" not in codes(report)


# --- report --------------------------------------------------------------


def test_report_separates_errors_from_warnings():
    report = analyze(
        _policy(
            """
            version: 2
            mode: shadow
            default_action: deny
            adapters:
              - name: fs
                type: mystery
            """
        )
    )
    assert [d.level for d in report.errors] == [ERROR]
    assert all(d.level == WARNING for d in report.warnings)
    assert not report.ok


def test_a_clean_policy_produces_no_diagnostics(examples_dir):
    report = analyze(_policy((examples_dir / "policy.yaml").read_text()))
    assert report.diagnostics == []
    assert report.ok


# --- plan ----------------------------------------------------------------


def test_plan_covers_the_declared_surface(examples_dir):
    entries = plan(_policy((examples_dir / "policy.yaml").read_text()))
    assert [(e.resource, e.action) for e in entries] == [
        ("read_file", "allow"),
        ("delete_record", "deny"),
        ("execute_shell", "review"),
    ]


def test_plan_names_the_deciding_rule(examples_dir):
    entries = {e.resource: e for e in plan(_policy((examples_dir / "policy.yaml").read_text()))}
    assert entries["delete_record"].rule == "block-destructive-deletes"
    assert entries["delete_record"].reason == "Destructive operation. Blocked by default."


def test_plan_reports_the_default_when_no_rule_matches():
    entries = plan(
        _policy(
            """
            version: 2
            default_action: deny
            adapters:
              - name: fs
                type: local_tools
                resources: [fs.read]
            """
        )
    )
    assert entries[0].rule is None
    assert entries[0].action == "deny"


def test_plan_flags_resources_whose_outcome_depends_on_the_request(examples_dir):
    entries = {e.resource: e for e in plan(_policy((examples_dir / "policy.yaml").read_text()))}
    assert entries["read_file"].conditional
    assert entries["read_file"].conditional_rules == ("block-sensitive-paths",)
    assert not entries["delete_record"].conditional


def test_plan_stops_listing_conditional_rules_after_an_unconditional_match():
    # `allow-all` always wins for fs.read, so the rule below it cannot change
    # the outcome and is not listed.
    entries = plan(
        _policy(
            """
            version: 2
            default_action: deny
            adapters:
              - name: fs
                type: local_tools
                resources: [fs.read]
            rules:
              - name: allow-all
                resource: fs.**
                action: allow
              - name: later-conditional
                resource: fs.read
                action: deny
                where:
                  path: {matches: ["secret"]}
            """
        )
    )
    assert entries[0].conditional_rules == ()


def test_plan_includes_rule_resources_not_declared_by_an_adapter():
    entries = plan(
        _policy(
            """
            version: 2
            default_action: deny
            rules:
              - resource: fs.read
                action: allow
              - resource: fs.**
                action: deny
            """
        )
    )
    # Wildcards describe a set, not a resource, so only fs.read is planned.
    assert [e.resource for e in entries] == ["fs.read"]


def test_plan_is_empty_without_a_declared_surface():
    assert plan(_policy("version: 2\ndefault_action: deny\n")) == []


def test_plan_is_deterministic(examples_dir):
    policy = _policy((examples_dir / "policy-advanced.yaml").read_text())
    assert plan(policy) == plan(policy)
