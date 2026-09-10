//! Read-only policy introspection.
//!
//! Backs `hcuda validate` and `hcuda plan`. Everything here is pure analysis of
//! an already-loaded policy: no tool is executed, no audit record is written, no
//! file is touched. A policy author can run either command against production
//! policy without side effects.
//!
//! `validate` answers "is this policy well-formed, and does it say what you think
//! it says". `plan` answers "what does it decide". They are separate because a
//! policy can be perfectly valid and still decide something surprising.
//!
//! # One check is missing here, on purpose
//!
//! `src/hydracuda/introspect.py` also reports `adapter-unbuildable`, by calling
//! `build_adapter` on every declared adapter and catching the failure. This crate
//! has no adapter registry to call — [`crate::adapter`] is a trait an integrator
//! implements, not a table of names — so that diagnostic cannot fire and is not
//! pretended at. `hcuda validate` states the omission in its output rather than
//! quietly checking less than `hydracuda validate` does, because a validator that
//! silently runs fewer checks is the exact failure this project is about.
//!
//! Every other diagnostic is a port, and the messages are byte-identical to
//! Python's so the two commands cannot drift into disagreeing about the same
//! file.

use std::collections::BTreeSet;

use crate::conditions::{pattern_subsumes, resource_matches, Conditions, Operator};
use crate::engine::{Fields, PolicyEngine};
use crate::policy::{Action, Policy, Rule};
use crate::test_cases::Expect;
use crate::value::{py_repr, py_repr_str_list, Value};

/// Operators that an absent field does not satisfy, even though the English
/// reading of them suggests it would. See [`check_negative_conditions`].
const NEGATIVE_OPERATORS: &[&str] = &["not_equals", "not_in", "not_matches"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Warning,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warning => "warning",
        }
    }
}

/// One finding about a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: Level,
    pub code: String,
    pub message: String,
    pub location: Option<String>,
}

impl Diagnostic {
    fn new(level: Level, code: &str, message: String, location: Option<String>) -> Diagnostic {
        Diagnostic {
            level,
            code: code.to_string(),
            message,
            location,
        }
    }

    pub fn format(&self) -> String {
        let where_ = match &self.location {
            Some(location) => format!(" [{location}]"),
            None => String::new(),
        };
        format!(
            "{}: {}{where_}\n  {}",
            self.level.as_str(),
            self.code,
            self.message
        )
    }
}

/// The decision for one resource on the declared surface.
#[derive(Debug, Clone)]
pub struct PlanEntry {
    pub resource: String,
    pub action: Action,
    pub rule: Option<String>,
    pub reason: String,
    /// Rules that match this resource and carry `where`/`when` conditions. The
    /// reported action holds for a call with no parameters and no context; these
    /// are the rules that could change it for a real call.
    pub conditional_rules: Vec<String>,
}

impl PlanEntry {
    pub fn conditional(&self) -> bool {
        !self.conditional_rules.is_empty()
    }
}

/// The result of validating a policy.
#[derive(Debug, Default)]
pub struct Report {
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    pub fn errors(&self) -> Vec<&Diagnostic> {
        self.of_level(Level::Error)
    }

    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.of_level(Level::Warning)
    }

    fn of_level(&self, level: Level) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.level == level)
            .collect()
    }

    pub fn ok(&self) -> bool {
        self.errors().is_empty()
    }

    fn push(&mut self, level: Level, code: &str, message: String, location: Option<String>) {
        self.diagnostics
            .push(Diagnostic::new(level, code, message, location));
    }
}

fn location(index: usize, rule: &Rule) -> Option<String> {
    Some(format!("rules[{index}] {}", rule.label()))
}

/// Inspect a loaded policy for anything that would surprise its author.
///
/// Schema problems are already hard errors at load time, so everything found here
/// is a policy that parses but does not mean what it appears to.
///
/// Checks run in the order the Python implementation runs them, minus
/// `adapter-unbuildable`, because the output is a list and a reordered list is a
/// diff for anyone comparing the two.
pub fn analyze(policy: &Policy) -> Report {
    let mut report = Report::default();
    check_trust(policy, &mut report);
    check_negative_conditions(policy, &mut report);
    check_posture(policy, &mut report);
    check_rule_order(policy, &mut report);
    check_rules_against_surface(policy, &mut report);
    check_tests(policy, &mut report);
    report
}

/// Report `when` fields the policy does not require to be pinned.
///
/// An unpinned `when` field is read from per-call context, and HYDRACUDA cannot
/// tell whether the integrator sourced that value from a session record or from
/// model output. A rule gating on an unpinned field is therefore only as
/// trustworthy as the calling code, which is worth saying out loud rather than
/// leaving in the specification.
fn check_trust(policy: &Policy, report: &mut Report) {
    let pinned: BTreeSet<&String> = policy.pinned_context.iter().collect();

    for (index, rule) in policy.rules.iter().enumerate() {
        let unpinned: Vec<String> = rule
            .when
            .keys()
            .filter(|field| !pinned.contains(field))
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        if unpinned.is_empty() {
            continue;
        }
        report.push(
            Level::Warning,
            "unpinned-when-field",
            format!(
                "tests context field(s) {}, which are not listed in \
                 `pinned_context`. Those values are supplied per call, so this \
                 rule can only be trusted if the calling code never derives \
                 them from model output. Add them to `pinned_context` to make \
                 HYDRACUDA enforce that.",
                py_repr_str_list(&unpinned)
            ),
            location(index, rule),
        );
    }
}

/// Report blocking rules that a missing field lets through.
///
/// An absent field satisfies no value operator, including the negative ones. That
/// is deliberate and load-bearing elsewhere — it is why a `when` condition can
/// never be satisfied by a same-named request parameter — but it has a
/// consequence worth stating: `deny ... where path not_matches ^/workspace/` does
/// not fire on a call that omits `path` entirely, because the condition is false
/// rather than true. The rule reads as "deny writes outside the workspace" and
/// behaves as "deny writes to a stated path outside the workspace".
fn check_negative_conditions(policy: &Policy, report: &mut Report) {
    for (index, rule) in policy.rules.iter().enumerate() {
        if !rule.action.is_blocking() {
            continue;
        }

        let mut exposed: Vec<String> = Vec::new();
        for (block_name, block) in [("where", &rule.where_), ("when", &rule.when)] {
            for (field, ops) in block.iter() {
                let negative: Vec<&str> = NEGATIVE_OPERATORS
                    .iter()
                    .copied()
                    .filter(|op| ops.contains_key(*op))
                    .collect();
                if negative.is_empty() {
                    continue;
                }
                if absence_is_covered(policy, index, block_name, field) {
                    continue;
                }
                exposed.push(format!("{block_name}.{field} ({})", negative.join(", ")));
            }
        }

        if exposed.is_empty() {
            continue;
        }

        let action = rule.action.as_str();
        report.push(
            Level::Warning,
            "negative-condition-fails-open",
            format!(
                "{}: an absent field satisfies no value operator, so this \
                 '{action}' rule does not fire on a request that omits the field \
                 entirely. Cover that case with a separate '{action}' rule \
                 testing `absent: true` on the same field. Adding `present: \
                 true` here documents the intent but changes nothing — \
                 conditions are ANDed, so the rule still needs the field to be \
                 there.",
                exposed.join("; ")
            ),
            location(index, rule),
        );
    }
}

/// True when another blocking rule handles the field being absent.
///
/// Looks for the actual fix rather than an acknowledgement of the problem: a rule
/// that blocks, covers at least the same resources, and tests the same field with
/// `absent: true`.
fn absence_is_covered(policy: &Policy, index: usize, block_name: &str, field: &str) -> bool {
    let rule = &policy.rules[index];

    policy
        .rules
        .iter()
        .enumerate()
        // Python compares identity (`other is rule`); the index is that
        // comparison here, and it is not the same as comparing contents — two
        // textually identical rules must not cover each other.
        .filter(|(other_index, other)| *other_index != index && other.action.is_blocking())
        .filter(|(_, other)| pattern_subsumes(&other.resource, &rule.resource))
        .any(|(_, other)| {
            let block = if block_name == "where" {
                &other.where_
            } else {
                &other.when
            };
            matches!(
                block.get(field).and_then(|ops| ops.get("absent")),
                Some(Operator::Absent(true))
            )
        })
}

fn check_posture(policy: &Policy, report: &mut Report) {
    if policy.mode.as_str() == "shadow" {
        report.push(
            Level::Warning,
            "shadow-mode",
            "`mode: shadow` computes and logs every decision but executes the \
             call regardless. This policy enforces nothing."
                .to_string(),
            Some("mode".to_string()),
        );
    }

    if policy.default_action == Action::Allow {
        report.push(
            Level::Warning,
            "default-allow",
            "`default_action: allow` means a resource no rule mentions is \
             permitted, so adding a tool without adding a rule fails open."
                .to_string(),
            Some("default_action".to_string()),
        );
    }

    if policy.rules.is_empty() {
        report.push(
            Level::Warning,
            "no-rules",
            format!(
                "the policy declares no rules, so every request falls through to \
                 `default_action: {}`.",
                policy.default_action.as_str()
            ),
            Some("rules".to_string()),
        );
    }
}

/// Find rules an earlier rule makes unreachable.
///
/// First match wins, so a broad rule above a narrow one silently disables it.
/// Only provable cases are reported — see [`pattern_subsumes`].
fn check_rule_order(policy: &Policy, report: &mut Report) {
    let mut names: Vec<(&str, usize)> = Vec::new();

    for (index, rule) in policy.rules.iter().enumerate() {
        if let Some(name) = rule.name.as_deref().filter(|name| !name.is_empty()) {
            match names.iter().find(|(seen, _)| *seen == name) {
                Some((_, first)) => report.push(
                    Level::Warning,
                    "duplicate-rule-name",
                    format!(
                        "another rule at rules[{first}] has the same name; names \
                         appear in decisions and audit records, so duplicates \
                         make a log ambiguous"
                    ),
                    location(index, rule),
                ),
                None => names.push((name, index)),
            }
        }

        for earlier_index in 0..index {
            let earlier = &policy.rules[earlier_index];
            if !pattern_subsumes(&earlier.resource, &rule.resource) {
                continue;
            }

            let same_conditions = conditions_key(earlier) == conditions_key(rule);
            // Equivalent patterns, not merely overlapping ones. A broad rule
            // above a narrow one shadows it, but it is not a conflict between two
            // rules about the same thing.
            let same_resources = pattern_subsumes(&rule.resource, &earlier.resource);
            let unconditional = earlier.where_.is_empty() && earlier.when.is_empty();

            if same_resources && same_conditions {
                if earlier.action != rule.action {
                    report.push(
                        Level::Warning,
                        "conflicting-rules",
                        format!(
                            "rules[{earlier_index}] {} matches the same resources \
                             under the same conditions but decides '{}' instead \
                             of '{}'. First match wins, so '{}' is what happens.",
                            earlier.label(),
                            earlier.action.as_str(),
                            rule.action.as_str(),
                            earlier.action.as_str(),
                        ),
                        location(index, rule),
                    );
                } else {
                    report.push(
                        Level::Warning,
                        "duplicate-rule",
                        format!(
                            "rules[{earlier_index}] {} already decides '{}' for \
                             these resources under the same conditions; this rule \
                             never fires.",
                            earlier.label(),
                            rule.action.as_str(),
                        ),
                        location(index, rule),
                    );
                }
            } else if unconditional || same_conditions {
                let qualifier = if unconditional {
                    "unconditionally"
                } else {
                    "under the same conditions as this rule"
                };
                report.push(
                    Level::Warning,
                    "unreachable-rule",
                    format!(
                        "rules[{earlier_index}] {} matches '{}' {qualifier} and \
                         decides '{}', so this rule is never reached. Move it \
                         above rules[{earlier_index}].",
                        earlier.label(),
                        rule.resource,
                        earlier.action.as_str(),
                    ),
                    location(index, rule),
                );
            } else {
                // The earlier rule covers these resources but only under its own
                // conditions, so this rule is still reachable.
                continue;
            }
            break;
        }
    }
}

/// Report rules that no declared resource can match.
///
/// Only meaningful once adapters declare a surface. A version 1 policy, or one
/// with no `adapters` block, has nothing to check against.
fn check_rules_against_surface(policy: &Policy, report: &mut Report) {
    let declared = crate::test_cases::adapter_surface(policy);
    if declared.is_empty() {
        return;
    }

    for (index, rule) in policy.rules.iter().enumerate() {
        if declared
            .iter()
            .any(|name| resource_matches(&rule.resource, name))
        {
            continue;
        }
        report.push(
            Level::Warning,
            "unmatched-rule-resource",
            format!(
                "resource pattern '{}' matches nothing any adapter declares. \
                 Either the pattern is misspelled, or the adapter's `resources` \
                 list is incomplete — in which case the rule will still apply at \
                 runtime but `plan` cannot show it.",
                rule.resource
            ),
            location(index, rule),
        );
    }
}

/// Check the `tests:` block itself, before any case runs.
///
/// The first two findings are errors, which is how the specification's "hard
/// error" survives being a diagnostic rather than a load failure: `validate` and
/// `test` both exit non-zero on an error. They are not load errors because the
/// specification assigns them codes and levels in the diagnostic table, and a
/// diagnostic that can never fire — because loading already refused the file —
/// is worse than no diagnostic.
fn check_tests(policy: &Policy, report: &mut Report) {
    let declared = crate::test_cases::adapter_surface(policy);
    let when_fields = policy.when_fields();

    let mut names: Vec<(&str, usize)> = Vec::new();

    for (index, case) in policy.tests.iter().enumerate() {
        let at = Some(format!("tests[{index}] {}", case.name));

        match names.iter().find(|(seen, _)| *seen == case.name.as_str()) {
            Some((_, first)) => report.push(
                Level::Error,
                "test-duplicate-name",
                format!(
                    "the case at tests[{first}] has the same name; the output is \
                     per-case pass/fail, so two cases sharing a name make that \
                     report unreadable"
                ),
                at.clone(),
            ),
            None => names.push((case.name.as_str(), index)),
        }

        if case.resource.contains('*') {
            report.push(
                Level::Error,
                "test-resource-is-a-pattern",
                format!(
                    "resource '{}' contains a wildcard. A test case asserts one \
                     request, so `resource` is an exact name — use one case per \
                     resource the pattern covers.",
                    case.resource
                ),
                at.clone(),
            );
        }

        if case.expect != Expect::Refused
            && !declared.is_empty()
            && !declared.contains(&case.resource)
        {
            report.push(
                Level::Warning,
                "test-undeclared-resource",
                format!(
                    "no adapter declares '{}', so it is refused at the adapter \
                     boundary before any rule is consulted and this case cannot \
                     pass. Add it to an adapter's `resources`, or expect \
                     `refused`.",
                    case.resource
                ),
                at.clone(),
            );
        }

        let missing: Vec<String> = policy
            .pinned_context
            .iter()
            .filter(|field| !case.context.contains_key(field.as_str()))
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        if !missing.is_empty() {
            report.push(
                Level::Warning,
                "test-missing-pinned-context",
                format!(
                    "`pinned_context` names {}, which this case does not set. \
                     Context construction fails without a pinned field at \
                     runtime, so the case is evaluating a state that cannot \
                     occur.",
                    py_repr_str_list(&missing)
                ),
                at.clone(),
            );
        }

        let unread: Vec<String> = case
            .context
            .keys()
            .filter(|field| !when_fields.contains(field.as_str()))
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        if !unread.is_empty() {
            report.push(
                Level::Warning,
                "test-unread-context-field",
                format!(
                    "sets context field(s) {}, which no rule's `when` block \
                     reads. Usually a typo, and a typo'd field name makes the \
                     case assert something other than what it appears to.",
                    py_repr_str_list(&unread)
                ),
                at,
            );
        }
    }
}

/// Decide every resource on the declared surface, without executing any.
///
/// Each entry is evaluated with no parameters and no context, which is the only
/// input a policy file supplies on its own. Rules that depend on either are
/// listed in `conditional_rules` rather than guessed at.
pub fn plan(policy: &Policy) -> Vec<PlanEntry> {
    let engine = PolicyEngine::new(policy);
    let empty = Fields::new();

    policy
        .declared_resources()
        .into_iter()
        .map(|resource| {
            let decision = engine.evaluate(&resource, &empty, &empty);
            PlanEntry {
                conditional_rules: conditional_rules(policy, &resource),
                resource,
                action: decision.action,
                rule: decision.rule,
                reason: decision.reason,
            }
        })
        .collect()
}

/// Rules whose applicability to `resource` depends on params or context.
///
/// Rules below the first unconditional match are skipped: that match always wins,
/// so nothing after it can change the outcome for this resource.
fn conditional_rules(policy: &Policy, resource: &str) -> Vec<String> {
    let mut labels = Vec::new();
    for rule in &policy.rules {
        if !resource_matches(&rule.resource, resource) {
            continue;
        }
        if rule.where_.is_empty() && rule.when.is_empty() {
            break;
        }
        labels.push(rule.label());
    }
    labels
}

/// A comparable form of a rule's conditions.
///
/// Python compares nested dicts with `==`. There is no `PartialEq` on
/// [`Operator`] — a compiled regex is not comparable, and comparing two [`Value`]s
/// is Python's cross-type equality rather than a derive — so the comparison is
/// done on a canonical string instead. Fields and operators are sorted, matching
/// Python's `sorted(...)`, because file order is not part of what a condition
/// block means.
fn conditions_key(rule: &Rule) -> (String, String) {
    (block_key(&rule.where_), block_key(&rule.when))
}

fn block_key(block: &Conditions) -> String {
    let mut fields: Vec<(&String, &_)> = block.iter().collect();
    fields.sort_by(|a, b| a.0.cmp(b.0));

    fields
        .into_iter()
        .map(|(field, ops)| {
            let mut ops: Vec<(&String, &Operator)> = ops.iter().collect();
            ops.sort_by(|a, b| a.0.cmp(b.0));
            let ops: Vec<String> = ops
                .into_iter()
                .map(|(name, op)| format!("{name}:{}", operator_key(op)))
                .collect();
            format!("{field}={}", ops.join(","))
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn operator_key(op: &Operator) -> String {
    match op {
        Operator::Matches(patterns) | Operator::NotMatches(patterns) => patterns
            .iter()
            .map(|p| p.source.clone())
            .collect::<Vec<_>>()
            .join("\u{1f}"),
        Operator::Equals(value) | Operator::NotEquals(value) => scalar_key(value),
        Operator::In(values) | Operator::NotIn(values) => values
            .iter()
            .map(scalar_key)
            .collect::<Vec<_>>()
            .join("\u{1f}"),
        Operator::Present(flag) | Operator::Absent(flag) => flag.to_string(),
    }
}

/// One scalar's key, under Python's equality rather than Rust's.
///
/// `True == 1` and `1.0 == 1` in Python, so a policy writing `equals: 1` in one
/// rule and `equals: true` in another has two rules Python calls identical. The
/// numeric types collapse to one key so `duplicate-rule` fires on that pair in
/// both implementations.
fn scalar_key(value: &Value) -> String {
    match value {
        Value::Bool(flag) => format!("n{}", i64::from(*flag)),
        Value::Int(i) => format!("n{i}"),
        Value::Float(f) if f.fract() == 0.0 && f.is_finite() => format!("n{}", *f as i64),
        other => py_repr(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_str(source: &str) -> Report {
        analyze(&Policy::from_yaml_str(source).unwrap())
    }

    fn codes(report: &Report) -> Vec<&str> {
        report.diagnostics.iter().map(|d| d.code.as_str()).collect()
    }

    #[test]
    fn a_clean_policy_reports_nothing() {
        let report = analyze_str(
            "version: 2\n\
             pinned_context: [trust]\n\
             adapters:\n  - {name: local, type: local_tools, resources: [fs.read]}\n\
             rules:\n  - {resource: fs.read, action: allow, when: {trust: {equals: ok}}}\n",
        );
        assert_eq!(codes(&report), Vec::<&str>::new());
        assert!(report.ok());
    }

    #[test]
    fn an_unpinned_when_field_is_reported_per_rule() {
        let report = analyze_str(
            "version: 2\n\
             rules:\n  - {resource: fs.read, action: allow, when: {trust: {equals: ok}}}\n",
        );
        let found = &report.diagnostics[0];
        assert_eq!(found.code, "unpinned-when-field");
        assert!(found.message.contains("['trust']"), "{}", found.message);
        assert_eq!(found.location.as_deref(), Some("rules[0] allow:fs.read"));
    }

    #[test]
    fn a_negative_condition_on_a_blocking_rule_is_reported() {
        let report = analyze_str(
            "version: 2\n\
             default_action: allow\n\
             rules:\n  - {resource: fs.write, action: deny, \
             where: {path: {not_matches: '^/workspace/'}}}\n",
        );
        assert!(codes(&report).contains(&"negative-condition-fails-open"));
    }

    #[test]
    fn a_covering_absent_rule_silences_it() {
        // The fix, not an acknowledgement of the problem.
        let report = analyze_str(
            "version: 2\n\
             default_action: allow\n\
             rules:\n  \
             - {resource: 'fs.**', action: deny, where: {path: {absent: true}}}\n  \
             - {resource: fs.write, action: deny, where: {path: {not_matches: '^/w/'}}}\n",
        );
        assert!(!codes(&report).contains(&"negative-condition-fails-open"));
    }

    #[test]
    fn an_identical_rule_does_not_cover_its_own_absence_case() {
        // Two textually identical rules: Python's `other is rule` identity check
        // excludes only the rule itself, so the *other* one must still count as
        // uncovered. Comparing by contents instead of index would silence both.
        let report = analyze_str(
            "version: 2\n\
             default_action: allow\n\
             rules:\n  \
             - {resource: fs.write, action: deny, where: {path: {not_matches: '^/w/'}}}\n  \
             - {resource: fs.write, action: deny, where: {path: {not_matches: '^/w/'}}}\n",
        );
        let reported = report
            .diagnostics
            .iter()
            .filter(|d| d.code == "negative-condition-fails-open")
            .count();
        assert_eq!(reported, 2);
    }

    #[test]
    fn posture_warnings_name_their_own_key() {
        let report = analyze_str("version: 2\nmode: shadow\ndefault_action: allow\nrules: []\n");
        assert_eq!(codes(&report), ["shadow-mode", "default-allow", "no-rules"]);
        assert_eq!(report.diagnostics[0].location.as_deref(), Some("mode"));
    }

    #[test]
    fn a_broad_rule_above_a_narrow_one_makes_it_unreachable() {
        let report = analyze_str(
            "version: 2\n\
             rules:\n  \
             - {name: broad, resource: 'fs.**', action: allow}\n  \
             - {name: narrow, resource: fs.read, action: deny}\n",
        );
        let found = &report.diagnostics[0];
        assert_eq!(found.code, "unreachable-rule");
        assert!(
            found.message.contains("unconditionally"),
            "{}",
            found.message
        );
        assert_eq!(found.location.as_deref(), Some("rules[1] narrow"));
    }

    #[test]
    fn equivalent_patterns_disagreeing_is_a_conflict_not_a_shadow() {
        let report = analyze_str(
            "version: 2\n\
             rules:\n  \
             - {name: first, resource: fs.read, action: allow}\n  \
             - {name: second, resource: fs.read, action: deny}\n",
        );
        assert_eq!(codes(&report), ["conflicting-rules"]);
        assert!(report.diagnostics[0]
            .message
            .contains("'allow' is what happens"));
    }

    #[test]
    fn equivalent_patterns_agreeing_is_a_duplicate() {
        let report = analyze_str(
            "version: 2\n\
             rules:\n  \
             - {name: first, resource: fs.read, action: deny}\n  \
             - {name: second, resource: fs.read, action: deny}\n",
        );
        assert_eq!(codes(&report), ["duplicate-rule"]);
    }

    #[test]
    fn a_conditional_earlier_rule_leaves_a_later_one_reachable() {
        let report = analyze_str(
            "version: 2\n\
             pinned_context: []\n\
             rules:\n  \
             - {name: conditional, resource: 'fs.**', action: allow, \
             where: {path: {matches: '^/w/'}}}\n  \
             - {name: narrow, resource: fs.read, action: deny}\n",
        );
        assert!(!codes(&report).contains(&"unreachable-rule"));
    }

    #[test]
    fn a_duplicate_rule_name_points_at_the_first_one() {
        let report = analyze_str(
            "version: 2\n\
             rules:\n  \
             - {name: same, resource: fs.read, action: allow}\n  \
             - {name: same, resource: fs.write, action: allow}\n",
        );
        assert_eq!(codes(&report), ["duplicate-rule-name"]);
        assert!(report.diagnostics[0].message.contains("rules[0]"));
    }

    #[test]
    fn a_rule_matching_nothing_declared_is_reported() {
        let report = analyze_str(
            "version: 2\n\
             adapters:\n  - {name: local, type: local_tools, resources: [fs.read]}\n\
             rules:\n  - {resource: 'net.*', action: deny}\n",
        );
        assert!(codes(&report).contains(&"unmatched-rule-resource"));
    }

    #[test]
    fn integers_and_booleans_compare_the_way_python_compares_them() {
        // `equals: 1` and `equals: true` are the same condition in Python, so
        // these two rules are a duplicate pair in both implementations.
        let report = analyze_str(
            "version: 2\n\
             pinned_context: [flag]\n\
             rules:\n  \
             - {resource: fs.read, action: deny, when: {flag: {equals: 1}}}\n  \
             - {resource: fs.read, action: deny, when: {flag: {equals: true}}}\n",
        );
        assert_eq!(codes(&report), ["duplicate-rule"]);
    }

    // --- the `tests:` block ----------------------------------------------

    const SURFACE: &str = "version: 2\n\
        adapters:\n  - {name: local, type: local_tools, resources: [fs.read]}\n\
        rules:\n  - {resource: fs.read, action: allow}\n";

    #[test]
    fn a_duplicate_test_name_is_an_error_not_a_warning() {
        // Stricter than `duplicate-rule-name` on purpose: rule names can be
        // generated by version 1 translation, test names are always written.
        let report = analyze_str(&format!(
            "{SURFACE}tests:\n  \
             - {{name: same, resource: fs.read, expect: allow}}\n  \
             - {{name: same, resource: fs.read, expect: allow}}\n"
        ));
        assert_eq!(codes(&report), ["test-duplicate-name"]);
        assert_eq!(report.diagnostics[0].level, Level::Error);
        assert!(!report.ok());
    }

    #[test]
    fn a_wildcard_test_resource_is_an_error() {
        let report = analyze_str(&format!(
            "{SURFACE}tests:\n  - {{name: a, resource: 'fs.*', expect: allow}}\n"
        ));
        assert!(codes(&report).contains(&"test-resource-is-a-pattern"));
        assert!(!report.ok());
    }

    #[test]
    fn a_case_no_adapter_declares_is_reported_unless_it_expects_refusal() {
        let report = analyze_str(&format!(
            "{SURFACE}tests:\n  \
             - {{name: bad, resource: fs.chmod, expect: deny}}\n  \
             - {{name: fine, resource: fs.chmod, expect: refused}}\n"
        ));
        assert_eq!(codes(&report), ["test-undeclared-resource"]);
        assert_eq!(
            report.diagnostics[0].location.as_deref(),
            Some("tests[0] bad")
        );
    }

    #[test]
    fn a_case_that_skips_a_pinned_field_is_testing_an_impossible_state() {
        let report = analyze_str(
            "version: 2\n\
             pinned_context: [trust]\n\
             adapters:\n  - {name: local, type: local_tools, resources: [fs.read]}\n\
             rules:\n  - {resource: fs.read, action: allow, when: {trust: {equals: ok}}}\n\
             tests:\n  - {name: a, resource: fs.read, expect: deny}\n",
        );
        assert_eq!(codes(&report), ["test-missing-pinned-context"]);
        assert!(report.diagnostics[0].message.contains("['trust']"));
    }

    #[test]
    fn a_context_field_no_rule_reads_is_probably_a_typo() {
        let report = analyze_str(&format!(
            "{SURFACE}tests:\n  \
             - {{name: a, resource: fs.read, context: {{trsut: ok}}, expect: allow}}\n"
        ));
        assert_eq!(codes(&report), ["test-unread-context-field"]);
        assert!(report.diagnostics[0].message.contains("['trsut']"));
    }

    #[test]
    fn a_policy_with_no_tests_reports_nothing_about_them() {
        let report = analyze_str(SURFACE);
        assert_eq!(codes(&report), Vec::<&str>::new());
    }

    // --- plan -------------------------------------------------------------

    #[test]
    fn plan_decides_every_declared_resource() {
        let policy = Policy::from_yaml_str(
            "version: 2\n\
             adapters:\n  - {name: local, type: local_tools, resources: [fs.read, fs.write]}\n\
             rules:\n  - {name: reads, resource: fs.read, action: allow}\n",
        )
        .unwrap();
        let entries = plan(&policy);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].resource, "fs.read");
        assert_eq!(entries[0].action.as_str(), "allow");
        assert_eq!(entries[0].rule.as_deref(), Some("reads"));
        assert!(!entries[0].conditional());
        // No rule mentions it, so it falls to `default_action`.
        assert_eq!(entries[1].action.as_str(), "deny");
        assert_eq!(entries[1].rule, None);
    }

    #[test]
    fn plan_flags_a_resource_whose_outcome_depends_on_the_request() {
        let policy = Policy::from_yaml_str(
            "version: 2\n\
             adapters:\n  - {name: local, type: local_tools, resources: [fs.read]}\n\
             rules:\n  \
             - {name: traversal, resource: fs.read, action: deny, \
             where: {path: {matches: '\\.\\.'}}}\n  \
             - {name: reads, resource: fs.read, action: allow}\n",
        )
        .unwrap();
        let entry = &plan(&policy)[0];

        // Reported for a call with no parameters, with the rule that could
        // change it named rather than guessed at.
        assert_eq!(entry.action.as_str(), "allow");
        assert_eq!(entry.conditional_rules, ["traversal"]);
    }

    #[test]
    fn plan_stops_listing_after_the_first_unconditional_match() {
        // That rule always wins, so nothing below it can change the outcome.
        let policy = Policy::from_yaml_str(
            "version: 2\n\
             adapters:\n  - {name: local, type: local_tools, resources: [fs.read]}\n\
             rules:\n  \
             - {name: reads, resource: fs.read, action: allow}\n  \
             - {name: later, resource: fs.read, action: deny, \
             where: {path: {matches: x}}}\n",
        )
        .unwrap();
        assert!(plan(&policy)[0].conditional_rules.is_empty());
    }

    #[test]
    fn a_diagnostic_formats_with_its_location() {
        let diagnostic = Diagnostic::new(
            Level::Warning,
            "shadow-mode",
            "enforces nothing.".to_string(),
            Some("mode".to_string()),
        );
        assert_eq!(
            diagnostic.format(),
            "warning: shadow-mode [mode]\n  enforces nothing."
        );
    }
}
