//! The `tests:` block: what the author believed the policy allowed.
//!
//! A policy file states what is allowed. A `tests:` block states what the author
//! *believed* it allowed, in a form the tool can check. Strict validation catches
//! a misspelled key; it cannot catch a correctly spelled rule in the wrong order,
//! and rule order is first-match-wins. That is the gap this block closes.
//!
//! The schema is specified in `docs/policy-spec.md`; this is the implementation
//! of it. Two things about the division of labour here:
//!
//! - **Loading checks shape, not sense.** A bad key, a missing `name`, an
//!   `expect` that is not one of the four words: load errors, like everywhere
//!   else in the format. Duplicate names and a `resource` containing a wildcard
//!   are *diagnostics* instead, even though the specification calls them hard
//!   errors, because the diagnostics table gives them codes and an error level —
//!   and a diagnostic that can never fire, because loading already refused the
//!   file, is worse than no diagnostic. They are still hard: `validate` and
//!   `test` both exit non-zero on an error-level finding.
//! - **Running is pure.** No tool is executed, no audit record is written, no
//!   clock is read. The policy file is the only input, which is what makes a
//!   `tests:` block something CI can run on every commit.

use indexmap::IndexMap;

use crate::engine::{Fields, PolicyEngine};
use crate::policy::{reject_unknown_keys, require_mapping, Policy, PolicyError};
use crate::value::{py_repr, py_truthy, Value};

const TEST_KEYS: &[&str] = &[
    "context",
    "expect",
    "expect_rule",
    "name",
    "params",
    "resource",
];

/// What a test case asserts about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Allow,
    Deny,
    Review,
    /// Refused at the adapter boundary before any rule was consulted.
    ///
    /// Separate from `Deny` rather than folded into it because they are different
    /// mechanisms, and a test that accepted either would pass for the wrong
    /// reason — reporting a policy rule as the control when confinement was doing
    /// the work, or the reverse.
    Refused,
}

impl Expect {
    pub fn parse(value: &Value) -> Option<Expect> {
        match value.as_str()? {
            "allow" => Some(Expect::Allow),
            "deny" => Some(Expect::Deny),
            "review" => Some(Expect::Review),
            "refused" => Some(Expect::Refused),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Expect::Allow => "allow",
            Expect::Deny => "deny",
            Expect::Review => "review",
            Expect::Refused => "refused",
        }
    }
}

/// One assertion about one request.
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub resource: String,
    pub expect: Expect,
    /// Literal parameter values — the agent-controlled side, tested by `where`.
    pub params: Fields,
    /// Literal context values — the integrator-controlled side, tested by `when`.
    pub context: Fields,
    /// The rule that must produce the decision.
    ///
    /// `expect` alone cannot tell the right answer from the right answer for the
    /// wrong reason: with first-match-wins, a rule moved above another can leave
    /// every `expect` satisfied while the policy has changed meaning.
    pub expect_rule: Option<String>,
}

/// What running one case produced.
///
/// There is no `Unsupported` variant, unlike the Python runner's `UNSUPPORTED`.
/// Python produces that when an adapter cannot be *built*, which needs the
/// registry this crate does not have — so `hcuda` cannot detect the condition at
/// all, and a variant nothing ever constructs is the same defect as a diagnostic
/// that can never fire. `hcuda validate` states the omission in its header
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed { detail: String },
}

impl Outcome {
    /// The word the CLI prints, and the word the Python runner uses for the same
    /// state, so `--compare-engines` compares like with like.
    pub fn status(&self) -> &'static str {
        match self {
            Outcome::Passed => "pass",
            Outcome::Failed { .. } => "fail",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Outcome::Passed => "",
            Outcome::Failed { detail } => detail,
        }
    }
}

/// One case and what happened to it.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub name: String,
    pub resource: String,
    pub expect: Expect,
    pub outcome: Outcome,
}

impl CaseResult {
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Passed
    }
}

/// Parse the `tests:` block. Version 2 only — see `Policy::parse`.
pub fn parse_tests(raw: &IndexMap<String, Value>) -> Result<Vec<TestCase>, PolicyError> {
    let raw_tests = match raw.get("tests") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value) => value
            .as_seq()
            .ok_or_else(|| PolicyError("'tests' must be a list".into()))?,
    };

    let mut cases = Vec::with_capacity(raw_tests.len());
    for (index, raw_case) in raw_tests.iter().enumerate() {
        let mut where_ = format!("tests[{index}]");
        let raw_case = require_mapping(raw_case, &where_)?;
        reject_unknown_keys(&where_, raw_case, TEST_KEYS)?;

        // `name` is required here, unlike a rule's, because the output is
        // per-case pass/fail and an unnamed case cannot be reported on. Read
        // first so every later message about this case identifies it.
        let name = match raw_case.get("name").and_then(|v| v.as_str()) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => {
                return Err(PolicyError(format!(
                    "{where_}: 'name' is required and must be a string"
                )))
            }
        };
        where_ = format!("tests[{index}] ('{name}')");

        let resource = match raw_case.get("resource").and_then(|v| v.as_str()) {
            Some(resource) if !resource.is_empty() => resource.to_string(),
            _ => {
                return Err(PolicyError(format!(
                    "{where_}: 'resource' is required and must be a string"
                )))
            }
        };

        let raw_expect = raw_case.get("expect").cloned().unwrap_or(Value::Null);
        let expect = Expect::parse(&raw_expect).ok_or_else(|| {
            PolicyError(format!(
                "{where_}: 'expect' must be one of ['allow', 'deny', 'refused', 'review'], got {}",
                py_repr(&raw_expect)
            ))
        })?;

        cases.push(TestCase {
            name,
            resource,
            expect,
            params: literal_fields(raw_case.get("params"), &where_, "params")?,
            context: literal_fields(raw_case.get("context"), &where_, "context")?,
            expect_rule: match raw_case.get("expect_rule") {
                None | Some(Value::Null) => None,
                Some(Value::Str(rule)) => Some(rule.clone()),
                Some(_) => {
                    return Err(PolicyError(format!(
                        "{where_}: 'expect_rule' must be a string"
                    )))
                }
            },
        });
    }

    Ok(cases)
}

/// A `params:`/`context:` mapping of literal values.
///
/// Deliberately *not* run through `validate_conditions`. These are the values a
/// request carries, not operators on them, which is why the keys are `params` and
/// `context` rather than `where` and `when`: reusing those names would let
/// `path: {matches: [...]}` parse as a literal mapping and produce a case that
/// passes or fails for a reason unrelated to the policy.
fn literal_fields(value: Option<&Value>, where_: &str, key: &str) -> Result<Fields, PolicyError> {
    match value {
        // `py_truthy`, not just a null check, because Python writes this as
        // `raw_case.get("params") or {}` — so `params: []` and `params: 0` become
        // an empty mapping there rather than a type error, and the two loaders
        // have to refuse the same files.
        None => Ok(Fields::new()),
        Some(value) if !py_truthy(value) => Ok(Fields::new()),
        Some(value) => Ok(require_mapping(value, &format!("{where_}: '{key}'"))?.clone()),
    }
}

/// Run every case in the policy's `tests:` block.
///
/// Pure: `PolicyEngine::evaluate` is called exactly as `plan` calls it, with no
/// proxy, no execution and no audit record.
pub fn run_tests(policy: &Policy) -> Vec<CaseResult> {
    let engine = PolicyEngine::new(policy);
    let declared = adapter_surface(policy);

    policy
        .tests
        .iter()
        .map(|case| CaseResult {
            name: case.name.clone(),
            resource: case.resource.clone(),
            expect: case.expect,
            outcome: run_case(&engine, &declared, case),
        })
        .collect()
}

fn run_case(engine: &PolicyEngine<'_>, declared: &[String], case: &TestCase) -> Outcome {
    // Adapter normalization first, in the order the proxy uses. A policy that
    // declares no adapters has no adapter boundary at all — `ToolCallProxy` skips
    // normalization when it was built without one — so nothing is refused and
    // every case is evaluated.
    if declared.is_empty() {
        if case.expect == Expect::Refused {
            return Outcome::Failed {
                detail: "expected refused, but the policy declares no adapters, \
                         so there is no boundary to refuse at and every request \
                         reaches the rules"
                    .to_string(),
            };
        }
    } else if !declared.iter().any(|name| name == &case.resource) {
        return if case.expect == Expect::Refused {
            Outcome::Passed
        } else {
            Outcome::Failed {
                detail: format!(
                    "expected {}, got refused — no adapter declares '{}'",
                    case.expect.as_str(),
                    case.resource
                ),
            }
        };
    }
    // A *declared* resource is not refused. The specification's other refusal —
    // a path failing canonicalization or root confinement — cannot arise from a
    // policy file alone: `build_adapter` declares each resource with no
    // `path_parameters`, and `normalize` only canonicalizes those, so an adapter
    // built from an `adapters:` block rewrites nothing. Refusing or hedging here
    // would report on a control that was never run. An `expect: refused` case on
    // a declared resource therefore falls through and fails against whatever the
    // rules decide, which is also what the Python runner reports.

    let decision = engine.evaluate(&case.resource, &case.params, &case.context);

    if decision.action.as_str() != case.expect.as_str() {
        return Outcome::Failed {
            detail: format!(
                "expected {}, got {} from {}",
                case.expect.as_str(),
                decision.action.as_str(),
                decision.rule.as_deref().unwrap_or("(default)"),
            ),
        };
    }

    // The right answer for the wrong reason is still wrong.
    if let Some(expected_rule) = &case.expect_rule {
        let actual = decision.rule.as_deref().unwrap_or("(default)");
        if actual != expected_rule {
            return Outcome::Failed {
                detail: format!(
                    "expected {} from '{expected_rule}', got {} from '{actual}'",
                    case.expect.as_str(),
                    decision.action.as_str(),
                ),
            };
        }
    }

    Outcome::Passed
}

/// Every resource an adapter declares.
///
/// Adapter resources only, not `Policy::declared_resources`, which also folds in
/// concrete rule resources. Refusal is an adapter-boundary outcome: a rule
/// mentioning a resource does not make it exist.
pub fn adapter_surface(policy: &Policy) -> Vec<String> {
    policy
        .adapters
        .iter()
        .flat_map(|adapter| adapter.resources.iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(source: &str) -> Policy {
        Policy::from_yaml_str(source).unwrap()
    }

    fn error(source: &str) -> String {
        Policy::from_yaml_str(source).unwrap_err().to_string()
    }

    const SURFACE: &str = "version: 2\n\
        adapters:\n  - {name: local, type: local_tools, resources: [fs.read, fs.write]}\n";

    #[test]
    fn a_case_is_parsed_with_its_literal_values() {
        let policy = policy(&format!(
            "{SURFACE}rules:\n  - {{resource: fs.read, action: allow}}\n\
             tests:\n  - name: reads-are-allowed\n    resource: fs.read\n    \
             params: {{path: /srv/x}}\n    context: {{trust: verified}}\n    \
             expect: allow\n    expect_rule: allow:fs.read\n"
        ));
        let case = &policy.tests[0];
        assert_eq!(case.name, "reads-are-allowed");
        assert_eq!(case.expect, Expect::Allow);
        // `py_repr` rather than `==`: `Value` has no `PartialEq`, because
        // comparing two of them is Python's cross-type equality and lives in
        // `py_equal`. A derive would be a second, subtly different answer.
        assert_eq!(py_repr(&case.params["path"]), "'/srv/x'");
        assert_eq!(py_repr(&case.context["trust"]), "'verified'");
        assert_eq!(case.expect_rule.as_deref(), Some("allow:fs.read"));
    }

    #[test]
    fn params_and_context_default_to_empty() {
        let policy = policy(&format!(
            "{SURFACE}tests:\n  - {{name: a, resource: fs.read, expect: deny}}\n"
        ));
        assert!(policy.tests[0].params.is_empty());
        assert!(policy.tests[0].context.is_empty());
    }

    #[test]
    fn an_unknown_key_is_a_load_error_with_a_suggestion() {
        let message = error(&format!(
            "{SURFACE}tests:\n  - {{name: a, resource: fs.read, expect: deny, expectRule: r}}\n"
        ));
        assert!(
            message.contains("unrecognized key(s) ['expectRule']"),
            "{message}"
        );
        assert!(message.contains("did you mean 'expect_rule'"), "{message}");
    }

    #[test]
    fn name_resource_and_expect_are_all_required() {
        for (source, expected) in [
            (
                "  - {resource: fs.read, expect: deny}\n",
                "'name' is required",
            ),
            ("  - {name: a, expect: deny}\n", "'resource' is required"),
            (
                "  - {name: a, resource: fs.read}\n",
                "'expect' must be one of",
            ),
        ] {
            let message = error(&format!("{SURFACE}tests:\n{source}"));
            assert!(message.contains(expected), "{message}");
        }
    }

    #[test]
    fn a_named_case_identifies_itself_in_its_own_error() {
        let message = error(&format!(
            "{SURFACE}tests:\n  - {{name: my-case, resource: fs.read, expect: maybe}}\n"
        ));
        assert!(message.contains("tests[0] ('my-case')"), "{message}");
    }

    #[test]
    fn tests_are_not_a_version_1_key() {
        // A legacy file gets no new surface. `tests:` reaches the unknown-key
        // sweep, which is the same answer as any other v2 key in a v1 file.
        let message = error("version: 1\ntools: {}\ntests: []\n");
        assert!(
            message.contains("unrecognized key(s) ['tests']"),
            "{message}"
        );
    }

    #[test]
    fn a_case_passes_when_the_decision_matches() {
        let policy = policy(&format!(
            "{SURFACE}rules:\n  - {{resource: fs.read, action: allow}}\n\
             tests:\n  - {{name: a, resource: fs.read, expect: allow}}\n"
        ));
        let results = run_tests(&policy);
        assert!(results[0].passed(), "{:?}", results[0].outcome);
    }

    #[test]
    fn a_case_fails_naming_both_decisions() {
        let policy = policy(&format!(
            "{SURFACE}rules:\n  - {{name: blocked, resource: fs.read, action: deny}}\n\
             tests:\n  - {{name: a, resource: fs.read, expect: allow}}\n"
        ));
        let Outcome::Failed { detail } = &run_tests(&policy)[0].outcome else {
            panic!("expected a failure");
        };
        assert_eq!(detail, "expected allow, got deny from blocked");
    }

    #[test]
    fn expect_rule_catches_the_right_answer_for_the_wrong_reason() {
        // Both rules deny, so `expect` alone passes either way. This is the
        // reordering that `expect_rule` exists to catch.
        let policy = policy(&format!(
            "{SURFACE}rules:\n  \
             - {{name: broad, resource: 'fs.*', action: deny}}\n  \
             - {{name: specific, resource: fs.read, action: deny}}\n\
             tests:\n  - {{name: a, resource: fs.read, expect: deny, expect_rule: specific}}\n"
        ));
        let Outcome::Failed { detail } = &run_tests(&policy)[0].outcome else {
            panic!("expected a failure");
        };
        assert_eq!(
            detail,
            "expected deny from 'specific', got deny from 'broad'"
        );
    }

    #[test]
    fn an_undeclared_resource_is_refused_before_any_rule_is_consulted() {
        // The rule would allow it. The adapter boundary comes first.
        let policy = policy(&format!(
            "{SURFACE}rules:\n  - {{resource: 'fs.**', action: allow}}\n\
             tests:\n  \
             - {{name: refused, resource: fs.chmod, expect: refused}}\n  \
             - {{name: wrong, resource: fs.chmod, expect: allow}}\n"
        ));
        let results = run_tests(&policy);
        assert!(results[0].passed());
        let Outcome::Failed { detail } = &results[1].outcome else {
            panic!("expected a failure");
        };
        assert!(
            detail.contains("no adapter declares 'fs.chmod'"),
            "{detail}"
        );
    }

    #[test]
    fn a_declared_resource_is_never_refused() {
        // `fs.read` is declared, so it reaches the rules. Canonicalization cannot
        // refuse it either: `build_adapter` declares resources with no
        // `path_parameters`, so an adapter built from a policy file rewrites
        // nothing. The case fails against the actual decision.
        let policy = policy(&format!(
            "{SURFACE}rules:\n  - {{name: reads, resource: fs.read, action: allow}}\n\
             tests:\n  \
             - {{name: a, resource: fs.read, params: {{path: /etc/passwd}}, expect: refused}}\n"
        ));
        let Outcome::Failed { detail } = &run_tests(&policy)[0].outcome else {
            panic!("expected a failure");
        };
        assert_eq!(detail, "expected refused, got allow from reads");
    }

    #[test]
    fn with_no_adapters_there_is_no_boundary_to_refuse_at() {
        // `ToolCallProxy` skips normalization entirely when it was built without
        // an adapter, so a policy declaring none refuses nothing and every case
        // reaches the rules. Refusing here instead would fail every case in a
        // rules-only policy for a reason that never happens at runtime.
        let policy = policy(
            "version: 2\n\
             rules:\n  - {resource: fs.read, action: allow}\n\
             tests:\n  \
             - {name: evaluated, resource: fs.read, expect: allow}\n  \
             - {name: impossible, resource: fs.read, expect: refused}\n",
        );
        let results = run_tests(&policy);
        assert!(results[0].passed(), "{:?}", results[0].outcome);
        assert!(results[1].outcome.detail().contains("no adapters"));
    }

    #[test]
    fn a_case_reaches_the_default_action_like_any_other_request() {
        let policy = policy(&format!(
            "{SURFACE}tests:\n  - {{name: a, resource: fs.read, expect: deny}}\n"
        ));
        assert!(run_tests(&policy)[0].passed());
    }
}
