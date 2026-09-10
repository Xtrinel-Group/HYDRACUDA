//! Policy evaluation core.
//!
//! Rules are evaluated in file order and the first match wins. If nothing
//! matches, the policy's `default_action` applies. Evaluation is pure: no I/O,
//! no clock reads, no model calls, so the same request always yields the same
//! decision.

use indexmap::IndexMap;

use crate::conditions::{matches_conditions, resource_matches};
use crate::policy::{Action, Mode, Policy};
use crate::value::Value;

/// A request's parameters or its evaluation context.
pub type Fields = IndexMap<String, Value>;

/// Result of evaluating a tool call against a policy.
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    /// The resource the request named. `resource` is the version 2 vocabulary
    /// for the same thing.
    pub tool: String,
    pub params: Fields,
    pub rule: Option<String>,
    pub mode: Mode,
    pub enforced: bool,
    pub context: Fields,
    /// How the adapter canonicalized the request before evaluation. Set by the
    /// caller, not the engine, and recorded in the audit log so a decision can
    /// be reproduced from the params that were actually evaluated.
    pub notes: Vec<String>,
}

impl Decision {
    /// Alias for `tool`, using the version 2 vocabulary.
    pub fn resource(&self) -> &str {
        &self.tool
    }

    /// True when this decision actually stops the call from executing.
    pub fn blocked(&self) -> bool {
        self.enforced && self.action.is_blocking()
    }
}

/// Evaluates tool calls against a loaded policy.
pub struct PolicyEngine<'a> {
    policy: &'a Policy,
}

impl<'a> PolicyEngine<'a> {
    pub fn new(policy: &'a Policy) -> Self {
        PolicyEngine { policy }
    }

    pub fn policy(&self) -> &Policy {
        self.policy
    }

    /// Evaluate a proposed action and return an allow/deny/review decision.
    ///
    /// `params` are the request arguments, tested by each rule's `where` block.
    /// `context` is caller-supplied evaluation state (agent name, environment,
    /// session), tested by each rule's `when` block.
    pub fn evaluate(&self, tool_name: &str, params: &Fields, context: &Fields) -> Decision {
        for rule in &self.policy.rules {
            if !resource_matches(&rule.resource, tool_name) {
                continue;
            }
            if !matches_conditions(&rule.where_, params) {
                continue;
            }
            if !matches_conditions(&rule.when, context) {
                continue;
            }
            let reason = rule
                .reason
                .as_deref()
                .filter(|reason| !reason.is_empty())
                .unwrap_or_else(|| rule.action.as_str())
                .to_string();
            return self.decide(
                rule.action,
                reason,
                tool_name,
                params,
                context,
                Some(rule.label()),
            );
        }

        let reason = safe_format(
            &self.policy.default_reason,
            tool_name,
            self.policy.default_action.as_str(),
        );
        self.decide(
            self.policy.default_action,
            reason,
            tool_name,
            params,
            context,
            None,
        )
    }

    fn decide(
        &self,
        action: Action,
        reason: String,
        tool_name: &str,
        params: &Fields,
        context: &Fields,
        rule: Option<String>,
    ) -> Decision {
        // `shadow` computes the real verdict but does not act on it, so a policy
        // can be trialled against live traffic. `review` mode is reserved for the
        // human-approval workflow and behaves as `enforce`.
        let enforced = !(self.policy.mode == Mode::Shadow && action.is_blocking());
        Decision {
            action,
            reason,
            tool: tool_name.to_string(),
            params: params.clone(),
            rule,
            mode: self.policy.mode,
            enforced,
            context: context.clone(),
            notes: Vec::new(),
        }
    }
}

/// Format a reason template, falling back to the raw string on error.
///
/// Reason text can legitimately contain braces (regex quantifiers, JSON
/// fragments), and a bad template must not turn into a runtime error in the
/// enforcement path — so anything this cannot interpret is returned unchanged,
/// which is what Python's `str.format` failure path does here.
///
/// Only `{resource}`, `{action}`, and the `{{`/`}}` escapes are interpreted.
/// Python's `str.format` would also accept a conversion or a format spec
/// (`{resource!r}`, `{resource:>20}`); those fall back to the raw template here
/// rather than being formatted. A reason string using one is the single known
/// behavioural gap in this port, and it is recorded in the tests below.
pub fn safe_format(template: &str, resource: &str, action: &str) -> String {
    match try_format(template, resource, action) {
        Some(formatted) => formatted,
        None => template.to_string(),
    }
}

fn try_format(template: &str, resource: &str, action: &str) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    out.push('{');
                    continue;
                }
                let mut field = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    field.push(c);
                }
                if !closed {
                    // Python raises ValueError on an unmatched brace.
                    return None;
                }
                match field.as_str() {
                    "resource" => out.push_str(resource),
                    "action" => out.push_str(action),
                    // An unknown field is a KeyError in Python; a conversion or
                    // format spec is not interpreted here.
                    _ => return None,
                }
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    out.push('}');
                } else {
                    // A lone `}` is a ValueError in Python.
                    return None;
                }
            }
            c => out.push(c),
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(source: &str) -> Policy {
        Policy::from_yaml_str(source).unwrap()
    }

    fn fields(source: &str) -> Fields {
        crate::yaml::load(source)
            .unwrap()
            .as_map()
            .cloned()
            .unwrap()
    }

    fn evaluate(policy: &Policy, tool: &str, params: &str) -> Decision {
        PolicyEngine::new(policy).evaluate(tool, &fields(params), &Fields::new())
    }

    #[test]
    fn an_empty_policy_denies_by_default() {
        let policy = policy("version: 2\nrules: []\n");
        let decision = evaluate(&policy, "fs.read", "{}");
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule, None);
        assert_eq!(decision.reason, "fs.read: no matching rule — default deny");
        assert!(decision.blocked());
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let policy = policy(
            "version: 2\nrules:\n  - {name: first, resource: 'fs.**', action: allow}\n  - {name: second, resource: fs.read, action: deny}\n",
        );
        let decision = evaluate(&policy, "fs.read", "{}");
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.rule.as_deref(), Some("first"));
    }

    #[test]
    fn a_rule_matches_only_when_resource_where_and_when_all_hold() {
        let policy = policy(
            "version: 2\ndefault_action: allow\nrules:\n  - name: block-etc\n    resource: fs.read\n    action: deny\n    where:\n      path: {matches: ['^/etc/']}\n    when:\n      environment: {equals: prod}\n",
        );
        let engine = PolicyEngine::new(&policy);

        let prod = fields("{environment: prod}");
        let dev = fields("{environment: dev}");
        let etc = fields("{path: /etc/passwd}");
        let tmp = fields("{path: /tmp/x}");

        assert_eq!(engine.evaluate("fs.read", &etc, &prod).action, Action::Deny);
        assert_eq!(
            engine.evaluate("fs.read", &tmp, &prod).action,
            Action::Allow
        );
        assert_eq!(engine.evaluate("fs.read", &etc, &dev).action, Action::Allow);
        assert_eq!(
            engine.evaluate("fs.write", &etc, &prod).action,
            Action::Allow
        );
        // A missing context field fails the `when` block, so the deny does not
        // fire — the same fail-open shape `validate` warns about.
        assert_eq!(
            engine.evaluate("fs.read", &etc, &Fields::new()).action,
            Action::Allow
        );
    }

    #[test]
    fn shadow_mode_records_a_blocking_verdict_without_enforcing_it() {
        let policy = policy(
            "version: 2\nmode: shadow\nrules:\n  - {resource: fs.read, action: deny}\n  - {resource: fs.write, action: allow}\n",
        );
        let denied = evaluate(&policy, "fs.read", "{}");
        assert_eq!(denied.action, Action::Deny);
        assert!(!denied.enforced);
        assert!(!denied.blocked(), "shadow mode must not block");
        assert_eq!(denied.mode, Mode::Shadow);

        // An allow is not a blocking verdict, so it is still marked enforced.
        let allowed = evaluate(&policy, "fs.write", "{}");
        assert!(allowed.enforced);
    }

    #[test]
    fn review_mode_behaves_as_enforce() {
        let policy =
            policy("version: 2\nmode: review\nrules:\n  - {resource: fs.read, action: deny}\n");
        let decision = evaluate(&policy, "fs.read", "{}");
        assert!(decision.enforced);
        assert!(decision.blocked());
    }

    #[test]
    fn the_decision_carries_the_request_it_was_made_about() {
        let policy = policy("version: 2\ndefault_action: allow\nrules: []\n");
        let engine = PolicyEngine::new(&policy);
        let params = fields("{path: /tmp/x}");
        let context = fields("{agent: bot}");
        let decision = engine.evaluate("fs.read", &params, &context);
        assert_eq!(decision.resource(), "fs.read");
        assert_eq!(decision.params.len(), 1);
        assert_eq!(decision.context.len(), 1);
        assert!(decision.notes.is_empty());
    }

    #[test]
    fn a_version_1_policy_evaluates_through_the_same_path() {
        let policy = policy(
            "version: 1\ntools:\n  read_file:\n    parameter_rules:\n      path:\n        deny_patterns: ['\\.\\.']\n  write_file:\n    allow: false\n",
        );
        let engine = PolicyEngine::new(&policy);

        let traversal = engine.evaluate("read_file", &fields("{path: ../etc}"), &Fields::new());
        assert_eq!(traversal.action, Action::Deny);
        assert_eq!(
            traversal.rule.as_deref(),
            Some("legacy:read_file:path:deny_pattern[0]")
        );
        assert_eq!(
            traversal.reason,
            "read_file: parameter 'path' matched deny pattern '\\.\\.'"
        );

        assert_eq!(
            engine
                .evaluate("read_file", &fields("{path: /tmp/x}"), &Fields::new())
                .action,
            Action::Allow
        );
        assert_eq!(
            engine
                .evaluate("write_file", &Fields::new(), &Fields::new())
                .action,
            Action::Deny
        );
        // Nothing else is listed, so nothing else is permitted.
        let unlisted = engine.evaluate("deploy", &Fields::new(), &Fields::new());
        assert_eq!(unlisted.action, Action::Deny);
        assert_eq!(
            unlisted.reason,
            "deploy: not listed in policy — default deny"
        );
    }

    #[test]
    fn reason_templates_are_substituted() {
        assert_eq!(
            safe_format("{resource} was {action}ed", "fs.read", "deny"),
            "fs.read was denyed"
        );
        assert_eq!(safe_format("{{literal}}", "r", "a"), "{literal}");
    }

    #[test]
    fn a_template_that_cannot_be_formatted_is_returned_unchanged() {
        // Regex quantifiers and JSON fragments are legitimate reason text.
        for template in ["a{2,3}b", "{\"k\": 1}", "unmatched {", "stray }"] {
            assert_eq!(safe_format(template, "r", "a"), template);
        }
    }

    /// The one recorded gap: Python's `str.format` would render these, and this
    /// implementation returns the template unchanged instead. Reason strings
    /// using a conversion or a format spec are the only inputs affected.
    #[test]
    fn format_specs_and_conversions_fall_back_to_the_raw_template() {
        assert_eq!(
            safe_format("{resource!r}", "fs.read", "deny"),
            "{resource!r}"
        );
        assert_eq!(
            safe_format("{resource:>10}", "fs.read", "deny"),
            "{resource:>10}"
        );
    }
}
