//! Condition and resource-pattern matching for policy rules.
//!
//! Everything here is pure: no I/O, no clock reads, no model calls. The same
//! inputs always produce the same result, which is what lets `plan` and `test`
//! report decisions without executing anything.
//!
//! ## Regex compatibility
//!
//! Patterns in `matches`/`not_matches` were written against Python's `re`, so
//! this uses `fancy-regex` rather than the `regex` crate: lookaround and
//! backreferences are common in real deny patterns and `regex` rejects them
//! outright. Compilation happens at load time, and a pattern that will not
//! compile is a policy error — never a rule that quietly matches nothing, which
//! would fail open.
//!
//! `fancy-regex` still spells two anchors differently from Python, and both
//! differences would fail *open* — a deny pattern matching less than its author
//! tested. [`crate::regex_compat`] translates them at compile time; the tests at
//! the bottom of this file pin the resulting behaviour against Python's.

use indexmap::IndexMap;

use crate::fnmatch::fnmatchcase;
use crate::value::{py_contains, py_eq, py_str, Value};

/// Every operator a `where`/`when` field may use, in the order the Python
/// implementation reports them (sorted), because that order appears in the
/// "unknown operator" message.
pub const OPERATORS: &[&str] = &[
    "absent",
    "equals",
    "in",
    "matches",
    "not_equals",
    "not_in",
    "not_matches",
    "present",
];

/// A condition block was malformed. Raised at load time, never at decision time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionError(pub String);

impl std::fmt::Display for ConditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConditionError {}

/// One operator, with its argument already validated and any regex compiled.
#[derive(Debug)]
pub enum Operator {
    Matches(Vec<Pattern>),
    NotMatches(Vec<Pattern>),
    Equals(Value),
    NotEquals(Value),
    In(Vec<Value>),
    NotIn(Vec<Value>),
    Present(bool),
    Absent(bool),
}

impl Operator {
    /// The operator's key as it is spelled in a policy file.
    pub fn name(&self) -> &'static str {
        match self {
            Operator::Matches(_) => "matches",
            Operator::NotMatches(_) => "not_matches",
            Operator::Equals(_) => "equals",
            Operator::NotEquals(_) => "not_equals",
            Operator::In(_) => "in",
            Operator::NotIn(_) => "not_in",
            Operator::Present(_) => "present",
            Operator::Absent(_) => "absent",
        }
    }
}

/// A compiled regex kept alongside its source text, so diagnostics can quote the
/// pattern the author wrote rather than the translated form.
#[derive(Debug)]
pub struct Pattern {
    pub source: String,
    regex: fancy_regex::Regex,
}

impl Pattern {
    pub fn compile(source: &str) -> Result<Self, fancy_regex::Error> {
        Ok(Pattern {
            source: source.to_string(),
            regex: fancy_regex::Regex::new(&crate::regex_compat::translate(source))?,
        })
    }

    /// Python's `re.search(pattern, subject)` as a boolean.
    ///
    /// A backtracking limit inside `fancy-regex` can abort a match on a
    /// pathological pattern. That is reported as "no match", which for
    /// `matches` means a deny rule does not fire — so the limit is a
    /// fail-open edge, and it is why `validate` should keep flagging
    /// catastrophic patterns rather than trusting the engine to survive them.
    pub fn searches(&self, subject: &str) -> bool {
        self.regex.is_match(subject).unwrap_or(false)
    }
}

/// A validated `where` or `when` block: field name to its operators, both in
/// file order.
pub type Conditions = IndexMap<String, IndexMap<String, Operator>>;

/// Validate and normalize a `where`/`when` block.
///
/// Scalar arguments to list-taking operators are wrapped in a list, and regexes
/// are compiled once so a malformed pattern surfaces as a policy error rather
/// than a runtime failure.
pub fn validate_conditions(
    block: Option<&Value>,
    where_: &str,
) -> Result<Conditions, ConditionError> {
    let block = match block {
        None | Some(Value::Null) => return Ok(Conditions::new()),
        Some(value) => value,
    };

    let map = block.as_map().ok_or_else(|| {
        ConditionError(format!(
            "{where_} must be a mapping of field names to conditions"
        ))
    })?;

    let mut normalized = Conditions::new();
    for (field, ops) in map {
        let ops = ops.as_map().ok_or_else(|| {
            ConditionError(format!(
                "{where_}.{field} must be a mapping of operators, got {}",
                ops.type_name()
            ))
        })?;

        let mut normalized_ops = IndexMap::new();
        for (op, arg) in ops {
            let operator = validate_operator(op, arg, where_, field)?;
            normalized_ops.insert(op.clone(), operator);
        }
        normalized.insert(field.clone(), normalized_ops);
    }

    Ok(normalized)
}

fn validate_operator(
    op: &str,
    arg: &Value,
    where_: &str,
    field: &str,
) -> Result<Operator, ConditionError> {
    match op {
        "matches" | "not_matches" => {
            let patterns = compile_patterns(arg, where_, field, op)?;
            Ok(if op == "matches" {
                Operator::Matches(patterns)
            } else {
                Operator::NotMatches(patterns)
            })
        }
        "in" | "not_in" => {
            let items = arg
                .as_seq()
                .ok_or_else(|| ConditionError(format!("{where_}.{field}.{op} must be a list")))?
                .to_vec();
            Ok(if op == "in" {
                Operator::In(items)
            } else {
                Operator::NotIn(items)
            })
        }
        "present" | "absent" => {
            // A strict boolean: `present: 1` is a policy error, because a
            // condition that reads as a switch must be a switch.
            let flag = arg.as_bool_strict().ok_or_else(|| {
                ConditionError(format!("{where_}.{field}.{op} must be true or false"))
            })?;
            Ok(if op == "present" {
                Operator::Present(flag)
            } else {
                Operator::Absent(flag)
            })
        }
        "equals" => Ok(Operator::Equals(arg.clone())),
        "not_equals" => Ok(Operator::NotEquals(arg.clone())),
        _ => Err(ConditionError(format!(
            "{where_}.{field}: unknown operator '{op}' — allowed: {}",
            crate::value::py_repr_str_list(
                &OPERATORS.iter().map(|o| o.to_string()).collect::<Vec<_>>()
            )
        ))),
    }
}

fn compile_patterns(
    arg: &Value,
    where_: &str,
    field: &str,
    op: &str,
) -> Result<Vec<Pattern>, ConditionError> {
    let sources: Vec<&str> = match arg {
        Value::Str(single) => vec![single.as_str()],
        Value::Seq(items) => {
            let mut sources = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(source) => sources.push(source),
                    None => {
                        return Err(ConditionError(format!(
                            "{where_}.{field}.{op} must be a regex string or a list of them"
                        )))
                    }
                }
            }
            sources
        }
        _ => {
            return Err(ConditionError(format!(
                "{where_}.{field}.{op} must be a regex string or a list of them"
            )))
        }
    };

    sources
        .into_iter()
        .map(|source| {
            Pattern::compile(source).map_err(|e| {
                ConditionError(format!(
                    "{where_}.{field}.{op}: invalid regex {}: {e}",
                    crate::value::py_repr(&Value::Str(source.to_string()))
                ))
            })
        })
        .collect()
}

/// True when every operator on every field holds. An empty block matches.
pub fn matches_conditions(conditions: &Conditions, subject: &IndexMap<String, Value>) -> bool {
    conditions.iter().all(|(field, ops)| {
        let value = subject.get(field);
        ops.values().all(|op| evaluate_operator(op, value))
    })
}

/// Evaluate one operator. `None` means the subject does not supply the field.
fn evaluate_operator(op: &Operator, value: Option<&Value>) -> bool {
    let is_present = value.is_some();

    match op {
        Operator::Present(expected) => return is_present == *expected,
        Operator::Absent(expected) => return is_present != *expected,
        _ => {}
    }

    // Every remaining operator needs a value to compare against. An absent
    // field therefore fails the condition, so a rule keyed on a parameter the
    // request never supplied does not fire.
    let Some(value) = value else {
        return false;
    };

    match op {
        Operator::Matches(patterns) => {
            let subject = py_str(value);
            patterns.iter().any(|p| p.searches(&subject))
        }
        Operator::NotMatches(patterns) => {
            let subject = py_str(value);
            !patterns.iter().any(|p| p.searches(&subject))
        }
        Operator::Equals(expected) => py_eq(value, expected),
        Operator::NotEquals(expected) => !py_eq(value, expected),
        Operator::In(items) => py_contains(items, value),
        Operator::NotIn(items) => !py_contains(items, value),
        Operator::Present(_) | Operator::Absent(_) => unreachable!("handled above"),
    }
}

/// True when a rule's resource pattern matches a concrete resource name.
pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == resource {
        return true;
    }
    let pattern: Vec<&str> = pattern.split('.').collect();
    let resource: Vec<&str> = resource.split('.').collect();
    match_segments(&pattern, &resource)
}

/// Match dot-separated resource segments, honouring `*` and `**`.
fn match_segments(pattern: &[&str], resource: &[&str]) -> bool {
    let Some((head, rest)) = pattern.split_first() else {
        return resource.is_empty();
    };

    if *head == "**" {
        if rest.is_empty() {
            return true;
        }
        // `**` absorbs zero or more segments; try each split point.
        return (0..=resource.len()).any(|i| match_segments(rest, &resource[i..]));
    }

    let Some((first, remaining)) = resource.split_first() else {
        return false;
    };
    if !fnmatchcase(first, head) {
        return false;
    }
    match_segments(rest, remaining)
}

/// True when everything `inner` matches, `outer` also matches.
///
/// Deliberately conservative: it returns true only when subsumption is
/// provable, and false when it merely cannot be ruled out. `validate` uses this
/// to report a rule as unreachable, and a false positive there would accuse a
/// working policy of being broken.
pub fn pattern_subsumes(outer: &str, inner: &str) -> bool {
    if outer == inner {
        return true;
    }
    let outer: Vec<&str> = outer.split('.').collect();
    let inner: Vec<&str> = inner.split('.').collect();
    subsumes_segments(&outer, &inner)
}

fn subsumes_segments(outer: &[&str], inner: &[&str]) -> bool {
    let Some((head, rest)) = outer.split_first() else {
        return inner.is_empty();
    };

    if *head == "**" {
        if rest.is_empty() {
            return true;
        }
        return (0..=inner.len()).any(|i| subsumes_segments(rest, &inner[i..]));
    }

    let Some((first, remaining)) = inner.split_first() else {
        return false;
    };
    if !segment_subsumes(head, first) {
        return false;
    }
    subsumes_segments(rest, remaining)
}

/// True when a single pattern segment provably covers another.
fn segment_subsumes(outer: &str, inner: &str) -> bool {
    if outer == inner {
        return true;
    }
    // `**` in the inner pattern spans a variable number of segments, which a
    // single outer segment cannot cover.
    if inner == "**" {
        return false;
    }
    if outer == "*" {
        return true;
    }
    // An inner segment carrying its own wildcards describes a set. Proving that
    // one glob covers another is more than this needs to do, so it is treated as
    // not provable.
    if inner.contains(['*', '?', '[']) {
        return false;
    }
    fnmatchcase(inner, outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(source: &str) -> Value {
        crate::yaml::load(source).unwrap()
    }

    fn subject(source: &str) -> IndexMap<String, Value> {
        yaml(source).as_map().cloned().unwrap()
    }

    fn conditions(source: &str) -> Conditions {
        validate_conditions(Some(&yaml(source)), "rules[0].where").unwrap()
    }

    #[test]
    fn an_empty_block_matches_everything() {
        assert!(matches_conditions(&Conditions::new(), &subject("{}")));
    }

    #[test]
    fn every_operator_on_every_field_must_hold() {
        let block = conditions("path: {matches: ['^/etc'], not_matches: ['passwd$']}");
        assert!(matches_conditions(&block, &subject("{path: /etc/hosts}")));
        assert!(!matches_conditions(&block, &subject("{path: /etc/passwd}")));
        assert!(!matches_conditions(&block, &subject("{path: /tmp/hosts}")));
    }

    #[test]
    fn an_absent_field_fails_every_operator_but_present_and_absent() {
        for source in [
            "path: {matches: ['.']}",
            "path: {not_matches: ['.']}",
            "path: {equals: x}",
            "path: {not_equals: x}",
            "path: {in: [x]}",
            "path: {not_in: [x]}",
            "path: {present: true}",
            "path: {absent: false}",
        ] {
            assert!(
                !matches_conditions(&conditions(source), &subject("{other: 1}")),
                "{source} should not match a request without `path`"
            );
        }
        assert!(matches_conditions(
            &conditions("path: {present: false}"),
            &subject("{other: 1}")
        ));
        assert!(matches_conditions(
            &conditions("path: {absent: true}"),
            &subject("{other: 1}")
        ));
    }

    #[test]
    fn a_present_field_holding_null_is_still_present() {
        assert!(matches_conditions(
            &conditions("path: {present: true}"),
            &subject("{path: null}")
        ));
    }

    #[test]
    fn matches_stringifies_the_value_first() {
        let block = conditions("flag: {matches: ['True']}");
        assert!(matches_conditions(&block, &subject("{flag: true}")));
        assert!(!matches_conditions(&block, &subject("{flag: false}")));
        // Not the YAML spelling: Python stringifies the parsed value.
        assert!(!matches_conditions(
            &conditions("flag: {matches: ['^true$']}"),
            &subject("{flag: true}")
        ));
    }

    #[test]
    fn regexes_are_unanchored_searches() {
        assert!(matches_conditions(
            &conditions("path: {matches: ['etc']}"),
            &subject("{path: /var/etc/x}")
        ));
    }

    #[test]
    fn lookaround_compiles_because_policies_were_written_against_python_re() {
        let block = conditions(r"path: {matches: ['^(?!/tmp/).*\.key$']}");
        assert!(matches_conditions(&block, &subject("{path: /etc/tls.key}")));
        assert!(!matches_conditions(
            &block,
            &subject("{path: /tmp/tls.key}")
        ));
    }

    #[test]
    fn a_malformed_regex_is_a_load_error() {
        let error = validate_conditions(Some(&yaml("path: {matches: ['(']}")), "rules[0].where")
            .unwrap_err();
        assert!(
            error
                .0
                .starts_with("rules[0].where.path.matches: invalid regex '('"),
            "unexpected message: {}",
            error.0
        );
    }

    /// The anchors that would otherwise fail open. A trailing newline is exactly
    /// the kind of thing an agent can append to a parameter, so `path$` has to
    /// mean here what it means in Python.
    #[test]
    fn python_anchor_semantics_hold_for_deny_patterns() {
        let block = conditions(r"path: {matches: ['passwd$']}");
        assert!(matches_conditions(&block, &subject("{path: /etc/passwd}")));
        assert!(matches_conditions(
            &block,
            &subject("{path: \"/etc/passwd\\n\"}")
        ));
        assert!(!matches_conditions(
            &block,
            &subject("{path: /etc/passwd_backup}")
        ));

        // `\Z` is Python's stricter end-of-string anchor: it does not reach past
        // a trailing newline.
        let strict = conditions(r"path: {matches: ['passwd\Z']}");
        assert!(matches_conditions(&strict, &subject("{path: /etc/passwd}")));
        assert!(!matches_conditions(
            &strict,
            &subject("{path: \"/etc/passwd\\n\"}")
        ));
    }

    #[test]
    fn unknown_operators_are_rejected_with_the_allowed_list() {
        let error =
            validate_conditions(Some(&yaml("path: {contains: x}")), "rules[0].when").unwrap_err();
        assert_eq!(
            error.0,
            "rules[0].when.path: unknown operator 'contains' — allowed: ['absent', \
             'equals', 'in', 'matches', 'not_equals', 'not_in', 'not_matches', 'present']"
        );
    }

    #[test]
    fn operator_arguments_are_type_checked() {
        assert!(validate_conditions(Some(&yaml("path: {in: x}")), "w").is_err());
        assert!(validate_conditions(Some(&yaml("path: {present: 1}")), "w").is_err());
        assert!(validate_conditions(Some(&yaml("path: {matches: [1]}")), "w").is_err());
        assert!(validate_conditions(Some(&yaml("path: not-a-mapping")), "w").is_err());
        assert!(validate_conditions(Some(&yaml("[a, b]")), "w").is_err());
    }

    #[test]
    fn a_scalar_regex_is_wrapped_in_a_list() {
        assert!(matches_conditions(
            &conditions("path: {matches: 'etc'}"),
            &subject("{path: /etc}")
        ));
    }

    #[test]
    fn equality_uses_python_semantics() {
        assert!(matches_conditions(
            &conditions("retries: {equals: 1}"),
            &subject("{retries: true}")
        ));
        assert!(matches_conditions(
            &conditions("env: {in: [0]}"),
            &subject("{env: false}")
        ));
    }

    #[test]
    fn resource_patterns_treat_a_single_star_as_one_segment() {
        assert!(resource_matches("fs.read", "fs.read"));
        assert!(resource_matches("fs.*", "fs.read"));
        assert!(!resource_matches("fs.*", "fs.read.bytes"));
        assert!(!resource_matches("fs.*", "fs"));
        assert!(resource_matches("fs.read_*", "fs.read_file"));
        assert!(!resource_matches("fs.read", "fs.write"));
    }

    #[test]
    fn a_double_star_spans_zero_or_more_segments() {
        assert!(resource_matches("**", "fs"));
        assert!(resource_matches("**", "fs.read.bytes"));
        assert!(resource_matches("fs.**", "fs.read.bytes"));
        // Zero segments included: `fs.**` covers `fs` itself.
        assert!(resource_matches("fs.**", "fs"));
        assert!(resource_matches("fs.**.bytes", "fs.read.bytes"));
        assert!(resource_matches("fs.**.bytes", "fs.bytes"));
        assert!(!resource_matches("fs.**.bytes", "fs.read.lines"));
    }

    #[test]
    fn subsumption_is_only_reported_when_provable() {
        assert!(pattern_subsumes("**", "fs.read"));
        assert!(pattern_subsumes("fs.*", "fs.read"));
        assert!(pattern_subsumes("fs.read_*", "fs.read_file"));
        assert!(!pattern_subsumes("fs.read", "fs.*"));
        assert!(!pattern_subsumes("fs.*", "fs.**"));
        // An inner glob is a set; covering it is not attempted.
        assert!(!pattern_subsumes("fs.read_*", "fs.read_?"));
    }
}
