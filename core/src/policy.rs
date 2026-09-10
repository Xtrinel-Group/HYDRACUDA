//! YAML policy parser and validator.
//!
//! Two policy versions are supported. Version 2 is the ordered-rule format
//! described in `docs/policy-spec.md`. Version 1 is the flat `tools:` map from
//! v0.1.0–v0.2.0; it is translated into version 2 rules at load time so there is
//! a single evaluation path, and its decisions are unchanged.
//!
//! Validation is strict: an unrecognized key anywhere in a policy file is an
//! error. Silently ignoring a misspelled key means the author believes a rule is
//! active when it is not, which fails open.
//!
//! Checks run in the same order as the Python loader, and messages are written
//! to match it. That is not cosmetic: the two implementations ship together
//! during 0.4.0, and a policy file that loads in one and fails in the other —
//! or fails differently — is a defect that would surface as a support question
//! rather than a test failure.

use std::collections::BTreeSet;
use std::path::Path;

use indexmap::{IndexMap, IndexSet};

use crate::conditions::{validate_conditions, ConditionError, Conditions};
use crate::difflib::closest_match;
use crate::test_cases::TestCase;
use crate::value::{py_repr, py_repr_str_list, py_str, py_truthy, Value};

pub const DEFAULT_AUDIT_PATH: &str = ".hydracuda/audit.db";

pub const DEFAULT_REASON: &str = "{resource}: no matching rule — default {action}";
pub const DEFAULT_REASON_V1: &str = "{resource}: not listed in policy — default deny";

const SUPPORTED_VERSIONS: &[i64] = &[1, 2];

const TOP_LEVEL_KEYS_V1: &[&str] = &["audit", "audit_path", "mode", "tools", "version"];
const TOP_LEVEL_KEYS_V2: &[&str] = &[
    "adapters",
    "audit",
    "audit_path",
    "default_action",
    "default_reason",
    "mode",
    "pinned_context",
    "rules",
    // Version 2 only, and deliberately absent from `TOP_LEVEL_KEYS_V1`: a
    // legacy file gets no new surface, so `tests:` there is an unrecognized
    // key like any other v2 addition.
    "tests",
    "version",
];
const TOOL_KEYS: &[&str] = &["allow", "parameter_rules", "reason"];
const PARAMETER_RULE_KEYS: &[&str] = &["deny_patterns"];
const RULE_KEYS: &[&str] = &["action", "name", "reason", "resource", "when", "where"];
const ADAPTER_KEYS: &[&str] = &["config", "name", "resources", "type"];
const AUDIT_KEYS: &[&str] = &["path"];

/// Keys rejected outright with a specific explanation, wherever they appear.
///
/// A key that reads as an active control but has no effect is the failure this
/// loader exists to prevent, so it must not be merely ignored.
const REJECTED_KEYS: &[(&str, &str)] = &[(
    "rate_limit",
    "'rate_limit' is not enforced by HYDRACUDA and never has been — it was \
     parsed and discarded in v0.1.0-v0.2.0. Remove it. Rate limiting is \
     stateful and belongs in the calling layer; leaving the key in a policy \
     file asserts a control that does not exist.",
)];

/// A policy file is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

impl From<ConditionError> for PolicyError {
    fn from(error: ConditionError) -> Self {
        PolicyError(error.0)
    }
}

/// A policy could not be loaded. Separate from [`PolicyError`] so a caller can
/// tell "this file is not YAML" from "this policy is invalid".
#[derive(Debug)]
pub enum LoadError {
    Yaml(String),
    Policy(PolicyError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Yaml(message) => write!(f, "{message}"),
            LoadError::Policy(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<PolicyError> for LoadError {
    fn from(error: PolicyError) -> Self {
        LoadError::Policy(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Review,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Review => "review",
        }
    }

    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "allow" => Some(Action::Allow),
            "deny" => Some(Action::Deny),
            "review" => Some(Action::Review),
            _ => None,
        }
    }

    /// The reason recorded when a rule does not supply one.
    fn default_reason(self) -> &'static str {
        match self {
            Action::Allow => "all policy checks passed",
            Action::Deny => "tool blocked by policy",
            Action::Review => "tool requires human review",
        }
    }

    /// Verdicts that `mode: shadow` records without acting on.
    pub fn is_blocking(self) -> bool {
        matches!(self, Action::Deny | Action::Review)
    }
}

fn valid_actions() -> Vec<String> {
    ["allow", "deny", "review"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Shadow,
    Review,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Shadow => "shadow",
            Mode::Review => "review",
        }
    }
}

/// What a version 1 `tools:` entry said about a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allow {
    Yes,
    No,
    Review,
}

#[derive(Debug)]
pub struct ToolPolicy {
    pub allow: Allow,
    /// Parameter name to its deny patterns, in file order.
    pub parameter_rules: IndexMap<String, Vec<String>>,
    pub reason: Option<String>,
}

/// A single ordered policy rule.
#[derive(Debug)]
pub struct Rule {
    pub resource: String,
    pub action: Action,
    pub name: Option<String>,
    pub reason: Option<String>,
    pub where_: Conditions,
    pub when: Conditions,
}

impl Rule {
    /// Stable identifier for logs and `plan` output.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => format!("{}:{}", self.action.as_str(), self.resource),
        }
    }
}

/// Declaration of one adapter instance and the resources it exposes.
#[derive(Debug, Clone)]
pub struct AdapterSpec {
    pub name: String,
    pub type_: String,
    pub resources: Vec<String>,
    pub config: IndexMap<String, Value>,
}

/// Top-level policy configuration.
#[derive(Debug)]
pub struct Policy {
    pub version: i64,
    pub mode: Mode,
    pub audit_path: String,
    pub default_action: Action,
    pub default_reason: String,
    pub rules: Vec<Rule>,
    pub adapters: Vec<AdapterSpec>,
    pub pinned_context: Vec<String>,
    /// Assertions about this policy's own decisions. Version 2 only.
    pub tests: Vec<TestCase>,
    /// Present only for a version 1 file, which is kept so `validate` can report
    /// on the file as written rather than on its translation.
    pub tools: Option<IndexMap<String, ToolPolicy>>,
}

impl Policy {
    /// Load and validate a policy file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Policy, LoadError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path).map_err(|_| {
            // Matches the Python loader, which reports a missing file as a
            // policy error rather than an OS error.
            LoadError::Policy(PolicyError(format!(
                "Policy file not found: {}",
                path.display()
            )))
        })?;
        Policy::from_yaml_str(&source)
    }

    pub fn from_yaml_str(source: &str) -> Result<Policy, LoadError> {
        let raw = crate::yaml::load(source).map_err(|e| LoadError::Yaml(e.0))?;
        Ok(Policy::parse(&raw)?)
    }

    /// Validate an already-parsed policy mapping and build a `Policy`.
    pub fn parse(raw: &Value) -> Result<Policy, PolicyError> {
        let raw = raw.as_map().ok_or_else(|| {
            PolicyError(format!(
                "Policy file must be a YAML mapping, got {}",
                raw.type_name()
            ))
        })?;

        let version = raw
            .get("version")
            .ok_or_else(|| PolicyError("Policy file missing required key: 'version'".into()))?;
        let version = match version {
            Value::Int(i) => *i,
            other => {
                return Err(PolicyError(format!(
                    "'version' must be an integer, got {}",
                    other.type_name()
                )))
            }
        };
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(PolicyError(format!(
                "Unsupported policy version {version} — supported: [1, 2]"
            )));
        }

        // Mode and audit path are validated before the unknown-key sweep,
        // because that is the order the Python loader checks them in and the
        // first error is the one a user sees.
        let mode = parse_mode(raw)?;
        let audit_path = parse_audit_path(raw)?;

        if version == 1 {
            reject_unknown_keys("Policy file", raw, TOP_LEVEL_KEYS_V1)?;
            let tools = parse_tools(raw)?;
            let rules = rules_from_tools(&tools)?;
            return Ok(Policy {
                version,
                mode,
                audit_path,
                // A version 1 file has no configurable default: it denies
                // anything it does not list.
                default_action: Action::Deny,
                default_reason: DEFAULT_REASON_V1.to_string(),
                rules,
                adapters: Vec::new(),
                pinned_context: Vec::new(),
                tests: Vec::new(),
                tools: Some(tools),
            });
        }

        reject_unknown_keys("Policy file", raw, TOP_LEVEL_KEYS_V2)?;

        let default_action = match raw.get("default_action") {
            // Fail closed: an unlisted resource is denied unless the policy says
            // otherwise.
            None => Action::Deny,
            Some(value) => Action::parse(value).ok_or_else(|| {
                PolicyError(format!(
                    "'default_action' must be one of {}, got {}",
                    py_repr_str_list(&valid_actions()),
                    py_repr(value)
                ))
            })?,
        };

        let default_reason = match raw.get("default_reason") {
            None => DEFAULT_REASON.to_string(),
            Some(Value::Str(s)) => s.clone(),
            Some(_) => return Err(PolicyError("'default_reason' must be a string".into())),
        };

        let pinned_context = match raw.get("pinned_context") {
            None => Vec::new(),
            Some(value) if !py_truthy(value) => Vec::new(),
            Some(value) => string_list(value).ok_or_else(|| {
                PolicyError("'pinned_context' must be a list of context field names".into())
            })?,
        };

        Ok(Policy {
            version,
            mode,
            audit_path,
            default_action,
            default_reason,
            rules: parse_rules(raw)?,
            adapters: parse_adapters(raw)?,
            pinned_context,
            tests: crate::test_cases::parse_tests(raw)?,
            tools: None,
        })
    }

    /// Every context field any rule's `when` block tests.
    pub fn when_fields(&self) -> BTreeSet<String> {
        self.rules
            .iter()
            .flat_map(|rule| rule.when.keys().cloned())
            .collect()
    }

    /// Context fields that gate decisions but are not pinned.
    ///
    /// A `when` field that is not listed in `pinned_context` is supplied per
    /// call, so the guarantee that the agent cannot influence it rests on the
    /// integrator rather than on HYDRACUDA. `validate` reports these.
    pub fn unpinned_when_fields(&self) -> BTreeSet<String> {
        let pinned: BTreeSet<&String> = self.pinned_context.iter().collect();
        self.when_fields()
            .into_iter()
            .filter(|field| !pinned.contains(field))
            .collect()
    }

    /// Every concrete resource named by an adapter, then by a rule.
    ///
    /// Rule resources containing wildcards are skipped — they describe a set,
    /// not a resource that can be planned against.
    pub fn declared_resources(&self) -> Vec<String> {
        let mut seen: IndexSet<String> = IndexSet::new();
        for adapter in &self.adapters {
            for resource in &adapter.resources {
                seen.insert(resource.clone());
            }
        }
        for rule in &self.rules {
            if !rule.resource.contains('*') {
                seen.insert(rule.resource.clone());
            }
        }
        seen.into_iter().collect()
    }
}

/// A tool's own reason, if it supplied a non-empty one.
///
/// The Python translation reads `tool_policy.reason or DEFAULT`, so an empty
/// string falls through to the default rather than producing a decision with a
/// blank explanation.
fn explicit_reason(tool_policy: &ToolPolicy) -> Option<String> {
    tool_policy
        .reason
        .as_deref()
        .filter(|reason| !reason.is_empty())
        .map(|reason| reason.to_string())
}

/// Translate the version 1 `tools:` map into ordered version 2 rules.
///
/// Rule order reproduces the v0.2.0 evaluation order exactly: blocked and review
/// tools short-circuit, then parameter deny patterns are tried in declaration
/// order, then the call is allowed.
fn rules_from_tools(tools: &IndexMap<String, ToolPolicy>) -> Result<Vec<Rule>, PolicyError> {
    let mut rules = Vec::new();

    for (tool_name, tool_policy) in tools {
        match tool_policy.allow {
            Allow::No => {
                rules.push(Rule {
                    resource: tool_name.clone(),
                    action: Action::Deny,
                    name: Some(format!("legacy:{tool_name}:blocked")),
                    reason: Some(
                        explicit_reason(tool_policy)
                            .unwrap_or_else(|| Action::Deny.default_reason().to_string()),
                    ),
                    where_: Conditions::new(),
                    when: Conditions::new(),
                });
                continue;
            }
            Allow::Review => {
                rules.push(Rule {
                    resource: tool_name.clone(),
                    action: Action::Review,
                    name: Some(format!("legacy:{tool_name}:review")),
                    reason: Some(
                        explicit_reason(tool_policy)
                            .unwrap_or_else(|| Action::Review.default_reason().to_string()),
                    ),
                    where_: Conditions::new(),
                    when: Conditions::new(),
                });
                continue;
            }
            Allow::Yes => {}
        }

        for (param_name, patterns) in &tool_policy.parameter_rules {
            // The index keeps generated names unique. Without it a tool with
            // several deny patterns produced several identically named rules,
            // which made an audit record ambiguous about which pattern fired.
            for (position, pattern) in patterns.iter().enumerate() {
                let mut field = IndexMap::new();
                field.insert(
                    "matches".to_string(),
                    Value::Seq(vec![Value::Str(pattern.clone())]),
                );
                let mut block = IndexMap::new();
                block.insert(param_name.clone(), Value::Map(field));

                rules.push(Rule {
                    resource: tool_name.clone(),
                    action: Action::Deny,
                    name: Some(format!(
                        "legacy:{tool_name}:{param_name}:deny_pattern[{position}]"
                    )),
                    reason: Some(format!(
                        "{tool_name}: parameter '{param_name}' matched deny pattern '{pattern}'"
                    )),
                    where_: validate_conditions(
                        Some(&Value::Map(block)),
                        &format!("Tool '{tool_name}'"),
                    )?,
                    when: Conditions::new(),
                });
            }
        }

        rules.push(Rule {
            resource: tool_name.clone(),
            action: Action::Allow,
            name: Some(format!("legacy:{tool_name}:allow")),
            reason: Some(Action::Allow.default_reason().to_string()),
            where_: Conditions::new(),
            when: Conditions::new(),
        });
    }

    Ok(rules)
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Find the key the author probably meant.
///
/// Catches the camelCase drift the v0.2.0 README encouraged (`denyPatterns` for
/// `deny_patterns`) as an exact match after normalization, then falls back to
/// fuzzy matching for ordinary typos.
fn suggest_key(key: &str, allowed: &[&str]) -> Option<String> {
    let target = normalize_key(key);
    // `allowed` is kept sorted at its definition, which is the order the Python
    // loader searches in.
    for candidate in allowed {
        if normalize_key(candidate) == target {
            return Some(candidate.to_string());
        }
    }
    let candidates: Vec<String> = allowed.iter().map(|k| k.to_string()).collect();
    closest_match(key, &candidates, 0.8).map(|k| k.to_string())
}

pub(crate) fn reject_unknown_keys(
    where_: &str,
    mapping: &IndexMap<String, Value>,
    allowed: &[&str],
) -> Result<(), PolicyError> {
    for key in mapping.keys() {
        let normalized = normalize_key(key);
        if let Some((_, message)) = REJECTED_KEYS
            .iter()
            .find(|(rejected, _)| normalize_key(rejected) == normalized)
        {
            return Err(PolicyError(format!("{where_}: {message}")));
        }
    }

    let mut unknown: Vec<&String> = mapping
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort();

    let hints: Vec<String> = unknown
        .iter()
        .filter_map(|key| {
            suggest_key(key, allowed).map(|s| format!("'{key}' — did you mean '{s}'?"))
        })
        .collect();
    let hint = if hints.is_empty() {
        String::new()
    } else {
        format!(" {}", hints.join(" "))
    };

    let unknown: Vec<String> = unknown.into_iter().cloned().collect();
    let allowed: Vec<String> = allowed.iter().map(|k| k.to_string()).collect();
    Err(PolicyError(format!(
        "{where_}: unrecognized key(s) {}.{hint} Allowed: {}",
        py_repr_str_list(&unknown),
        py_repr_str_list(&allowed),
    )))
}

pub(crate) fn require_mapping<'a>(
    value: &'a Value,
    where_: &str,
) -> Result<&'a IndexMap<String, Value>, PolicyError> {
    value.as_map().ok_or_else(|| {
        PolicyError(format!(
            "{where_} must be a mapping, got {}",
            value.type_name()
        ))
    })
}

fn string_list(value: &Value) -> Option<Vec<String>> {
    let items = value.as_seq()?;
    items
        .iter()
        .map(|item| item.as_str().map(|s| s.to_string()))
        .collect()
}

fn parse_mode(raw: &IndexMap<String, Value>) -> Result<Mode, PolicyError> {
    let mode = match raw.get("mode") {
        None => return Ok(Mode::Enforce),
        Some(value) => value,
    };
    match mode.as_str() {
        Some("enforce") => Ok(Mode::Enforce),
        Some("shadow") => Ok(Mode::Shadow),
        Some("review") => Ok(Mode::Review),
        _ => Err(PolicyError(format!(
            "'mode' must be one of ['enforce', 'review', 'shadow'], got '{}'",
            py_str(mode)
        ))),
    }
}

/// Resolve the audit log path, honouring the deprecated nested form.
///
/// `audit: {path: ...}` was documented in the v0.2.0 README but never read, so
/// policies using it silently logged to the default location. It is now honoured
/// as an alias; `audit_path` wins when both are present.
fn parse_audit_path(raw: &IndexMap<String, Value>) -> Result<String, PolicyError> {
    let nested = match raw.get("audit") {
        None => DEFAULT_AUDIT_PATH.to_string(),
        Some(audit) => {
            let audit = require_mapping(audit, "'audit'")?;
            reject_unknown_keys("'audit'", audit, AUDIT_KEYS)?;
            match audit.get("path") {
                None => DEFAULT_AUDIT_PATH.to_string(),
                Some(Value::Str(path)) => path.clone(),
                Some(_) => return Err(PolicyError("'audit.path' must be a string".into())),
            }
        }
    };

    match raw.get("audit_path") {
        None => Ok(nested),
        Some(Value::Str(path)) => Ok(path.clone()),
        Some(_) => Err(PolicyError("'audit_path' must be a string".into())),
    }
}

fn parse_tools(raw: &IndexMap<String, Value>) -> Result<IndexMap<String, ToolPolicy>, PolicyError> {
    let raw_tools = raw
        .get("tools")
        .ok_or_else(|| PolicyError("Policy file missing required key: 'tools'".into()))?;
    let raw_tools = raw_tools.as_map().ok_or_else(|| {
        PolicyError("'tools' must be a mapping of tool names to configurations".into())
    })?;

    let mut tools = IndexMap::new();
    for (tool_name, tool_conf) in raw_tools {
        let where_ = format!("Tool '{tool_name}'");
        let tool_conf = require_mapping(tool_conf, &format!("{where_} configuration"))?;
        reject_unknown_keys(&where_, tool_conf, TOOL_KEYS)?;

        let allow = parse_allow(tool_conf.get("allow"), &where_)?;

        let mut parameter_rules = IndexMap::new();
        // `parameter_rules: null` is treated as absent, as it is in Python.
        if let Some(raw_rules) = tool_conf
            .get("parameter_rules")
            .filter(|value| !matches!(value, Value::Null))
        {
            let raw_rules = require_mapping(raw_rules, &format!("{where_}: 'parameter_rules'"))?;
            for (param_name, param_rules) in raw_rules {
                let param_where = format!("{where_}: parameter_rules.{param_name}");
                let param_rules = require_mapping(param_rules, &param_where)?;
                reject_unknown_keys(&param_where, param_rules, PARAMETER_RULE_KEYS)?;

                let patterns = match param_rules.get("deny_patterns") {
                    None => Vec::new(),
                    Some(value) => string_list(value).ok_or_else(|| {
                        PolicyError(format!(
                            "{param_where}: 'deny_patterns' must be a list of strings"
                        ))
                    })?,
                };

                // Compile now so a malformed regex is a load error, matching
                // version 2 condition behaviour.
                let mut field = IndexMap::new();
                field.insert(
                    "matches".to_string(),
                    Value::Seq(patterns.iter().cloned().map(Value::Str).collect()),
                );
                let mut block = IndexMap::new();
                block.insert(param_name.clone(), Value::Map(field));
                validate_conditions(Some(&Value::Map(block)), &param_where)?;

                parameter_rules.insert(param_name.clone(), patterns);
            }
        }

        let reason = match tool_conf.get("reason") {
            None | Some(Value::Null) => None,
            Some(Value::Str(reason)) => Some(reason.clone()),
            Some(_) => return Err(PolicyError(format!("{where_}: 'reason' must be a string"))),
        };

        tools.insert(
            tool_name.clone(),
            ToolPolicy {
                allow,
                parameter_rules,
                reason,
            },
        );
    }

    Ok(tools)
}

/// Parse a version 1 `allow:` value.
///
/// Only a genuine boolean or the string `"review"` is accepted. An integer is
/// rejected rather than coerced, which matters because the earlier check
/// compared by value: `0 == False` made `allow: 0` valid, while the branch that
/// denies asked `is False` and an integer never satisfies it, so the tool was
/// *allowed*. Rejecting is the fail-closed answer and it surfaces the generator
/// that emitted `0` instead of guessing at what it meant.
fn parse_allow(value: Option<&Value>, where_: &str) -> Result<Allow, PolicyError> {
    let Some(value) = value else {
        return Ok(Allow::Yes);
    };

    match (value.as_bool_strict(), value.as_str()) {
        (Some(true), _) => Ok(Allow::Yes),
        (Some(false), _) => Ok(Allow::No),
        (_, Some("review")) => Ok(Allow::Review),
        _ => Err(PolicyError(format!(
            "{where_}: 'allow' must be true, false, or 'review', got '{}'",
            py_str(value)
        ))),
    }
}

fn parse_rules(raw: &IndexMap<String, Value>) -> Result<Vec<Rule>, PolicyError> {
    let raw_rules = match raw.get("rules") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value) => value
            .as_seq()
            .ok_or_else(|| PolicyError("'rules' must be a list".into()))?,
    };

    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, raw_rule) in raw_rules.iter().enumerate() {
        let mut where_ = format!("rules[{index}]");
        let raw_rule = require_mapping(raw_rule, &where_)?;
        reject_unknown_keys(&where_, raw_rule, RULE_KEYS)?;

        let name = match raw_rule.get("name") {
            None | Some(Value::Null) => None,
            Some(Value::Str(name)) => Some(name.clone()),
            Some(_) => return Err(PolicyError(format!("{where_}: 'name' must be a string"))),
        };
        // A named rule identifies itself in every later message about it.
        if let Some(name) = name.as_deref().filter(|n| !n.is_empty()) {
            where_ = format!("rules[{index}] ('{name}')");
        }

        let resource = match raw_rule.get("resource").and_then(|v| v.as_str()) {
            Some(resource) if !resource.is_empty() => resource.to_string(),
            _ => {
                return Err(PolicyError(format!(
                    "{where_}: 'resource' is required and must be a string"
                )))
            }
        };

        // An absent `action` reports as `None`, which is what a reader of the
        // Python message sees.
        let raw_action = raw_rule.get("action").cloned().unwrap_or(Value::Null);
        let action = Action::parse(&raw_action).ok_or_else(|| {
            PolicyError(format!(
                "{where_}: 'action' must be one of {}, got {}",
                py_repr_str_list(&valid_actions()),
                py_repr(&raw_action)
            ))
        })?;

        let reason = match raw_rule.get("reason") {
            None | Some(Value::Null) => None,
            Some(Value::Str(reason)) if reason.is_empty() => None,
            Some(Value::Str(reason)) => Some(reason.clone()),
            Some(_) => return Err(PolicyError(format!("{where_}: 'reason' must be a string"))),
        };

        rules.push(Rule {
            resource,
            action,
            name,
            // An omitted reason is filled in at load time, so a decision always
            // carries an explanation.
            reason: Some(reason.unwrap_or_else(|| action.default_reason().to_string())),
            where_: validate_conditions(raw_rule.get("where"), &format!("{where_}.where"))?,
            when: validate_conditions(raw_rule.get("when"), &format!("{where_}.when"))?,
        });
    }

    Ok(rules)
}

fn parse_adapters(raw: &IndexMap<String, Value>) -> Result<Vec<AdapterSpec>, PolicyError> {
    let raw_adapters = match raw.get("adapters") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value) => value
            .as_seq()
            .ok_or_else(|| PolicyError("'adapters' must be a list".into()))?,
    };

    let mut adapters = Vec::with_capacity(raw_adapters.len());
    let mut names: IndexSet<String> = IndexSet::new();
    for (index, raw_adapter) in raw_adapters.iter().enumerate() {
        let where_ = format!("adapters[{index}]");
        let raw_adapter = require_mapping(raw_adapter, &where_)?;
        reject_unknown_keys(&where_, raw_adapter, ADAPTER_KEYS)?;

        let name = match raw_adapter.get("name").and_then(|v| v.as_str()) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => {
                return Err(PolicyError(format!(
                    "{where_}: 'name' is required and must be a string"
                )))
            }
        };
        if !names.insert(name.clone()) {
            return Err(PolicyError(format!(
                "{where_}: duplicate adapter name '{name}'"
            )));
        }

        let type_ = match raw_adapter.get("type").and_then(|v| v.as_str()) {
            Some(type_) if !type_.is_empty() => type_.to_string(),
            _ => {
                return Err(PolicyError(format!(
                    "{where_}: 'type' is required and must be a string"
                )))
            }
        };

        let resources = match raw_adapter.get("resources") {
            None => Vec::new(),
            Some(value) if !py_truthy(value) => Vec::new(),
            Some(value) => string_list(value).ok_or_else(|| {
                PolicyError(format!("{where_}: 'resources' must be a list of strings"))
            })?,
        };

        let config = match raw_adapter.get("config") {
            None => IndexMap::new(),
            Some(value) if !py_truthy(value) => IndexMap::new(),
            Some(value) => require_mapping(value, &format!("{where_}: 'config'"))?.clone(),
        };

        adapters.push(AdapterSpec {
            name,
            type_,
            resources,
            config,
        });
    }

    Ok(adapters)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&crate::yaml::load(source).unwrap())
    }

    fn error(source: &str) -> String {
        parse(source).unwrap_err().0
    }

    #[test]
    fn a_minimal_version_2_policy_fails_closed() {
        let policy = parse("version: 2\nrules: []\n").unwrap();
        assert_eq!(policy.default_action, Action::Deny);
        assert_eq!(policy.default_reason, DEFAULT_REASON);
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.audit_path, DEFAULT_AUDIT_PATH);
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn version_is_required_and_must_be_an_integer() {
        assert_eq!(
            error("rules: []\n"),
            "Policy file missing required key: 'version'"
        );
        assert_eq!(
            error("version: '2'\n"),
            "'version' must be an integer, got str"
        );
        // A YAML boolean is not an integer, even though Python would compare it
        // equal to one.
        assert_eq!(
            error("version: true\n"),
            "'version' must be an integer, got bool"
        );
        assert_eq!(
            error("version: 3\n"),
            "Unsupported policy version 3 — supported: [1, 2]"
        );
    }

    #[test]
    fn an_unrecognized_key_is_an_error_with_a_suggestion() {
        assert_eq!(
            error("version: 2\nrules: []\ndefaultaction: allow\n"),
            "Policy file: unrecognized key(s) ['defaultaction']. 'defaultaction' — \
             did you mean 'default_action'? Allowed: ['adapters', 'audit', 'audit_path', \
             'default_action', 'default_reason', 'mode', 'pinned_context', 'rules', 'tests', \
             'version']"
        );
    }

    #[test]
    fn the_tests_block_loads_on_version_2_and_nowhere_else() {
        // Inverted deliberately in 0.4.0: `docs/policy-spec.md` specified
        // `tests:` while the loader still rejected it, and this test pinned the
        // rejection so nobody could copy the spec into a file that silently did
        // nothing. The implementation has landed, so the pin moves to the
        // remaining half — a version 1 file gets no new surface.
        assert!(parse("version: 2\nrules: []\ntests: []\n").is_ok());
        assert!(
            error("version: 1\ntools: {}\ntests: []\n").contains("unrecognized key(s) ['tests']")
        );
    }

    #[test]
    fn camel_case_drift_is_caught_as_an_exact_normalized_match() {
        let message = error(
            "version: 1\ntools:\n  read_file:\n    parameterRules:\n      path:\n        deny_patterns: ['x']\n",
        );
        assert!(
            message.contains("'parameterRules' — did you mean 'parameter_rules'?"),
            "{message}"
        );
    }

    #[test]
    fn rate_limit_is_rejected_wherever_it_appears() {
        for source in [
            "version: 2\nrules: []\nrate_limit: 5\n",
            "version: 2\nrules: []\nrateLimit: 5\n",
            "version: 1\ntools:\n  read_file:\n    rate_limit: 5\n",
        ] {
            let message = parse(source).unwrap_err().0;
            assert!(
                message.contains("'rate_limit' is not enforced"),
                "{message}"
            );
        }
    }

    #[test]
    fn mode_and_audit_path_are_validated_before_unknown_keys() {
        // Both problems are present; the mode error is the one reported, because
        // that is the order the Python loader checks in.
        let message = error("version: 2\nmode: audit\nbogus: 1\n");
        assert_eq!(
            message,
            "'mode' must be one of ['enforce', 'review', 'shadow'], got 'audit'"
        );
    }

    #[test]
    fn the_nested_audit_form_is_honoured_as_an_alias() {
        let policy = parse("version: 2\naudit:\n  path: /tmp/a.db\n").unwrap();
        assert_eq!(policy.audit_path, "/tmp/a.db");
        // `audit_path` wins when both are present.
        let policy =
            parse("version: 2\naudit:\n  path: /tmp/a.db\naudit_path: /tmp/b.db\n").unwrap();
        assert_eq!(policy.audit_path, "/tmp/b.db");
        assert_eq!(
            error("version: 2\naudit:\n  pathh: /tmp/a.db\n"),
            "'audit': unrecognized key(s) ['pathh']. 'pathh' — did you mean 'path'? \
             Allowed: ['path']"
        );
    }

    #[test]
    fn rules_are_validated_field_by_field() {
        assert_eq!(
            error("version: 2\nrules:\n  - action: allow\n"),
            "rules[0]: 'resource' is required and must be a string"
        );
        assert_eq!(
            error("version: 2\nrules:\n  - {name: r, resource: fs.read}\n"),
            "rules[0] ('r'): 'action' must be one of ['allow', 'deny', 'review'], got None"
        );
        assert_eq!(
            error("version: 2\nrules:\n  - {resource: fs.read, action: block}\n"),
            "rules[0]: 'action' must be one of ['allow', 'deny', 'review'], got 'block'"
        );
        assert_eq!(error("version: 2\nrules: 3\n"), "'rules' must be a list");
    }

    #[test]
    fn an_omitted_reason_is_filled_in_at_load_time() {
        let policy = parse("version: 2\nrules:\n  - {resource: fs.read, action: deny}\n").unwrap();
        assert_eq!(
            policy.rules[0].reason.as_deref(),
            Some("tool blocked by policy")
        );
        assert_eq!(policy.rules[0].label(), "deny:fs.read");
    }

    #[test]
    fn adapters_declare_the_resource_surface() {
        let policy = parse(
            "version: 2\nadapters:\n  - name: local\n    type: local_tools\n    resources: [fs.read, fs.write]\n    config: {root: /srv}\nrules:\n  - {resource: 'fs.*', action: allow}\n  - {resource: net.get, action: deny}\n",
        )
        .unwrap();
        assert_eq!(policy.adapters.len(), 1);
        assert_eq!(policy.adapters[0].type_, "local_tools");
        // Wildcarded rule resources are not plannable, so they are left out.
        assert_eq!(
            policy.declared_resources(),
            vec!["fs.read", "fs.write", "net.get"]
        );
        assert_eq!(
            error("version: 2\nadapters:\n  - {name: a, type: t}\n  - {name: a, type: t}\n"),
            "adapters[1]: duplicate adapter name 'a'"
        );
    }

    #[test]
    fn pinned_context_drives_the_unpinned_field_report() {
        let policy = parse(
            "version: 2\npinned_context: [environment]\nrules:\n  - resource: fs.read\n    action: allow\n    when:\n      environment: {equals: prod}\n      agent: {equals: bot}\n",
        )
        .unwrap();
        assert_eq!(
            policy.when_fields().into_iter().collect::<Vec<_>>(),
            vec!["agent", "environment"]
        );
        assert_eq!(
            policy
                .unpinned_when_fields()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["agent"]
        );
    }

    #[test]
    fn version_1_translates_to_ordered_rules() {
        let policy = parse(
            "version: 1\ntools:\n  read_file:\n    parameter_rules:\n      path:\n        deny_patterns: ['\\.\\.', '/etc/']\n  write_file:\n    allow: false\n    reason: no writes\n  deploy:\n    allow: review\n",
        )
        .unwrap();

        let labels: Vec<String> = policy.rules.iter().map(|r| r.label()).collect();
        assert_eq!(
            labels,
            vec![
                "legacy:read_file:path:deny_pattern[0]",
                "legacy:read_file:path:deny_pattern[1]",
                "legacy:read_file:allow",
                "legacy:write_file:blocked",
                "legacy:deploy:review",
            ]
        );
        assert_eq!(policy.default_reason, DEFAULT_REASON_V1);
        assert_eq!(policy.default_action, Action::Deny);
        assert_eq!(
            policy.rules[3].reason.as_deref(),
            Some("no writes"),
            "an explicit reason survives translation"
        );
        assert_eq!(
            policy.rules[0].reason.as_deref(),
            Some("read_file: parameter 'path' matched deny pattern '\\.\\.'")
        );
    }

    #[test]
    fn version_1_requires_tools() {
        assert_eq!(
            error("version: 1\n"),
            "Policy file missing required key: 'tools'"
        );
        assert_eq!(
            error("version: 1\ntools: []\n"),
            "'tools' must be a mapping of tool names to configurations"
        );
    }

    /// `allow: 0` used to mean *allow*, because validation compared by value
    /// (`0 == False`) and the deny branch compared by identity. An integer is
    /// now a load error, so the value that reads as a denial can no longer be
    /// silently read as a permission.
    #[test]
    fn an_integer_is_not_a_boolean_and_no_longer_fails_open() {
        for (value, expected) in [
            ("false", Allow::No),
            ("no", Allow::No),
            ("off", Allow::No),
            ("true", Allow::Yes),
            ("yes", Allow::Yes),
            ("'review'", Allow::Review),
        ] {
            let policy = parse(&format!("version: 1\ntools:\n  t:\n    allow: {value}\n")).unwrap();
            assert_eq!(
                policy.tools.as_ref().unwrap()["t"].allow,
                expected,
                "allow: {value}"
            );
        }

        // `0` and `0.0` are the two that used to fail open. `1` and `2` were
        // already allowed, correctly and by accident respectively; all four are
        // now rejected by the same rule, because none of them is a boolean.
        for value in ["0", "0.0", "1", "2"] {
            assert_eq!(
                error(&format!("version: 1\ntools:\n  t:\n    allow: {value}\n")),
                format!("Tool 't': 'allow' must be true, false, or 'review', got '{value}'"),
                "allow: {value}"
            );
        }
    }

    /// Also recorded rather than endorsed: the loader reaches for Python's `or`
    /// in several places, so a falsy value of the wrong type is replaced with an
    /// empty container instead of being reported.
    #[test]
    fn falsy_values_are_silently_replaced_with_empty_containers() {
        let policy =
            parse("version: 2\nadapters:\n  - {name: a, type: t, resources: 0, config: 0}\n")
                .unwrap();
        assert!(policy.adapters[0].resources.is_empty());
        assert!(policy.adapters[0].config.is_empty());
        // A truthy value of the wrong type is still reported.
        assert_eq!(
            error("version: 2\nadapters:\n  - {name: a, type: t, config: 3}\n"),
            "adapters[0]: 'config' must be a mapping, got int"
        );
    }

    #[test]
    fn a_malformed_deny_pattern_is_a_load_error() {
        let message = error(
            "version: 1\ntools:\n  t:\n    parameter_rules:\n      path:\n        deny_patterns: ['(']\n",
        );
        assert!(message.contains("invalid regex '('"), "{message}");
    }

    #[test]
    fn a_policy_file_must_be_a_mapping() {
        assert_eq!(
            error("- 1\n"),
            "Policy file must be a YAML mapping, got list"
        );
        assert_eq!(
            error(""),
            "Policy file must be a YAML mapping, got NoneType"
        );
    }

    /// `allow: no` is a *boolean* in a Python-loaded policy file, and this is the
    /// test that would fail if the YAML dialect ever drifted back to 1.2.
    #[test]
    fn yaml_1_1_booleans_reach_the_version_1_loader() {
        let policy = parse("version: 1\ntools:\n  t:\n    allow: no\n").unwrap();
        assert_eq!(policy.tools.as_ref().unwrap()["t"].allow, Allow::No);
        // Quoted, it is the string `'no'` and therefore not permitted.
        assert!(
            error("version: 1\ntools:\n  t:\n    allow: 'no'\n").contains("must be true, false")
        );
    }
}
