//! HYDRACUDA's decision engine.
//!
//! Policy in, decision out. A policy file declares ordered rules; a request
//! names a resource and carries parameters and context; evaluating the two
//! produces an allow/deny/review [`Decision`] with the rule that decided it.
//!
//! ```
//! use hydracuda_core::{Fields, Policy, PolicyEngine, Value};
//!
//! let policy = Policy::from_yaml_str(
//!     "version: 2\n\
//!      rules:\n\
//!      \x20 - name: block-traversal\n\
//!      \x20   resource: fs.read\n\
//!      \x20   action: deny\n\
//!      \x20   where:\n\
//!      \x20     path: {matches: ['\\.\\.']}\n\
//!      \x20 - {resource: fs.read, action: allow}\n",
//! )
//! .unwrap();
//!
//! let engine = PolicyEngine::new(&policy);
//! let mut params = Fields::new();
//! params.insert("path".into(), Value::Str("../etc/passwd".into()));
//!
//! let decision = engine.evaluate("fs.read", &params, &Fields::new());
//! assert_eq!(decision.action.as_str(), "deny");
//! assert_eq!(decision.rule.as_deref(), Some("block-traversal"));
//! assert!(decision.blocked());
//! ```
//!
//! # What this crate does not do
//!
//! No network calls, no clock reads, and no model calls anywhere in the decision
//! path. Policy evaluation is local, which is the guarantee the README makes and
//! the reason `plan` and `test` can report a decision without performing one.
//! The only filesystem access in the crate is [`Policy::from_path`], which reads
//! the policy file itself.
//!
//! Executing an allowed call is not this crate's job either — see
//! [`adapter`] for why the adapter trait stops at normalization.
//!
//! # Relationship to the Python package
//!
//! This is a port of `src/hydracuda/`, not a redesign of it. Both ship in 0.4.0
//! and both must decide identically: `core/tests/differential.rs` replays a
//! corpus of policies and requests against decisions recorded from the Python
//! engine, and `tests/test_differential.py` fails if that recording has gone
//! stale. Where Python's own semantics are load-bearing — cross-type numeric
//! equality, `str()` before a regex search, `difflib`'s similarity ratio — they
//! are reproduced rather than replaced. See [`value`] for the list.
//!
//! Two of the reproductions are whole modules, because the library a policy file
//! is read with turns out to be part of the decision: [`yaml`] resolves plain
//! scalars with PyYAML's YAML 1.1 rules (`allow: no` is a boolean), and
//! [`regex_compat`] rewrites Python's `$` and `\Z` anchors so a deny pattern
//! cannot match less here than it does there.

pub mod adapter;
pub mod conditions;
pub mod difflib;
pub mod engine;
mod fnmatch;
pub mod introspect;
pub mod policy;
pub mod regex_compat;
pub mod test_cases;
pub mod value;
pub mod yaml;

pub use adapter::{Adapter, AdapterError, DeclaredSurface, NormalizedAction, ResourceSpec};
pub use conditions::{
    matches_conditions, pattern_subsumes, resource_matches, ConditionError, Conditions,
};
pub use engine::{Decision, Fields, PolicyEngine};
pub use introspect::{analyze, plan, Diagnostic, Level, PlanEntry, Report};
pub use policy::{
    Action, AdapterSpec, Allow, LoadError, Mode, Policy, PolicyError, Rule, ToolPolicy,
};
pub use test_cases::{run_tests, CaseResult, Expect, Outcome, TestCase};
pub use value::Value;
pub use yaml::YamlError;

/// The version of the policy format and engine this crate implements.
///
/// Kept equal to the Python package's `__version__` by `tests/test_packaging.py`
/// so a release cannot ship two different numbers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
