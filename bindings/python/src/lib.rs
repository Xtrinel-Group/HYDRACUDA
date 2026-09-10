//! PyO3 bindings exposing the Rust decision engine to Python.
//!
//! The surface here is deliberately narrow. Python keeps its loader, its
//! `Policy`/`Rule`/`Decision` dataclasses, its adapters and its proxy; what
//! crosses this boundary is one question — *given these rules, what is the
//! verdict for this request?* — and one answer, the `(action, reason, rule)`
//! triple. `hydracuda/engine.py` builds the `Decision` from it.
//!
//! Keeping the boundary there is what makes the swap testable. The whole
//! existing Python suite can run with `HYDRACUDA_ENGINE=rust` and every
//! assertion about a `Decision` — its `params` identity, its `notes`, its
//! `blocked` property, the audit record the proxy writes from it — is still
//! testing Python code. Only the verdict comes from somewhere else. A
//! divergence therefore shows up as a failing assertion about a decision, not
//! as an object that merely looks different.
//!
//! Two things are *not* delegated, on purpose:
//!
//! - **Loading.** `parse_policy` stays in Python. The engine is handed a rule
//!   list that Python already validated, so a policy file's schema errors and
//!   their message text are still Python's. Loader parity has its own proof in
//!   `core/tests/differential.rs`, which compares 38 policies including 23 load
//!   errors; re-proving it through this boundary would test the conversion code
//!   below rather than the loader.
//! - **Condition *validation*.** Python validated the `where`/`when` blocks
//!   before they got here. This module re-runs them through
//!   [`hydracuda_core::validate_conditions`] because that is where a regex gets
//!   compiled, and a pattern Python accepted that Rust rejects must be a loud
//!   error rather than a rule that silently never matches — that would fail
//!   open. `core/src/regex_compat.rs` exists so this does not happen; the error
//!   path is here in case it ever does.

use hydracuda_core::conditions::Conditions;
use hydracuda_core::value::Value;
use hydracuda_core::{Action, Fields, Mode, Policy, PolicyEngine, Rule};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

pyo3::create_exception!(
    _core,
    EngineError,
    PyValueError,
    "A rule list the Rust engine cannot accept. Translated to `hydracuda.PolicyError`."
);

/// A policy's evaluable content, owned on the Rust side.
///
/// Built once from a Python `Policy` and reused for every request, so a regex is
/// compiled once per policy rather than once per call.
#[pyclass(name = "Engine", module = "hydracuda._core", frozen)]
struct Engine {
    policy: Policy,
}

#[pymethods]
impl Engine {
    /// Build an engine from the evaluable part of a Python `Policy`.
    ///
    /// The spec is a plain mapping rather than the dataclass itself: this module
    /// should not know the attribute names of a Python class it cannot see, and
    /// a mapping keeps the conversion in one readable place in
    /// `hydracuda/_backend.py`.
    #[new]
    fn new(spec: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mode = match required_str(spec, "mode")?.as_str() {
            "enforce" => Mode::Enforce,
            "shadow" => Mode::Shadow,
            "review" => Mode::Review,
            other => return Err(EngineError::new_err(format!("unknown mode {other:?}"))),
        };
        let default_action = parse_action(&required_str(spec, "default_action")?)?;
        let default_reason = required_str(spec, "default_reason")?;

        let raw_rules = spec
            .get_item("rules")?
            .ok_or_else(|| EngineError::new_err("spec is missing 'rules'"))?;
        let raw_rules = raw_rules.cast::<PyList>().map_err(|_| {
            EngineError::new_err(format!(
                "'rules' must be a list, got {}",
                type_name(&raw_rules)
            ))
        })?;

        let mut rules = Vec::with_capacity(raw_rules.len());
        for (index, raw_rule) in raw_rules.iter().enumerate() {
            rules.push(build_rule(&raw_rule, index)?);
        }

        Ok(Engine {
            policy: Policy {
                // Only the fields `evaluate` reads are carried across. `version`,
                // `audit_path`, `adapters`, `pinned_context`, `tests` and `tools`
                // belong to loading and introspection, which stay in Python, and
                // inventing values for them here would be inventing a second
                // source of truth for `validate` to disagree with.
                version: 2,
                mode,
                audit_path: String::new(),
                default_action,
                default_reason,
                rules,
                adapters: Vec::new(),
                pinned_context: Vec::new(),
                tests: Vec::new(),
                tools: None,
            },
        })
    }

    /// The verdict for one request, as `(action, reason, rule)`.
    ///
    /// `rule` is the matched rule's label, or `None` when the default applied.
    /// Everything else about the resulting `Decision` — `params`, `context`,
    /// `mode`, `enforced`, `notes` — is Python's to fill in, and `mode`/
    /// `enforced` are recomputed there from the same policy, so this returns the
    /// three values that could actually differ between engines.
    fn evaluate<'py>(
        &self,
        py: Python<'py>,
        resource: &str,
        params: Option<&Bound<'py, PyDict>>,
        context: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let params = fields_from(params)?;
        let context = fields_from(context)?;

        let decision = PolicyEngine::new(&self.policy).evaluate(resource, &params, &context);

        PyTuple::new(
            py,
            [
                decision.action.as_str().into_pyobject(py)?.into_any(),
                decision.reason.into_pyobject(py)?.into_any(),
                match decision.rule {
                    Some(label) => label.into_pyobject(py)?.into_any(),
                    None => py.None().into_bound(py),
                },
            ],
        )
    }

    /// The number of rules the engine holds, so a caller can assert the
    /// conversion did not silently drop any.
    #[getter]
    fn rule_count(&self) -> usize {
        self.policy.rules.len()
    }
}

fn build_rule(raw: &Bound<'_, PyAny>, index: usize) -> PyResult<Rule> {
    let raw = raw.cast::<PyDict>().map_err(|_| {
        EngineError::new_err(format!(
            "rules[{index}] must be a mapping, got {}",
            type_name(raw)
        ))
    })?;
    let at = |field: &str| format!("rules[{index}] '{field}'");

    Ok(Rule {
        resource: required_str(raw, "resource")?,
        action: parse_action(&required_str(raw, "action")?)?,
        name: optional_str(raw, "name")?,
        reason: optional_str(raw, "reason")?,
        where_: conditions_from(raw, "where", &at("where"))?,
        when: conditions_from(raw, "when", &at("when"))?,
    })
}

/// Convert and re-validate a `where`/`when` block.
///
/// Python validated it already; this is where the regexes get compiled. See the
/// module doc on why a rejection here has to be an exception and not a rule that
/// quietly never fires.
fn conditions_from(rule: &Bound<'_, PyDict>, key: &str, at: &str) -> PyResult<Conditions> {
    let block = match rule.get_item(key)? {
        None => return Ok(Conditions::new()),
        Some(block) if block.is_none() => return Ok(Conditions::new()),
        Some(block) => value_from(&block)?,
    };
    hydracuda_core::conditions::validate_conditions(Some(&block), at)
        .map_err(|error| EngineError::new_err(error.to_string()))
}

fn fields_from(mapping: Option<&Bound<'_, PyDict>>) -> PyResult<Fields> {
    let Some(mapping) = mapping else {
        return Ok(Fields::new());
    };
    let mut fields = Fields::with_capacity(mapping.len());
    for (key, value) in mapping.iter() {
        fields.insert(key_string(&key)?, value_from(&value)?);
    }
    Ok(fields)
}

/// A Python object as a [`Value`].
///
/// `bool` is tested before `int` because in Python a `bool` *is* an `int`, and
/// the distinction is load-bearing: [`Value::Bool`] and [`Value::Int`] compare
/// equal to each other but stringify differently, and `matches` runs against the
/// stringification. Getting this backwards would make a rule testing `^True$`
/// stop matching `True`.
fn value_from(object: &Bound<'_, PyAny>) -> PyResult<Value> {
    if object.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(value) = object.cast::<PyBool>() {
        return Ok(Value::Bool(value.is_true()));
    }
    if object.cast::<PyInt>().is_ok() {
        return match object.extract::<i64>() {
            Ok(value) => Ok(Value::Int(value)),
            // Python integers are unbounded. Beyond `i64` the engine cannot
            // represent one exactly, and silently narrowing it would change an
            // `equals:` comparison, so it becomes a float — which is what
            // `core/src/yaml.rs` does with the same overflow from a policy file.
            Err(_) => Ok(Value::Float(object.extract::<f64>()?)),
        };
    }
    if object.cast::<PyFloat>().is_ok() {
        return Ok(Value::Float(object.extract::<f64>()?));
    }
    if let Ok(value) = object.cast::<PyString>() {
        return Ok(Value::Str(value.to_str()?.to_string()));
    }
    if let Ok(items) = object.cast::<PyList>() {
        return Ok(Value::Seq(
            items
                .iter()
                .map(|item| value_from(&item))
                .collect::<PyResult<Vec<_>>>()?,
        ));
    }
    if let Ok(mapping) = object.cast::<PyDict>() {
        let mut map = indexmap::IndexMap::with_capacity(mapping.len());
        for (key, value) in mapping.iter() {
            map.insert(key_string(&key)?, value_from(&value)?);
        }
        return Ok(Value::Map(map));
    }
    if is_date(object)? {
        // `yaml.safe_load` resolves a bare `YYYY-MM-DD` to a `datetime.date`,
        // and a date is equal to no string in Python. `Value::Date` preserves
        // that, so a request carrying a date behaves here as it does there.
        return Ok(Value::Date(object.str()?.to_str()?.to_string()));
    }

    // Anything else — a tuple, a set, an arbitrary object — reaches a rule's
    // operators as whatever `str()` makes of it in Python. Rather than guess at
    // a `repr` this crate does not implement, refuse: an unrepresentable
    // parameter must not become a comparison that silently succeeds.
    Err(EngineError::new_err(format!(
        "cannot evaluate a parameter of type {}; the Rust engine accepts \
         None, bool, int, float, str, date, list and dict",
        type_name(object)
    )))
}

/// True for a `datetime.date` that is not a `datetime.datetime`.
///
/// `datetime` subclasses `date`, but `yaml.safe_load` produces a full
/// `datetime` for a timestamp scalar and `core/src/yaml.rs` deliberately does
/// not support those, so the two must not be conflated.
fn is_date(object: &Bound<'_, PyAny>) -> PyResult<bool> {
    let datetime = object.py().import("datetime")?;
    Ok(object.is_instance(&datetime.getattr("date")?)?
        && !object.is_instance(&datetime.getattr("datetime")?)?)
}

/// A mapping key as a string.
///
/// Policy field names are strings. A non-string key cannot address one, so it is
/// refused rather than stringified into something that might collide with a real
/// field name.
fn key_string(key: &Bound<'_, PyAny>) -> PyResult<String> {
    match key.cast::<PyString>() {
        Ok(key) => Ok(key.to_str()?.to_string()),
        Err(_) => Err(EngineError::new_err(format!(
            "mapping keys must be strings, got {}",
            type_name(key)
        ))),
    }
}

fn parse_action(action: &str) -> PyResult<Action> {
    match action {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "review" => Ok(Action::Review),
        other => Err(EngineError::new_err(format!("unknown action {other:?}"))),
    }
}

fn required_str(mapping: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    let value = mapping
        .get_item(key)?
        .ok_or_else(|| EngineError::new_err(format!("missing '{key}'")))?;
    match value.cast::<PyString>() {
        Ok(value) => Ok(value.to_str()?.to_string()),
        Err(_) => Err(EngineError::new_err(format!(
            "'{key}' must be a string, got {}",
            type_name(&value)
        ))),
    }
}

/// An optional string field, where Python's absent and `None` mean the same
/// thing — as they do in the dataclasses this mirrors.
fn optional_str(mapping: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match mapping.get_item(key)? {
        None => Ok(None),
        Some(value) if value.is_none() => Ok(None),
        Some(value) => match value.cast::<PyString>() {
            Ok(value) => Ok(Some(value.to_str()?.to_string())),
            Err(_) => Err(EngineError::new_err(format!(
                "'{key}' must be a string or None, got {}",
                type_name(&value)
            ))),
        },
    }
}

fn type_name(object: &Bound<'_, PyAny>) -> String {
    object
        .get_type()
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|_| "?".to_string())
}

#[pymodule]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("EngineError", module.py().get_type::<EngineError>())?;
    module.add_class::<Engine>()?;
    Ok(())
}
