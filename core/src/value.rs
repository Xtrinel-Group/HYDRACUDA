//! Policy values, with Python's comparison and stringification semantics.
//!
//! The engine compares caller-supplied parameters against literals written in a
//! YAML policy file. Those comparisons were specified by a Python
//! implementation, so "what does `equals: 1` do when the request sends `true`?"
//! already has an answer, and it is Python's answer. Reimplementing them with
//! Rust's semantics instead would change decisions without changing a single
//! policy file — which is the exact failure this port has to avoid.
//!
//! Three behaviours are therefore reproduced deliberately rather than
//! inherited:
//!
//! - **Numeric/boolean equality is cross-type.** Python's `True == 1` and
//!   `1 == 1.0` are both true, so `equals: 1` matches a request sending `true`.
//! - **`in` compares with `==`.** `not_in: [0]` therefore rejects `false`.
//! - **`matches` stringifies first.** `re.search(pattern, str(value))` means a
//!   regex is tested against `"True"`, `"None"`, `"1.0"`, or `"['a', 'b']"` —
//!   Python's spelling of those values, not Rust's.
//!
//! [`py_repr`] exists for the same reason: it renders error messages and the
//! elements of stringified containers the way Python does, so diagnostics do
//! not drift between the two implementations.

use std::fmt::Write as _;

use indexmap::IndexMap;

/// A value from a policy file or a request.
///
/// Deliberately its own type rather than a YAML crate's: the comparison rules
/// below are Python's rather than YAML's or Rust's, and owning the type keeps the
/// parser swappable in one place ([`crate::yaml`]).
#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// A bare `YYYY-MM-DD` scalar, which `yaml.safe_load` turns into a
    /// `datetime.date`. Kept as a distinct type because a date is equal to no
    /// string, so `equals: 2026-09-09` can never match a request carrying the
    /// text `"2026-09-09"` — a trap worth reproducing rather than smoothing over.
    Date(String),
    Seq(Vec<Value>),
    /// Insertion order is preserved because policy diagnostics report keys in
    /// file order, as the Python loader does.
    Map(IndexMap<String, Value>),
}

impl Value {
    /// The name Python's `type(value).__name__` would give, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Date(_) => "date",
            Value::Seq(_) => "list",
            Value::Map(_) => "dict",
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_seq(&self) -> Option<&[Value]> {
        match self {
            Value::Seq(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&IndexMap<String, Value>> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }

    /// True for a genuine YAML boolean.
    ///
    /// Distinct from `py_eq(&Value::Bool(..))`: `0` is *equal* to `false` but is
    /// not a boolean, and the version 1 loader's `allow:` check turns on
    /// exactly that difference.
    pub fn as_bool_strict(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Python's `==`.
///
/// The cross-type numeric cases are the point: `True == 1 == 1.0` in Python, so
/// a policy comparing against `1` matches a request sending `true`.
pub fn py_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Str(a), Value::Str(b)) => a == b,
        // Two dates are equal when they name the same day, and a date is equal
        // to nothing else — including the string that spells it.
        (Value::Date(a), Value::Date(b)) => a == b,

        // Numbers and booleans form one comparison domain, because in Python
        // `bool` is a subclass of `int`.
        (Value::Bool(_) | Value::Int(_) | Value::Float(_), _) => match numeric(right) {
            Some(b) => numeric(left) == Some(b),
            None => false,
        },
        (_, Value::Bool(_) | Value::Int(_) | Value::Float(_)) => false,

        (Value::Seq(a), Value::Seq(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
        }
        (Value::Map(a), Value::Map(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|other| py_eq(v, other)))
        }
        _ => false,
    }
}

/// The numeric view of a value, or None when it has none.
///
/// NaN is excluded so that `py_eq` reports NaN as unequal to itself, matching
/// Python.
fn numeric(value: &Value) -> Option<f64> {
    let n = match value {
        Value::Bool(true) => 1.0,
        Value::Bool(false) => 0.0,
        Value::Int(i) => *i as f64,
        Value::Float(f) => *f,
        _ => return None,
    };
    if n.is_nan() {
        None
    } else {
        Some(n)
    }
}

/// Python's truthiness.
///
/// The loader leans on it in several places — `raw.get("config") or {}` — so a
/// falsy value of the wrong type is silently replaced with an empty container
/// rather than reported. Reproduced because those are live policy files'
/// behaviour, not because it is good; see the tests in `policy.rs`.
pub fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => !s.is_empty(),
        // A `datetime.date` has no `__bool__`, so it is always truthy.
        Value::Date(_) => true,
        Value::Seq(items) => !items.is_empty(),
        Value::Map(map) => !map.is_empty(),
    }
}

/// Python's `value in items`, which compares with `==`.
pub fn py_contains(items: &[Value], value: &Value) -> bool {
    items.iter().any(|item| py_eq(value, item))
}

/// Python's `str()`.
///
/// This is what `matches`/`not_matches` test a regex against, so it is part of
/// the decision, not just of the diagnostics.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        // `str(date)` is its ISO form, which is also how it was written.
        Value::Date(iso) => iso.clone(),
        other => py_repr(other),
    }
}

/// Python's `repr()`.
pub fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => py_float_repr(*f),
        Value::Str(s) => py_str_repr(s),
        Value::Date(iso) => {
            // `repr(datetime.date(2026, 9, 9))`, whose components carry no
            // leading zeros even though the ISO text does.
            let part = |range: std::ops::Range<usize>| match iso[range].trim_start_matches('0') {
                "" => "0".to_string(),
                trimmed => trimmed.to_string(),
            };
            format!(
                "datetime.date({}, {}, {})",
                part(0..4),
                part(5..7),
                part(8..10),
            )
        }
        Value::Seq(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&py_repr(item));
            }
            out.push(']');
            out
        }
        Value::Map(map) => {
            if map.is_empty() {
                return "{}".to_string();
            }
            let mut out = String::from("{");
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "{}: {}", py_str_repr(key), py_repr(item));
            }
            out.push('}');
            out
        }
    }
}

/// Python's `repr()` for a float.
///
/// Python switches to exponent notation when the decimal exponent is at least
/// 16 or below -4, and always leaves a visible fractional part otherwise, so
/// `1.0` is `"1.0"` and not Rust's `"1"`.
fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_string();
    }

    // Rust's `{:e}` yields the shortest round-tripping mantissa, which is the
    // same digit string Python's repr uses; only the presentation differs.
    let scientific = format!("{:e}", value);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` always emits an exponent");
    let exponent: i32 = exponent.parse().expect("`{:e}` emits a decimal exponent");

    // Spelled out rather than as a range check, because these are CPython's two
    // thresholds and each one should be visible next to the doc comment naming it.
    #[allow(clippy::manual_range_contains)]
    if exponent >= 16 || exponent < -4 {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{}e{}{:02}", mantissa, sign, exponent.abs())
    } else {
        let decimal = format!("{}", value);
        if decimal.contains('.') {
            decimal
        } else {
            format!("{}.0", decimal)
        }
    }
}

/// Python's `repr()` for a string: single quotes unless that would need
/// escaping and double quotes would not.
fn py_str_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };

    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            // Python escapes C0/C1 controls and leaves other printable
            // characters, including non-ASCII, as themselves.
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `repr()` of a list of strings, used by the "allowed keys" messages.
pub fn py_repr_str_list(items: &[String]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&py_str_repr(item));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(source: &str) -> Value {
        crate::yaml::load(source).unwrap()
    }

    #[test]
    fn booleans_and_numbers_compare_across_types_as_python_does() {
        assert!(py_eq(&Value::Bool(true), &Value::Int(1)));
        assert!(py_eq(&Value::Int(1), &Value::Float(1.0)));
        assert!(py_eq(&Value::Bool(false), &Value::Int(0)));
        assert!(!py_eq(&Value::Bool(true), &Value::Int(2)));
        assert!(!py_eq(&Value::Bool(true), &Value::Str("true".into())));
        assert!(!py_eq(&Value::Int(1), &Value::Str("1".into())));
    }

    #[test]
    fn nan_is_not_equal_to_itself() {
        assert!(!py_eq(&Value::Float(f64::NAN), &Value::Float(f64::NAN)));
    }

    #[test]
    fn null_only_equals_null() {
        assert!(py_eq(&Value::Null, &Value::Null));
        assert!(!py_eq(&Value::Null, &Value::Bool(false)));
        assert!(!py_eq(&Value::Null, &Value::Int(0)));
    }

    #[test]
    fn containers_compare_elementwise() {
        assert!(py_eq(&yaml("[1, true]"), &yaml("[1.0, 1]")));
        assert!(!py_eq(&yaml("[1, 2]"), &yaml("[1]")));
        assert!(py_eq(&yaml("{a: 1}"), &yaml("{a: true}")));
        assert!(!py_eq(&yaml("{a: 1}"), &yaml("{b: 1}")));
    }

    #[test]
    fn stringification_matches_python() {
        assert_eq!(py_str(&Value::Bool(true)), "True");
        assert_eq!(py_str(&Value::Null), "None");
        assert_eq!(py_str(&Value::Int(7)), "7");
        assert_eq!(py_str(&Value::Str("../etc".into())), "../etc");
        assert_eq!(py_str(&yaml("[a, 1, null]")), "['a', 1, None]");
        assert_eq!(py_str(&yaml("{k: v}")), "{'k': 'v'}");
    }

    #[test]
    fn float_repr_matches_python() {
        assert_eq!(py_float_repr(1.0), "1.0");
        assert_eq!(py_float_repr(-0.0), "-0.0");
        assert_eq!(py_float_repr(0.1), "0.1");
        assert_eq!(py_float_repr(0.0001), "0.0001");
        assert_eq!(py_float_repr(0.00001), "1e-05");
        assert_eq!(py_float_repr(1e15), "1000000000000000.0");
        assert_eq!(py_float_repr(1e16), "1e+16");
        assert_eq!(py_float_repr(1.5e20), "1.5e+20");
        assert_eq!(py_float_repr(f64::INFINITY), "inf");
        assert_eq!(py_float_repr(f64::NAN), "nan");
    }

    #[test]
    fn string_repr_picks_the_quote_python_would() {
        assert_eq!(py_str_repr("plain"), "'plain'");
        assert_eq!(py_str_repr("it's"), "\"it's\"");
        assert_eq!(py_str_repr("it's \"both\""), "'it\\'s \"both\"'");
        assert_eq!(py_str_repr("a\nb"), "'a\\nb'");
        assert_eq!(py_str_repr("back\\slash"), "'back\\\\slash'");
    }

    #[test]
    fn zero_is_equal_to_false_but_is_not_a_boolean() {
        // The version 1 loader's `allow:` check depends on this distinction.
        assert!(py_eq(&Value::Int(0), &Value::Bool(false)));
        assert_eq!(Value::Int(0).as_bool_strict(), None);
        assert_eq!(Value::Bool(false).as_bool_strict(), Some(false));
    }

    #[test]
    fn a_date_equals_no_string_and_no_other_date() {
        let date = Value::Date("2026-09-09".into());
        assert!(py_eq(&date, &Value::Date("2026-09-09".into())));
        assert!(!py_eq(&date, &Value::Date("2026-09-10".into())));
        assert!(!py_eq(&date, &Value::Str("2026-09-09".into())));
        assert!(!py_eq(&date, &Value::Null));
        assert!(py_truthy(&date));
        assert_eq!(date.type_name(), "date");
        assert_eq!(
            py_repr(&Value::Date("0001-01-01".into())),
            "datetime.date(1, 1, 1)"
        );
    }
}
