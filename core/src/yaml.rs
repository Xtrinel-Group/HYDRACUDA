//! A PyYAML-compatible YAML loader.
//!
//! This exists because **the YAML parser is part of the decision.** A policy
//! file is untyped text until something resolves it, and `yaml.safe_load` — the
//! function the Python package calls — follows YAML **1.1**: `allow: no` is the
//! boolean `false`, `012` is the integer `10`, and `1:30` is `90`. Rust's YAML
//! crates follow YAML 1.2, where all three are strings.
//!
//! Left alone, that difference silently changes decisions. `allow: no` is a
//! denial in the Python engine and a load error in a 1.2 parser; a rule keyed on
//! `equals: 012` compares against a different number. So the resolver below is
//! PyYAML's, applied to plain scalars only — a quoted `'no'` stays a string in
//! both, which is why the underlying parser has to report scalar style.
//!
//! ## Known differences from `yaml.safe_load`
//!
//! - **Datetimes.** PyYAML resolves `2026-09-09T10:00:00Z` to a `datetime`.
//!   Only the bare `YYYY-MM-DD` form is resolved here (to [`Value::Date`]); a
//!   full timestamp stays a string.
//! - **Merge keys.** `<<: *anchor` is not merged. PyYAML's `SafeLoader` merges
//!   it.
//! - **Non-string mapping keys** become their `str()`. In Python an integer key
//!   reaches the strict-key check and raises `AttributeError` from inside
//!   `difflib`, so nothing depends on the current behaviour there.
//! - **Integers beyond `i64`** become floats. Python has arbitrary precision.

use indexmap::IndexMap;
use yaml_rust2::parser::{Event, EventReceiver, Parser, Tag};
use yaml_rust2::scanner::TScalarStyle;

use crate::value::{py_str, Value};

/// A YAML document could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError(pub String);

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for YamlError {}

/// Load a single YAML document, resolving plain scalars as PyYAML does.
pub fn load(source: &str) -> Result<Value, YamlError> {
    let mut builder = Builder::default();
    Parser::new_from_str(source)
        .load(&mut builder, false)
        .map_err(|e| YamlError(e.to_string()))?;
    if let Some(error) = builder.error {
        return Err(YamlError(error));
    }
    // An empty document is `None` in Python, and the policy loader reports that
    // as "must be a YAML mapping, got NoneType".
    Ok(builder.document.unwrap_or(Value::Null))
}

#[derive(Default)]
struct Builder {
    stack: Vec<Frame>,
    anchors: IndexMap<usize, Value>,
    document: Option<Value>,
    error: Option<String>,
}

enum Frame {
    Seq {
        items: Vec<Value>,
        anchor: usize,
    },
    Map {
        entries: IndexMap<String, Value>,
        pending_key: Option<Value>,
        anchor: usize,
    },
}

impl Builder {
    fn complete(&mut self, value: Value, anchor: usize) {
        if anchor != 0 {
            self.anchors.insert(anchor, value.clone());
        }
        match self.stack.last_mut() {
            None => self.document = Some(value),
            Some(Frame::Seq { items, .. }) => items.push(value),
            Some(Frame::Map {
                entries,
                pending_key,
                ..
            }) => match pending_key.take() {
                None => *pending_key = Some(value),
                Some(key) => {
                    let key = match key {
                        Value::Str(key) => key,
                        other => py_str(&other),
                    };
                    // A duplicate key replaces the value and keeps its original
                    // position, which is what a Python dict does.
                    entries.insert(key, value);
                }
            },
        }
    }
}

impl EventReceiver for Builder {
    fn on_event(&mut self, event: Event) {
        if self.error.is_some() {
            return;
        }
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                let value = match resolve_scalar(&text, style, tag.as_ref()) {
                    Ok(value) => value,
                    Err(message) => {
                        self.error = Some(message);
                        return;
                    }
                };
                self.complete(value, anchor);
            }
            Event::SequenceStart(anchor, _) => self.stack.push(Frame::Seq {
                items: Vec::new(),
                anchor,
            }),
            Event::MappingStart(anchor, _) => self.stack.push(Frame::Map {
                entries: IndexMap::new(),
                pending_key: None,
                anchor,
            }),
            Event::SequenceEnd | Event::MappingEnd => {
                let Some(frame) = self.stack.pop() else {
                    self.error = Some("unbalanced YAML collection".into());
                    return;
                };
                let (value, anchor) = match frame {
                    Frame::Seq { items, anchor } => (Value::Seq(items), anchor),
                    Frame::Map {
                        entries, anchor, ..
                    } => (Value::Map(entries), anchor),
                };
                self.complete(value, anchor);
            }
            Event::Alias(id) => match self.anchors.get(&id).cloned() {
                Some(value) => self.complete(value, 0),
                None => {
                    self.error = Some(format!("found undefined alias with id {id}"));
                }
            },
            Event::StreamStart | Event::StreamEnd | Event::DocumentStart | Event::DocumentEnd => {}
            Event::Nothing => {}
        }
    }
}

/// PyYAML's implicit resolver plus the handful of explicit `!!` tags a policy
/// file might carry.
fn resolve_scalar(text: &str, style: TScalarStyle, tag: Option<&Tag>) -> Result<Value, String> {
    if let Some(tag) = tag {
        if tag.handle == "tag:yaml.org,2002:" {
            return resolve_tagged(text, &tag.suffix);
        }
        return Err(format!(
            "could not determine a constructor for the tag '!{}{}'",
            tag.handle, tag.suffix
        ));
    }

    // A quoted scalar is always a string: quoting is how a policy file says
    // "the literal text `no`", and both implementations must honour it.
    if style != TScalarStyle::Plain {
        return Ok(Value::Str(text.to_string()));
    }

    resolve_plain(text)
}

fn resolve_tagged(text: &str, suffix: &str) -> Result<Value, String> {
    match suffix {
        "str" => Ok(Value::Str(text.to_string())),
        "null" => Ok(Value::Null),
        "bool" => resolve_bool(text)
            .map(Value::Bool)
            .ok_or_else(|| format!("could not determine a bool from {text:?}")),
        "int" => {
            resolve_int(text).ok_or_else(|| format!("could not determine an int from {text:?}"))
        }
        "float" => {
            resolve_float(text).ok_or_else(|| format!("could not determine a float from {text:?}"))
        }
        other => Err(format!(
            "could not determine a constructor for the tag 'tag:yaml.org,2002:{other}'"
        )),
    }
}

/// The implicit resolution PyYAML applies to a plain scalar, in its order.
pub fn resolve_plain(text: &str) -> Result<Value, String> {
    if matches!(text, "" | "~" | "null" | "Null" | "NULL") {
        return Ok(Value::Null);
    }
    if let Some(flag) = resolve_bool(text) {
        return Ok(Value::Bool(flag));
    }
    // Ints are tried before floats because the sexagesimal forms overlap and
    // PyYAML registers the int resolver's patterns as the narrower ones.
    if let Some(value) = resolve_int(text) {
        return Ok(value);
    }
    if let Some(value) = resolve_float(text) {
        return Ok(value);
    }
    if looks_like_a_date(text) {
        // The shape resolved; whether it names a real day is a separate
        // question, and PyYAML raises on `2026-13-45` rather than falling back
        // to a string.
        return match valid_date(text) {
            true => Ok(Value::Date(text.to_string())),
            false => Err(format!("{text} is not a valid date")),
        };
    }
    Ok(Value::Str(text.to_string()))
}

/// YAML 1.1 booleans, exactly the spellings PyYAML lists. `y` and `n` alone are
/// *not* included, which is PyYAML's own deviation from the 1.1 spec.
fn resolve_bool(text: &str) -> Option<bool> {
    match text {
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => Some(true),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => Some(false),
        _ => None,
    }
}

fn split_sign(text: &str) -> (i64, &str) {
    match text.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, text.strip_prefix('+').unwrap_or(text)),
    }
}

/// PyYAML's int resolver: binary, octal (bare leading zero), decimal,
/// hexadecimal, and base-60.
fn resolve_int(text: &str) -> Option<Value> {
    let (sign, digits) = split_sign(text);
    if digits.is_empty() {
        return None;
    }

    let radix_parse = |body: &str, radix: u32, allowed: fn(char) -> bool| -> Option<Value> {
        let cleaned: String = body.chars().filter(|c| *c != '_').collect();
        if cleaned.is_empty() || !body.chars().all(|c| c == '_' || allowed(c)) {
            return None;
        }
        i64::from_str_radix(&cleaned, radix)
            .ok()
            .map(|n| Value::Int(sign * n))
    };

    if let Some(body) = digits.strip_prefix("0b") {
        return radix_parse(body, 2, |c| matches!(c, '0' | '1'));
    }
    if let Some(body) = digits.strip_prefix("0x") {
        return radix_parse(body, 16, |c| c.is_ascii_hexdigit());
    }
    // A bare leading zero is octal in YAML 1.1, which is why `012` is ten.
    if digits.len() > 1 && digits.starts_with('0') && !digits.contains(':') {
        return radix_parse(&digits[1..], 8, |c| ('0'..='7').contains(&c));
    }
    if digits == "0" {
        return Some(Value::Int(0));
    }

    if digits.contains(':') {
        return resolve_sexagesimal_int(sign, digits);
    }

    // Decimal, with no leading zero permitted: `08` is a string, not eight.
    if !digits.starts_with(['1', '2', '3', '4', '5', '6', '7', '8', '9']) {
        return None;
    }
    if !digits.chars().all(|c| c == '_' || c.is_ascii_digit()) {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    cleaned.parse::<i64>().ok().map(|n| Value::Int(sign * n))
}

/// `1:30` is ninety: base-60, most significant part first.
fn resolve_sexagesimal_int(sign: i64, digits: &str) -> Option<Value> {
    let mut parts = digits.split(':');
    let first: String = parts.next()?.chars().filter(|c| *c != '_').collect();
    if first.is_empty() || !first.starts_with(['1', '2', '3', '4', '5', '6', '7', '8', '9']) {
        return None;
    }
    if !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut total: i64 = first.parse().ok()?;
    let mut seen = 0;
    for part in parts {
        if !is_sexagesimal_part(part) {
            return None;
        }
        total = total
            .checked_mul(60)?
            .checked_add(part.parse::<i64>().ok()?)?;
        seen += 1;
    }
    if seen == 0 {
        return None;
    }
    Some(Value::Int(sign * total))
}

/// A base-60 digit group: one or two decimal digits below sixty.
fn is_sexagesimal_part(part: &str) -> bool {
    matches!(part.len(), 1 | 2)
        && part.chars().all(|c| c.is_ascii_digit())
        && part.parse::<u32>().is_ok_and(|n| n < 60)
}

/// PyYAML's float resolver.
///
/// Narrower than it looks: the exponent must carry an explicit sign, so `1e5`
/// and `1.0e5` are **strings** in a Python-loaded policy file. That is
/// surprising enough to be worth reproducing rather than improving.
fn resolve_float(text: &str) -> Option<Value> {
    let (sign, body) = split_sign(text);
    let signed = |n: f64| Some(Value::Float(sign as f64 * n));

    match body {
        ".inf" | ".Inf" | ".INF" => return signed(f64::INFINITY),
        _ => {}
    }
    // `.nan` takes no sign in PyYAML's pattern.
    if text == ".nan" || text == ".NaN" || text == ".NAN" {
        return Some(Value::Float(f64::NAN));
    }

    if body.contains(':') {
        return resolve_sexagesimal_float(sign, body);
    }

    let (mantissa, exponent) = match body.split_once(['e', 'E']) {
        None => (body, None),
        Some((mantissa, exponent)) => {
            // The sign is mandatory here; without it PyYAML does not see a float.
            if !exponent.starts_with(['+', '-']) || exponent.len() < 2 {
                return None;
            }
            if !exponent[1..].chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            (mantissa, Some(exponent))
        }
    };

    // A decimal point is required, on one side or the other.
    let (whole, fraction) = mantissa.split_once('.')?;
    let whole_clean: String = whole.chars().filter(|c| *c != '_').collect();
    let fraction_clean: String = fraction.chars().filter(|c| *c != '_').collect();
    if !whole.chars().all(|c| c == '_' || c.is_ascii_digit())
        || !fraction.chars().all(|c| c == '_' || c.is_ascii_digit())
    {
        return None;
    }
    if whole_clean.is_empty() && fraction_clean.is_empty() {
        return None;
    }
    // `.5` is allowed; `1.` is allowed; a leading zero is not restricted here.
    let literal = format!(
        "{}.{}{}",
        if whole_clean.is_empty() {
            "0"
        } else {
            &whole_clean
        },
        if fraction_clean.is_empty() {
            "0"
        } else {
            &fraction_clean
        },
        match exponent {
            Some(exponent) => format!("e{exponent}"),
            None => String::new(),
        }
    );
    literal
        .parse::<f64>()
        .ok()
        .map(|n| Value::Float(sign as f64 * n))
}

fn resolve_sexagesimal_float(sign: i64, body: &str) -> Option<Value> {
    let (int_part, fraction) = match body.split_once('.') {
        None => return None,
        Some((int_part, fraction)) => (int_part, fraction),
    };
    if !fraction.chars().all(|c| c == '_' || c.is_ascii_digit()) {
        return None;
    }
    let mut parts = int_part.split(':');
    let first: String = parts.next()?.chars().filter(|c| *c != '_').collect();
    if first.is_empty() || !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut total: f64 = first.parse().ok()?;
    let mut seen = 0;
    for part in parts {
        if !is_sexagesimal_part(part) {
            return None;
        }
        total = total * 60.0 + part.parse::<f64>().ok()?;
        seen += 1;
    }
    if seen == 0 {
        return None;
    }
    let fraction_clean: String = fraction.chars().filter(|c| *c != '_').collect();
    let fraction_value: f64 = if fraction_clean.is_empty() {
        0.0
    } else {
        format!("0.{fraction_clean}").parse().ok()?
    };
    Some(Value::Float(sign as f64 * (total + fraction_value)))
}

/// Only the rigid `YYYY-MM-DD` form, which PyYAML turns into a `datetime.date`.
fn looks_like_a_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| text[range].chars().all(|c| c.is_ascii_digit());
    digits(0..4) && digits(5..7) && digits(8..10)
}

/// Whether a `YYYY-MM-DD` string names a day `datetime.date` would accept.
fn valid_date(text: &str) -> bool {
    let number = |range: std::ops::Range<usize>| text[range].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    if year == 0 || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= last
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(source: &str) -> Value {
        let document = load(&format!("a: {source}")).unwrap();
        document.as_map().unwrap()["a"].clone()
    }

    /// Each expectation was read off `yaml.safe_load` rather than off the spec.
    /// `tests/test_differential.py` re-derives them from the live library.
    #[test]
    fn plain_scalars_resolve_as_pyyaml_resolves_them() {
        assert!(matches!(scalar("no"), Value::Bool(false)));
        assert!(matches!(scalar("yes"), Value::Bool(true)));
        assert!(matches!(scalar("off"), Value::Bool(false)));
        assert!(matches!(scalar("TRUE"), Value::Bool(true)));
        assert!(matches!(scalar("true"), Value::Bool(true)));
        // PyYAML omits the bare `y`/`n` spellings.
        assert!(matches!(scalar("y"), Value::Str(_)));
        assert!(matches!(scalar("n"), Value::Str(_)));

        assert!(matches!(scalar("~"), Value::Null));
        assert!(matches!(scalar("null"), Value::Null));
        assert!(matches!(scalar("NULL"), Value::Null));
        assert!(matches!(
            load("a:").unwrap().as_map().unwrap()["a"],
            Value::Null
        ));

        assert!(matches!(scalar("0"), Value::Int(0)));
        assert!(matches!(scalar("00"), Value::Int(0)));
        assert!(
            matches!(scalar("012"), Value::Int(10)),
            "a leading zero is octal"
        );
        assert!(
            matches!(scalar("08"), Value::Str(_)),
            "8 is not an octal digit"
        );
        assert!(matches!(scalar("0x1f"), Value::Int(31)));
        assert!(matches!(scalar("0b101"), Value::Int(5)));
        assert!(matches!(scalar("1_000"), Value::Int(1000)));
        assert!(matches!(scalar("+1"), Value::Int(1)));
        assert!(matches!(scalar("-7"), Value::Int(-7)));
        assert!(matches!(scalar("1:30"), Value::Int(90)), "base sixty");

        assert!(matches!(scalar("'no'"), Value::Str(_)));
        assert!(matches!(scalar("\"012\""), Value::Str(_)));
    }

    #[test]
    fn the_float_resolver_requires_a_signed_exponent() {
        // Surprising, and PyYAML's actual behaviour.
        assert!(matches!(scalar("1e5"), Value::Str(_)));
        assert!(matches!(scalar("1.0e5"), Value::Str(_)));
        assert!(matches!(scalar("1e+5"), Value::Str(_)));
        assert_eq!(float(scalar("1.0e+5")), 100000.0);
        assert_eq!(float(scalar(".5")), 0.5);
        assert_eq!(float(scalar("5.")), 5.0);
        assert_eq!(float(scalar("-1.5")), -1.5);
        assert_eq!(float(scalar(".inf")), f64::INFINITY);
        assert_eq!(float(scalar("-.INF")), f64::NEG_INFINITY);
        assert!(float(scalar(".nan")).is_nan());
        assert_eq!(float(scalar("1:30.5")), 90.5);
    }

    fn float(value: Value) -> f64 {
        match value {
            Value::Float(f) => f,
            other => panic!("expected a float, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_date_becomes_a_date_and_is_not_a_string() {
        // PyYAML gives `datetime.date`, which compares unequal to every string,
        // so a policy comparing against one can never match a request.
        assert!(matches!(scalar("2026-09-09"), Value::Date(_)));
        assert!(matches!(scalar("2026-9-9"), Value::Str(_)));
        assert!(matches!(scalar("'2026-09-09'"), Value::Str(_)));
        assert_eq!(crate::value::py_str(&scalar("2026-09-09")), "2026-09-09");
        assert_eq!(
            crate::value::py_repr(&scalar("2026-09-09")),
            "datetime.date(2026, 9, 9)"
        );
        // PyYAML raises rather than falling back to a string.
        assert!(load("a: 2026-13-45").is_err());
        assert!(load("a: 2026-02-30").is_err());
        assert!(load("a: 2024-02-29").is_ok(), "2024 is a leap year");
    }

    #[test]
    fn structure_anchors_and_duplicate_keys() {
        let document = load("a: &x [1, 2]\nb: *x\nc: {d: 1}\na: 3\n").unwrap();
        let map = document.as_map().unwrap();
        // A duplicate key keeps its position and takes the last value, as a
        // Python dict does.
        assert_eq!(map.keys().collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert!(matches!(map["a"], Value::Int(3)));
        assert_eq!(map["b"].as_seq().unwrap().len(), 2);
        assert!(map["c"].as_map().is_some());
    }

    #[test]
    fn an_explicit_tag_overrides_the_resolver() {
        assert!(matches!(scalar("!!str 5"), Value::Str(_)));
        assert!(matches!(scalar("!!int '5'"), Value::Int(5)));
    }

    #[test]
    fn an_empty_document_is_null() {
        assert!(matches!(load("").unwrap(), Value::Null));
        assert!(matches!(load("# just a comment\n").unwrap(), Value::Null));
    }

    #[test]
    fn a_syntax_error_is_reported_rather_than_guessed_at() {
        assert!(load("a: [1, 2\n").is_err());
        assert!(load("a: *missing\n").is_err());
    }
}
