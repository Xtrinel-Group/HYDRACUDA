//! Differential test: the Rust engine against decisions recorded from Python.
//!
//! `differential/cases.yaml` holds the inputs, `differential/expected.json` holds
//! what the Python implementation did with them, and this test replays the same
//! inputs through this crate. A disagreement fails here with both values printed.
//!
//! Both files are committed, so this test needs no Python interpreter and runs in
//! CI on a machine that has none. The other half of the guarantee lives in
//! `tests/test_differential.py`, which re-records and fails if the committed JSON
//! has gone stale — without it, a change to the Python engine could drift away
//! from a golden file that keeps passing.
//!
//! Regenerate after any intentional behaviour change:
//!
//! ```text
//! python scripts/record_differential.py
//! ```

use std::path::Path;

use hydracuda_core::conditions::Pattern;
use hydracuda_core::value::{py_repr, Value};
use hydracuda_core::{Fields, Policy, PolicyEngine};
use serde_json::Value as Json;

/// A mismatch, collected rather than asserted, so one run reports every
/// divergence instead of only the first.
struct Report {
    failures: Vec<String>,
    compared: usize,
}

impl Report {
    fn check(&mut self, what: &str, got: impl std::fmt::Debug, expected: impl std::fmt::Debug) {
        self.compared += 1;
        let (got, expected) = (format!("{got:?}"), format!("{expected:?}"));
        if got != expected {
            self.failures
                .push(format!("{what}\n     rust: {got}\n   python: {expected}"));
        }
    }
}

#[test]
fn the_rust_engine_decides_what_the_python_engine_decided() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differential");
    let cases = hydracuda_core::yaml::load(
        &std::fs::read_to_string(directory.join("cases.yaml")).expect("cases.yaml"),
    )
    .expect("cases.yaml must parse");
    let expected: Json = serde_json::from_str(
        &std::fs::read_to_string(directory.join("expected.json")).expect(
            "expected.json is committed; run `python scripts/record_differential.py` if missing",
        ),
    )
    .expect("expected.json must parse");

    let cases = cases.as_map().expect("cases.yaml is a mapping");
    let mut report = Report {
        failures: Vec::new(),
        compared: 0,
    };

    compare_scalars(&mut report, &cases["scalars"], &expected["scalars"]);
    compare_regexes(&mut report, &cases["regexes"], &expected["regexes"]);
    compare_examples(&mut report, &cases["examples"], &expected["examples"]);
    compare_policies(&mut report, &cases["policies"], &expected["policies"]);

    assert!(
        !report.failures.is_empty() || report.compared > 0,
        "the corpus compared nothing, which means it is not wired up"
    );
    assert!(
        report.failures.is_empty(),
        "{} of {} comparisons diverged from the Python engine:\n\n{}\n",
        report.failures.len(),
        report.compared,
        report.failures.join("\n\n")
    );
    eprintln!(
        "{} comparisons agreed with the Python engine",
        report.compared
    );
}

/// The YAML dialect. `allow: no` has to be a boolean here as it is there.
fn compare_scalars(report: &mut Report, cases: &Value, expected: &Json) {
    for source in cases.as_seq().expect("scalars is a list") {
        let source = source.as_str().expect("a scalar case is a string");
        let expected = &expected[source];
        assert!(
            !expected.is_null(),
            "no recording for scalar {source:?}; re-run scripts/record_differential.py"
        );

        match hydracuda_core::yaml::load(&format!("a: {source}")) {
            Err(_) => report.check(
                &format!("scalar {source:?}"),
                "load error",
                expected["error"].as_str().unwrap_or("a value"),
            ),
            Ok(document) => {
                let value = &document.as_map().expect("a mapping")["a"];
                report.check(
                    &format!("scalar {source:?} repr"),
                    py_repr(value),
                    expected["repr"].as_str().unwrap_or_default(),
                );
                report.check(
                    &format!("scalar {source:?} type"),
                    value.type_name(),
                    expected["type"].as_str().unwrap_or_default(),
                );
            }
        }
    }
}

/// `re.search`, pattern by pattern and subject by subject. The end-of-string
/// anchors are the cases that would otherwise fail open.
fn compare_regexes(report: &mut Report, cases: &Value, expected: &Json) {
    for (index, case) in cases
        .as_seq()
        .expect("regexes is a list")
        .iter()
        .enumerate()
    {
        let case = case.as_map().expect("a regex case is a mapping");
        let pattern = case["pattern"].as_str().expect("pattern is a string");
        let recorded = &expected[index];
        assert_eq!(
            recorded["pattern"].as_str(),
            Some(pattern),
            "the recording is out of step with cases.yaml; re-run scripts/record_differential.py"
        );

        let compiled = match Pattern::compile(pattern) {
            Ok(compiled) => compiled,
            Err(_) => {
                report.check(
                    &format!("regex {pattern:?}"),
                    "compile error",
                    recorded["error"].as_str().unwrap_or("compiles"),
                );
                continue;
            }
        };

        for (subject, expected) in case["subjects"]
            .as_seq()
            .expect("subjects is a list")
            .iter()
            .zip(recorded["matches"].as_array().expect("matches is a list"))
        {
            let subject = subject.as_str().expect("a subject is a string");
            report.check(
                &format!("re.search({pattern:?}, {subject:?})"),
                compiled.searches(subject),
                expected.as_bool().expect("a recorded match is a bool"),
            );
        }
    }
}

/// The policy files the project ships, read from disk rather than from the
/// corpus. A divergence on one of these is a divergence a user would hit by
/// copying a documented example, so they are worth replaying separately from the
/// synthetic cases even though the comparison is the same.
fn compare_examples(report: &mut Report, cases: &Value, expected: &Json) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives inside the workspace");

    for (index, case) in cases
        .as_seq()
        .expect("examples is a list")
        .iter()
        .enumerate()
    {
        let case = case.as_map().expect("an example case is a mapping");
        let path = case["path"].as_str().expect("path is a string");
        let recorded = &expected[index];
        assert_eq!(
            recorded["path"].as_str(),
            Some(path),
            "the recording is out of step with cases.yaml; re-run scripts/record_differential.py"
        );

        // An example that no longer loads is a broken example, not a divergence
        // to report — the Python recording proves it loaded when it was made.
        let policy = Policy::from_path(root.join(path))
            .unwrap_or_else(|error| panic!("{path} must load, but: {error}"));

        compare_loaded_policy(report, path, &policy, &recorded["policy"]);
        compare_decisions(report, path, &policy, case, &recorded["decisions"]);
    }
}

fn compare_policies(report: &mut Report, cases: &Value, expected: &Json) {
    for (index, case) in cases
        .as_seq()
        .expect("policies is a list")
        .iter()
        .enumerate()
    {
        let case = case.as_map().expect("a policy case is a mapping");
        let name = case["name"].as_str().expect("name is a string");
        let source = case["policy"].as_str().expect("policy is a string");
        let recorded = &expected[index];
        assert_eq!(
            recorded["name"].as_str(),
            Some(name),
            "the recording is out of step with cases.yaml; re-run scripts/record_differential.py"
        );

        let policy = match Policy::from_yaml_str(source) {
            Ok(policy) => policy,
            Err(error) => {
                // A load error is a case in its own right: the two engines must
                // reject the same file, and say the same thing about it.
                let expected_error = recorded["load_error"]
                    .as_str()
                    .or_else(|| recorded["yaml_error"].as_str());
                match expected_error {
                    Some(expected_error) => report.check(
                        &format!("policy {name:?} load error"),
                        normalize_error(&error.to_string()),
                        normalize_error(expected_error),
                    ),
                    None => report.check(
                        &format!("policy {name:?}"),
                        format!("load error: {error}"),
                        "loads successfully",
                    ),
                }
                continue;
            }
        };

        if let Some(expected_error) = recorded["load_error"]
            .as_str()
            .or_else(|| recorded["yaml_error"].as_str())
        {
            report.check(
                &format!("policy {name:?}"),
                "loads successfully",
                format!("load error: {expected_error}"),
            );
            continue;
        }

        compare_loaded_policy(report, name, &policy, &recorded["policy"]);
        compare_decisions(report, name, &policy, case, &recorded["decisions"]);
    }
}

/// The loaded shape, not just the decisions: a policy that parsed into different
/// rules would eventually decide differently on a request the corpus lacks.
fn compare_loaded_policy(report: &mut Report, name: &str, policy: &Policy, expected: &Json) {
    let at = |field: &str| format!("policy {name:?} {field}");
    report.check(
        &at("version"),
        policy.version,
        expected["version"].as_i64().unwrap_or_default(),
    );
    report.check(
        &at("mode"),
        policy.mode.as_str(),
        expected["mode"].as_str().unwrap_or_default(),
    );
    report.check(
        &at("audit_path"),
        policy.audit_path.as_str(),
        expected["audit_path"].as_str().unwrap_or_default(),
    );
    report.check(
        &at("default_action"),
        policy.default_action.as_str(),
        expected["default_action"].as_str().unwrap_or_default(),
    );
    report.check(
        &at("default_reason"),
        policy.default_reason.as_str(),
        expected["default_reason"].as_str().unwrap_or_default(),
    );
    report.check(
        &at("rules"),
        policy
            .rules
            .iter()
            .map(|rule| rule.label())
            .collect::<Vec<_>>(),
        strings(&expected["rules"]),
    );
    report.check(
        &at("when_fields"),
        policy.when_fields().into_iter().collect::<Vec<_>>(),
        strings(&expected["when_fields"]),
    );
    report.check(
        &at("unpinned_when_fields"),
        policy
            .unpinned_when_fields()
            .into_iter()
            .collect::<Vec<_>>(),
        strings(&expected["unpinned_when_fields"]),
    );
    report.check(
        &at("declared_resources"),
        policy.declared_resources(),
        strings(&expected["declared_resources"]),
    );
}

fn compare_decisions(
    report: &mut Report,
    name: &str,
    policy: &Policy,
    case: &indexmap::IndexMap<String, Value>,
    expected: &Json,
) {
    let engine = PolicyEngine::new(policy);
    let requests = case.get("requests").and_then(Value::as_seq).unwrap_or(&[]);
    let expected = expected.as_array().map(Vec::as_slice).unwrap_or(&[]);
    assert_eq!(
        requests.len(),
        expected.len(),
        "policy {name:?} has {} requests but {} recorded decisions; re-run \
         scripts/record_differential.py",
        requests.len(),
        expected.len()
    );

    for (request, expected) in requests.iter().zip(expected) {
        let request = request.as_map().expect("a request is a mapping");
        let resource = request["resource"].as_str().expect("resource is a string");
        let params = fields(request.get("params"));
        let context = fields(request.get("context"));
        let decision = engine.evaluate(resource, &params, &context);

        let at = |field: &str| format!("policy {name:?} request {resource:?} {field}");
        report.check(
            &at("resource"),
            decision.resource(),
            expected["resource"].as_str().unwrap_or_default(),
        );
        report.check(
            &at("action"),
            decision.action.as_str(),
            expected["action"].as_str().unwrap_or_default(),
        );
        report.check(
            &at("reason"),
            decision.reason.as_str(),
            expected["reason"].as_str().unwrap_or_default(),
        );
        report.check(
            &at("rule"),
            decision.rule.clone(),
            expected["rule"].as_str().map(str::to_string),
        );
        report.check(
            &at("mode"),
            decision.mode.as_str(),
            expected["mode"].as_str().unwrap_or_default(),
        );
        report.check(
            &at("enforced"),
            decision.enforced,
            expected["enforced"].as_bool().unwrap_or_default(),
        );
        report.check(
            &at("blocked"),
            decision.blocked(),
            expected["blocked"].as_bool().unwrap_or_default(),
        );
    }
}

fn fields(value: Option<&Value>) -> Fields {
    match value {
        Some(Value::Map(map)) => map.clone(),
        _ => Fields::new(),
    }
}

fn strings(value: &Json) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The same truncation `scripts/record_differential.py` applies: an invalid
/// pattern must be a load error in both engines and must name the same field,
/// but the wording past that point belongs to `re` or to `fancy-regex`.
fn normalize_error(message: &str) -> String {
    const MARKER: &str = "invalid regex";
    match message.find(MARKER) {
        Some(index) => format!(
            "{}{MARKER} <engine-specific detail elided>",
            &message[..index]
        ),
        None => message.to_string(),
    }
}
