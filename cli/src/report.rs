//! What `validate`, `plan` and `test` print.
//!
//! The output is deliberately byte-identical to `src/hydracuda/cli.py`, apart
//! from the `Loader:` field and one note `validate` and `test` add about the
//! check this binary cannot perform. Two commands the specification calls
//! interchangeable should be diffable, and matching output is what makes a
//! disagreement between them visible instead of buried in formatting.

use std::fmt::Write as _;

use hydracuda_core::introspect::{analyze, plan};
use hydracuda_core::test_cases::run_tests;
use hydracuda_core::Policy;

/// Column width for the action in `plan` output. "REVIEW" is the longest.
const ACTION_WIDTH: usize = 6;

/// Column width for a test case's status.
///
/// 11, matching the Python CLI, even though "UNSUPPORTED" is the only status
/// that long and this binary never produces it. Narrowing the column would make
/// every line of `hcuda test` output differ from `hydracuda test` by whitespace.
const STATUS_WIDTH: usize = 11;

/// The check this binary structurally cannot perform.
///
/// Stated rather than skipped quietly. Building an adapter needs the type
/// registry, which lives in the Python package — `hydracuda-core` has the
/// `adapters:` declarations and no way to construct anything from them. A user
/// comparing a clean `hcuda validate` against a failing `hydracuda validate`
/// should be able to see why from the output of the first one.
const NO_REGISTRY_NOTE: &str = "\
note: this binary has no adapter registry, so it cannot check that a declared
  adapter can be built — `hydracuda validate` does that. Every other check runs.";

/// A rendered command: what to print, and the exit status.
pub struct Output {
    pub text: String,
    pub status: i32,
}

fn header(policy_file: &str) -> String {
    // Two fields rather than one, and `rust` in both: this binary loads the
    // policy with the Rust loader as well as deciding with the Rust engine, which
    // is the difference from `hydracuda`, where the loader is always Python.
    format!("Engine: rust    Loader: rust\nPolicy: {policy_file}\n")
}

fn describe(policy: &Policy) -> String {
    let mut parts = vec![
        format!("Version {}", policy.version),
        format!("mode {}", policy.mode.as_str()),
        format!("default {}", policy.default_action.as_str()),
        format!("{} rule(s)", policy.rules.len()),
    ];
    if !policy.adapters.is_empty() {
        parts.push(format!("{} adapter(s)", policy.adapters.len()));
    }
    parts.join(", ")
}

/// Load a policy, or render the schema error the way the Python CLI does.
fn load(policy_file: &str) -> Result<Policy, String> {
    Policy::from_path(policy_file).map_err(|error| format!("error: schema\n  {error}"))
}

pub fn validate(policy_file: &str, strict: bool) -> Output {
    let mut text = header(policy_file);
    let policy = match load(policy_file) {
        Ok(policy) => policy,
        Err(message) => {
            let _ = writeln!(text, "{message}\nPolicy is invalid.");
            return Output { text, status: 1 };
        }
    };

    let _ = writeln!(text, "{NO_REGISTRY_NOTE}");
    let _ = writeln!(text, "{}", describe(&policy));

    let report = analyze(&policy);
    for diagnostic in &report.diagnostics {
        let _ = writeln!(text, "\n{}", diagnostic.format());
    }

    let (errors, warnings) = (report.errors().len(), report.warnings().len());
    let _ = writeln!(text, "\n{errors} error(s), {warnings} warning(s)");

    if errors > 0 {
        let _ = writeln!(text, "Policy is invalid.");
        return Output { text, status: 1 };
    }
    if warnings > 0 && strict {
        let _ = writeln!(
            text,
            "Policy is valid, but --strict treats warnings as failures."
        );
        return Output { text, status: 1 };
    }

    let _ = writeln!(text, "Policy is valid.");
    Output { text, status: 0 }
}

pub fn plan_command(policy_file: &str, reasons: bool) -> Output {
    let mut text = header(policy_file);
    let policy = match load(policy_file) {
        Ok(policy) => policy,
        Err(message) => {
            let _ = writeln!(text, "{message}\nCannot plan: the policy did not load.");
            return Output { text, status: 1 };
        }
    };

    let _ = writeln!(text, "{}", describe(&policy));
    let entries = plan(&policy);

    text.push('\n');
    if entries.is_empty() {
        let _ = writeln!(
            text,
            "Declared surface: 0 resources. Add an `adapters` block naming the \
             resources this policy governs — `plan` walks that list."
        );
        return Output { text, status: 0 };
    }

    let _ = writeln!(
        text,
        "Declared surface: {} resource(s). Evaluated with no parameters and no \
         context.",
        entries.len()
    );
    text.push('\n');

    let width = entries
        .iter()
        .map(|entry| entry.resource.chars().count())
        .max()
        .unwrap_or(0);
    for entry in &entries {
        let rule = entry.rule.as_deref().unwrap_or("(default)");
        let action = entry.action.as_str().to_uppercase();
        let _ = write!(
            text,
            "  {action:<ACTION_WIDTH$}  {resource:<width$}  {rule}",
            resource = entry.resource,
        );
        if entry.conditional() {
            let _ = write!(
                text,
                "  [conditional: {}]",
                entry.conditional_rules.join(", ")
            );
        }
        text.push('\n');
        if reasons {
            let _ = writeln!(
                text,
                "  {blank:<ACTION_WIDTH$}  {blank:<width$}  {reason}",
                blank = "",
                reason = entry.reason,
            );
        }
    }

    text.push('\n');
    let counts: Vec<String> = ["allow", "deny", "review"]
        .iter()
        .map(|action| {
            let count = entries
                .iter()
                .filter(|entry| entry.action.as_str() == *action)
                .count();
            format!("{count} {action}")
        })
        .collect();
    let _ = writeln!(text, "{}", counts.join(", "));

    let conditional = entries.iter().filter(|entry| entry.conditional()).count();
    if conditional > 0 {
        let _ = writeln!(
            text,
            "{conditional} resource(s) have a conditional outcome: the action \
             above holds for a call with no parameters and no context, and the \
             listed rules can change it for a real call."
        );
    }

    Output { text, status: 0 }
}

pub fn test_command(policy_file: &str) -> Output {
    let mut text = header(policy_file);
    let policy = match load(policy_file) {
        Ok(policy) => policy,
        Err(message) => {
            let _ = writeln!(
                text,
                "{message}\nCannot run tests: the policy did not load."
            );
            return Output { text, status: 1 };
        }
    };

    let _ = writeln!(text, "{NO_REGISTRY_NOTE}");
    let _ = writeln!(text, "{}", describe(&policy));

    // Diagnostics before any case runs, and an error-level finding stops the run:
    // a duplicate case name makes the per-case report unreadable, and a wildcard
    // `resource` means the case does not stand for one request.
    let report = analyze(&policy);
    let errors = report.errors();
    if !errors.is_empty() {
        for diagnostic in &errors {
            let _ = writeln!(text, "\n{}", diagnostic.format());
        }
        let _ = writeln!(text, "\n{} error(s). No cases were run.", errors.len());
        return Output { text, status: 1 };
    }

    for diagnostic in report.warnings() {
        let _ = writeln!(text, "\n{}", diagnostic.format());
    }

    text.push('\n');
    if policy.tests.is_empty() {
        let _ = writeln!(
            text,
            "No test cases. Add a `tests:` block naming the requests this policy \
             is supposed to allow and refuse — validation catches a misspelled \
             key, not a correctly spelled rule in the wrong order."
        );
        return Output { text, status: 0 };
    }

    let results = run_tests(&policy);
    let width = results
        .iter()
        .map(|result| result.name.chars().count())
        .max()
        .unwrap_or(0);
    for result in &results {
        let status = result.outcome.status().to_uppercase();
        let _ = writeln!(
            text,
            "  {status:<STATUS_WIDTH$}  {name:<width$}  {resource}",
            name = result.name,
            resource = result.resource,
        );
        if !result.outcome.detail().is_empty() {
            let _ = writeln!(
                text,
                "  {blank:<STATUS_WIDTH$}  {detail}",
                blank = "",
                detail = result.outcome.detail(),
            );
        }
    }

    let passed = results.iter().filter(|result| result.passed()).count();
    let failed = results.len() - passed;
    let _ = writeln!(
        text,
        "\n{passed} passed, {failed} failed of {} case(s)",
        results.len()
    );

    Output {
        text,
        status: if failed == 0 { 0 } else { 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A policy file on disk, since every command here takes a path.
    struct Fixture {
        path: std::path::PathBuf,
    }

    impl Fixture {
        fn new(name: &str, source: &str) -> Fixture {
            let path =
                std::env::temp_dir().join(format!("hcuda-{}-{name}.yaml", std::process::id()));
            let mut file = std::fs::File::create(&path).expect("the fixture must be writable");
            file.write_all(source.as_bytes()).expect("write");
            Fixture { path }
        }

        fn path(&self) -> &str {
            self.path.to_str().expect("a UTF-8 temporary path")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    const SURFACE: &str = "version: 2\n\
        adapters:\n  - {name: local, type: local_tools, resources: [fs.read, fs.write]}\n";

    #[test]
    fn the_header_states_both_the_engine_and_the_loader() {
        let fixture = Fixture::new("header", "version: 2\nrules: []\n");
        let output = validate(fixture.path(), false);
        assert!(
            output
                .text
                .starts_with("Engine: rust    Loader: rust\nPolicy: "),
            "{}",
            output.text
        );
    }

    #[test]
    fn validate_states_the_check_it_cannot_run() {
        let fixture = Fixture::new("note", "version: 2\nrules: []\n");
        assert!(validate(fixture.path(), false)
            .text
            .contains("no adapter registry"));
        assert!(test_command(fixture.path())
            .text
            .contains("no adapter registry"));
        // Not on `plan`, which does not build adapters in either implementation.
        assert!(!plan_command(fixture.path(), false)
            .text
            .contains("no adapter registry"));
    }

    #[test]
    fn a_missing_file_is_a_policy_error_not_a_panic() {
        let output = validate("/nonexistent/hydracuda.yaml", false);
        assert_eq!(output.status, 1);
        assert!(
            output.text.contains("Policy file not found"),
            "{}",
            output.text
        );
        assert!(
            output.text.ends_with("Policy is invalid.\n"),
            "{}",
            output.text
        );
    }

    #[test]
    fn strict_turns_a_warning_into_a_failure() {
        let fixture = Fixture::new("strict", "version: 2\nrules: []\n");
        assert_eq!(validate(fixture.path(), false).status, 0);
        let strict = validate(fixture.path(), true);
        assert_eq!(strict.status, 1);
        assert!(strict.text.contains("--strict treats warnings as failures"));
    }

    #[test]
    fn plan_walks_the_declared_surface() {
        let fixture = Fixture::new(
            "plan",
            &format!("{SURFACE}rules:\n  - {{name: reads, resource: fs.read, action: allow}}\n"),
        );
        let output = plan_command(fixture.path(), false);
        assert_eq!(output.status, 0);
        assert!(
            output.text.contains("Declared surface: 2 resource(s)"),
            "{}",
            output.text
        );
        assert!(
            output.text.contains("  ALLOW   fs.read   reads"),
            "{}",
            output.text
        );
        assert!(
            output.text.contains("1 allow, 1 deny, 0 review"),
            "{}",
            output.text
        );
    }

    #[test]
    fn plan_names_the_rules_that_could_change_a_decision() {
        let fixture = Fixture::new(
            "conditional",
            &format!(
                "{SURFACE}rules:\n  - {{name: gated, resource: fs.read, action: deny, \
                 when: {{trust: {{equals: low}}}}}}\n"
            ),
        );
        let output = plan_command(fixture.path(), true);
        assert!(
            output.text.contains("[conditional: gated]"),
            "{}",
            output.text
        );
        assert!(
            output
                .text
                .contains("resource(s) have a conditional outcome"),
            "{}",
            output.text
        );
    }

    #[test]
    fn an_empty_surface_says_what_to_add() {
        let fixture = Fixture::new("empty-surface", "version: 2\nrules: []\n");
        let output = plan_command(fixture.path(), false);
        assert_eq!(output.status, 0);
        assert!(
            output.text.contains("Declared surface: 0 resources"),
            "{}",
            output.text
        );
    }

    #[test]
    fn test_reports_each_case_and_counts_them() {
        let fixture = Fixture::new(
            "cases",
            &format!(
                "{SURFACE}rules:\n  - {{name: reads, resource: fs.read, action: allow}}\n\
                 tests:\n  \
                 - {{name: allowed, resource: fs.read, expect: allow}}\n  \
                 - {{name: wrong, resource: fs.write, expect: allow}}\n"
            ),
        );
        let output = test_command(fixture.path());
        assert_eq!(output.status, 1);
        assert!(
            output.text.contains("  PASS         allowed  fs.read"),
            "{}",
            output.text
        );
        assert!(
            output
                .text
                .contains("expected allow, got deny from (default)"),
            "{}",
            output.text
        );
        assert!(
            output.text.contains("1 passed, 1 failed of 2 case(s)"),
            "{}",
            output.text
        );
    }

    #[test]
    fn an_error_level_diagnostic_stops_the_run_before_any_case() {
        // Two cases share a name, which makes per-case output unreadable. The
        // count has to say nothing ran, not report a pass alongside the error.
        let fixture = Fixture::new(
            "duplicate",
            &format!(
                "{SURFACE}rules:\n  - {{name: reads, resource: fs.read, action: allow}}\n\
                 tests:\n  \
                 - {{name: same, resource: fs.read, expect: allow}}\n  \
                 - {{name: same, resource: fs.read, expect: allow}}\n"
            ),
        );
        let output = test_command(fixture.path());
        assert_eq!(output.status, 1);
        assert!(
            output.text.contains("test-duplicate-name"),
            "{}",
            output.text
        );
        assert!(
            output.text.contains("1 error(s). No cases were run."),
            "{}",
            output.text
        );
        assert!(!output.text.contains("PASS"), "{}", output.text);
    }

    #[test]
    fn a_policy_with_no_cases_is_not_a_failure() {
        let fixture = Fixture::new(
            "no-cases",
            &format!("{SURFACE}rules:\n  - {{name: reads, resource: fs.read, action: allow}}\n"),
        );
        let output = test_command(fixture.path());
        assert_eq!(output.status, 0);
        assert!(output.text.contains("No test cases."), "{}", output.text);
    }

    #[test]
    fn the_status_column_is_wide_enough_for_a_word_this_binary_never_prints() {
        // `unsupported` is a Python-only outcome, and the column is sized for it
        // anyway so the two commands' output differs by content and not by
        // whitespace. If this ever shrinks, every `diff` between them fills with
        // noise.
        assert_eq!(STATUS_WIDTH, "unsupported".len());
    }
}
