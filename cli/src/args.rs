//! Command line parsing for `hcuda`.
//!
//! Hand-written rather than delegated to a crate, for the reasons in
//! `Cargo.toml`. The flags mirror `src/hydracuda/cli.py` exactly, because the two
//! commands are meant to be interchangeable — `hcuda plan --reasons` and
//! `hydracuda plan --reasons` differing in spelling would be a worse defect than
//! either one lacking the flag.

/// The default policy file, the same name the Python CLI uses.
pub const DEFAULT_POLICY_FILE: &str = "hydracuda.yaml";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Validate { strict: bool },
    Plan { reasons: bool },
    Test,
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Validate { .. } => "validate",
            Command::Plan { .. } => "plan",
            Command::Test => "test",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub command: Command,
    pub policy_file: String,
    /// `--engine`, unresolved. Checked in `main` rather than here, because "this
    /// binary contains only the Rust engine" is a fact about the build and not
    /// about the syntax of the command line.
    pub engine: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Run(Args),
    Help,
    Version,
}

pub const HELP: &str = "\
hcuda - offline policy checks for HYDRACUDA policy files.

Usage:
  hcuda validate [POLICY] [--strict]
  hcuda plan     [POLICY] [--reasons]
  hcuda test     [POLICY]
  hcuda --help | --version

Commands:
  validate  Check a policy for schema errors, conflicting and unreachable rules,
            and unpinned trust assumptions.
  plan      Print the decision for every declared resource, without executing
            anything.
  test      Run the policy's `tests:` block: the requests the author says it
            should allow and refuse.

Arguments:
  POLICY    Path to the policy YAML file (default: hydracuda.yaml)

Options:
  --strict           validate: exit non-zero on warnings as well as errors.
  --reasons          plan: print the reason attached to each decision.
  --engine ENGINE    Which engine decides. This binary contains only `rust`;
                     `python` is an error naming the command that has it.
  -h, --help         Print this help.
  -V, --version      Print the version.

Exit codes:
  0  the policy is valid / every case passed
  1  the policy has an error, or a case failed
  2  the command line could not be parsed

Nothing here executes a tool, writes an audit record, reads the clock, or makes
a network call. The policy file is the only input.
";

/// Parse `argv` without the program name.
pub fn parse<I, S>(argv: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let argv: Vec<String> = argv.into_iter().map(|a| a.as_ref().to_string()).collect();

    let mut command: Option<String> = None;
    let mut policy_file: Option<String> = None;
    let mut engine: Option<String> = None;
    let mut strict = false;
    let mut reasons = false;
    let mut compare_engines = false;

    let mut index = 0;
    while index < argv.len() {
        let argument = argv[index].as_str();
        index += 1;

        match argument {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--strict" => strict = true,
            "--reasons" => reasons = true,
            "--compare-engines" => compare_engines = true,
            _ if argument.starts_with("--engine=") => {
                engine = Some(argument["--engine=".len()..].to_string());
            }
            "--engine" => {
                engine = Some(
                    argv.get(index)
                        .ok_or_else(|| "--engine needs a value: 'rust' or 'python'".to_string())?
                        .clone(),
                );
                index += 1;
            }
            // Not silently ignored, and not treated as a policy path either: an
            // unknown flag is usually a misspelling, and running as if it had
            // never been typed is how a `--strict` that reads `--stict` stops
            // being strict without saying so.
            _ if argument.starts_with('-') => {
                return Err(format!("unrecognized option '{argument}'"))
            }
            _ if command.is_none() => command = Some(argument.to_string()),
            _ if policy_file.is_none() => policy_file = Some(argument.to_string()),
            _ => return Err(format!("unexpected argument '{argument}'")),
        }
    }

    if compare_engines {
        // Refused rather than accepted-and-ignored. This binary has one engine,
        // so there is no comparison it could run, and a flag that appears to have
        // been honoured would report agreement it never checked.
        return Err(
            "--compare-engines runs both engines, and this binary contains only the \
             Rust engine. Run `python -m hydracuda test --compare-engines`, which \
             has both."
                .to_string(),
        );
    }

    let command = match command.as_deref() {
        None => return Ok(Parsed::Help),
        Some("validate") => Command::Validate { strict },
        Some("plan") => Command::Plan { reasons },
        Some("test") => Command::Test,
        Some("init") => {
            return Err(
                "`init` writes a starter policy and is only in the Python package. \
                 Run `hydracuda init`."
                    .to_string(),
            )
        }
        Some("check") => {
            return Err("`check` is a deprecated alias the Python CLI keeps for \
                 compatibility; this binary never had it. Use `hcuda validate`."
                .to_string())
        }
        Some(other) => {
            return Err(format!(
                "unknown command '{other}' — expected 'validate', 'plan' or 'test'"
            ))
        }
    };

    // Flag/command mismatches are errors for the same reason an unknown flag is:
    // `hcuda plan --strict` accepted-and-ignored looks like it asked for
    // something.
    if strict && !matches!(command, Command::Validate { .. }) {
        return Err(format!(
            "--strict is a `validate` option, not `{}`",
            command.name()
        ));
    }
    if reasons && !matches!(command, Command::Plan { .. }) {
        return Err(format!(
            "--reasons is a `plan` option, not `{}`",
            command.name()
        ));
    }

    Ok(Parsed::Run(Args {
        command,
        policy_file: policy_file.unwrap_or_else(|| DEFAULT_POLICY_FILE.to_string()),
        engine,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Args {
        match parse(argv).unwrap() {
            Parsed::Run(args) => args,
            other => panic!("expected a command, got {other:?}"),
        }
    }

    fn error(argv: &[&str]) -> String {
        parse(argv).unwrap_err()
    }

    #[test]
    fn a_command_defaults_to_the_conventional_policy_file() {
        let args = args(&["validate"]);
        assert_eq!(args.command, Command::Validate { strict: false });
        assert_eq!(args.policy_file, DEFAULT_POLICY_FILE);
        assert_eq!(args.engine, None);
    }

    #[test]
    fn a_policy_path_is_positional() {
        assert_eq!(args(&["plan", "other.yaml"]).policy_file, "other.yaml");
    }

    #[test]
    fn flags_may_come_before_the_path() {
        // `hcuda validate --strict p.yaml` and `hcuda validate p.yaml --strict`
        // are the same command; a parser that only accepted one order would make
        // muscle memory from the Python CLI fail here.
        for argv in [
            ["validate", "--strict", "p.yaml"],
            ["validate", "p.yaml", "--strict"],
        ] {
            let args = args(&argv);
            assert_eq!(args.command, Command::Validate { strict: true });
            assert_eq!(args.policy_file, "p.yaml");
        }
    }

    #[test]
    fn engine_takes_either_spelling() {
        assert_eq!(
            args(&["test", "--engine", "rust"]).engine.as_deref(),
            Some("rust")
        );
        assert_eq!(
            args(&["test", "--engine=python"]).engine.as_deref(),
            Some("python")
        );
        assert!(error(&["test", "--engine"]).contains("needs a value"));
    }

    #[test]
    fn no_command_prints_help_rather_than_guessing() {
        assert_eq!(parse::<[&str; 0], &str>([]).unwrap(), Parsed::Help);
    }

    #[test]
    fn help_and_version_win_over_everything_else() {
        assert_eq!(parse(["validate", "--help"]).unwrap(), Parsed::Help);
        assert_eq!(parse(["nonsense", "-V"]).unwrap(), Parsed::Version);
    }

    #[test]
    fn a_misspelled_flag_is_refused_not_ignored() {
        // The failure mode this prevents: `--stict` parsed as a path, the policy
        // read from `hydracuda.yaml` anyway, and warnings quietly not fatal.
        let message = error(&["validate", "--stict"]);
        assert!(
            message.contains("unrecognized option '--stict'"),
            "{message}"
        );
    }

    #[test]
    fn a_flag_belonging_to_another_command_is_refused() {
        assert!(error(&["plan", "--strict"]).contains("`validate` option"));
        assert!(error(&["test", "--reasons"]).contains("`plan` option"));
    }

    #[test]
    fn compare_engines_names_the_command_that_has_both() {
        let message = error(&["test", "--compare-engines"]);
        assert!(
            message.contains("python -m hydracuda test --compare-engines"),
            "{message}"
        );
    }

    #[test]
    fn the_python_only_commands_say_where_they_live() {
        assert!(error(&["init"]).contains("hydracuda init"));
        assert!(error(&["check"]).contains("hcuda validate"));
        assert!(error(&["validat"]).contains("unknown command 'validat'"));
    }

    #[test]
    fn a_second_path_is_an_error_rather_than_the_last_one_winning() {
        assert!(error(&["plan", "a.yaml", "b.yaml"]).contains("unexpected argument 'b.yaml'"));
    }
}
