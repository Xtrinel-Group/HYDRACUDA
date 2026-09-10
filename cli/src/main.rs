//! `hcuda` — offline policy checks, with no Python and no network.
//!
//! Three commands, all read-only: `validate`, `plan`, `test`. Nothing here
//! executes a tool, writes an audit record, reads the clock, or opens a socket.
//! The policy file is the only input, which is what makes any of them safe to run
//! in CI on every commit and what makes their output reproducible.
//!
//! This binary contains one engine, the Rust one. Everything about engine
//! selection below exists so that fact is stated rather than discovered: a
//! consumer who pinned `HYDRACUDA_ENGINE=python` for reproducibility and then ran
//! this binary would otherwise get Rust decisions labelled nothing at all.

mod args;
mod report;

use args::{Command, Parsed};

/// Exit status for a command line that could not be parsed.
///
/// 2, matching `argparse` in the Python CLI, so a wrapper script that tells a
/// typo from a policy failure keeps working across both.
const USAGE_EXIT: i32 = 2;

/// The environment variable `hydracuda._backend` reads. Honoured here to the
/// extent it can be: `rust` is what this binary is, and `python` is refused
/// loudly rather than ignored.
const ENGINE_ENV_VAR: &str = "HYDRACUDA_ENGINE";

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let parsed = match args::parse(&argv) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("hcuda: {message}\n\nRun `hcuda --help` for usage.");
            std::process::exit(USAGE_EXIT);
        }
    };

    let arguments = match parsed {
        Parsed::Help => {
            print!("{}", args::HELP);
            std::process::exit(0);
        }
        Parsed::Version => {
            println!("hcuda {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Parsed::Run(arguments) => arguments,
    };

    // The flag beats the variable, the same precedence the Python CLI uses, so a
    // `HYDRACUDA_ENGINE` left in a shell profile does not override what was typed.
    let requested = arguments
        .engine
        .clone()
        .map(|value| ("--engine", value))
        .or_else(|| {
            std::env::var(ENGINE_ENV_VAR)
                .ok()
                .map(|value| (ENGINE_ENV_VAR, value))
        });

    if let Some((source, value)) = requested {
        if let Err(message) = check_engine(source, &value) {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }

    let output = match arguments.command {
        Command::Validate { strict } => report::validate(&arguments.policy_file, strict),
        Command::Plan { reasons } => report::plan_command(&arguments.policy_file, reasons),
        Command::Test => report::test_command(&arguments.policy_file),
    };

    print!("{}", output.text);
    std::process::exit(output.status);
}

/// Whether a requested engine is the one this binary has.
///
/// `python` is an error rather than a warning-and-continue. The point of pinning
/// an engine is that the decisions came from the one you named; producing Rust
/// decisions under a `python` pin would answer a question nobody asked. The
/// message names the command that does have the pure-Python engine, because
/// explaining why a request cannot be honoured without saying what to run instead
/// leaves the reader exactly where they started.
fn check_engine(source: &str, value: &str) -> Result<(), String> {
    let setting = if source == "--engine" {
        format!("--engine {value}")
    } else {
        format!("{source}={value}")
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "rust" => Ok(()),
        "python" => Err(format!(
            "{setting}, but this is the compiled binary and it\n\
             contains only the Rust engine. Run `python -m hydracuda test` for\n\
             the pure-Python engine, or set {ENGINE_ENV_VAR}=rust."
        )),
        "" => Err(format!(
            "{setting} is empty; use 'rust', or unset it — this binary contains \
             only the Rust engine."
        )),
        _ => Err(format!(
            "{setting} is not an engine; use 'rust'. This binary contains only \
             the Rust engine, so 'python' is an error here and every other value \
             is a typo."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_is_the_engine_this_binary_has() {
        assert!(check_engine("--engine", "rust").is_ok());
        assert!(check_engine(ENGINE_ENV_VAR, "RUST").is_ok());
        assert!(check_engine(ENGINE_ENV_VAR, " rust ").is_ok());
    }

    #[test]
    fn the_python_pin_names_the_command_that_can_honour_it() {
        // The whole requirement: not merely an explanation of why this binary
        // cannot comply, but the command that can.
        let message = check_engine(ENGINE_ENV_VAR, "python").unwrap_err();
        assert!(
            message.contains("HYDRACUDA_ENGINE=python, but this is the compiled binary"),
            "{message}"
        );
        assert!(message.contains("python -m hydracuda test"), "{message}");
        assert!(message.contains("HYDRACUDA_ENGINE=rust"), "{message}");
    }

    #[test]
    fn the_flag_form_reports_itself_as_the_flag() {
        // Reporting `HYDRACUDA_ENGINE=python` when the user typed `--engine
        // python` would send them looking for a variable they never set.
        let message = check_engine("--engine", "python").unwrap_err();
        assert!(
            message.starts_with("--engine python, but this is"),
            "{message}"
        );
    }

    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        assert!(check_engine("--engine", "rustt")
            .unwrap_err()
            .contains("not an engine"));
        assert!(check_engine(ENGINE_ENV_VAR, "")
            .unwrap_err()
            .contains("is empty"));
    }
}
