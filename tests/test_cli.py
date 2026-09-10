"""Tests for the CLI: `init`, `validate`, `plan`, and the `check` alias.

`validate` and `plan` are read-only introspection, so alongside the output
these check that neither command writes anything — no audit database, no
rewritten policy file.
"""

import pytest

from hydracuda import cli


def run(monkeypatch, *argv) -> int:
    """Invoke main() as the installed entry point does, returning its exit code."""
    monkeypatch.setattr("sys.argv", ["hydracuda", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return exit_info.value.code


@pytest.fixture
def policy_file(tmp_path):
    """A clean v2 policy whose audit path points somewhere checkable."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        f"""
version: 2
default_action: deny
audit_path: {tmp_path / "audit.db"}
adapters:
  - name: local
    type: local_tools
    resources: [read_file, delete_record, execute_shell]
rules:
  - name: block-sensitive-paths
    resource: read_file
    action: deny
    where:
      path:
        matches: ["/etc/"]
  - name: allow-file-reads
    resource: read_file
    action: allow
  - name: block-deletes
    resource: delete_record
    action: deny
    reason: "Destructive operation."
  - name: shell-requires-approval
    resource: execute_shell
    action: review
"""
    )
    return path


# --- validate ------------------------------------------------------------


def test_validate_passes_a_clean_policy(monkeypatch, capsys, policy_file):
    assert run(monkeypatch, "validate", str(policy_file)) == 0
    out = capsys.readouterr().out
    assert "Policy is valid." in out
    assert "0 error(s), 0 warning(s)" in out


def test_validate_summarizes_the_policy(monkeypatch, capsys, policy_file):
    run(monkeypatch, "validate", str(policy_file))
    out = capsys.readouterr().out
    assert "Version 2" in out
    assert "mode enforce" in out
    assert "default deny" in out
    assert "4 rule(s)" in out
    assert "1 adapter(s)" in out


def test_validate_warns_about_unpinned_when_fields(monkeypatch, capsys, tmp_path):
    """The warning must reach the user, not just exist as a queryable method.

    A rule gating on unpinned context is only as trustworthy as the calling
    code, and a policy author cannot act on that unless the tool says so.
    """
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
version: 2
default_action: deny
rules:
  - name: untrusted-agents-cannot-write
    resource: fs.write
    action: deny
    when:
      trust:
        equals: untrusted
"""
    )

    assert run(monkeypatch, "validate", str(path)) == 0
    out = capsys.readouterr().out
    assert "unpinned-when-field" in out
    assert "untrusted-agents-cannot-write" in out
    assert "pinned_context" in out


def test_validate_reports_schema_errors_and_fails(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 2\ndefaultaction: deny\n")

    assert run(monkeypatch, "validate", str(path)) == 1
    out = capsys.readouterr().out
    assert "error: schema" in out
    assert "did you mean 'default_action'" in out
    assert "Policy is invalid." in out


def test_validate_reports_a_missing_file_without_a_traceback(
    monkeypatch, capsys, tmp_path
):
    assert run(monkeypatch, "validate", str(tmp_path / "nope.yaml")) == 1
    assert "not found" in capsys.readouterr().out


def test_validate_fails_on_an_unbuildable_adapter(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 2\ndefault_action: deny\nadapters:\n"
        "  - name: fs\n    type: mystery\n"
    )

    assert run(monkeypatch, "validate", str(path)) == 1
    out = capsys.readouterr().out
    assert "adapter-unbuildable" in out
    assert "Policy is invalid." in out


def test_validate_exits_zero_on_warnings_by_default(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 2\nmode: shadow\ndefault_action: deny\n")

    assert run(monkeypatch, "validate", str(path)) == 0
    assert "Policy is valid." in capsys.readouterr().out


def test_strict_turns_warnings_into_a_failure(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 2\nmode: shadow\ndefault_action: deny\n")

    assert run(monkeypatch, "validate", str(path), "--strict") == 1
    assert "--strict treats warnings as failures" in capsys.readouterr().out


def test_validate_accepts_the_v1_examples(monkeypatch, capsys, examples_dir):
    assert run(monkeypatch, "validate", str(examples_dir / "policy-v1-legacy.yaml")) == 0
    assert "Policy is valid." in capsys.readouterr().out


def test_validate_defaults_to_hydracuda_yaml(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hydracuda.yaml").write_text("version: 2\ndefault_action: deny\n")

    assert run(monkeypatch, "validate") == 0
    assert "Policy: hydracuda.yaml" in capsys.readouterr().out


# --- plan ----------------------------------------------------------------


def test_plan_prints_a_decision_per_declared_resource(
    monkeypatch, capsys, policy_file
):
    assert run(monkeypatch, "plan", str(policy_file)) == 0
    out = capsys.readouterr().out

    assert "Declared surface: 3 resource(s)" in out
    assert "ALLOW   read_file" in out
    assert "DENY    delete_record" in out
    assert "REVIEW  execute_shell" in out
    assert "1 allow, 1 deny, 1 review" in out


def test_plan_names_the_deciding_rule(monkeypatch, capsys, policy_file):
    run(monkeypatch, "plan", str(policy_file))
    assert "block-deletes" in capsys.readouterr().out


def test_plan_flags_conditional_outcomes(monkeypatch, capsys, policy_file):
    run(monkeypatch, "plan", str(policy_file))
    out = capsys.readouterr().out
    assert "[conditional: block-sensitive-paths]" in out
    assert "conditional outcome" in out


def test_plan_states_the_inputs_it_used(monkeypatch, capsys, policy_file):
    # Without this the output looks like a full answer rather than the answer
    # for a call carrying no parameters.
    run(monkeypatch, "plan", str(policy_file))
    assert "no parameters and no context" in capsys.readouterr().out


def test_plan_reasons_flag_prints_the_reason(monkeypatch, capsys, policy_file):
    run(monkeypatch, "plan", str(policy_file), "--reasons")
    assert "Destructive operation." in capsys.readouterr().out


def test_plan_without_reasons_flag_omits_them(monkeypatch, capsys, policy_file):
    run(monkeypatch, "plan", str(policy_file))
    assert "Destructive operation." not in capsys.readouterr().out


def test_plan_explains_an_empty_surface(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 2\ndefault_action: deny\n")

    assert run(monkeypatch, "plan", str(path)) == 0
    assert "Declared surface: 0 resources" in capsys.readouterr().out


def test_plan_fails_on_an_unloadable_policy(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 3\n")

    assert run(monkeypatch, "plan", str(path)) == 1
    assert "Cannot plan" in capsys.readouterr().out


def test_plan_handles_the_advanced_example(monkeypatch, capsys, examples_dir):
    assert run(monkeypatch, "plan", str(examples_dir / "policy-advanced.yaml")) == 0
    out = capsys.readouterr().out
    assert "filesystem.read_file" in out
    assert "github.issue.comment" in out


# --- test ----------------------------------------------------------------


@pytest.fixture
def tested_policy(tmp_path):
    """A policy with a `tests:` block covering a pass, a failure and a refusal."""
    path = tmp_path / "tested.yaml"
    path.write_text(
        """
version: 2
adapters:
  - name: local
    type: local_tools
    resources: [read_file, delete_record]
rules:
  - name: block-etc
    resource: read_file
    action: deny
    where:
      path: {matches: ['^/etc/']}
  - name: allow-reads
    resource: read_file
    action: allow
tests:
  - name: etc-is-denied
    resource: read_file
    params: {path: /etc/passwd}
    expect: deny
    expect_rule: block-etc
  - name: other-reads-are-allowed
    resource: read_file
    params: {path: /srv/notes.md}
    expect: allow
  - name: undeclared-is-refused
    resource: chmod
    expect: refused
"""
    )
    return path


def test_test_reports_every_case_and_a_count(monkeypatch, capsys, tested_policy):
    assert run(monkeypatch, "test", str(tested_policy)) == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "etc-is-denied" in out
    assert "3 passed, 0 failed of 3 case(s)" in out


def test_test_fails_naming_the_decision_that_was_produced(
    monkeypatch, capsys, tested_policy
):
    tested_policy.write_text(
        tested_policy.read_text().replace(
            "expect_rule: block-etc", "expect_rule: allow-reads"
        )
    )

    assert run(monkeypatch, "test", str(tested_policy)) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "expected deny from 'allow-reads', got deny from 'block-etc'" in out
    assert "2 passed, 1 failed of 3 case(s)" in out


def test_test_stops_on_an_error_level_diagnostic(monkeypatch, capsys, tested_policy):
    """A duplicate name makes per-case output unreadable, so nothing runs."""
    tested_policy.write_text(
        tested_policy.read_text().replace(
            "name: other-reads-are-allowed", "name: etc-is-denied"
        )
    )

    assert run(monkeypatch, "test", str(tested_policy)) == 1
    out = capsys.readouterr().out
    assert "test-duplicate-name" in out
    assert "1 error(s). No cases were run." in out
    assert "PASS" not in out


def test_test_says_what_to_add_when_there_are_no_cases(
    monkeypatch, capsys, policy_file
):
    assert run(monkeypatch, "test", str(policy_file)) == 0
    assert "No test cases." in capsys.readouterr().out


def test_test_reports_an_unbuildable_adapter_as_unsupported(
    monkeypatch, capsys, tmp_path
):
    """A case nobody ran is not a case that succeeded.

    This is the one thing the Python CLI can do that `hcuda` cannot: building an
    adapter needs the type registry, which only this package has.
    """
    path = tmp_path / "unbuildable.yaml"
    path.write_text(
        """
version: 2
adapters:
  - {name: local, type: local_tools, resources: [read_file], config: {roto: /tmp}}
rules:
  - {name: reads, resource: read_file, action: allow}
tests:
  - {name: reads-are-allowed, resource: read_file, expect: allow}
"""
    )

    # `validate`-level errors stop the run first, which is the path a user hits.
    assert run(monkeypatch, "test", str(path)) == 1
    out = capsys.readouterr().out
    assert "adapter-unbuildable" in out
    assert "No cases were run." in out

    # Reached only by a direct caller of `run_tests`, and reported rather than
    # silently passed.
    from hydracuda.introspect import UNSUPPORTED, run_tests
    from hydracuda.policy import load_policy

    results = run_tests(load_policy(str(path)))
    assert [result.status for result in results] == [UNSUPPORTED]
    assert not results[0].passed


def test_test_writes_nothing(monkeypatch, tmp_path, tested_policy):
    before = tested_policy.read_text()
    run(monkeypatch, "test", str(tested_policy))

    assert tested_policy.read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tested.yaml"]


# --- engine selection ----------------------------------------------------


def test_every_introspection_command_states_the_engine(
    monkeypatch, capsys, tested_policy
):
    for command in ("validate", "plan", "test"):
        run(monkeypatch, command, str(tested_policy))
        out = capsys.readouterr().out
        assert "Engine: " in out, command
        assert "Loader: python" in out, command


def test_the_engine_flag_beats_the_environment_variable(
    monkeypatch, capsys, tested_policy
):
    monkeypatch.setenv("HYDRACUDA_ENGINE", "rust")
    assert run(monkeypatch, "validate", str(tested_policy), "--engine", "python") == 0
    assert "Engine: python" in capsys.readouterr().out


def test_an_unusable_engine_pin_is_an_error_not_a_fallback(
    monkeypatch, capsys, tested_policy
):
    """A pin that cannot be honoured must fail rather than quietly use the other.

    Silently falling back would mean a reproducibility run measured whichever
    engine happened to be built, which is the failure the pin exists to prevent.
    """
    monkeypatch.setenv("HYDRACUDA_ENGINE", "haskell")
    assert run(monkeypatch, "validate", str(tested_policy)) == 1
    assert "error: engine" in capsys.readouterr().out


def test_only_one_engine_runs_by_default(monkeypatch, capsys, tested_policy):
    """The output names one engine, and it is the one that was asked for."""
    monkeypatch.setenv("HYDRACUDA_ENGINE", "python")
    run(monkeypatch, "test", str(tested_policy))
    out = capsys.readouterr().out
    assert "Engine: python" in out
    assert "Engine: rust" not in out
    assert "Both engines agree" not in out


def test_compare_engines_reports_agreement(monkeypatch, capsys, tested_policy):
    if not cli.rust_available():
        pytest.skip("the compiled engine is not built in this environment")

    assert run(monkeypatch, "test", str(tested_policy), "--compare-engines") == 0
    out = capsys.readouterr().out
    assert "Both engines agree (exit 0)." in out


def test_compare_engines_keeps_the_policy_exit_status_when_they_agree(
    monkeypatch, capsys, tested_policy
):
    """Agreement is not success: a failing case still exits 1."""
    if not cli.rust_available():
        pytest.skip("the compiled engine is not built in this environment")

    tested_policy.write_text(
        tested_policy.read_text().replace("expect: allow", "expect: review")
    )

    assert run(monkeypatch, "test", str(tested_policy), "--compare-engines") == 1
    assert "Both engines agree (exit 1)." in capsys.readouterr().out


def test_compare_engines_needs_both_engines(monkeypatch, capsys, tested_policy):
    monkeypatch.setattr(cli, "rust_available", lambda: False)

    assert run(monkeypatch, "validate", str(tested_policy), "--compare-engines") == 1
    assert "there is only one to run" in capsys.readouterr().out


def test_a_divergence_exits_distinctly_from_a_policy_failure(
    monkeypatch, capsys, tested_policy
):
    """The exit code has to tell "your policy is wrong" from "we are broken".

    Forced rather than found, because a real divergence is a bug the differential
    corpus is there to prevent — but the reporting path still has to work the day
    one appears.
    """
    monkeypatch.setattr(cli, "rust_available", lambda: True)
    outputs = iter(["Engine: python\nsame\ndiffers-python\n", "Engine: rust\nsame\ndiffers-rust\n"])

    def fake_command(args):
        print(next(outputs), end="")
        return 0

    assert cli._compare_engines(fake_command, object()) == cli.ENGINE_DIVERGENCE_EXIT
    out = capsys.readouterr().out
    assert "The engines disagree." in out
    assert "-differs-python" in out
    assert "+differs-rust" in out
    # The header names the engine, so it differs by construction and must not be
    # what the diff reports.
    assert "-Engine: python" not in out


def test_a_differing_exit_status_is_a_divergence_too(monkeypatch, capsys):
    monkeypatch.setattr(cli, "rust_available", lambda: True)
    statuses = iter([0, 1])

    def fake_command(args):
        print("identical output")
        return next(statuses)

    assert cli._compare_engines(fake_command, object()) == cli.ENGINE_DIVERGENCE_EXIT
    assert "exit status: python 0, rust 1" in capsys.readouterr().out


def test_init_needs_no_engine(monkeypatch, capsys, tmp_path):
    """`init` evaluates nothing, so an unusable pin must not block it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HYDRACUDA_ENGINE", "haskell")

    assert run(monkeypatch, "init") == 0
    assert (tmp_path / "hydracuda.yaml").exists()
    capsys.readouterr()


# --- read-only -----------------------------------------------------------


def test_validate_writes_nothing(monkeypatch, tmp_path, policy_file):
    before = policy_file.read_text()
    run(monkeypatch, "validate", str(policy_file))

    assert not (tmp_path / "audit.db").exists()
    assert policy_file.read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["policy.yaml"]


def test_plan_writes_nothing(monkeypatch, tmp_path, policy_file):
    before = policy_file.read_text()
    run(monkeypatch, "plan", str(policy_file))

    assert not (tmp_path / "audit.db").exists()
    assert policy_file.read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["policy.yaml"]


def test_plan_executes_no_handler(monkeypatch, capsys, tmp_path):
    """`plan` decides; it must not call anything.

    The adapter built from a policy file has no handlers at all, which is what
    makes this structurally true rather than merely tested.
    """
    from hydracuda.adapters.registry import build_adapter
    from hydracuda.policy import AdapterSpec

    adapter = build_adapter(
        AdapterSpec(name="local", type="local_tools", resources=["read_file"])
    )
    assert adapter.resources() == ["read_file"]
    assert adapter._handlers == {}


# --- check alias ---------------------------------------------------------


def test_check_still_works_and_says_it_is_deprecated(
    monkeypatch, capsys, policy_file
):
    assert run(monkeypatch, "check", str(policy_file)) == 0
    out = capsys.readouterr().out
    assert "deprecated alias" in out
    assert "Policy is valid." in out


def test_check_handles_a_v2_policy(monkeypatch, capsys, policy_file):
    """Regression: `check` read `len(policy.tools)`, which is None under v2.

    The v0.2.0 implementation raised TypeError on any version 2 policy.
    """
    assert run(monkeypatch, "check", str(policy_file)) == 0


def test_check_fails_on_an_invalid_policy(monkeypatch, capsys, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 9\n")
    assert run(monkeypatch, "check", str(path)) == 1


# --- init ----------------------------------------------------------------


def test_init_writes_a_starter_policy_that_validates(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)

    assert run(monkeypatch, "init") == 0
    assert (tmp_path / "hydracuda.yaml").exists()
    capsys.readouterr()

    # The file `init` writes must pass the tool's own validation.
    assert run(monkeypatch, "validate") == 0
    assert "Policy is valid." in capsys.readouterr().out


def test_init_does_not_overwrite(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hydracuda.yaml").write_text("version: 2\n")

    assert run(monkeypatch, "init") == 0
    assert (tmp_path / "hydracuda.yaml").read_text() == "version: 2\n"
    assert "Not overwriting" in capsys.readouterr().out


# --- argument handling ---------------------------------------------------


def test_bare_invocation_prints_usage(monkeypatch, capsys):
    assert run(monkeypatch) == 0
    assert "usage:" in capsys.readouterr().out


def test_unknown_command_is_rejected(monkeypatch):
    # argparse exits 2 for a usage error.
    assert run(monkeypatch, "nonsense") == 2
