"""`hcuda` and `hydracuda` must print the same thing.

The specification calls the two commands interchangeable, and the cheapest way to
keep that true is to hold their output to being byte-identical rather than merely
equivalent. Two lines are excused, and only two: the header names the engine and
the loader, which differ by construction, and `hcuda` adds a note about the one
check it structurally cannot run. Everything else — every diagnostic, every
column, every summary count — has to match, because a difference in wording is
how two tools start telling one policy author different things.

Skipped when the binary is not built. That is the common case for a Python-only
checkout, and a test that silently passed by comparing nothing would be worse
than one that says it did not run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Lines `hcuda` prints that `hydracuda` does not, or prints differently.
#: Deliberately short and deliberately checked below: an entry added here is a
#: divergence excused, so each one needs a reason that survives review.
_EXCUSED_PREFIXES = (
    # Names the engine and the loader. `hydracuda` says `Loader: python` even when
    # the Rust engine decides, because the extension is handed an already-parsed
    # policy; `hcuda` loads with Rust too. That difference is the point of the
    # line, so it cannot also be compared.
    "Engine: ",
    # `hcuda` has no adapter registry, so it cannot try to build a declared
    # adapter. Stated in its output rather than quietly skipped.
    "note: this binary has no adapter registry",
    "  adapter can be built",
)


def _binary() -> Path | None:
    override = os.environ.get("HCUDA_BIN")
    if override:
        return Path(override) if Path(override).exists() else None
    for profile in ("release", "debug"):
        candidate = ROOT / "target" / profile / "hcuda"
        if candidate.exists():
            return candidate
    return None


BINARY = _binary()

pytestmark = pytest.mark.skipif(
    BINARY is None,
    reason="hcuda is not built; run `cargo build -p hydracuda-cli`",
)


def _comparable(output: str) -> list[str]:
    return [
        line
        for line in output.splitlines()
        if not line.startswith(_EXCUSED_PREFIXES)
    ]


def _python(argv: list[str]) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    # Pinned rather than left to the build, so the comparison is against the
    # reference implementation and not against Rust twice.
    environment["HYDRACUDA_ENGINE"] = "python"
    return subprocess.run(
        [sys.executable, "-m", "hydracuda", *argv],
        capture_output=True,
        text=True,
        env=environment,
        cwd=ROOT,
    )


def _rust(argv: list[str]) -> subprocess.CompletedProcess[str]:
    assert BINARY is not None
    # Pinned too, and to `rust`, because the inherited environment may carry
    # `HYDRACUDA_ENGINE=python` — CI runs the whole suite that way. The binary
    # refuses that pin by design, so inheriting it would compare a policy report
    # against a refusal message and blame the wrong thing.
    environment = dict(os.environ, HYDRACUDA_ENGINE="rust")
    return subprocess.run(
        [str(BINARY), *argv],
        capture_output=True,
        text=True,
        env=environment,
        cwd=ROOT,
    )


def _assert_same(argv: list[str]) -> None:
    python = _python(argv)
    rust = _rust(argv)

    assert python.returncode == rust.returncode, (
        f"`hydracuda {' '.join(argv)}` exited {python.returncode} and "
        f"`hcuda {' '.join(argv)}` exited {rust.returncode}"
    )
    assert _comparable(python.stdout) == _comparable(rust.stdout), (
        "the two commands printed different things:\n"
        f"--- hydracuda\n{python.stdout}\n--- hcuda\n{rust.stdout}"
    )


@pytest.mark.parametrize(
    "example",
    [
        "examples/policy.yaml",
        "examples/policy-v1-legacy.yaml",
        "examples/policy-advanced.yaml",
    ],
)
@pytest.mark.parametrize("command", ["validate", "plan", "test"])
def test_the_shipped_examples_read_the_same_from_both(command, example):
    """The documents users copy. A divergence here is one a user would hit."""
    _assert_same([command, example])


@pytest.mark.parametrize("flag", ["--strict", None])
def test_validate_agrees_including_under_strict(flag, tmp_path):
    policy = tmp_path / "warns.yaml"
    # `default_action: allow` and an unreachable rule: two warnings, so `--strict`
    # changes the exit code and both commands have to change it the same way.
    policy.write_text(
        "version: 2\n"
        "default_action: allow\n"
        "rules:\n"
        "  - {name: broad, resource: 'fs.**', action: deny}\n"
        "  - {name: shadowed, resource: fs.read, action: deny}\n"
    )
    argv = ["validate", str(policy)] + ([flag] if flag else [])
    _assert_same(argv)


def test_plan_agrees_with_reasons(tmp_path):
    policy = tmp_path / "surface.yaml"
    policy.write_text(
        "version: 2\n"
        "adapters:\n"
        "  - {name: local, type: local_tools, resources: [fs.read, fs.write]}\n"
        "rules:\n"
        "  - {name: gated, resource: fs.read, action: deny, when: {trust: {equals: low}}}\n"
        "  - {name: writes, resource: fs.write, action: review, reason: 'needs sign-off'}\n"
    )
    _assert_same(["plan", str(policy), "--reasons"])


def test_a_failing_case_is_explained_identically(tmp_path):
    """The failure text is the whole output of a failing case."""
    policy = tmp_path / "cases.yaml"
    policy.write_text(
        "version: 2\n"
        "adapters:\n"
        "  - {name: local, type: local_tools, resources: [fs.read]}\n"
        "rules:\n"
        "  - {name: broad, resource: 'fs.*', action: deny}\n"
        "  - {name: specific, resource: fs.read, action: deny}\n"
        "tests:\n"
        "  - {name: passes, resource: fs.read, expect: deny}\n"
        "  - {name: wrong-rule, resource: fs.read, expect: deny, expect_rule: specific}\n"
        "  - {name: wrong-action, resource: fs.read, expect: allow}\n"
        "  - {name: refused, resource: fs.chmod, expect: refused}\n"
        "  - {name: not-refused, resource: fs.read, expect: refused}\n"
    )
    result = _python(["test", str(policy)])
    assert result.returncode == 1, "the fixture is meant to have failing cases"
    _assert_same(["test", str(policy)])


def test_a_load_error_reads_the_same(tmp_path):
    policy = tmp_path / "broken.yaml"
    policy.write_text("version: 2\nrulez: []\n")
    _assert_same(["validate", str(policy)])


def test_a_missing_file_reads_the_same(tmp_path):
    _assert_same(["validate", str(tmp_path / "absent.yaml")])


def test_the_excused_lines_are_the_only_ones_excused(tmp_path):
    """The excuse list has to stay honest.

    Every prefix in `_EXCUSED_PREFIXES` must actually appear in `hcuda` output —
    an entry that matches nothing is dead weight that could later start hiding a
    real difference.
    """
    policy = tmp_path / "clean.yaml"
    policy.write_text(
        "version: 2\n"
        "adapters:\n"
        "  - {name: local, type: local_tools, resources: [fs.read]}\n"
        "rules:\n  - {name: reads, resource: fs.read, action: allow}\n"
    )
    output = _rust(["validate", str(policy)]).stdout
    for prefix in _EXCUSED_PREFIXES:
        assert any(line.startswith(prefix) for line in output.splitlines()), prefix
