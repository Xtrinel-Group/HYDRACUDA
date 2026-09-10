"""The other half of the Rust/Python differential check.

`core/tests/differential.rs` replays a corpus through the Rust engine and
compares against `core/tests/differential/expected.json` — a recording of what
the Python engine did with the same inputs. That recording is committed so
`cargo test` needs no Python interpreter.

Which leaves one way for the two engines to drift apart unnoticed: change the
Python engine and forget to re-record. The Rust test keeps passing, because it is
comparing against a snapshot of the old behaviour. So the check here is that the
committed recording is what today's Python code actually produces.

If this fails, run::

    python scripts/record_differential.py

and read the diff before committing it. A change in this file is a change in what
both engines are promising.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORE = REPO_ROOT / "core"
RECORDER = REPO_ROOT / "scripts" / "record_differential.py"
CASES = CORE / "tests" / "differential" / "cases.yaml"
EXPECTED = CORE / "tests" / "differential" / "expected.json"

# The Rust crate is not in the sdist — users receive the Python package, not the
# workspace that also builds a binary — so these tests skip outside a checkout.
# They do *not* skip when `core/` is present and the corpus is missing: that is
# the case where the differential harness has been broken rather than omitted.
pytestmark = pytest.mark.skipif(
    not CORE.is_dir(),
    reason="no core/ crate here, so there is no Rust engine to be differential against",
)


def load_recorder():
    """Import `scripts/record_differential.py` as a module."""
    spec = importlib.util.spec_from_file_location("record_differential", RECORDER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def recorder():
    if not RECORDER.exists():
        pytest.fail(f"{RECORDER} is missing; the differential harness cannot run")
    return load_recorder()


def test_the_corpus_and_its_recording_both_exist():
    # A missing corpus would make the Rust differential test vacuous rather than
    # failing, so its absence is worth its own assertion.
    assert CASES.exists(), f"{CASES} is missing"
    assert EXPECTED.exists(), f"{EXPECTED} is missing"


def test_the_recording_matches_the_current_python_engine(recorder):
    current = recorder.serialize(recorder.record())
    committed = EXPECTED.read_text()
    if current == committed:
        return

    # Point at the first differing line: the whole file is thousands of lines and
    # a bare "they differ" would not say what changed.
    current_lines = current.splitlines()
    committed_lines = committed.splitlines()
    for number, (got, expected) in enumerate(zip(current_lines, committed_lines), 1):
        if got != expected:
            detail = (
                f"first difference at line {number}:\n"
                f"  committed: {expected.strip()}\n"
                f"    current: {got.strip()}"
            )
            break
    else:
        detail = (
            f"the recording is {len(committed_lines)} lines and the current engine "
            f"produces {len(current_lines)}"
        )

    pytest.fail(
        f"{EXPECTED.relative_to(REPO_ROOT)} no longer matches the Python engine.\n"
        f"{detail}\n\n"
        "Re-record with: python scripts/record_differential.py"
    )


def test_the_corpus_covers_the_behaviours_worth_pinning(recorder):
    """A corpus can rot by shrinking, which no comparison would notice."""
    import yaml

    cases = yaml.safe_load(CASES.read_text())

    # YAML 1.1 booleans are the divergence that silently flips a decision, so the
    # corpus must keep testing them.
    assert "no" in cases["scalars"]
    assert "yes" in cases["scalars"]
    assert "012" in cases["scalars"]

    # Both end-of-string anchors, which are the fail-open cases.
    patterns = {case["pattern"] for case in cases["regexes"]}
    assert any(pattern.endswith("$") for pattern in patterns)
    assert any(r"\Z" in pattern for pattern in patterns)

    names = [case["name"] for case in cases["policies"]]
    assert len(names) == len(set(names)), "policy case names must be unique"

    # Both schema versions, every mode, and the load-error path.
    sources = "\n".join(case["policy"] for case in cases["policies"])
    assert "version: 1" in sources
    assert "version: 2" in sources
    assert "mode: shadow" in sources
    assert "mode: review" in sources
    assert sum(name.startswith("error-") for name in names) >= 10


def test_every_operator_appears_in_the_corpus():
    """An operator absent from the corpus is an operator with no parity check."""
    import yaml

    from hydracuda.conditions import OPERATORS

    sources = "\n".join(
        case["policy"] for case in yaml.safe_load(CASES.read_text())["policies"]
    )
    missing = sorted(
        operator for operator in OPERATORS if f"{operator}:" not in sources
    )
    assert not missing, f"operators with no differential coverage: {missing}"
