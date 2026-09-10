"""The release pipeline, checked without running it.

A release workflow runs on the one occasion where a mistake is expensive and
where nobody is watching a pull request. Most of what can go wrong in it is
static — a matrix that stopped covering a platform, a secret read under the wrong
name, a retired runner label, an account ID pasted inline — so it is worth
asserting here rather than discovering at the moment a version number gets spent.

Skipped when `.github/` is absent, which is the case in the sdist: the workflows
are deliberately not distributed, and `tests/` is.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

pytestmark = pytest.mark.skipif(
    not WORKFLOWS.is_dir(),
    reason="no .github/workflows (the sdist does not ship them)",
)

#: The four platforms 0.5.0 commits to, as Rust target triples.
TARGETS = {
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
}

#: The one target built on a runner of a different architecture, because GitHub
#: retired every Intel macOS image and the arm64 ones carry no Rosetta. It is
#: named here rather than derived so that a second cross-compiled target — which
#: would be a second artifact nothing can execute before release — has to be an
#: edit to this set and not a quiet matrix change.
CROSS_COMPILED = {"x86_64-apple-darwin"}

#: Runner labels GitHub has retired. `macos-13` was the last Intel image and
#: `macos-14` went with it; the runner-images releases now carry only arm64
#: macOS. A workflow naming one of these does not fail loudly — the job waits for
#: a runner that will never come — so it is worth a test rather than a comment.
RETIRED_RUNNERS = {"macos-11", "macos-12", "macos-13", "macos-14", "ubuntu-20.04"}


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


@pytest.fixture(scope="module")
def publish() -> dict:
    return load("publish.yml")


@pytest.fixture(scope="module")
def ci() -> dict:
    return load("ci.yml")


def workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


# --- shape ---


@pytest.mark.parametrize("path", workflow_files(), ids=lambda p: p.name)
def test_every_workflow_is_valid_yaml(path):
    assert isinstance(yaml.safe_load(path.read_text()), dict)


def test_there_is_a_workflow_that_runs_on_pull_requests(ci):
    """There was none until 0.5.0, so every check was one someone remembered."""
    # `True` because `on: pull_request:` with no filters parses as a null value,
    # and PyYAML turns the bare `on` key into the boolean True.
    triggers = ci.get("on") or ci.get(True)
    assert "pull_request" in triggers


def test_publishing_triggers_on_a_published_release_not_a_tag_push(publish):
    """A tag is cheap to push by accident. A PyPI version cannot be reused."""
    triggers = publish.get("on") or publish.get(True)
    assert set(triggers) == {"release"}
    assert triggers["release"]["types"] == ["published"]


# --- matrices ---


def matrix_targets(job: dict) -> set[str]:
    return {entry["target"] for entry in job["strategy"]["matrix"]["include"]}


def test_the_wheel_matrix_covers_every_committed_platform(publish):
    assert matrix_targets(publish["jobs"]["wheels"]) == TARGETS


def test_the_binary_matrix_covers_the_same_platforms_as_the_wheels(publish):
    """Two lists that are supposed to be the same list.

    A platform that gets a wheel but no binary, or the reverse, is a gap nobody
    notices until someone asks for the missing one.
    """
    assert matrix_targets(publish["jobs"]["binaries"]) == matrix_targets(
        publish["jobs"]["wheels"]
    )


def test_no_job_asks_for_a_retired_runner(publish, ci):
    """The failure mode is a job queued forever, not an error."""
    for name, workflow in (("publish.yml", publish), ("ci.yml", ci)):
        for job_name, job in workflow["jobs"].items():
            runners = {
                entry.get("runner")
                for entry in job.get("strategy", {}).get("matrix", {}).get("include", [])
            }
            runners.add(job.get("runs-on"))
            for runner in runners:
                if isinstance(runner, str) and not runner.startswith("${{"):
                    assert runner not in RETIRED_RUNNERS, (
                        f"{name}:{job_name} runs on retired runner {runner}"
                    )


def test_the_universal_wheel_is_built_and_is_not_a_platform_wheel(publish):
    """The fallback that makes `cargo` never a requirement."""
    assert "universal" in publish["jobs"]
    assert matrix_targets(publish["jobs"]["wheels"]) and "strategy" not in publish[
        "jobs"
    ]["universal"], "the universal wheel must not be built per-platform"


def test_pypi_waits_for_every_wheel_before_uploading(publish):
    """PyPI is append-only per version, so a partial upload cannot be fixed."""
    assert set(publish["jobs"]["pypi"]["needs"]) == {"universal", "wheels"}


# --- verification depth ---
#
# How far each artifact is checked before it ships differs by target, and the
# difference is not visible from the matrix. These tests pin the two tiers so a
# target cannot quietly drop from "installed and run" to "the file exists".


def steps(job: dict) -> list[dict]:
    return job["steps"]


def step_running(job: dict, fragment: str) -> dict | None:
    for step in steps(job):
        if fragment in step.get("run", ""):
            return step
    return None


def non_native(job: dict) -> set[str]:
    return {
        entry["target"]
        for entry in job["strategy"]["matrix"]["include"]
        if not entry.get("native")
    }


@pytest.mark.parametrize("job_name", ["wheels", "binaries"])
def test_every_target_declares_whether_it_is_native(publish, job_name):
    """`native` decides how far the target can be verified, so it is not optional.

    An entry missing the key reads as non-native, which would silently *skip* the
    execution check rather than fail it.
    """
    for entry in publish["jobs"][job_name]["strategy"]["matrix"]["include"]:
        assert "native" in entry, f"{job_name}: {entry['target']} does not say"


@pytest.mark.parametrize("job_name", ["wheels", "binaries"])
def test_only_the_known_target_is_cross_compiled(publish, job_name):
    """A new cross-compiled target is an artifact nothing can run before release."""
    assert non_native(publish["jobs"][job_name]) == CROSS_COMPILED


def test_every_native_wheel_is_installed_and_the_compiled_engine_asserted(publish):
    """Building a wheel does not prove it works.

    `hydracuda` imports fine when `_core` fails to load — it falls back to the
    pure-Python engine — so a wheel carrying a broken module installs, runs, and
    passes anything that does not check which engine answered.
    """
    step = step_running(publish["jobs"]["wheels"], "pip install")
    assert step is not None, "no wheel job step installs the wheel it built"
    assert step.get("if") == "matrix.native"
    assert 'backend != "rust"' in step["run"], "installs the wheel but not asserting"

    # Asserted against the invoking line, not the whole script: the step explains
    # the flag in a comment, and a substring check over the body is satisfied by
    # that comment even after the flag itself is gone.
    invocations = [
        line
        for line in step["run"].splitlines()
        if "pip install" in line and not line.lstrip().startswith("#")
    ]
    assert invocations, "the only mention of pip install is a comment"
    for line in invocations:
        # Without this, a wheel that will not install is rescued by pip falling
        # back to building the sdist, which yields a working pure-Python install
        # and a green step.
        assert "--only-binary" in line, f"pip may fall back to the sdist: {line}"


def test_the_wheel_that_cannot_be_executed_has_its_architecture_read(publish):
    """The cross-compiled wheel's one real check.

    maturin derives the platform tag from `--target`, so the tag agreeing with the
    target is true by construction. Reading the Mach-O header is what would catch
    a module built for the host and named for the target.
    """
    step = step_running(publish["jobs"]["wheels"], "lipo -archs")
    assert step is not None, "nothing reads the architecture of the compiled module"
    assert step.get("if") == "runner.os == 'macOS'"
    assert 'test "$archs" = "$EXPECTED"' in step["run"], "not compared to the target"

    # Every macOS target has to supply the expected architecture, or the
    # comparison above is against an empty string.
    for entry in publish["jobs"]["wheels"]["strategy"]["matrix"]["include"]:
        if "apple-darwin" in entry["target"]:
            assert entry.get("arch"), f"{entry['target']} has no `arch`"


# --- credentials ---


def test_the_r2_job_reads_all_four_values_from_secrets(publish):
    environment = publish["jobs"]["mirror"]["steps"][-1]["env"]
    expected = {
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "CLOUDFLARE_ACCOUNT_ID",
        "R2_BUCKET_NAME",
    }
    referenced = {
        match
        for value in environment.values()
        if isinstance(value, str)
        for match in re.findall(r"secrets\.([A-Z0-9_]+)", value)
    }
    assert expected <= referenced, f"missing: {expected - referenced}"


@pytest.mark.parametrize("path", workflow_files(), ids=lambda p: p.name)
def test_no_workflow_hardcodes_an_account_id_or_a_bucket_name(path):
    """An account ID is not a credential, but it is a free identifier for anyone
    enumerating targets, and a hardcoded bucket name is a config change that
    needs a commit. Both come from secrets."""
    text = path.read_text()

    # A Cloudflare account ID is 32 hex characters. Matched case-insensitively and
    # only on a standalone token, so ordinary words and pinned SHAs in a `uses:`
    # are not swept up.
    for candidate in re.findall(r"\b[0-9a-fA-F]{32}\b", text):
        assert False, f"{path.name} contains what looks like an account ID: {candidate}"

    assert "r2.cloudflarestorage.com" not in text.replace(
        "$ACCOUNT_ID.r2.cloudflarestorage.com", ""
    ), f"{path.name} has an R2 endpoint that is not built from the secret"
    assert "hydracuda-releases" not in text, f"{path.name} hardcodes the bucket name"


def test_only_the_publishing_job_can_mint_an_oidc_token(publish):
    """`id-token: write` is what trusted publishing authenticates with, so it is
    scoped to the job that uploads rather than granted workflow-wide."""
    assert publish.get("permissions") == {"contents": "read"}

    writers = [
        name
        for name, job in publish["jobs"].items()
        if job.get("permissions", {}).get("id-token") == "write"
    ]
    assert writers == ["pypi"]
    assert publish["jobs"]["pypi"]["environment"] == "pypi"


def test_the_release_upload_job_is_the_only_one_that_can_write_contents(publish):
    writers = [
        name
        for name, job in publish["jobs"].items()
        if job.get("permissions", {}).get("contents") == "write"
    ]
    assert writers == ["attach"]
