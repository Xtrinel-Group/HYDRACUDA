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


#: Everything an R2 write needs. Named once because more than one step does it.
R2_SECRETS = {
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
    "CLOUDFLARE_ACCOUNT_ID",
    "R2_BUCKET_NAME",
}


def secrets_referenced(step: dict) -> set[str]:
    return {
        match
        for value in step.get("env", {}).values()
        if isinstance(value, str)
        for match in re.findall(r"secrets\.([A-Z0-9_]+)", value)
    }


# Every step that talks to R2, not just the last one: the job gained a second
# such step when latest.txt arrived, and indexing by position would have moved
# the assertion onto it and left the upload unchecked.
@pytest.mark.parametrize("fragment", ["aws s3 cp .", "latest.txt"])
def test_every_r2_step_reads_all_four_values_from_secrets(publish, fragment):
    step = step_running(publish["jobs"]["mirror"], fragment)
    assert step is not None, f"no step in mirror runs {fragment!r}"
    referenced = secrets_referenced(step)
    assert R2_SECRETS <= referenced, f"missing: {R2_SECRETS - referenced}"


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


# --- the installer channel ---
#
# `curl | sh` resolves a version from latest.txt in the bucket, so a release that
# uploads artifacts but leaves that pointer behind ships a version nobody
# installs by default. The pointer is the one mutable key in the bucket, which is
# also the one place a release can regress silently: everything else is keyed by
# tag and would 404 rather than serve the wrong thing.


def latest_step(publish: dict) -> dict:
    step = step_running(publish["jobs"]["mirror"], "latest.txt")
    assert step is not None, "nothing in the mirror job writes latest.txt"
    return step


def test_a_release_moves_the_pointer_the_installer_reads(publish):
    run = latest_step(publish)["run"]

    # From the tag, not from a version file: the release event is the fact.
    assert 'printf ' in run and '"$TAG"' in run, "latest.txt is not written from the tag"
    # The mutable key, not one under the tag prefix — writing
    # hydracuda/<tag>/latest.txt would leave the default install unchanged.
    assert 'hydracuda/latest.txt"' in run, "latest.txt is not written to the bucket root"


def test_the_pointer_is_read_back_after_it_is_written(publish):
    """A write that succeeded and left the previous tag in place would send every
    new install to the old version, and nothing else here would notice."""
    run = latest_step(publish)["run"]
    copies = [line for line in run.splitlines() if "aws s3 cp" in line]
    assert len(copies) == 2, f"expected a write and a read back, got {len(copies)}"
    assert 'test "$(cat readback.txt)" = "$TAG"' in run, "the read back is not compared"


def test_a_prerelease_does_not_become_the_default_install(publish):
    """`latest` is what a first-time `curl | sh` gets, and that is never a
    release candidate. A prerelease stays installable by tag."""
    assert latest_step(publish)["if"] == "${{ !github.event.release.prerelease }}"
    assert publish["jobs"]["redeploy-installer"]["if"] == (
        "${{ !github.event.release.prerelease }}"
    )


def test_the_installer_worker_is_told_about_a_release(publish):
    job = publish["jobs"]["redeploy-installer"]
    # After the mirror: a redeploy that raced the upload could deploy against a
    # pointer for a release whose artifacts are not there yet.
    assert job["needs"] == ["mirror"]

    run = job["steps"][0]["run"]
    assert "repos/Xtrinel-Group/hydracuda-install/dispatches" in run
    # The event type the receiving workflow subscribes to. A typo here is a
    # dispatch that returns 204 and triggers nothing.
    assert 'event_type: "hydracuda-release"' in run
    # And the tag travels with it, so the deploy can check what it deployed
    # against what was released instead of deploying blind.
    assert "client_payload: {tag: $tag}" in run


def test_the_dispatch_uses_a_token_that_can_leave_this_repository(publish):
    """GITHUB_TOKEN is scoped to this repository, so a cross-repository dispatch
    with it fails at the moment of a release. This is the one place the pipeline
    needs a credential that is not minted by Actions."""
    step = publish["jobs"]["redeploy-installer"]["steps"][0]
    assert secrets_referenced(step) == {"INSTALL_DISPATCH_TOKEN"}
    assert "secrets.GITHUB_TOKEN" not in yaml.dump(step)


def test_a_missing_dispatch_token_fails_loudly(publish):
    """Skipping with a warning would make the redeploy silently stop happening,
    which is indistinguishable from it working. The job is terminal, so failing
    costs a red check on a release that has otherwise fully succeeded — and says
    which secret is missing."""
    run = publish["jobs"]["redeploy-installer"]["steps"][0]["run"]
    guard = run[run.index('if [ -z "${GH_TOKEN:-}" ]') :]
    assert "::error::" in guard
    assert "exit 1" in guard.split("fi")[0]
