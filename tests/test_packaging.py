"""Tests for what the published artifacts contain.

The dashboard reached PyPI because there was no sdist configuration at all.
Hatchling's default sdist is "every file git does not ignore", so the wheel
excluded the dashboard while the sdist quietly shipped it — along with CI
configuration and a retired package — and a cross-site scripting bug in it went
out in the v0.2.0 source distribution.

These tests are about the file list, not the code. The check that matters is that
adding a directory to the repository does not silently add it to a release.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"

#: Nothing here belongs in a release. `dashboard` is a development tool and far
#: too generic a name for site-packages; the rest is repository furniture.
NOT_DISTRIBUTED = ("dashboard", "deprecation", ".github")


@pytest.fixture(scope="module")
def config():
    if not PYPROJECT.exists():
        pytest.skip("pyproject.toml is not in the sdist tree")
    tomllib = pytest.importorskip("tomllib", reason="Python 3.11+ for tomllib")
    return tomllib.loads(PYPROJECT.read_text())


def build_targets(config) -> dict:
    return config["tool"]["hatch"]["build"]["targets"]


def sdist_include(config) -> list[str]:
    """The sdist file list, asserted rather than indexed into.

    A missing block is the original bug, so it gets a message that says so
    instead of a KeyError.
    """
    targets = build_targets(config)
    assert "sdist" in targets and "include" in targets["sdist"], (
        "no [tool.hatch.build.targets.sdist] include list: the default is a "
        "git-ignore-based sweep, which is how the dashboard reached PyPI"
    )
    return targets["sdist"]["include"]


def test_the_sdist_file_list_is_explicit(config):
    """The bug was an absent config block, not a wrong entry in one.

    Without `include`, the default is a git-ignore-based sweep, which means every
    new directory ships until someone notices.
    """
    assert sdist_include(config)


def test_neither_artifact_ships_the_dashboard_or_repository_furniture(config):
    listed = sdist_include(config) + build_targets(config)["wheel"]["packages"]

    for name in NOT_DISTRIBUTED:
        assert not [entry for entry in listed if name in entry], (
            f"{name!r} is in the artifact file list; "
            "see the comment in pyproject.toml before adding it"
        )


def test_every_sdist_pattern_is_anchored(config):
    """Gitignore-style patterns match at any depth unless anchored.

    Unanchored `README.md` also matched `deprecation/README.md`, which is how a
    file from a directory nobody meant to ship got in.
    """
    unanchored = [
        pattern
        for pattern in sdist_include(config)
        if not pattern.startswith("/")
    ]
    assert unanchored == [], f"unanchored pattern(s): {unanchored}"


def test_the_sdist_carries_the_tests_that_prove_the_boundary(config):
    """A source distribution a downstream packager cannot test is not much use,
    and the headless tests are exactly the ones that matter without the
    dashboard present."""
    assert "/tests" in sdist_include(config)


def test_the_readme_does_not_tell_pip_users_to_run_the_dashboard():
    """`pip install "hydracuda[dashboard]"` then `python -m dashboard.app` is a
    ModuleNotFoundError: the extra installs Flask, not the dashboard."""
    text = README.read_text()
    if "python -m dashboard.app" not in text:
        return

    section = text.split("## Dashboard", 1)[-1]
    assert re.search(r"not shipped in the wheel or the sdist", section), (
        "the README documents running the dashboard without saying it is not "
        "part of the installed package"
    )
    assert "git clone" in section.split("python -m dashboard.app", 1)[0], (
        "the dashboard instructions must start from a checkout, not a pip install"
    )
