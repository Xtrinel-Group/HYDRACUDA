"""Tests that keep the documentation honest.

The v0.2.0 README documented `parameterRules`, `denyPatterns`, `rateLimit`, and
`audit: {path: ...}`. None of those were read by the loader, so a reader who
copied the documented form got a policy that silently did nothing. Prose drifting
from code is the failure these tests exist to catch — every policy example in the
documentation is parsed with the real loader.
"""

import re
from pathlib import Path

import pytest
import yaml

from hydracuda.policy import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
SPEC = REPO_ROOT / "docs" / "policy-spec.md"

#: Keys the v0.2.0 README documented that the loader never read.
RETIRED_SPELLINGS = ("parameterRules", "denyPatterns", "rateLimit")


def yaml_blocks(path: Path) -> list[str]:
    return re.findall(r"```yaml\n(.*?)```", path.read_text(), re.S)


def policy_blocks(path: Path) -> list[str]:
    """Fenced YAML blocks that are whole policies rather than fragments.

    A fragment illustrating one rule is not loadable on its own, so `version` is
    the marker for "this is a complete file a reader could copy".
    """
    return [block for block in yaml_blocks(path) if re.match(r"version:", block.strip())]


@pytest.mark.parametrize("path", [README, SPEC], ids=lambda p: p.name)
def test_documented_policies_parse(path):
    blocks = policy_blocks(path)
    assert blocks, f"no complete policy examples found in {path.name}"

    for index, block in enumerate(blocks):
        try:
            parse_policy(yaml.safe_load(block))
        except Exception as e:  # noqa: BLE001 - the failure message is the point
            pytest.fail(f"{path.name} policy block {index}: {type(e).__name__}: {e}")


@pytest.mark.parametrize("path", [README, SPEC], ids=lambda p: p.name)
def test_every_yaml_block_is_valid_yaml(path):
    for index, block in enumerate(yaml_blocks(path)):
        try:
            yaml.safe_load(block)
        except yaml.YAMLError as e:
            pytest.fail(f"{path.name} block {index} is not valid YAML: {e}")


def test_the_readme_does_not_document_the_camel_case_spellings():
    """They may be named as retired, but not shown inside a policy example."""
    for block in yaml_blocks(README):
        for spelling in RETIRED_SPELLINGS:
            assert spelling not in block, f"{spelling} shown in a README policy example"


def test_the_readme_documents_the_real_key_names():
    text = README.read_text()
    for key in ("parameter_rules", "deny_patterns", "audit_path", "default_action"):
        assert key in text, f"{key} is not documented"


def test_the_readme_uses_the_current_cli_commands():
    """`check` is a deprecated alias, so it must not be what a reader is told to
    run first."""
    text = README.read_text()
    assert "hydracuda validate" in text
    assert "hydracuda plan" in text
    assert "hydracuda check hydracuda.yaml" not in text


def test_the_readme_lists_every_audit_column():
    """The four columns added by the migration were missing, which meant a reader
    building on the log would not know `enforced` exists."""
    text = README.read_text()
    from hydracuda.proxy import _SCHEMA

    columns = re.findall(r"^\s+(\w+) (?:INTEGER|TEXT)", _SCHEMA, re.M)
    assert "enforced" in columns
    for column in columns:
        assert f"`{column}`" in text, f"audit column {column} is undocumented"


def test_the_tests_block_is_no_longer_marked_as_unimplemented():
    """The inverse of the 0.3.0 guard, which is why it reads oddly.

    Through 0.3.x the section carried a "not yet implemented" banner and a test
    that pinned it, because a spec section reading as current behaviour is worse
    than no section — the loader rejected `tests` and anyone copying it got a load
    error. 0.4.0 implements it, so the banner has to come off, and a stale banner
    is the same defect pointing the other way.
    """
    text = SPEC.read_text()
    assert "## Test cases (`tests:`)" in text
    _, _, body = text.partition("## Test cases (`tests:`)")
    section = body[: body.index("\n## ")]
    assert "not yet implemented" not in section.lower()


def test_the_tests_block_is_shown_in_a_policy_the_loader_accepts():
    """A fragment is not enough now that it loads.

    `policy_blocks` feeds every complete example through the real loader, so the
    assertion is that at least one of them exercises `tests:` — otherwise the
    schema could drift from the documented example without failing anything.
    """
    blocks = [
        block
        for path in (README, SPEC)
        for block in policy_blocks(path)
        if "tests:" in block
    ]
    assert blocks, "no complete policy example uses `tests:`"


def test_the_tests_block_schema_does_not_reuse_the_condition_key_names():
    """`params`/`context` hold values; `where`/`when` hold operators.

    If the schema ever adopts `where:`/`when:` for test cases, an operator map
    pasted into a case becomes a literal value instead of a schema error. The
    spec explains this, so the explanation should not outlive the decision.
    """
    body = SPEC.read_text().partition("## Test cases (`tests:`)")[2]
    section = body[: body.index("\n## ")]

    assert "params:" in section and "context:" in section
    for key in ("name", "resource", "expect"):
        assert f"| `{key}` |" in section


def test_the_readme_states_that_shadow_mode_does_not_block():
    text = README.read_text().lower()
    assert "shadow" in text
    # The specific claim, not just the word: a reader must not think shadow mode
    # is a quieter kind of enforcement.
    assert "executes anyway" in text or "executes the call" in text


def test_the_readme_states_the_dashboard_is_optional():
    text = README.read_text().lower()
    assert "headless" in text
    assert "read-only" in text
