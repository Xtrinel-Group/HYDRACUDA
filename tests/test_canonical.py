"""Tests for parameter canonicalization.

These cover the bypasses that a `deny_patterns: ["\\.\\."]` rule does not:
encoded traversal, symlinked escapes, and NUL truncation.
"""

import os

import pytest

from hydracuda.canonical import (
    CanonicalizationError,
    canonicalize_path,
    looks_percent_encoded,
)


@pytest.fixture
def root(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("ok")
    (workspace / "sub").mkdir()
    return workspace


# --- lexical resolution --------------------------------------------------


def test_dot_segments_are_resolved(root):
    result = canonicalize_path("sub/../notes.txt", root=root)
    assert result.value == os.path.realpath(str(root / "notes.txt"))


def test_relative_paths_resolve_against_root(root):
    assert canonicalize_path("notes.txt", root=root).value == os.path.realpath(
        str(root / "notes.txt")
    )


def test_nonexistent_paths_still_canonicalize(root):
    # Enforcement happens before the call, so the target need not exist yet.
    result = canonicalize_path("sub/new.txt", root=root)
    assert result.value == os.path.realpath(str(root / "sub" / "new.txt"))


def test_resolution_is_recorded_as_a_note(root):
    result = canonicalize_path("sub/../notes.txt", root=root)
    assert any("resolved to" in note for note in result.notes)


# --- traversal confinement ----------------------------------------------


def test_traversal_out_of_root_is_refused(root):
    with pytest.raises(CanonicalizationError, match="outside the permitted root"):
        canonicalize_path("../../etc/passwd", root=root)


def test_absolute_path_out_of_root_is_refused(root):
    with pytest.raises(CanonicalizationError, match="outside the permitted root"):
        canonicalize_path("/etc/passwd", root=root)


def test_sibling_directory_prefix_is_not_inside_root(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    (tmp_path / "workspace").mkdir()

    # String-prefix confinement checks would wrongly accept this.
    with pytest.raises(CanonicalizationError, match="outside the permitted root"):
        canonicalize_path(str(tmp_path / "workspace" / "x"), root=root)


def test_root_itself_is_inside_root(root):
    assert canonicalize_path(".", root=root).value == os.path.realpath(str(root))


def test_symlink_escape_is_refused(root):
    (root / "escape").symlink_to("/etc")

    # The literal path contains no `..` and no `/etc/`, so pattern matching
    # alone would permit it.
    with pytest.raises(CanonicalizationError, match="outside the permitted root"):
        canonicalize_path("escape/passwd", root=root)


def test_symlink_inside_root_is_allowed(root):
    (root / "link").symlink_to(root / "notes.txt")
    assert canonicalize_path("link", root=root).value == os.path.realpath(
        str(root / "notes.txt")
    )


def test_symlink_resolution_can_be_disabled(root):
    (root / "escape").symlink_to("/etc")

    # Without symlink resolution the escape is invisible to confinement. The
    # option exists for adapters whose backend does not follow links; it is
    # not the default.
    result = canonicalize_path("escape/passwd", root=root, resolve_symlinks=False)
    assert result.value == os.path.join(os.path.abspath(root), "escape", "passwd")


# --- encoding -----------------------------------------------------------


def test_percent_encoded_traversal_is_refused(root):
    with pytest.raises(CanonicalizationError, match="percent-encoded"):
        canonicalize_path("%2e%2e%2f%2e%2e%2fetc%2fpasswd", root=root)


def test_double_encoded_traversal_is_refused(root):
    with pytest.raises(CanonicalizationError, match="percent-encoded"):
        canonicalize_path("%252e%252e%252fetc", root=root)


def test_encoded_input_is_never_silently_decoded(root):
    # Decoding would rewrite the caller's request into a different one, so the
    # permissive mode leaves the characters literal and relies on confinement.
    result = canonicalize_path(
        "%2e%2e%2fnotes.txt", root=root, reject_encoded=False
    )
    assert result.value.startswith(os.path.realpath(str(root)))
    assert any("left literal" in note for note in result.notes)


def test_looks_percent_encoded():
    assert looks_percent_encoded("%2e%2e") is True
    assert looks_percent_encoded("../plain") is False


# --- rejected input -----------------------------------------------------


def test_nul_byte_is_refused(root):
    # A NUL truncates the path at the OS boundary, so the value checked and the
    # value opened would differ.
    with pytest.raises(CanonicalizationError, match="NUL byte"):
        canonicalize_path("notes.txt\x00.png", root=root)


def test_empty_path_is_refused(root):
    with pytest.raises(CanonicalizationError, match="must not be empty"):
        canonicalize_path("", root=root)


def test_non_string_is_refused(root):
    with pytest.raises(CanonicalizationError, match="must be a string"):
        canonicalize_path(42, root=root)


def test_pathlike_is_accepted(root):
    assert canonicalize_path(root / "notes.txt", root=root).value == os.path.realpath(
        str(root / "notes.txt")
    )


# --- unicode ------------------------------------------------------------

#: FULLWIDTH SOLIDUS. Looks like a path separator, is not one.
FULLWIDTH_SOLIDUS = "\uff0f"
#: "cafe" + COMBINING ACUTE ACCENT.
DECOMPOSED = "cafe\u0301.txt"
#: The same name as a single precomposed U+00E9.
COMPOSED = "caf\u00e9.txt"


def test_compatibility_characters_are_reported_not_folded(root):
    # Folding U+FF0F to "/" would change which file is addressed, so it is
    # recorded for the audit trail instead of rewritten.
    result = canonicalize_path(f"a{FULLWIDTH_SOLIDUS}b", root=root)
    assert any("compatibility characters" in note for note in result.notes)
    assert FULLWIDTH_SOLIDUS in result.value


def test_decomposed_form_is_folded_to_nfc(root):
    # Unlike the case above, both spellings resolve to the same file, so
    # folding cannot change the target.
    result = canonicalize_path(DECOMPOSED, root=root)
    assert any("NFC" in note for note in result.notes)
    assert result.value.endswith(COMPOSED)


# --- unconfined mode ----------------------------------------------------


def test_without_root_paths_resolve_but_are_not_confined(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Resolution still happens; nothing bounds where the result lands. This is
    # why LocalToolsAdapter documents root as the control that matters.
    assert canonicalize_path("../etc/passwd").value == os.path.realpath(
        str(tmp_path.parent / "etc" / "passwd")
    )
