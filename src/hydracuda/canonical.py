"""Parameter canonicalization for adapters.

The policy engine matches parameter values literally — a regex is not a path
parser, and `deny_patterns: ["\\.\\."]` catches a literal `..` and nothing
else. Turning a caller-supplied string into the one true value it refers to is
therefore the adapter's job, and it has to happen *before* evaluation.

Two properties matter more than the pattern matching itself:

- The canonical value is what gets executed, not just what gets matched. A
  check performed on one string while a different string is passed to the
  handler is not a check.
- Confinement beats blocklisting. A path resolved with `realpath` and then
  required to sit under a root cannot escape via `..`, via a symlink, or via
  any encoding of either, because the escape is decided by where the path
  lands rather than by what it looks like.
"""

import os
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

#: Repeated decoding rounds tried when detecting percent-encoding. Bounded so
#: that a pathological input cannot spin here.
MAX_DECODE_ROUNDS = 4


class CanonicalizationError(ValueError):
    """Raised when a parameter cannot be canonicalized safely.

    Every caller treats this as a denial. It is raised rather than resolved to
    a best guess, because guessing what a hostile string meant is how bypasses
    happen.
    """


@dataclass
class CanonicalValue:
    """A canonicalized parameter value and what changed to produce it."""

    value: str
    notes: list[str] = field(default_factory=list)


def _percent_decoded(value: str) -> str:
    """Decode repeatedly until stable, catching double-encoding."""
    current = value
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def looks_percent_encoded(value: str) -> bool:
    """True when the value contains percent-encoded sequences."""
    return _percent_decoded(value) != value


def canonicalize_path(
    value: object,
    *,
    root: str | os.PathLike | None = None,
    reject_encoded: bool = True,
    resolve_symlinks: bool = True,
) -> CanonicalValue:
    """Resolve a path parameter to its canonical absolute form.

    `root`, when given, confines the result: the resolved path must sit inside
    it or a CanonicalizationError is raised. This is the control that actually
    stops traversal — the deny patterns are defence in depth on top of it.

    `reject_encoded` refuses percent-encoded input outright. A filesystem path
    arriving as `%2e%2e%2f` is either an attack or a layering bug, and the safe
    response to both is refusal: decoding it would silently rewrite the caller's
    request into a different one, while ignoring it would leave a value the
    deny patterns do not describe.
    """
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str):
        raise CanonicalizationError(
            f"path parameter must be a string, got {type(value).__name__}"
        )
    if not value:
        raise CanonicalizationError("path parameter must not be empty")

    notes: list[str] = []

    # A NUL byte truncates the path at the OS boundary, so the value checked
    # and the value opened would differ.
    if "\x00" in value:
        raise CanonicalizationError("path parameter contains a NUL byte")

    if looks_percent_encoded(value):
        decoded = _percent_decoded(value)
        if reject_encoded:
            raise CanonicalizationError(
                f"path parameter is percent-encoded ({value!r} decodes to "
                f"{decoded!r}); pass a decoded path"
            )
        # Left as-is deliberately: the literal characters are what the
        # filesystem will see, and confinement below is what keeps that safe.
        notes.append(f"percent-encoded sequences left literal (decodes to {decoded!r})")

    # NFC is the interchange form and resolves to the same file on Linux and
    # macOS, so applying it does not change which file is addressed.
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        notes.append("unicode normalized to NFC")
    # Compatibility characters (fullwidth solidus, for instance) are reported
    # but not rewritten — folding them would change the requested filename.
    if unicodedata.normalize("NFKC", normalized) != normalized:
        notes.append("contains unicode compatibility characters")

    candidate = normalized
    if root is not None and not os.path.isabs(candidate):
        candidate = os.path.join(os.fspath(root), candidate)

    if resolve_symlinks:
        resolved = os.path.realpath(candidate)
    else:
        resolved = os.path.normpath(os.path.abspath(candidate))

    if resolved != normalized:
        notes.append(f"resolved to {resolved!r}")

    if root is not None:
        # The root is resolved the same way the candidate was. Comparing an
        # unresolved path against a realpath'd root would report an escape
        # whenever the root's own ancestors run through a symlink (/var on
        # macOS, for one).
        if resolve_symlinks:
            root_resolved = os.path.realpath(os.fspath(root))
        else:
            root_resolved = os.path.normpath(os.path.abspath(os.fspath(root)))
        if not _is_inside(resolved, root_resolved):
            raise CanonicalizationError(
                f"path {value!r} resolves to {resolved!r}, which is outside the "
                f"permitted root {root_resolved!r}"
            )

    return CanonicalValue(value=resolved, notes=notes)


def _is_inside(path: str, root: str) -> bool:
    """True when `path` is `root` or sits beneath it.

    Compares whole path components, so `/rootless` is not treated as being
    inside `/root`.
    """
    if path == root:
        return True
    return path.startswith(root.rstrip(os.sep) + os.sep)
