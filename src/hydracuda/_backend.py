"""Which engine decides: the pure-Python one, or the Rust extension.

Both are shipped and both are supported. The Rust engine is used when the
compiled extension is importable, and the pure-Python engine when it is not —
so a platform with no wheel installs the universal one and keeps working, with
no Rust toolchain and no loss of function.

That makes the fallback a permanent code path rather than a temporary one, which
is the reason it can be trusted. `HYDRACUDA_ENGINE` forces the choice, and the
whole test suite is run both ways in CI:

    HYDRACUDA_ENGINE=python pytest      # the fallback
    HYDRACUDA_ENGINE=rust pytest        # the extension, error if unavailable

`engine_backend()` reports which one is live. A decision must not depend on the
answer; if it ever does, that is the bug this module exists to make visible.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any, Literal

Backend = Literal["python", "rust"]

#: Set to force a backend. `rust` raises if the extension is missing rather than
#: silently falling back, because a benchmark or a parity run that quietly
#: measured the wrong engine would be worse than a failure.
ENGINE_ENV_VAR = "HYDRACUDA_ENGINE"

try:  # pragma: no cover - which branch runs depends on how the wheel was built
    from hydracuda import _core
except ImportError:  # pragma: no cover
    _core = None


class BackendUnavailable(RuntimeError):
    """Raised when `HYDRACUDA_ENGINE=rust` is set and the extension is absent."""


def rust_available() -> bool:
    """True when the compiled engine can be imported."""
    return _core is not None


def engine_backend() -> Backend:
    """The engine that will decide: `"rust"` or `"python"`."""
    requested = os.environ.get(ENGINE_ENV_VAR, "").strip().lower()
    if requested == "python":
        return "python"
    if requested == "rust":
        if _core is None:
            raise BackendUnavailable(
                f"{ENGINE_ENV_VAR}=rust, but hydracuda._core is not importable. "
                "Build it with `maturin develop -m bindings/python/Cargo.toml`, "
                f"or unset {ENGINE_ENV_VAR} to use the pure-Python engine."
            )
        return "rust"
    if requested:
        raise BackendUnavailable(
            f"{ENGINE_ENV_VAR}={requested!r} is not a backend; use 'rust' or 'python'"
        )
    return "rust" if _core is not None else "python"


@contextlib.contextmanager
def use_backend(backend: Backend) -> Iterator[None]:
    """Force `backend` for `PolicyEngine`s constructed inside the block.

    A `PolicyEngine` picks its backend once, at construction, so only the
    construction has to happen inside the block — the engine it yields keeps
    using that backend for every later call.

    Two callers need this. `scripts/record_differential.py` records what the
    *Python* engine decides, so it must not be handed the Rust one on a machine
    where the extension is built, or the golden file the Rust tests compare
    against would be a recording of Rust. And the parity tests need both engines
    alive in one process to compare them.

    The setting is an environment variable, so this is process-global and not
    thread-safe. Both callers are single-threaded.
    """
    previous = os.environ.get(ENGINE_ENV_VAR)
    os.environ[ENGINE_ENV_VAR] = backend
    try:
        yield
    finally:
        if previous is None:
            del os.environ[ENGINE_ENV_VAR]
        else:
            os.environ[ENGINE_ENV_VAR] = previous


def engine_version() -> str | None:
    """The compiled engine's crate version, or None when it is not in use."""
    return None if _core is None else _core.__version__


def build_engine(policy: Any) -> Any | None:
    """A Rust engine for `policy`, or None to use the pure-Python path.

    The spec passed across is the *evaluable* part of the policy and nothing
    else. Building it here rather than in Rust keeps the attribute names of the
    dataclasses on this side of the boundary, and keeps the conversion short
    enough to read against `engine.py`.

    Built once per `PolicyEngine`, so each rule's regexes compile once for the
    life of the policy rather than once per request.
    """
    if engine_backend() == "python":
        return None

    spec = {
        "mode": policy.mode,
        "default_action": policy.default_action,
        "default_reason": policy.default_reason,
        "rules": [
            {
                "resource": rule.resource,
                "action": rule.action,
                # `name`, not `label`: the fallback to `action:resource` is part
                # of what the two engines have to agree on, so it is computed on
                # both sides rather than on one.
                "name": rule.name,
                "reason": rule.reason,
                "where": rule.where,
                "when": rule.when,
            }
            for rule in policy.rules
        ],
    }

    # A rule list Python accepted that Rust refuses is a policy problem, and it
    # is reported as one: callers already catch `PolicyError` around loading, and
    # an extension-specific exception type leaking out would make the backend
    # visible in a caller's `except` clause.
    from hydracuda.policy import PolicyError

    try:
        return _core.Engine(spec)
    except _core.EngineError as error:
        raise PolicyError(str(error)) from error
