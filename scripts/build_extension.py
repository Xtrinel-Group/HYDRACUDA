#!/usr/bin/env python3
"""Build `hydracuda._core` and drop it into `src/hydracuda/`.

    python scripts/build_extension.py            # debug build, fast to compile
    python scripts/build_extension.py --release   # what a release wheel contains

Why not `maturin develop`: the package is installed editable, so `hydracuda`
resolves to `src/hydracuda/` and a module maturin installs into
`site-packages/hydracuda/` would never be imported. So the wheel is built and the
one file that matters is copied to where the import will actually find it.

The module is deliberately not committed. It is packaged, but not by this script:
`maturin build` reads `[tool.maturin]` in `pyproject.toml` and produces a platform
wheel with the module inside it, which is what the release workflow ships. This
script exists for the checkout, where an editable install means the wheel is the
wrong shape and only the module's location matters.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "bindings" / "python" / "Cargo.toml"
WHEEL_DIR = ROOT / "target" / "wheels"
PACKAGE = ROOT / "src" / "hydracuda"


def build_wheel(release: bool) -> Path:
    # `--out` is emptied first so the newest wheel cannot be confused with a
    # stale one from an earlier build of a different profile.
    if WHEEL_DIR.exists():
        shutil.rmtree(WHEEL_DIR)

    command = [
        "maturin",
        "build",
        "--manifest-path",
        str(MANIFEST),
        "--out",
        str(WHEEL_DIR),
        "--interpreter",
        sys.executable,
    ]
    if release:
        command.append("--release")

    result = subprocess.run(command, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(result.returncode)

    wheels = sorted(WHEEL_DIR.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected one wheel in {WHEEL_DIR}, found {len(wheels)}")
    return wheels[0]


def install_module(wheel: Path) -> Path:
    with zipfile.ZipFile(wheel) as archive:
        # Matched by file name, not by directory: where in the wheel maturin puts
        # the module depends on the layout, and the only thing that matters here
        # is which file to copy. Its name inside `src/hydracuda/` is what makes
        # `from hydracuda import _core` resolve.
        members = [
            name
            for name in archive.namelist()
            if Path(name).name.startswith("_core")
            and name.endswith((".so", ".pyd", ".dylib"))
        ]
        if len(members) != 1:
            raise SystemExit(
                f"expected one extension module in {wheel.name}, found {members}"
            )
        member = members[0]
        target = PACKAGE / Path(member).name
        with archive.open(member) as source, open(target, "wb") as destination:
            shutil.copyfileobj(source, destination)

    # An extension has to be executable to be loaded on some platforms, and the
    # zip round-trip does not carry the mode bits.
    target.chmod(0o755)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        action="store_true",
        help="build optimized, as the release wheels are built",
    )
    arguments = parser.parse_args()

    target = install_module(build_wheel(arguments.release))
    # Flushed, or the subprocess below reaches the terminal first and the output
    # reads out of order.
    print(f"installed {target.relative_to(ROOT)}", flush=True)

    # Import it rather than claim success: a module that builds but will not load
    # (a link error, an ABI mismatch) is the failure this line catches.
    check = subprocess.run(
        [
            sys.executable,
            "-c",
            "import hydracuda;"
            "from hydracuda import engine_backend;"
            "print('backend:', engine_backend())",
        ],
        cwd=ROOT,
    )
    raise SystemExit(check.returncode)


if __name__ == "__main__":
    main()
