"""Shared fixtures for the HYDRACUDA test suite."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def examples_dir() -> Path:
    return REPO_ROOT / "examples"
