"""Tests for the release-owned version metadata utility."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_version.py"


def _write_fixture(root: Path, package_version: str, runtime_version: str) -> None:
    """Create the tracked version files expected by the sync utility."""
    (root / "netops").mkdir()
    (root / "pyproject.toml").write_text(
        f'[project]{chr(10)}version = "{package_version}"{chr(10)}', encoding="utf-8"
    )
    (root / "netops" / "__init__.py").write_text(
        f'__version__ = "{runtime_version}"{chr(10)}', encoding="utf-8"
    )


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the utility in a subprocess to cover its public interface."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_check_rejects_mismatched_metadata(tmp_path: Path) -> None:
    """A CI check must fail before a divergent version can be released."""
    _write_fixture(tmp_path, "1.2.3", "1.2.2")

    result = _run("--root", str(tmp_path), "--check")

    assert result.returncode == 1
    assert "Version metadata mismatch" in result.stderr
    assert "netops/__init__.py: 1.2.2" in result.stderr


def test_sync_updates_runtime_and_package_metadata(tmp_path: Path) -> None:
    """The release writer updates every tracked metadata source together."""
    _write_fixture(tmp_path, "1.2.3", "1.2.2")

    result = _run("--root", str(tmp_path), "--version", "2.0.0")

    assert result.returncode == 0, result.stderr
    assert 'version = "2.0.0"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert '__version__ = "2.0.0"' in (tmp_path / "netops" / "__init__.py").read_text(
        encoding="utf-8"
    )


def test_sync_rejects_non_semantic_versions(tmp_path: Path) -> None:
    """Release metadata remains valid even when manual dispatch input is wrong."""
    _write_fixture(tmp_path, "1.2.3", "1.2.3")

    result = _run("--root", str(tmp_path), "--version", "v2.0.0")

    assert result.returncode == 2
    assert "must be MAJOR.MINOR.PATCH" in result.stderr
