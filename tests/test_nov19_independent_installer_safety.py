"""Acceptance-first I02 installer preservation regression guards.

Source guards supplement, never replace, actual lifecycle effect tests.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["install.sh", "install.ps1"])
def test_t04_root_installer_does_not_clear_existing_environment(name):
    source = (ROOT / name).read_text(encoding="utf-8")
    executable_lines = [
        line.strip() for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any("--clear" in line for line in executable_lines), (
        "FR-007/044: an update must stage a new owned generation, not clear the active environment"
    )


def test_t02_shell_bootstrap_never_pipes_remote_script_to_shell():
    source = (ROOT / "install.sh").read_text(encoding="utf-8")
    executable_lines = [
        line.strip() for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any(
        ("curl " in line or "wget " in line)
        and any(suffix in line for suffix in ("| sh", "| bash"))
        for line in executable_lines
    ), "FR-002/004/035: acquisition needs registered verified assets and separate consent"
