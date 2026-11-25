"""Original I02 guided setup must not invent readiness, grants or missing pins."""

from __future__ import annotations

import pytest

from netops.dependencies.service import DependencyRegistry
from netops.setup import main


@pytest.mark.parametrize("action", ["plan", "install", "update", "uninstall", "verify"])
def test_actual_guided_full_scope_missing_pins_reports_non_success_preserves_user_state(
    tmp_path, capsys, action,
):
    root = tmp_path / "not-created-root"
    unrelated = tmp_path / "user-vault-inventory-backups"
    unrelated.write_bytes(b"PRIVATE_UNTOUCHED_USER_STATE")
    result = main([action, "--root", str(root), "--enhanced"])
    output = capsys.readouterr().out
    assert result == 3
    assert not root.exists()
    assert unrelated.read_bytes() == b"PRIVATE_UNTOUCHED_USER_STATE"
    assert "No OS/elevation/WSL" in output
    assert "Native Windows is not an Ansible controller" in output
    assert "--plan-file" in output
    registry = DependencyRegistry.load()
    for entry in registry.entries:
        assert f"  {entry.id} (" in output, f"full accepted catalog omission: {entry.id}"


def test_actual_guided_narrow_scope_is_explicit_not_full_readiness(tmp_path, capsys):
    root = tmp_path / "native-owned-not-created"
    result = main(["plan", "--root", str(root), "--capability", "native.stdlib"])
    output = capsys.readouterr().out
    assert result == 3 and not root.exists()
    assert "native-python" in output
    assert "A full catalog is not a grant or a platform qualification" in output
    assert "--plan-file" in output


def test_actual_guided_rejects_unknown_capability_without_effects(tmp_path, capsys):
    root = tmp_path / "not-created"
    result = main(["install", "--root", str(root), "--capability", "invented-controller"])
    assert result == 3 and not root.exists()
    output = capsys.readouterr().out
    assert "Setup did not complete" in output
