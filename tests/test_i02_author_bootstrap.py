"""Author root-entrypoint guards; source controls are not platform qualification."""

import json
from pathlib import Path

import pytest

from netops.ansible import contracts as c
from netops.dependencies._setup import _document, _scope

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("filename", ("install.ps1", "install.sh"))
def test_bootstrap_invokes_registered_host_without_destructive_or_network_fallback(filename):
    source = (ROOT / filename).read_text(encoding="utf-8")
    assert "from netops.setup import main" in source
    assert "-I -B -c" in source
    assert "--clear" not in source and "rm -rf" not in source
    assert "curl " not in source and "Invoke-WebRequest" not in source
    assert "Invoke-RestMethod" not in source and "Remove-Item" not in source
    assert ".bashrc" not in source and ".zshrc" not in source
    assert "pip install" not in source  # admitted installer owns verified offline pip


def test_powershell_forwards_all_actual_lifecycle_actions_and_selections():
    source = (ROOT / "install.ps1").read_text(encoding="utf-8")
    for action in ("plan", "install", "update", "resume", "verify", "restore", "uninstall"):
        assert '"' + action + '"' in source
    for option in ("--root", "--plan-file", "--capability", "--enhanced",
                   "--generation-id", "--installation-id"):
        assert option in source
    assert "exit $LASTEXITCODE" in source
    assert "-ExecutionPolicy Bypass" not in source


@pytest.mark.parametrize("value", (
    '{"scope":1,"scope":2}', '{"outer":{"scope":1,"scope":2}}',
    '["not-an-object"]', '"not-an-object"',
))
def test_local_descriptor_rejects_duplicate_or_nonobject_input(tmp_path, value):
    path = tmp_path / "descriptor.json"
    path.write_text(value, encoding="utf-8")
    with pytest.raises(c.ContractError):
        _document(path)


@pytest.mark.parametrize("field,value", (
    ("enhanced", "true"), ("enhanced", 1), ("full_toolkit", "true"),
    ("full_toolkit", 1), ("unexpected", "value"),
))
def test_scope_flags_are_closed_types_not_permission_coercions(field, value):
    raw = {"native_capabilities": [], "companions": [], "full_toolkit": True, "enhanced": False}
    raw[field] = value
    with pytest.raises(c.ContractError):
        _scope(json.loads(json.dumps(raw)))
