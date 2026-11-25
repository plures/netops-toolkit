"""AC-001/003/013 controls, without claiming controller or publisher authenticity."""

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from netops import __version__, setup
from netops.ansible import contracts as c
from netops.dependencies._family_lock import _Target
from netops.dependencies._lock_layout import (
    _InterpreterPin,
    _LayoutUnavailable,
    _selected_toolkit_roots,
)
from netops.dependencies._official_profiles import _PublisherContext
from netops.dependencies.service import DependencyRegistry


def target(role, platform, version="3.12.0"):
    """Describe synthetic facts, never permission to execute that platform."""
    return _Target(role, platform, "x86_64", version, "cp312", ("py3-none-any",), "a" * 64)


def test_ac013_public_layout_retains_independent_role_interpreters_without_effects(tmp_path):
    native = target("native", sys.platform)
    controller = target("controller", "linux", "3.11.0")
    pins = (
        _InterpreterPin(native, str(tmp_path / "native-python"), "b" * 64, "c" * 64),
        _InterpreterPin(controller, str(tmp_path / "controller-python"), "d" * 64, "e" * 64),
    )
    metadata = setup.SetupMetadata.publishers(None, (), (), (native, controller), interpreters=pins)
    layout = metadata._metadata().layout
    assert layout.interpreters == pins
    assert layout.interpreters[0].target.python == "3.12.0"
    assert layout.interpreters[1].target.python == "3.11.0"
    assert layout.interpreters[0].path != layout.interpreters[1].path
    assert not tuple(tmp_path.iterdir())


def test_ac001_public_native_profile_preflight_preserves_readonly_root(tmp_path):
    native = target("native", sys.platform)
    profile = _PublisherContext(sys.platform, native, "native", "fixture-version")
    metadata = setup.SetupMetadata.publishers(
        None, (), (), (native,), publisher_contexts=(profile,),
    )
    metadata._metadata().layout.preflight((native,))
    assert not tuple(tmp_path.iterdir())


@pytest.mark.parametrize("layout", ["vm-guest", "wsl2-guest"])
def test_ac001_guest_profile_is_precise_unqualified_need_not_host_fallback(tmp_path, layout):
    guest = target("controller", "linux")
    host = "win32" if layout == "wsl2-guest" else sys.platform
    profile = _PublisherContext(host, guest, layout, "fixture-guest-version")
    metadata = setup.SetupMetadata.publishers(
        None, (), (), (guest,), publisher_contexts=(profile,),
    )
    with pytest.raises(_LayoutUnavailable) as caught:
        metadata._metadata().layout.preflight((guest,))
    expected = (
        "qualified-guest-consuming-layout-required" if host == sys.platform
        else "independent-publisher-layout-profile-mismatch"
    )
    assert caught.value.reason == expected
    assert caught.value.context == "controller"
    assert caught.value.fields
    assert not tuple(tmp_path.iterdir())


def test_ac001_native_windows_controller_refused_before_any_root_creation(tmp_path):
    controller = target("controller", "win32")
    metadata = setup.SetupMetadata.publishers(None, (), (), (controller,))
    with pytest.raises(_LayoutUnavailable) as caught:
        metadata._metadata().layout.preflight((controller,))
    assert caught.value.reason == "native-windows-controller-prohibited"
    assert caught.value.context == "controller"
    assert not tuple(tmp_path.iterdir())


@pytest.mark.parametrize("field", ["interpreters", "publisher_contexts"])
def test_ac003_public_layout_rejects_duplicate_same_role_facts(tmp_path, field):
    native = target("native", sys.platform)
    value = (
        _InterpreterPin(native, str(tmp_path / "python"), "b" * 64, "c" * 64)
        if field == "interpreters"
        else _PublisherContext(sys.platform, native, "native", "fixture-version")
    )
    with pytest.raises(c.ContractError):
        setup.SetupMetadata.publishers(None, (), (), (native,), **{field: (value, value)})
    assert not tuple(tmp_path.iterdir())


def test_ac001_selected_ansible_only_keeps_current_toolkit_in_both_roles_without_molecule():
    registry = DependencyRegistry.load()
    entries = tuple(registry.entry(name) for name in ("native-python", "ansible-core"))
    roots = _selected_toolkit_roots(entries, registry)
    assert [(root.name, root.version, root.context, root.extras) for root in roots] == [
        ("netops-toolkit", "==" + __version__, "native", ()),
        ("netops-toolkit", "==" + __version__, "controller", ("ansible",)),
    ]
    assert all("molecule" not in root.extras for root in roots)


def test_ac001_selected_native_pdf_requires_complete_selected_extra_set():
    registry = DependencyRegistry.load()
    entries = tuple(registry.entry(name) for name in ("native-python", "jinja2", "weasyprint"))
    roots = _selected_toolkit_roots(entries, registry)
    assert len(roots) == 1
    assert roots[0].context == "native"
    assert roots[0].extras == ("report", "report-pdf")
    incomplete = _selected_toolkit_roots(
        tuple(entry for entry in entries if entry.id != "weasyprint"), registry,
    )
    assert incomplete[0].extras == ("report",)


def test_ac003_serialized_bootstrap_receipt_cannot_reconstitute_live_producer():
    publishers = setup.SetupMetadata.publishers(None, (), (), (target("native", sys.platform),))
    receipt = {"source": "b" * 64, "root": str(Path.cwd()), "generation_id": "c" * 64}
    with pytest.raises(TypeError, match="closed setup metadata"):
        setup.SetupMetadata.compose(receipt, publishers)
    with pytest.raises(TypeError, match="existing producer"):
        setup.SetupMetadata.compose(replace(publishers, _family_planning=None), publishers)
