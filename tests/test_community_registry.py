"""Tests for the community string registry."""

import json
import tempfile
from pathlib import Path

from netops.core.community import CommunityRegistry


def test_registry_creates_with_defaults():
    """New registry has 'public' as default string."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    assert reg.strings == ["public"]
    path.unlink(missing_ok=True)


def test_add_string_deduplicates():
    """Adding the same string twice doesn't create duplicates."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    reg.add_string("secret1")
    reg.add_string("secret1")
    assert reg.strings.count("secret1") == 1
    path.unlink(missing_ok=True)


def test_set_device_caches_community_and_vendor():
    """set_device stores community + vendor, get_device retrieves them."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    reg.set_device("10.0.0.1", "Pr1vat3!", "brocade_fastiron")
    cached = reg.get_device("10.0.0.1")
    assert cached["community"] == "Pr1vat3!"
    assert cached["vendor"] == "brocade_fastiron"
    path.unlink(missing_ok=True)


def test_get_strings_for_host_known_device_first():
    """Known device's community string is tried first."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    reg.add_string("community1")
    reg.add_string("community2")
    reg.set_device("10.0.0.5", "community2", "cisco_ios")
    order = reg.get_strings_for_host("10.0.0.5")
    assert order[0] == "community2"  # known-good first
    assert "community1" in order
    path.unlink(missing_ok=True)


def test_get_strings_for_host_unknown_device():
    """Unknown device gets the full list in registry order."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    reg.add_string("alpha")
    reg.add_string("beta")
    order = reg.get_strings_for_host("10.99.99.99")
    assert order == ["public", "alpha", "beta"]
    path.unlink(missing_ok=True)


def test_registry_persists_to_disk():
    """Registry data survives save/reload cycle."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    reg.add_string("persisted")
    reg.set_device("1.2.3.4", "persisted", "juniper_junos")

    # Reload from disk
    reg2 = CommunityRegistry(path)
    assert "persisted" in reg2.strings
    assert reg2.get_device("1.2.3.4")["vendor"] == "juniper_junos"
    path.unlink(missing_ok=True)


def test_set_device_also_adds_to_global_strings():
    """Setting a device with a new community auto-adds it to the string list."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)
    reg = CommunityRegistry(path)
    reg.set_device("10.0.0.1", "brand-new-community", "arista_eos")
    assert "brand-new-community" in reg.strings
    path.unlink(missing_ok=True)


def test_extract_communities_import():
    """extract_communities_via_ssh is importable and callable."""
    from netops.core.community import extract_communities_via_ssh
    assert callable(extract_communities_via_ssh)


def test_try_communities_import():
    """try_communities is importable and callable."""
    from netops.core.community import try_communities
    assert callable(try_communities)
