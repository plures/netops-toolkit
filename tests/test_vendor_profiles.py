"""Conformance tests for the canonical multivendor support registry."""

from __future__ import annotations

from netops.vendor_profiles import (
    PROBE_ORDER,
    PROFILES,
    SupportLevel,
    family_members,
    identify_vendor,
)


def test_every_probe_has_a_profile_and_required_deep_commands():
    """Auto-detection cannot target a vendor without an inventory command contract."""
    assert set(PROBE_ORDER) == set(PROFILES)
    for profile in PROFILES.values():
        commands = profile.commands_for("deep")
        assert commands["version"]
        assert commands["inventory"]
        assert profile.support["identification"] is SupportLevel.FULL
        assert profile.support["deep_inventory"] is SupportLevel.FULL


def test_known_fingerprints_resolve_to_the_canonical_profile():
    """Representative sysDescr and enterprise OID fingerprints remain stable."""
    cases = (
        ("Cisco IOS XE Software, Version 17.3", "", "cisco_xe"),
        ("Cisco IOS XR Software", "", "cisco_xr"),
        ("Cisco NX-OS Software", "", "cisco_nxos"),
        ("Cisco IOS Software, Version 15.4", "", "cisco_ios"),
        ("Nokia SRL Switch", "", "nokia_srl"),
        ("TiMOS-B-21.2.R1 SROS", "", "nokia_sros"),
        ("Linux", ".1.3.6.1.4.1.2636.1", "juniper_junos"),
        ("Linux", ".1.3.6.1.4.1.30065.1", "arista_eos"),
        ("Brocade Network OS VDX6740", "", "brocade_nos"),
        ("Foundry Networks FastIron GS", "", "brocade_fastiron"),
    )
    for description, object_id, expected in cases:
        assert identify_vendor(description, object_id) == expected


def test_md_cli_requires_an_explicit_capability_even_on_a_new_version():
    """An SR OS version alone cannot silently switch the command dialect."""
    profile = PROFILES["nokia_sros"]
    classic = profile.commands_for("show", version="24.10.R1")
    too_old = profile.commands_for("show", version="19.9.R1", capabilities={"md-cli"})
    md_cli = profile.commands_for("show", version="24.10.R1", capabilities={"md-cli"})

    assert classic["version"] == "show version"
    assert too_old["version"] == "show version"
    assert md_cli["version"] == "/show version"


def test_family_members_keep_requested_vendor_first():
    """Family probes retain the current retry behavior while using the registry."""
    assert family_members("cisco_xe") == ["cisco_xe", "cisco_ios", "cisco_xr", "cisco_nxos"]
    assert family_members("unmanaged") == ["unmanaged"]
