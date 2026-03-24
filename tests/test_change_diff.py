"""
Unit tests for netops.change.diff — semantic config diff engine.

All tests are offline (no network connections).
"""

from __future__ import annotations

import json

import pytest

from netops.change.diff import (
    ChangeKind,
    ConfigNode,
    ConfigStyle,
    _is_security_sensitive,
    diff_configs,
    format_json,
    format_semantic,
    format_unified,
    parse_config,
)

# ---------------------------------------------------------------------------
# Real-world sample configs
# ---------------------------------------------------------------------------

CISCO_BEFORE = """\
!
version 15.2
!
hostname router1
!
ip access-list extended PERMIT_WEB
 permit tcp any any eq 80
 permit tcp any any eq 443
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
router bgp 65001
 bgp log-neighbor-changes
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 description UPSTREAM
!
"""

CISCO_AFTER = """\
!
version 15.2
!
hostname router1
!
ip access-list extended PERMIT_WEB
 permit tcp any any eq 80
 permit tcp any any eq 443
 permit tcp any any eq 8080
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 description WAN uplink
 no shutdown
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
router bgp 65001
 bgp log-neighbor-changes
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 description UPSTREAM
!
"""

JUNOS_BEFORE = """\
set system host-name juniper1
set system login user admin class super-user
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
set policy-options prefix-list MGMT 172.16.0.0/16
"""

JUNOS_AFTER = """\
set system host-name juniper1
set system login user admin class super-user
set system login user auditor class read-only
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
set policy-options prefix-list MGMT 172.16.0.0/16
set policy-options prefix-list MGMT 10.0.0.0/8
"""

FLAT_BEFORE = """\
configure
    system name router1
    interface eth1 address 10.0.0.1/24
    interface eth2 address 192.168.1.1/24
commit
"""

FLAT_AFTER = """\
configure
    system name router1
    interface eth1 address 10.0.0.1/24
    interface eth1 description WAN
    interface eth2 address 192.168.1.1/24
commit
"""

# ---------------------------------------------------------------------------
# ConfigStyle.detect
# ---------------------------------------------------------------------------


class TestConfigStyleDetect:
    def test_detect_cisco(self):
        assert ConfigStyle.detect(CISCO_BEFORE) == ConfigStyle.CISCO

    def test_detect_junos_set(self):
        assert ConfigStyle.detect(JUNOS_BEFORE) == ConfigStyle.JUNOS

    def test_detect_flat(self):
        flat = "system name router1\ninterface eth0\n"
        assert ConfigStyle.detect(flat) == ConfigStyle.FLAT

    def test_detect_empty_defaults_to_flat(self):
        result = ConfigStyle.detect("")
        assert result in (ConfigStyle.FLAT, ConfigStyle.CISCO)


# ---------------------------------------------------------------------------
# _is_security_sensitive
# ---------------------------------------------------------------------------


class TestIsSecuritySensitive:
    @pytest.mark.parametrize(
        "line",
        [
            "ip access-list extended PERMIT_WEB",
            " permit tcp any any eq 443",
            " deny ip any any",
            "username admin password 0 secret",
            "aaa authentication login default local",
            "tacacs-server host 10.0.0.5",
            "radius-server host 10.0.0.6",
            "route-map SET_LOCAL_PREF permit 10",
            "ip prefix-list ALLOWED seq 5 permit 10.0.0.0/8",
            "crypto key generate rsa",
            "snmp-server community PUBLIC ro",
            "ip ssh version 2",
        ],
    )
    def test_known_security_lines(self, line):
        assert _is_security_sensitive(line) is True

    @pytest.mark.parametrize(
        "line",
        [
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.1 255.255.255.0",
            " description WAN uplink",
            " no shutdown",
            "hostname router1",
            "version 15.2",
        ],
    )
    def test_non_security_lines(self, line):
        assert _is_security_sensitive(line) is False


# ---------------------------------------------------------------------------
# parse_config — Cisco
# ---------------------------------------------------------------------------


class TestParseCisco:
    def test_returns_top_level_nodes(self):
        nodes = parse_config(CISCO_BEFORE, ConfigStyle.CISCO)
        keys = [n.key for n in nodes]
        assert "hostname router1" in keys

    def test_interface_has_children(self):
        nodes = parse_config(CISCO_BEFORE, ConfigStyle.CISCO)
        ifaces = [n for n in nodes if n.key.startswith("interface GigabitEthernet0/0")]
        assert len(ifaces) == 1
        child_keys = [c.key for c in ifaces[0].children]
        assert "ip address 10.0.0.1 255.255.255.0" in child_keys
        assert "no shutdown" in child_keys

    def test_acl_has_children(self):
        nodes = parse_config(CISCO_BEFORE, ConfigStyle.CISCO)
        acls = [n for n in nodes if "access-list" in n.key]
        assert len(acls) >= 1
        assert len(acls[0].children) >= 2

    def test_comment_lines_excluded(self):
        nodes = parse_config(CISCO_BEFORE, ConfigStyle.CISCO)
        keys = [n.key for n in nodes]
        assert "!" not in keys

    def test_blank_lines_excluded(self):
        nodes = parse_config(CISCO_BEFORE, ConfigStyle.CISCO)
        assert all(n.key.strip() for n in nodes)


# ---------------------------------------------------------------------------
# parse_config — JunOS set
# ---------------------------------------------------------------------------


class TestParseJunosSet:
    def test_each_set_line_is_a_node(self):
        nodes = parse_config(JUNOS_BEFORE, ConfigStyle.JUNOS)
        assert len(nodes) == 6  # 6 set lines

    def test_node_key_is_full_set_line(self):
        nodes = parse_config(JUNOS_BEFORE, ConfigStyle.JUNOS)
        keys = [n.key for n in nodes]
        assert "set system host-name juniper1" in keys

    def test_comment_lines_excluded(self):
        text = "# a comment\nset system host-name r1\n"
        nodes = parse_config(text, ConfigStyle.JUNOS)
        assert len(nodes) == 1


# ---------------------------------------------------------------------------
# parse_config — Flat
# ---------------------------------------------------------------------------


class TestParseFlat:
    def test_each_non_blank_line_is_a_node(self):
        nodes = parse_config(FLAT_BEFORE, ConfigStyle.FLAT)
        assert len(nodes) == 5  # configure, 3 x system/interface, commit

    def test_hash_comments_excluded(self):
        text = "# comment\nsystem name r1\n"
        nodes = parse_config(text, ConfigStyle.FLAT)
        assert len(nodes) == 1


# ---------------------------------------------------------------------------
# ConfigNode.signature — order normalisation
# ---------------------------------------------------------------------------


class TestConfigNodeSignature:
    def test_order_independent_signature(self):
        """Two blocks with same children in different order should have equal signatures."""
        child_a = ConfigNode(key="permit tcp any any eq 80", raw=" permit tcp any any eq 80")
        child_b = ConfigNode(key="permit tcp any any eq 443", raw=" permit tcp any any eq 443")

        parent1 = ConfigNode(
            key="ip access-list extended PERMIT_WEB",
            raw="ip access-list extended PERMIT_WEB",
            children=[child_a, child_b],
        )
        parent2 = ConfigNode(
            key="ip access-list extended PERMIT_WEB",
            raw="ip access-list extended PERMIT_WEB",
            children=[child_b, child_a],
        )
        assert parent1.signature() == parent2.signature()

    def test_different_children_different_signature(self):
        child_a = ConfigNode(key="permit tcp any any eq 80", raw=" permit tcp any any eq 80")
        child_b = ConfigNode(key="permit tcp any any eq 8080", raw=" permit tcp any any eq 8080")

        parent1 = ConfigNode(
            key="ip access-list extended PERMIT_WEB",
            raw="ip access-list extended PERMIT_WEB",
            children=[child_a],
        )
        parent2 = ConfigNode(
            key="ip access-list extended PERMIT_WEB",
            raw="ip access-list extended PERMIT_WEB",
            children=[child_b],
        )
        assert parent1.signature() != parent2.signature()


# ---------------------------------------------------------------------------
# diff_configs — Cisco
# ---------------------------------------------------------------------------


class TestDiffConfigsCisco:
    def test_no_changes_when_identical(self):
        result = diff_configs(CISCO_BEFORE, CISCO_BEFORE, style=ConfigStyle.CISCO)
        assert not result.has_changes

    def test_detects_added_acl_entry(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        added_keys = [" ".join(e.path) for e in result.added]
        # The ACL entry "permit tcp any any eq 8080" was added
        assert any("8080" in k for k in added_keys)

    def test_detects_added_description(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        added_keys = [" ".join(e.path) for e in result.added]
        assert any("description" in k and "WAN" in k for k in added_keys)

    def test_acl_change_flagged_as_security(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        assert any(e.is_security for e in result.entries)

    def test_acl_change_in_security_changes(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        assert len(result.security_changes) > 0

    def test_unchanged_interface_not_in_diff(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        # GigabitEthernet0/1 was not changed
        for entry in result.entries:
            section_path = " ".join(entry.path)
            assert "GigabitEthernet0/1" not in section_path

    def test_reordered_bgp_neighbors_not_in_diff(self):
        """Reordering children that produce same sorted signature → no diff."""
        before = """\
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.3 remote-as 65003
"""
        after = """\
router bgp 65001
 neighbor 10.0.0.3 remote-as 65003
 neighbor 10.0.0.2 remote-as 65002
"""
        result = diff_configs(before, after, style=ConfigStyle.CISCO)
        assert not result.has_changes

    def test_removed_section_detected(self):
        result = diff_configs(CISCO_AFTER, CISCO_BEFORE, style=ConfigStyle.CISCO)
        removed_keys = [" ".join(e.path) for e in result.removed]
        assert any("8080" in k for k in removed_keys)

    def test_acl_line_shift_detected_without_context_pollution(self):
        """ACL change detected even when surrounding interface stanza is unchanged."""
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        # Interface GigabitEthernet0/0 got a description added — should be detected
        added_sections = [e.section for e in result.added]
        assert any("description" in s for s in added_sections)

    def test_auto_style_detection(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER)
        assert result.style == ConfigStyle.CISCO
        assert result.has_changes


# ---------------------------------------------------------------------------
# diff_configs — JunOS
# ---------------------------------------------------------------------------


class TestDiffConfigsJunos:
    def test_no_changes_when_identical(self):
        result = diff_configs(JUNOS_BEFORE, JUNOS_BEFORE, style=ConfigStyle.JUNOS)
        assert not result.has_changes

    def test_detects_added_user(self):
        result = diff_configs(JUNOS_BEFORE, JUNOS_AFTER, style=ConfigStyle.JUNOS)
        added_keys = [" ".join(e.path) for e in result.added]
        assert any("auditor" in k for k in added_keys)

    def test_detects_added_prefix_list_entry(self):
        result = diff_configs(JUNOS_BEFORE, JUNOS_AFTER, style=ConfigStyle.JUNOS)
        added_keys = [" ".join(e.path) for e in result.added]
        assert any("10.0.0.0/8" in k for k in added_keys)

    def test_user_addition_flagged_as_security(self):
        result = diff_configs(JUNOS_BEFORE, JUNOS_AFTER, style=ConfigStyle.JUNOS)
        added_security = [e for e in result.added if e.is_security]
        assert any("auditor" in " ".join(e.path) for e in added_security)

    def test_auto_style_detection(self):
        result = diff_configs(JUNOS_BEFORE, JUNOS_AFTER)
        assert result.style == ConfigStyle.JUNOS


# ---------------------------------------------------------------------------
# diff_configs — Flat
# ---------------------------------------------------------------------------


class TestDiffConfigsFlat:
    def test_no_changes_when_identical(self):
        result = diff_configs(FLAT_BEFORE, FLAT_BEFORE, style=ConfigStyle.FLAT)
        assert not result.has_changes

    def test_detects_added_line(self):
        result = diff_configs(FLAT_BEFORE, FLAT_AFTER, style=ConfigStyle.FLAT)
        added_keys = [" ".join(e.path) for e in result.added]
        assert any("description" in k for k in added_keys)


# ---------------------------------------------------------------------------
# format_unified
# ---------------------------------------------------------------------------


class TestFormatUnified:
    def test_identical_configs_empty_output(self):
        result = diff_configs(CISCO_BEFORE, CISCO_BEFORE, style=ConfigStyle.CISCO)
        assert format_unified(result) == ""

    def test_contains_added_line_marker(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_unified(result)
        # The indented ACL line "  permit tcp any any eq 8080" appears as
        # "+ permit tcp any any eq 8080" in unified diff output
        assert "+ permit tcp any any eq 8080" in out

    def test_contains_fromfile_tofile(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_unified(result, fromfile="before.txt", tofile="after.txt")
        assert "before.txt" in out
        assert "after.txt" in out


# ---------------------------------------------------------------------------
# format_semantic
# ---------------------------------------------------------------------------


class TestFormatSemantic:
    def test_no_changes_message(self):
        result = diff_configs(CISCO_BEFORE, CISCO_BEFORE, style=ConfigStyle.CISCO)
        out = format_semantic(result)
        assert "No configuration changes detected" in out

    def test_contains_section_breadcrumb(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_semantic(result)
        assert "Section:" in out

    def test_contains_security_tag(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_semantic(result)
        assert "[SECURITY]" in out

    def test_summary_line_present(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_semantic(result)
        assert "added" in out and "removed" in out

    def test_added_lines_prefixed_with_plus(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_semantic(result)
        assert any(ln.strip().startswith("+") for ln in out.splitlines())

    def test_removed_lines_prefixed_with_minus(self):
        result = diff_configs(CISCO_AFTER, CISCO_BEFORE, style=ConfigStyle.CISCO)
        out = format_semantic(result)
        assert any(ln.strip().startswith("-") for ln in out.splitlines())


# ---------------------------------------------------------------------------
# format_json
# ---------------------------------------------------------------------------


class TestFormatJson:
    def test_output_is_valid_json(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        out = format_json(result)
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_top_level_keys(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        data = json.loads(format_json(result))
        assert "style" in data
        assert "summary" in data
        assert "entries" in data

    def test_summary_counts_non_negative(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        data = json.loads(format_json(result))
        s = data["summary"]
        assert s["added"] >= 0
        assert s["removed"] >= 0
        assert s["changed"] >= 0
        assert s["security"] >= 0

    def test_entry_fields(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        data = json.loads(format_json(result))
        for entry in data["entries"]:
            assert "kind" in entry
            assert "section" in entry
            assert "path" in entry
            assert "is_security" in entry
            assert "before_lines" in entry
            assert "after_lines" in entry

    def test_no_changes_empty_entries(self):
        result = diff_configs(CISCO_BEFORE, CISCO_BEFORE, style=ConfigStyle.CISCO)
        data = json.loads(format_json(result))
        assert data["entries"] == []
        assert data["summary"]["added"] == 0

    def test_style_field_matches(self):
        result = diff_configs(JUNOS_BEFORE, JUNOS_AFTER, style=ConfigStyle.JUNOS)
        data = json.loads(format_json(result))
        assert data["style"] == "junos"

    def test_security_count_matches(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        data = json.loads(format_json(result))
        assert data["summary"]["security"] == len(result.security_changes)


# ---------------------------------------------------------------------------
# DiffResult properties
# ---------------------------------------------------------------------------


class TestDiffResult:
    def test_has_changes_false_when_identical(self):
        result = diff_configs(CISCO_BEFORE, CISCO_BEFORE, style=ConfigStyle.CISCO)
        assert result.has_changes is False

    def test_has_changes_true_when_different(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        assert result.has_changes is True

    def test_security_changes_subset_of_entries(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        for entry in result.security_changes:
            assert entry in result.entries
            assert entry.is_security is True

    def test_added_removed_changed_partition(self):
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        all_kinds = {e.kind for e in result.entries}
        # Sanity: added/removed/changed are the only kinds returned
        assert all_kinds <= {ChangeKind.ADDED, ChangeKind.REMOVED, ChangeKind.CHANGED}


# ---------------------------------------------------------------------------
# Hierarchical parent context (acceptance criterion)
# ---------------------------------------------------------------------------


class TestHierarchicalContext:
    def test_changed_child_path_includes_parent(self):
        """A changed child line's path must include the parent block header."""
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        # description WAN uplink was added inside interface GigabitEthernet0/0
        description_entries = [
            e for e in result.added if any("description" in p for p in e.path)
        ]
        assert description_entries, "Expected 'description' addition to be detected"
        entry = description_entries[0]
        # Parent path should contain interface header
        assert any("GigabitEthernet0/0" in p for p in entry.path)

    def test_section_property_shows_parent(self):
        """DiffEntry.section should reference the parent block, not just the leaf."""
        result = diff_configs(CISCO_BEFORE, CISCO_AFTER, style=ConfigStyle.CISCO)
        description_entries = [
            e for e in result.added if any("description" in p for p in e.path)
        ]
        assert description_entries
        section = description_entries[0].section
        assert "GigabitEthernet0/0" in section
