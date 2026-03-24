"""Tests for VLAN parsers and audit check logic."""

from __future__ import annotations

import pytest

from netops.parsers.vlan import expand_vlan_range, parse_interfaces_trunk, parse_vlan_brief
from netops.check.vlan import (
    _check_name_mismatches,
    _check_trunk_vlans,
    _find_extra_vlans,
    _find_missing_vlans,
    _parse_vlan_db,
    build_vlan_report,
)

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

CISCO_VLAN_BRIEF = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/0, Gi0/1
10   MANAGEMENT                       active    Gi0/2, Gi0/3
20   SERVERS                          active    Gi1/0, Gi1/1
100  DMZ                              active    Gi1/2
200  GUEST                            active
1002 fddi-default                     act/unsup
1003 token-ring-default               act/unsup
1004 fddinet-default                  act/unsup
1005 trnet-default                    act/unsup
"""

CISCO_VLAN_BRIEF_MULTILINE_PORTS = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/0, Gi0/1, Gi0/2, Gi0/3,
                                                Gi0/4, Gi0/5
10   MANAGEMENT                       active    Gi1/0
"""

CISCO_VLAN_BRIEF_EMPTY = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
"""

CISCO_INTERFACES_TRUNK = """\
Port        Mode             Encapsulation  Status        Native vlan
Gi0/0       on               802.1q         trunking      1
Gi0/1       auto             n-802.1q       not-trunking  1

Port        Vlans allowed on trunk
Gi0/0       1-4094
Gi0/1       1-4094

Port        Vlans allowed and active in management domain
Gi0/0       1,10,20,100,200
Gi0/1       none

Port        Vlans in spanning tree forwarding state and not pruned
Gi0/0       1,10,20,100,200
Gi0/1       none
"""

CISCO_INTERFACES_TRUNK_EMPTY = """\
Port        Mode             Encapsulation  Status        Native vlan

Port        Vlans allowed on trunk

Port        Vlans allowed and active in management domain

Port        Vlans in spanning tree forwarding state and not pruned
"""


# ===========================================================================
# expand_vlan_range
# ===========================================================================


class TestExpandVlanRange:
    @pytest.mark.parametrize(
        "ranges,expected",
        [
            ("10", {10}),
            ("10,20,30", {10, 20, 30}),
            ("10-14", {10, 11, 12, 13, 14}),
            ("1,10-12,20", {1, 10, 11, 12, 20}),
            ("none", set()),
            ("", set()),
            ("NONE", set()),
        ],
    )
    def test_known_inputs(self, ranges, expected):
        assert expand_vlan_range(ranges) == expected

    def test_single_vlan(self):
        assert expand_vlan_range("100") == {100}

    def test_range_inclusive(self):
        result = expand_vlan_range("10-13")
        assert result == {10, 11, 12, 13}

    def test_whitespace_tolerance(self):
        assert expand_vlan_range(" 10 , 20 ") == {10, 20}

    def test_non_parseable_token_ignored(self):
        # "abc" is silently skipped, valid tokens are still parsed
        result = expand_vlan_range("10,abc,20")
        assert result == {10, 20}


# ===========================================================================
# parse_vlan_brief
# ===========================================================================


class TestParseVlanBrief:
    def test_returns_list(self):
        result = parse_vlan_brief(CISCO_VLAN_BRIEF)
        assert isinstance(result, list)

    def test_correct_vlan_count(self):
        result = parse_vlan_brief(CISCO_VLAN_BRIEF)
        assert len(result) == 9

    def test_vlan_fields_present(self):
        vlans = parse_vlan_brief(CISCO_VLAN_BRIEF)
        for v in vlans:
            for key in ("vlan_id", "name", "status", "ports"):
                assert key in v

    def test_first_vlan_id(self):
        vlans = parse_vlan_brief(CISCO_VLAN_BRIEF)
        assert vlans[0]["vlan_id"] == 1
        assert vlans[0]["name"] == "default"
        assert vlans[0]["status"] == "active"

    def test_vlan_with_ports(self):
        vlans = parse_vlan_brief(CISCO_VLAN_BRIEF)
        mgmt = next(v for v in vlans if v["vlan_id"] == 10)
        assert mgmt["name"] == "MANAGEMENT"
        assert "Gi0/2" in mgmt["ports"]
        assert "Gi0/3" in mgmt["ports"]

    def test_vlan_no_ports(self):
        vlans = parse_vlan_brief(CISCO_VLAN_BRIEF)
        guest = next(v for v in vlans if v["vlan_id"] == 200)
        assert guest["ports"] == []

    def test_system_vlan_status(self):
        vlans = parse_vlan_brief(CISCO_VLAN_BRIEF)
        fddi = next(v for v in vlans if v["vlan_id"] == 1002)
        assert fddi["status"] == "act/unsup"

    def test_multiline_ports_continuation(self):
        vlans = parse_vlan_brief(CISCO_VLAN_BRIEF_MULTILINE_PORTS)
        default = next(v for v in vlans if v["vlan_id"] == 1)
        # Should include ports from both lines
        assert "Gi0/4" in default["ports"]
        assert "Gi0/5" in default["ports"]

    def test_empty_table_returns_empty_list(self):
        assert parse_vlan_brief(CISCO_VLAN_BRIEF_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_vlan_brief("") == []


# ===========================================================================
# parse_interfaces_trunk
# ===========================================================================


class TestParseInterfacesTrunk:
    def test_returns_list(self):
        result = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        assert isinstance(result, list)

    def test_correct_port_count(self):
        result = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        assert len(result) == 2

    def test_trunking_port_fields(self):
        trunks = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        gi00 = next(t for t in trunks if t["port"] == "Gi0/0")
        assert gi00["mode"] == "on"
        assert gi00["encapsulation"] == "802.1q"
        assert gi00["status"] == "trunking"
        assert gi00["native_vlan"] == 1

    def test_not_trunking_port(self):
        trunks = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        gi01 = next(t for t in trunks if t["port"] == "Gi0/1")
        assert gi01["status"] == "not-trunking"

    def test_active_vlans_parsed(self):
        trunks = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        gi00 = next(t for t in trunks if t["port"] == "Gi0/0")
        assert gi00["active_vlans"] == {1, 10, 20, 100, 200}

    def test_active_vlans_none_for_not_trunking(self):
        trunks = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        gi01 = next(t for t in trunks if t["port"] == "Gi0/1")
        assert gi01["active_vlans"] == set()

    def test_forwarding_vlans_parsed(self):
        trunks = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        gi00 = next(t for t in trunks if t["port"] == "Gi0/0")
        assert gi00["forwarding_vlans"] == {1, 10, 20, 100, 200}

    def test_allowed_vlans_raw_string(self):
        trunks = parse_interfaces_trunk(CISCO_INTERFACES_TRUNK)
        gi00 = next(t for t in trunks if t["port"] == "Gi0/0")
        assert gi00["allowed_vlans"] == "1-4094"

    def test_empty_output_returns_empty_list(self):
        assert parse_interfaces_trunk("") == []

    def test_no_trunk_ports_returns_empty_list(self):
        assert parse_interfaces_trunk(CISCO_INTERFACES_TRUNK_EMPTY) == []


# ===========================================================================
# _find_missing_vlans
# ===========================================================================


class TestFindMissingVlans:
    def test_all_present_returns_empty(self):
        assert _find_missing_vlans({10, 20, 100}, {10, 20, 100}) == []

    def test_one_missing(self):
        assert _find_missing_vlans({10, 20}, {10, 20, 100}) == [100]

    def test_multiple_missing_sorted(self):
        result = _find_missing_vlans({10}, {10, 20, 100})
        assert result == [20, 100]

    def test_extra_vlans_not_flagged(self):
        # Actual has VLAN 999 which is not expected — that's not "missing"
        assert _find_missing_vlans({10, 20, 100, 999}, {10, 20, 100}) == []

    def test_empty_actual(self):
        result = _find_missing_vlans(set(), {10, 20})
        assert result == [10, 20]

    def test_empty_expected(self):
        assert _find_missing_vlans({10, 20}, set()) == []


# ===========================================================================
# _find_extra_vlans
# ===========================================================================


class TestFindExtraVlans:
    def test_no_extras(self):
        assert _find_extra_vlans({10, 20}, {10, 20}) == []

    def test_extra_vlan(self):
        assert _find_extra_vlans({10, 20, 999}, {10, 20}) == [999]

    def test_system_vlans_excluded(self):
        # 1002-1005 are always excluded
        result = _find_extra_vlans({10, 1002, 1003, 1004, 1005}, {10})
        assert result == []

    def test_ignore_vlans_excluded(self):
        result = _find_extra_vlans({10, 1, 2}, {10}, ignore_ids={1, 2})
        assert result == []

    def test_multiple_extras_sorted(self):
        result = _find_extra_vlans({10, 30, 50, 999}, {10})
        assert result == [30, 50, 999]


# ===========================================================================
# _check_name_mismatches
# ===========================================================================


class TestCheckNameMismatches:
    def _vlans(self, *pairs):
        return [{"vlan_id": vlan_id, "name": name, "status": "active", "ports": []}
                for vlan_id, name in pairs]

    def test_no_mismatches(self):
        vlans = self._vlans((10, "MANAGEMENT"), (20, "SERVERS"))
        result = _check_name_mismatches(vlans, {10: "MANAGEMENT", 20: "SERVERS"})
        assert result == []

    def test_one_mismatch(self):
        vlans = self._vlans((10, "MGMT"), (20, "SERVERS"))
        result = _check_name_mismatches(vlans, {10: "MANAGEMENT", 20: "SERVERS"})
        assert len(result) == 1
        assert result[0]["vlan_id"] == 10
        assert result[0]["expected_name"] == "MANAGEMENT"
        assert result[0]["actual_name"] == "MGMT"

    def test_vlan_absent_from_actual_not_flagged(self):
        # VLAN 100 in expected_names but not on switch — missing, not a name mismatch
        vlans = self._vlans((10, "MANAGEMENT"))
        result = _check_name_mismatches(vlans, {10: "MANAGEMENT", 100: "DMZ"})
        assert result == []

    def test_multiple_mismatches_sorted_by_vlan_id(self):
        vlans = self._vlans((20, "SRV"), (10, "MGT"))
        result = _check_name_mismatches(vlans, {10: "MANAGEMENT", 20: "SERVERS"})
        assert [r["vlan_id"] for r in result] == [10, 20]


# ===========================================================================
# _check_trunk_vlans
# ===========================================================================


class TestCheckTrunkVlans:
    def _trunk(self, port, status="trunking", active_vlans=None):
        return {
            "port": port,
            "mode": "on",
            "encapsulation": "802.1q",
            "status": status,
            "native_vlan": 1,
            "allowed_vlans": "1-4094",
            "active_vlans": active_vlans or set(),
            "forwarding_vlans": active_vlans or set(),
        }

    def test_all_vlans_active_no_mismatch(self):
        trunks = [self._trunk("Gi0/0", active_vlans={10, 20, 100})]
        result = _check_trunk_vlans(trunks, {10, 20, 100})
        assert result == []

    def test_missing_vlan_on_trunk(self):
        trunks = [self._trunk("Gi0/0", active_vlans={10, 20})]
        result = _check_trunk_vlans(trunks, {10, 20, 100})
        assert len(result) == 1
        assert result[0]["port"] == "Gi0/0"
        assert 100 in result[0]["missing_vlans"]

    def test_not_trunking_port_skipped(self):
        trunks = [self._trunk("Gi0/1", status="not-trunking", active_vlans=set())]
        result = _check_trunk_vlans(trunks, {10, 20, 100})
        assert result == []

    def test_multiple_trunks_one_mismatch(self):
        trunks = [
            self._trunk("Gi0/0", active_vlans={10, 20, 100}),
            self._trunk("Gi0/1", active_vlans={10, 20}),
        ]
        result = _check_trunk_vlans(trunks, {10, 20, 100})
        assert len(result) == 1
        assert result[0]["port"] == "Gi0/1"

    def test_empty_trunks(self):
        assert _check_trunk_vlans([], {10, 20}) == []


# ===========================================================================
# build_vlan_report
# ===========================================================================


class TestBuildVlanReport:
    def _make_result(
        self,
        host,
        success=True,
        compliant=True,
        missing_vlans=None,
        extra_vlans=None,
        name_mismatches=None,
        trunk_mismatches=None,
    ):
        return {
            "host": host,
            "timestamp": "2026-01-01T00:00:00Z",
            "success": success,
            "actual_vlans": [],
            "trunks": [],
            "missing_vlans": missing_vlans or [],
            "extra_vlans": extra_vlans or [],
            "name_mismatches": name_mismatches or [],
            "trunk_mismatches": trunk_mismatches or [],
            "compliant": compliant,
            "alerts": [],
            "error": None,
        }

    def test_empty_results(self):
        report = build_vlan_report([])
        assert report["switches"] == 0
        assert report["switches_reachable"] == 0
        assert report["switches_compliant"] == 0
        assert report["overall_alert"] is False

    def test_single_compliant_switch(self):
        result = self._make_result("sw1")
        report = build_vlan_report([result])
        assert report["switches"] == 1
        assert report["switches_reachable"] == 1
        assert report["switches_compliant"] == 1
        assert report["overall_alert"] is False

    def test_unreachable_switch_not_compliant(self):
        result = self._make_result("sw1", success=False, compliant=False)
        report = build_vlan_report([result])
        assert report["switches"] == 1
        assert report["switches_reachable"] == 0
        assert report["switches_compliant"] == 0
        assert report["overall_alert"] is False

    def test_missing_vlans_triggers_alert(self):
        result = self._make_result("sw1", compliant=False, missing_vlans=[100, 200])
        report = build_vlan_report([result])
        assert report["overall_alert"] is True
        assert len(report["missing_vlan_switches"]) == 1
        assert report["missing_vlan_switches"][0]["host"] == "sw1"
        assert report["missing_vlan_switches"][0]["missing_vlans"] == [100, 200]

    def test_extra_vlans_triggers_alert(self):
        result = self._make_result("sw1", compliant=False, extra_vlans=[999])
        report = build_vlan_report([result])
        assert report["overall_alert"] is True
        assert len(report["extra_vlan_switches"]) == 1

    def test_name_mismatch_triggers_alert(self):
        nm = [{"vlan_id": 10, "expected_name": "MANAGEMENT", "actual_name": "MGMT"}]
        result = self._make_result("sw1", compliant=False, name_mismatches=nm)
        report = build_vlan_report([result])
        assert report["overall_alert"] is True
        assert len(report["name_mismatch_switches"]) == 1

    def test_trunk_mismatch_triggers_alert(self):
        tm = [{"port": "Gi0/0", "missing_vlans": [100]}]
        result = self._make_result("sw1", compliant=False, trunk_mismatches=tm)
        report = build_vlan_report([result])
        assert report["overall_alert"] is True
        assert len(report["trunk_mismatch_switches"]) == 1

    def test_multi_switch_aggregation(self):
        r1 = self._make_result("sw1")
        r2 = self._make_result("sw2", compliant=False, missing_vlans=[100])
        r3 = self._make_result("sw3", success=False, compliant=False)
        report = build_vlan_report([r1, r2, r3])
        assert report["switches"] == 3
        assert report["switches_reachable"] == 2
        assert report["switches_compliant"] == 1
        assert report["overall_alert"] is True

    def test_compliant_switches_counted_correctly(self):
        results = [self._make_result(f"sw{i}") for i in range(3)]
        report = build_vlan_report(results)
        assert report["switches_compliant"] == 3
        assert report["overall_alert"] is False


# ===========================================================================
# _parse_vlan_db
# ===========================================================================


class TestParseVlanDb:
    def test_basic_vlan_db(self, tmp_path):
        db = tmp_path / "vlans.yaml"
        db.write_text("vlans:\n  10: MANAGEMENT\n  20: SERVERS\n  100: DMZ\n")
        expected_vlans, expected_names = _parse_vlan_db(str(db))
        assert expected_vlans == {10, 20, 100}
        assert expected_names == {10: "MANAGEMENT", 20: "SERVERS", 100: "DMZ"}

    def test_empty_vlans_section(self, tmp_path):
        db = tmp_path / "vlans.yaml"
        db.write_text("vlans: {}\n")
        expected_vlans, expected_names = _parse_vlan_db(str(db))
        assert expected_vlans == set()
        assert expected_names == {}

    def test_missing_vlans_key(self, tmp_path):
        db = tmp_path / "vlans.yaml"
        db.write_text("{}\n")
        expected_vlans, expected_names = _parse_vlan_db(str(db))
        assert expected_vlans == set()
        assert expected_names == {}

    def test_string_keys_converted_to_int(self, tmp_path):
        db = tmp_path / "vlans.yaml"
        # YAML string keys
        db.write_text("vlans:\n  '10': MANAGEMENT\n")
        expected_vlans, expected_names = _parse_vlan_db(str(db))
        assert 10 in expected_vlans
        assert expected_names[10] == "MANAGEMENT"
