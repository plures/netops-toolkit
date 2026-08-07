"""Tests for Juniper JunOS CLI parsers."""

from __future__ import annotations

from netops.parsers.juniper import (
    parse_lldp_neighbors_junos,
    parse_lacp_interfaces_junos,
)

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

LLDP_NEIGHBORS_OUTPUT = """\
Local Interface    Parent Interface    Chassis Id          Port info          System Name
ge-0/0/0           -                   00:11:22:33:44:55   Ethernet1          switch-1
ge-0/0/1           ae0                 00:11:22:33:44:66   ge-0/0/0           router-2
xe-0/1/0           -                   aa:bb:cc:dd:ee:ff   1/1/1              nokia-3
"""

LLDP_NEIGHBORS_EMPTY = """\
Local Interface    Parent Interface    Chassis Id          Port info          System Name
"""

LACP_INTERFACES_OUTPUT = """\
Aggregated interface: ae0
    LACP state:       Role     Exp   Def  Dist  Col  Syn  Aggr  Timeout  Activity
      ge-0/0/0       Actor      No    No   Yes  Yes  Yes   Yes     Fast    Active
      ge-0/0/0     Partner      No    No   Yes  Yes  Yes   Yes     Fast    Active
      ge-0/0/1       Actor      No    No   Yes  Yes  Yes   Yes     Fast    Active
      ge-0/0/1     Partner      No    No   Yes  Yes  Yes   Yes     Fast    Active
    LACP protocol:        Receive State  Transmit State          Mux State
      ge-0/0/0                  Current   Fast periodic Collecting distributing
      ge-0/0/1                  Current   Fast periodic Collecting distributing
Aggregated interface: ae1
    LACP state:       Role     Exp   Def  Dist  Col  Syn  Aggr  Timeout  Activity
      xe-0/1/0       Actor      No    No   No   No   No    Yes     Slow   Passive
      xe-0/1/0     Partner      No    No   No   No   No    Yes     Slow   Passive
    LACP protocol:        Receive State  Transmit State          Mux State
      xe-0/1/0                  Current   Slow periodic Detached
"""

LACP_INTERFACES_EMPTY = """\
"""


# ===========================================================================
# parse_lldp_neighbors_junos
# ===========================================================================


class TestParseLldpNeighborsJunos:
    def test_returns_list(self):
        result = parse_lldp_neighbors_junos(LLDP_NEIGHBORS_OUTPUT)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_lldp_neighbors_junos(LLDP_NEIGHBORS_OUTPUT)
        assert len(result) == 3

    def test_first_neighbor(self):
        nbr = parse_lldp_neighbors_junos(LLDP_NEIGHBORS_OUTPUT)[0]
        assert nbr["local_interface"] == "ge-0/0/0"
        assert nbr["parent_interface"] == "-"
        assert nbr["chassis_id"] == "00:11:22:33:44:55"
        assert nbr["port_id"] == "Ethernet1"
        assert nbr["system_name"] == "switch-1"

    def test_parent_interface(self):
        nbr = parse_lldp_neighbors_junos(LLDP_NEIGHBORS_OUTPUT)[1]
        assert nbr["parent_interface"] == "ae0"

    def test_empty_output_returns_empty_list(self):
        result = parse_lldp_neighbors_junos(LLDP_NEIGHBORS_EMPTY)
        assert result == []

    def test_blank_string_returns_empty_list(self):
        assert parse_lldp_neighbors_junos("") == []


# ===========================================================================
# parse_lacp_interfaces_junos
# ===========================================================================


class TestParseLacpInterfacesJunos:
    def test_returns_list(self):
        result = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)
        assert len(result) == 2

    def test_ae0_name(self):
        ae0 = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)[0]
        assert ae0["name"] == "ae0"

    def test_ae0_member_count(self):
        ae0 = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)[0]
        assert ae0["member_count"] == 2

    def test_ae0_members(self):
        ae0 = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)[0]
        member_names = [m["interface"] for m in ae0["members"]]
        assert "ge-0/0/0" in member_names
        assert "ge-0/0/1" in member_names

    def test_ae0_member_activity(self):
        ae0 = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)[0]
        for m in ae0["members"]:
            assert m["activity"] == "Active"

    def test_ae1_single_member(self):
        ae1 = parse_lacp_interfaces_junos(LACP_INTERFACES_OUTPUT)[1]
        assert ae1["name"] == "ae1"
        assert ae1["member_count"] == 1
        assert ae1["members"][0]["interface"] == "xe-0/1/0"
        assert ae1["members"][0]["activity"] == "Passive"

    def test_empty_output_returns_empty_list(self):
        result = parse_lacp_interfaces_junos(LACP_INTERFACES_EMPTY)
        assert result == []

    def test_blank_string_returns_empty_list(self):
        assert parse_lacp_interfaces_junos("") == []
